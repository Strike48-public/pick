//! Conversation-document listing + shareable-link creation over Matrix GraphQL.
//!
//! Reuses `MatrixChatClient::execute_gql` (the same authed path as agent/
//! conversation queries). Documents are written by the server-side agent
//! (via its `document_write` tool); Pick only lists and shares them.

use serde::Deserialize;

use super::client::MatrixChatClient;

/// A conversation document as shown in the Easy Mode Documents list.
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentSummary {
    pub id: String,
    pub title: String,
    pub doc_type: String,
    /// The conversation the document belongs to (used to build open/share refs).
    pub conversation_id: String,
    /// ISO-8601 creation time — the document's `created_at` metadata (when Pick's
    /// agent wrote it), surfaced by the GraphQL `timestamp` field. Used to pick
    /// the most recently created report. Empty if the server didn't supply one.
    pub timestamp: String,
}

/// Build the shared-link `resource_id` for a conversation document.
pub fn share_resource_id(conversation_id: &str, document_id: &str) -> String {
    format!("{conversation_id}:{document_id}")
}

/// Add `preview=1` to a share URL. Without it, the `/s/:token` route redirects
/// to the Studio SPA documents view; `preview=1` renders the report's markdown
/// inline as a standalone page. Appends `?preview=1` when the URL has no query
/// string, `&preview=1` otherwise.
pub fn preview_url(url: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}preview=1")
}

// -- GraphQL deserialize shapes --

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListDocumentsData {
    list_documents: DocumentEdges,
}

#[derive(Deserialize)]
struct DocumentEdges {
    edges: Vec<DocumentEdge>,
}

#[derive(Deserialize)]
struct DocumentEdge {
    node: DocumentNode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DocumentNode {
    id: String,
    title: String,
    #[serde(rename = "type")]
    doc_type: String,
    conversation: Option<DocumentConversation>,
    #[serde(default)]
    timestamp: Option<String>,
}

#[derive(Deserialize)]
struct DocumentConversation {
    id: String,
}

pub(crate) fn documents_from_data(data: ListDocumentsData) -> Vec<DocumentSummary> {
    data.list_documents
        .edges
        .into_iter()
        .map(|e| DocumentSummary {
            id: e.node.id,
            title: e.node.title,
            doc_type: e.node.doc_type,
            conversation_id: e.node.conversation.map(|c| c.id).unwrap_or_default(),
            timestamp: e.node.timestamp.unwrap_or_default(),
        })
        .collect()
}

/// Return the document Pick's agent created most recently, by its `created_at`
/// metadata (the `timestamp` field), or `None` if there are none. The caller
/// passes docs already filtered to this connector's agent, so this is "the
/// latest report this connector produced." Easy Mode shows that single current
/// report rather than an accumulating list of near-identical scan reports.
pub fn latest_document(mut docs: Vec<DocumentSummary>) -> Option<DocumentSummary> {
    // ISO-8601 timestamps sort lexicographically in chronological order, so the
    // max by string compare is the most recently created.
    docs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    docs.into_iter().next()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSharedLinkData {
    create_shared_link: CreateSharedLinkPayload,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSharedLinkPayload {
    shared_link: Option<SharedLinkNode>,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct SharedLinkNode {
    url: String,
}

// `listDocuments` is a Relay connection, so it requires a pagination arg
// (`first` or `last`) even though the schema only lists `filter` explicitly —
// omitting it returns a "You must provide either 'first' or 'last'" error.
const LIST_DOCUMENTS_QUERY: &str = r#"
    query ListDocuments($first: Int, $filter: ListDocumentsFilter) {
        listDocuments(first: $first, filter: $filter) {
            edges {
                node {
                    id
                    title
                    type
                    timestamp
                    conversation { id }
                }
            }
        }
    }
"#;

/// Page size for the document list. Easy Mode shows a flat report list, so one
/// generous page is enough (no infinite scroll).
const DOCUMENTS_PAGE_SIZE: i32 = 100;

const CREATE_SHARED_LINK_QUERY: &str = r#"
    mutation CreateSharedLink($input: CreateSharedLinkInput!) {
        createSharedLink(input: $input) {
            sharedLink { url }
            errors
        }
    }
"#;

const GET_DOCUMENT_QUERY: &str = r#"
    query GetDocument($conversationId: ID!, $documentId: ID!) {
        document(conversationId: $conversationId, documentId: $documentId) {
            id
            title
            type
            content
        }
    }
"#;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetDocumentData {
    document: Option<DocumentContentNode>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DocumentContentNode {
    #[serde(default)]
    content: Option<String>,
}

impl MatrixChatClient {
    /// List conversation documents visible to the authenticated user, optionally
    /// filtered to a single agent.
    pub async fn list_documents(
        &self,
        agent_id: Option<&str>,
    ) -> crate::error::Result<Vec<DocumentSummary>> {
        let filter = match agent_id {
            Some(id) => serde_json::json!({ "agentId": id }),
            None => serde_json::Value::Null,
        };
        let data: ListDocumentsData = self
            .execute_gql(
                LIST_DOCUMENTS_QUERY,
                serde_json::json!({ "first": DOCUMENTS_PAGE_SIZE, "filter": filter }),
            )
            .await?;
        Ok(documents_from_data(data))
    }

    /// Create a shareable link for a conversation document; returns the URL.
    pub async fn create_shared_link(
        &self,
        conversation_id: &str,
        document_id: &str,
    ) -> crate::error::Result<String> {
        let variables = serde_json::json!({
            "input": {
                "resourceType": "conversation_document",
                "resourceId": share_resource_id(conversation_id, document_id),
                // Public scope so the /s/:token page opens without a Studio
                // login — both for tapping "open" and for sharing the link with
                // someone who has no account.
                "accessScope": "public",
            }
        });
        let data: CreateSharedLinkData = self
            .execute_gql(CREATE_SHARED_LINK_QUERY, variables)
            .await?;
        let payload = data.create_shared_link;
        if let Some(link) = payload.shared_link {
            Ok(link.url)
        } else {
            let msg = if payload.errors.is_empty() {
                "createSharedLink returned no link and no error".to_string()
            } else {
                payload.errors.join("; ")
            };
            Err(crate::error::Error::Matrix(msg))
        }
    }

    /// Fetch a single document's markdown content for in-app rendering.
    pub async fn get_document_content(
        &self,
        conversation_id: &str,
        document_id: &str,
    ) -> crate::error::Result<String> {
        let variables = serde_json::json!({
            "conversationId": conversation_id,
            "documentId": document_id,
        });
        let data: GetDocumentData = self.execute_gql(GET_DOCUMENT_QUERY, variables).await?;
        match data.document {
            Some(doc) => Ok(doc.content.unwrap_or_default()),
            None => Err(crate::error::Error::Matrix(
                "document not found".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_id_joins_conversation_and_document() {
        assert_eq!(share_resource_id("conv-1", "doc-9"), "conv-1:doc-9");
    }

    #[test]
    fn preview_url_appends_preview_param() {
        assert_eq!(
            preview_url("https://studio.example.test/s/tok"),
            "https://studio.example.test/s/tok?preview=1"
        );
    }

    #[test]
    fn preview_url_uses_ampersand_when_query_present() {
        assert_eq!(
            preview_url("https://studio.example.test/s/tok?x=1"),
            "https://studio.example.test/s/tok?x=1&preview=1"
        );
    }

    #[test]
    fn documents_from_data_maps_edges_flattens_conversation_and_timestamp() {
        let raw = serde_json::json!({
            "listDocuments": { "edges": [
                { "node": { "id": "network-discovery-report", "title": "Local Network Discovery Report",
                            "type": "markdown", "timestamp": "2026-07-20T21:27:58Z",
                            "conversation": { "id": "conv-abc" } } },
                { "node": { "id": "d2", "title": "Other", "type": "markdown", "conversation": null } }
            ]}
        });
        let data: ListDocumentsData = serde_json::from_value(raw).unwrap();
        let out = documents_from_data(data);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, "network-discovery-report");
        assert_eq!(out[0].conversation_id, "conv-abc");
        assert_eq!(out[0].timestamp, "2026-07-20T21:27:58Z");
        assert_eq!(out[1].conversation_id, ""); // null conversation -> empty
        assert_eq!(out[1].timestamp, ""); // missing timestamp -> empty
    }

    fn doc(id: &str, ts: &str) -> DocumentSummary {
        DocumentSummary {
            id: id.to_string(),
            title: "Local Network Discovery Report".to_string(),
            doc_type: "markdown".to_string(),
            conversation_id: "c".to_string(),
            timestamp: ts.to_string(),
        }
    }

    #[test]
    fn latest_document_picks_most_recent_by_timestamp() {
        let docs = vec![
            doc("old", "2026-07-20T10:00:00Z"),
            doc("newest", "2026-07-20T21:27:58Z"),
            doc("mid", "2026-07-20T15:00:00Z"),
        ];
        assert_eq!(latest_document(docs).unwrap().id, "newest");
    }

    #[test]
    fn latest_document_none_when_empty() {
        assert!(latest_document(vec![]).is_none());
    }
}
