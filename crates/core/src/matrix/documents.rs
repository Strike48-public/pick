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
}

/// Build the shared-link `resource_id` for a conversation document.
pub fn share_resource_id(conversation_id: &str, document_id: &str) -> String {
    format!("{conversation_id}:{document_id}")
}

/// Derive the Studio browser base URL (scheme + host) from `MATRIX_API_URL`,
/// dropping any `/api/...` path so we can build `/conversations/:id` links.
pub fn studio_web_base(api_url: &str) -> String {
    // `normalize_url` returns `&str`; pass it directly (no extra `&`).
    let normalized = super::normalize_url(api_url);
    match reqwest::Url::parse(normalized) {
        Ok(u) => {
            let scheme = u.scheme();
            match u.host_str() {
                Some(host) => match u.port() {
                    Some(port) => format!("{scheme}://{host}:{port}"),
                    None => format!("{scheme}://{host}"),
                },
                None => normalized.trim_end_matches('/').to_string(),
            }
        }
        Err(_) => normalized.trim_end_matches('/').to_string(),
    }
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
        })
        .collect()
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

const LIST_DOCUMENTS_QUERY: &str = r#"
    query ListDocuments($filter: ListDocumentsFilter) {
        listDocuments(filter: $filter) {
            edges {
                node {
                    id
                    title
                    type
                    conversation { id }
                }
            }
        }
    }
"#;

const CREATE_SHARED_LINK_QUERY: &str = r#"
    mutation CreateSharedLink($input: CreateSharedLinkInput!) {
        createSharedLink(input: $input) {
            sharedLink { url }
            errors
        }
    }
"#;

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
            .execute_gql(LIST_DOCUMENTS_QUERY, serde_json::json!({ "filter": filter }))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_id_joins_conversation_and_document() {
        assert_eq!(share_resource_id("conv-1", "doc-9"), "conv-1:doc-9");
    }

    #[test]
    fn studio_web_base_strips_api_path() {
        assert_eq!(studio_web_base("https://studio.example.test/api/v1alpha"), "https://studio.example.test");
        assert_eq!(studio_web_base("https://studio.example.test"), "https://studio.example.test");
        assert_eq!(studio_web_base("https://studio.example.test/"), "https://studio.example.test");
    }

    #[test]
    fn documents_from_data_maps_edges_and_flattens_conversation_id() {
        let raw = serde_json::json!({
            "listDocuments": { "edges": [
                { "node": { "id": "network-discovery-report", "title": "Local Network Discovery Report",
                            "type": "markdown", "conversation": { "id": "conv-abc" } } },
                { "node": { "id": "d2", "title": "Other", "type": "markdown", "conversation": null } }
            ]}
        });
        let data: ListDocumentsData = serde_json::from_value(raw).unwrap();
        let out = documents_from_data(data);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, "network-discovery-report");
        assert_eq!(out[0].conversation_id, "conv-abc");
        assert_eq!(out[1].conversation_id, ""); // null conversation -> empty
    }
}
