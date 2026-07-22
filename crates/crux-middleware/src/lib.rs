//! EffectMiddleware fulfilling PentestOperation via pentest-core. The App is
//! pure; this crate owns all I/O, on a background tokio runtime.

use crux_core::middleware::{EffectMiddleware, EffectResolver};
use pentest_core::matrix::ChatClient;
use pick_crux_core::effect::{ConversationDelta, PentestOperation, PentestOutcome};
use pick_crux_core::view::{ConversationRef, DocRef, MessageView};

#[async_trait::async_trait]
pub trait MatrixApi: Send + Sync {
    async fn send(&self, conversation_id: Option<String>, text: String) -> Result<String, String>;
    async fn poll(&self, conversation_id: String) -> Result<ConversationDelta, String>;
    async fn list_documents(&self, agent_id: Option<String>) -> Result<Vec<DocRef>, String>;
    async fn sign_in(&self, api_url: String) -> Result<String, String>;
    async fn doc_content(
        &self,
        document_id: String,
        conversation_id: String,
    ) -> Result<String, String>;
    async fn shared_link(
        &self,
        conversation_id: String,
        document_id: String,
    ) -> Result<String, String>;
    async fn list_conversations(&self) -> Result<Vec<ConversationRef>, String>;
    async fn load_conversation(&self, conversation_id: String) -> Result<Vec<MessageView>, String>;
}

/// Pure mapping from an operation to an outcome via the injected api. Unit-tested.
pub async fn map_operation(api: &dyn MatrixApi, op: PentestOperation) -> PentestOutcome {
    match op {
        PentestOperation::SendScan {
            conversation_id,
            prompt,
        } => match api.send(conversation_id, prompt).await {
            Ok(c) => PentestOutcome::ScanQueued { conversation_id: c },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::SendMessage {
            conversation_id,
            text,
        } => match api.send(conversation_id, text).await {
            Ok(c) => PentestOutcome::ScanQueued { conversation_id: c },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::PollConversation { conversation_id } => {
            match api.poll(conversation_id).await {
                Ok(d) => PentestOutcome::Delta(d),
                Err(m) => PentestOutcome::Error { message: m },
            }
        }
        PentestOperation::ListDocuments { agent_id } => match api.list_documents(agent_id).await {
            Ok(l) => PentestOutcome::Documents { list: l },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::SignIn { api_url } => match api.sign_in(api_url).await {
            Ok(t) => PentestOutcome::SignedIn { token: t },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::Connect { .. } => PentestOutcome::Connected,
        PentestOperation::GetDocumentContent {
            document_id,
            conversation_id,
        } => match api.doc_content(document_id, conversation_id).await {
            Ok(md) => PentestOutcome::DocumentContent { markdown: md },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::CreateSharedLink {
            conversation_id,
            document_id,
        } => match api.shared_link(conversation_id, document_id).await {
            Ok(u) => PentestOutcome::SharedLink { url: u },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::ListConversations => match api.list_conversations().await {
            Ok(l) => PentestOutcome::Conversations { list: l },
            Err(m) => PentestOutcome::Error { message: m },
        },
        PentestOperation::LoadConversation { conversation_id } => {
            match api.load_conversation(conversation_id).await {
                Ok(m) => PentestOutcome::LoadedMessages { messages: m },
                Err(e) => PentestOutcome::Error { message: e },
            }
        }
    }
}

/// The real MatrixApi backed by pentest-core (constructed with api_url + token).
pub struct CoreMatrixApi {
    pub api_url: String,
    pub token: String,
    pub agent_id: Option<String>,
}

#[async_trait::async_trait]
impl MatrixApi for CoreMatrixApi {
    async fn send(&self, conversation_id: Option<String>, text: String) -> Result<String, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        let agent = self.agent_id.clone().unwrap_or_default();
        let conv = conversation_id.unwrap_or_default();
        // send_message returns a message_id; we return the conversation_id.
        // When conv is empty, server creates a new conversation, but send_message doesn't
        // return the conversation id - we'd need to poll or create explicitly. For slice-1
        // this just returns the same conv id.
        client
            .send_message(&conv, &agent, &text)
            .await
            .map_err(|e| e.to_string())?;
        Ok(conv)
    }

    async fn poll(&self, conversation_id: String) -> Result<ConversationDelta, String> {
        // Wire to GetConversation in a follow-up; minimal stub for slice-1
        let _ = conversation_id;
        Ok(ConversationDelta {
            messages: vec![],
            tool_calls: vec![],
            done: true,
        })
    }

    async fn list_documents(&self, agent_id: Option<String>) -> Result<Vec<DocRef>, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        let docs = client
            .list_documents(agent_id.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        Ok(docs
            .into_iter()
            .map(|d| DocRef {
                id: d.id,
                title: d.title,
                conversation_id: d.conversation_id,
            })
            .collect())
    }

    async fn sign_in(&self, api_url: String) -> Result<String, String> {
        pentest_core::matrix::fetch_matrix_token_browser(&api_url)
            .await
            .map_err(|e| e.to_string())
    }

    async fn doc_content(
        &self,
        document_id: String,
        conversation_id: String,
    ) -> Result<String, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        client
            .get_document_content(&conversation_id, &document_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn shared_link(
        &self,
        conversation_id: String,
        document_id: String,
    ) -> Result<String, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        client
            .create_shared_link(&conversation_id, &document_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn list_conversations(&self) -> Result<Vec<ConversationRef>, String> {
        // Wire to ListConversations in a follow-up; empty is valid for slice-1
        Ok(vec![])
    }

    async fn load_conversation(
        &self,
        _conversation_id: String,
    ) -> Result<Vec<MessageView>, String> {
        // Wire to GetConversation in a follow-up
        Ok(vec![])
    }
}

pub struct PentestMiddleware {
    runtime: tokio::runtime::Handle,
    api: std::sync::Arc<dyn MatrixApi>,
}

impl PentestMiddleware {
    pub fn new(runtime: tokio::runtime::Handle, api: std::sync::Arc<dyn MatrixApi>) -> Self {
        Self { runtime, api }
    }
}

impl EffectMiddleware for PentestMiddleware {
    type Op = PentestOperation;
    fn try_process_effect(
        &self,
        operation: PentestOperation,
        mut resolver: EffectResolver<PentestOutcome>,
    ) {
        let api = self.api.clone();
        self.runtime.spawn(async move {
            let out = map_operation(api.as_ref(), operation).await;
            resolver.resolve(out);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pick_crux_core::effect::{PentestOperation, PentestOutcome};

    struct FakeApi;
    #[async_trait::async_trait]
    impl MatrixApi for FakeApi {
        async fn send(&self, _c: Option<String>, _t: String) -> Result<String, String> {
            Ok("conv-9".into())
        }
        async fn poll(
            &self,
            _c: String,
        ) -> Result<pick_crux_core::effect::ConversationDelta, String> {
            Ok(pick_crux_core::effect::ConversationDelta {
                messages: vec![],
                tool_calls: vec![],
                done: true,
            })
        }
        async fn list_documents(
            &self,
            _a: Option<String>,
        ) -> Result<Vec<pick_crux_core::view::DocRef>, String> {
            Ok(vec![])
        }
        async fn sign_in(&self, _u: String) -> Result<String, String> {
            Ok("tok".into())
        }
        async fn doc_content(&self, _id: String, _c: String) -> Result<String, String> {
            Ok("# report".into())
        }
        async fn shared_link(&self, _c: String, _d: String) -> Result<String, String> {
            Ok("https://s/x".into())
        }
        async fn list_conversations(
            &self,
        ) -> Result<Vec<pick_crux_core::view::ConversationRef>, String> {
            Ok(vec![])
        }
        async fn load_conversation(
            &self,
            _c: String,
        ) -> Result<Vec<pick_crux_core::view::MessageView>, String> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn send_scan_maps_to_scan_queued() {
        let api = FakeApi;
        let out = map_operation(
            &api,
            PentestOperation::SendScan {
                conversation_id: None,
                prompt: "p".into(),
            },
        )
        .await;
        assert!(
            matches!(out, PentestOutcome::ScanQueued { conversation_id } if conversation_id == "conv-9")
        );
    }
    #[tokio::test]
    async fn final_poll_maps_to_delta_done() {
        let api = FakeApi;
        let out = map_operation(
            &api,
            PentestOperation::PollConversation {
                conversation_id: "c".into(),
            },
        )
        .await;
        assert!(matches!(out, PentestOutcome::Delta(d) if d.done));
    }
    #[tokio::test]
    async fn signin_maps_to_signed_in() {
        let api = FakeApi;
        let out = map_operation(
            &api,
            PentestOperation::SignIn {
                api_url: "u".into(),
            },
        )
        .await;
        assert!(matches!(out, PentestOutcome::SignedIn { token } if token == "tok"));
    }
}
