use crux_core::{render::render, Command};
use crate::effect::{PentestOperation, PentestOutcome};
use crate::model::{Model, Phase};
use crate::{Effect, Event, PickApp};

pub fn update(_app: &PickApp, event: Event, model: &mut Model) -> Command<Effect, Event> {
    match event {
        Event::StartScan => {
            model.scan_active = true;
            model.error = None;
            let conv = model.conversation_id.clone();
            Command::request_from_shell(PentestOperation::SendScan {
                conversation_id: conv,
                prompt: pentest_core::easy_mode_scan_prompt(),
            })
            .then_send(|out| match out {
                PentestOutcome::ScanQueued { conversation_id } => Event::ScanResult(Ok(conversation_id)),
                PentestOutcome::Error { message } => Event::ScanResult(Err(message)),
                _ => Event::ScanResult(Err("unexpected outcome".into())),
            })
        }
        Event::SendMessage(text) => {
            model.error = None;
            let conv = model.conversation_id.clone();
            Command::request_from_shell(PentestOperation::SendMessage { conversation_id: conv, text })
                .then_send(|out| match out {
                    PentestOutcome::ScanQueued { conversation_id } => Event::ScanResult(Ok(conversation_id)),
                    PentestOutcome::Error { message } => Event::ScanResult(Err(message)),
                    _ => Event::ScanResult(Err("unexpected outcome".into())),
                })
        }
        Event::ScanResult(Ok(conv)) => {
            model.conversation_id = Some(conv.clone());
            Command::request_from_shell(PentestOperation::PollConversation { conversation_id: conv })
                .then_send(delta_event)
        }
        Event::ScanResult(Err(e)) => { model.scan_active = false; model.error = Some(e); render() }
        Event::Delta(Ok(delta)) => {
            model.messages.extend(delta.messages);
            // tool_calls are folded into messages by the middleware; kept separate here for future use
            if delta.done {
                model.scan_active = false;
                let agent = None; // agent id resolved by middleware/session
                Command::request_from_shell(PentestOperation::ListDocuments { agent_id: agent })
                    .then_send(|out| match out {
                        PentestOutcome::Documents { list } => Event::DocumentsResult(Ok(list)),
                        PentestOutcome::Error { message } => Event::DocumentsResult(Err(message)),
                        _ => Event::DocumentsResult(Err("unexpected outcome".into())),
                    })
            } else {
                let conv = model.conversation_id.clone().unwrap_or_default();
                Command::request_from_shell(PentestOperation::PollConversation { conversation_id: conv })
                    .then_send(delta_event)
            }
        }
        Event::Delta(Err(e)) => { model.scan_active = false; model.error = Some(e); render() }
        Event::DocumentsResult(Ok(docs)) => {
            let conv = model.conversation_id.clone().unwrap_or_default();
            model.conversation_docs = docs.iter().filter(|d| d.conversation_id == conv).cloned().collect();
            model.all_documents = docs;
            render()
        }
        Event::DocumentsResult(Err(e)) => { model.error = Some(e); render() }
        Event::RetrySignIn => {
            model.phase = Phase::SigningIn;
            model.error = None;
            Command::request_from_shell(PentestOperation::SignIn { api_url: model.api_url.clone() })
                .then_send(|out| match out {
                    PentestOutcome::SignedIn { token } => Event::SignInResult(Ok(token)),
                    PentestOutcome::Error { message } => Event::SignInResult(Err(message)),
                    _ => Event::SignInResult(Err("unexpected outcome".into())),
                })
        }
        Event::SignInResult(Ok(_token)) => { model.phase = Phase::Connected; render() }
        Event::SignInResult(Err(e)) => { model.phase = Phase::NeedsSignIn; model.error = Some(e); render() }
        Event::ConnectResult(Ok(())) => { model.phase = Phase::Connected; render() }
        Event::ConnectResult(Err(e)) => { model.error = Some(e); render() }
        Event::NewChat => {
            model.conversation_id = None;
            model.messages.clear();
            model.conversation_docs.clear();
            model.scan_active = false;
            render()
        }
        Event::OpenHistory => {
            model.history_open = true;
            Command::request_from_shell(PentestOperation::ListConversations)
                .then_send(|out| match out {
                    PentestOutcome::Conversations { list } => Event::ConversationsResult(Ok(list)),
                    PentestOutcome::Error { message } => Event::ConversationsResult(Err(message)),
                    _ => Event::ConversationsResult(Err("unexpected outcome".into())),
                })
        }
        Event::CloseHistory => { model.history_open = false; render() }
        Event::ConversationsResult(Ok(list)) => { model.history = list; render() }
        Event::ConversationsResult(Err(e)) => { model.error = Some(e); render() }
        Event::SelectConversation(id) => {
            model.conversation_id = Some(id.clone());
            model.history_open = false;
            Command::request_from_shell(PentestOperation::LoadConversation { conversation_id: id })
                .then_send(|out| match out {
                    PentestOutcome::LoadedMessages { messages } => Event::LoadConversationResult(Ok(messages)),
                    PentestOutcome::Error { message } => Event::LoadConversationResult(Err(message)),
                    _ => Event::LoadConversationResult(Err("unexpected outcome".into())),
                })
        }
        Event::LoadConversationResult(Ok(msgs)) => { model.messages = msgs; render() }
        Event::LoadConversationResult(Err(e)) => { model.error = Some(e); render() }
        Event::OpenDocument(id) => {
            let conv = model.conversation_id.clone().unwrap_or_default();
            Command::request_from_shell(PentestOperation::GetDocumentContent { document_id: id.clone(), conversation_id: conv })
                .then_send(move |out| match out {
                    PentestOutcome::DocumentContent { markdown } => Event::DocumentContentResult(Ok(markdown)),
                    PentestOutcome::Error { message } => Event::DocumentContentResult(Err(message)),
                    _ => Event::DocumentContentResult(Err("unexpected outcome".into())),
                })
        }
        Event::DocumentContentResult(Ok(markdown)) => {
            model.open_document = Some(crate::view::DocView {
                id: String::new(), title: "Report".into(), markdown_body: markdown, share_url: None,
            });
            render()
        }
        Event::DocumentContentResult(Err(e)) => { model.error = Some(e); render() }
        Event::CloseDocument => { model.open_document = None; render() }
        Event::CreateShareLink(doc_id) => {
            let conv = model.conversation_id.clone().unwrap_or_default();
            Command::request_from_shell(PentestOperation::CreateSharedLink { conversation_id: conv, document_id: doc_id })
                .then_send(|out| match out {
                    PentestOutcome::SharedLink { url } => Event::ShareLinkResult(Ok(url)),
                    PentestOutcome::Error { message } => Event::ShareLinkResult(Err(message)),
                    _ => Event::ShareLinkResult(Err("unexpected outcome".into())),
                })
        }
        Event::ShareLinkResult(Ok(url)) => {
            if let Some(doc) = model.open_document.as_mut() { doc.share_url = Some(url); }
            render()
        }
        Event::ShareLinkResult(Err(e)) => { model.error = Some(e); render() }
        Event::DismissError => { model.error = None; render() }
    }
}

fn delta_event(out: PentestOutcome) -> Event {
    match out {
        PentestOutcome::Delta(d) => Event::Delta(Ok(d)),
        PentestOutcome::Error { message } => Event::Delta(Err(message)),
        _ => Event::Delta(Err("unexpected outcome".into())),
    }
}

#[cfg(test)]
mod tests {
    use crate::effect::{ConversationDelta, PentestOperation};
    use crate::view::MessageView;
    use crate::{Effect, Event, Model, PickApp};
    use crux_core::App;

    #[test]
    fn start_scan_emits_send_scan_and_hides_card() {
        let app = PickApp;
        let mut model = Model::default();
        let mut cmd = app.update(Event::StartScan, &mut model);
        assert!(model.scan_active);
        // ViewModel hides the scan card once scan active + messages arrive
        let req = cmd.effects().next().expect("an effect");
        let op = match req {
            Effect::Pentest(op) => op.operation,
            _ => panic!("expected Pentest effect"),
        };
        assert!(matches!(op, PentestOperation::SendScan { .. }));
    }

    #[test]
    fn scan_result_starts_polling() {
        let app = PickApp;
        let mut model = Model::default();
        let _ = app.update(Event::StartScan, &mut model);
        let mut cmd = app.update(Event::ScanResult(Ok("conv-1".into())), &mut model);
        assert_eq!(model.conversation_id.as_deref(), Some("conv-1"));
        let op = match cmd.effects().next().unwrap() {
            Effect::Pentest(op) => op.operation,
            _ => panic!("expected Pentest effect"),
        };
        assert!(matches!(op, PentestOperation::PollConversation { conversation_id } if conversation_id == "conv-1"));
    }

    #[test]
    fn non_final_delta_merges_and_reloops() {
        let app = PickApp;
        let mut model = Model::default();
        model.conversation_id = Some("conv-1".into());
        let delta = ConversationDelta {
            messages: vec![MessageView {
                sender: "pentest-connector".into(),
                kind: crate::view::MessageKind::AgentText,
                markdown: "scanning...".into(),
                tool: None,
            }],
            tool_calls: vec![],
            done: false,
        };
        let mut cmd = app.update(Event::Delta(Ok(delta)), &mut model);
        assert_eq!(model.messages.len(), 1);
        let op = match cmd.effects().next().unwrap() {
            Effect::Pentest(op) => op.operation,
            _ => panic!("expected Pentest effect"),
        };
        assert!(matches!(op, PentestOperation::PollConversation { .. }));
    }

    #[test]
    fn final_delta_requests_documents() {
        let app = PickApp;
        let mut model = Model::default();
        model.conversation_id = Some("conv-1".into());
        let delta = ConversationDelta { messages: vec![], tool_calls: vec![], done: true };
        let mut cmd = app.update(Event::Delta(Ok(delta)), &mut model);
        assert!(!model.scan_active);
        let op = match cmd.effects().next().unwrap() {
            Effect::Pentest(op) => op.operation,
            _ => panic!("expected Pentest effect"),
        };
        assert!(matches!(op, PentestOperation::ListDocuments { .. }));
    }

    #[test]
    fn signin_error_sets_needs_sign_in() {
        let app = PickApp;
        let mut model = Model::default();
        let _ = app.update(Event::SignInResult(Err("nope".into())), &mut model);
        assert_eq!(model.phase, crate::model::Phase::NeedsSignIn);
        assert_eq!(app.view(&model).needs_sign_in, true);
    }
}
