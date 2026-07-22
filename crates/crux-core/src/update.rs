use crate::effect::{PentestOperation, PentestOutcome};
use crate::model::{Model, Phase};
use crate::{Effect, Event, PickApp};
use crux_core::{render::render, Command};

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
                PentestOutcome::ScanQueued { conversation_id } => {
                    Event::ScanResult(crate::ScanOutcome {
                        conversation_id: Some(conversation_id),
                        error: None,
                    })
                }
                PentestOutcome::Error { message } => Event::ScanResult(crate::ScanOutcome {
                    conversation_id: None,
                    error: Some(message),
                }),
                _ => Event::ScanResult(crate::ScanOutcome {
                    conversation_id: None,
                    error: Some("unexpected outcome".into()),
                }),
            })
        }
        Event::SendMessage(text) => {
            model.error = None;
            let conv = model.conversation_id.clone();
            Command::request_from_shell(PentestOperation::SendMessage {
                conversation_id: conv,
                text,
            })
            .then_send(|out| match out {
                PentestOutcome::ScanQueued { conversation_id } => {
                    Event::ScanResult(crate::ScanOutcome {
                        conversation_id: Some(conversation_id),
                        error: None,
                    })
                }
                PentestOutcome::Error { message } => Event::ScanResult(crate::ScanOutcome {
                    conversation_id: None,
                    error: Some(message),
                }),
                _ => Event::ScanResult(crate::ScanOutcome {
                    conversation_id: None,
                    error: Some("unexpected outcome".into()),
                }),
            })
        }
        Event::ScanResult(outcome) => {
            if let Some(conv) = outcome.conversation_id {
                model.conversation_id = Some(conv.clone());
                Command::request_from_shell(PentestOperation::PollConversation {
                    conversation_id: conv,
                })
                .then_send(delta_event)
            } else {
                model.scan_active = false;
                model.error = outcome.error;
                render()
            }
        }
        Event::Delta(outcome) => {
            if let Some(delta) = outcome.delta {
                // A delta carries the FULL current message/tool-call snapshot
                // (the server returns the whole conversation), so REPLACE rather
                // than extend — extending re-appended every message on every
                // poll/update, rendering the same message dozens of times.
                model.messages = delta.messages;
                model.tool_calls = delta.tool_calls;
                if delta.done {
                    model.scan_active = false;
                    let agent = None; // agent id resolved by middleware/session
                    Command::request_from_shell(PentestOperation::ListDocuments { agent_id: agent })
                        .then_send(|out| match out {
                            PentestOutcome::Documents { list } => {
                                Event::DocumentsResult(crate::DocumentsOutcome {
                                    documents: Some(list),
                                    error: None,
                                })
                            }
                            PentestOutcome::Error { message } => {
                                Event::DocumentsResult(crate::DocumentsOutcome {
                                    documents: None,
                                    error: Some(message),
                                })
                            }
                            _ => Event::DocumentsResult(crate::DocumentsOutcome {
                                documents: None,
                                error: Some("unexpected outcome".into()),
                            }),
                        })
                } else {
                    let conv = model.conversation_id.clone().unwrap_or_default();
                    Command::request_from_shell(PentestOperation::PollConversation {
                        conversation_id: conv,
                    })
                    .then_send(delta_event)
                }
            } else {
                model.scan_active = false;
                model.error = outcome.error;
                render()
            }
        }
        Event::DocumentsResult(outcome) => {
            if let Some(docs) = outcome.documents {
                let conv = model.conversation_id.clone().unwrap_or_default();
                model.conversation_docs = docs
                    .iter()
                    .filter(|d| d.conversation_id == conv)
                    .cloned()
                    .collect();
                model.all_documents = docs;
                render()
            } else {
                model.error = outcome.error;
                render()
            }
        }
        Event::RetrySignIn => {
            model.phase = Phase::SigningIn;
            model.error = None;
            Command::request_from_shell(PentestOperation::SignIn {
                api_url: model.api_url.clone(),
            })
            .then_send(|out| match out {
                PentestOutcome::SignedIn { token } => Event::SignInResult(crate::SignInOutcome {
                    token: Some(token),
                    error: None,
                }),
                PentestOutcome::Error { message } => Event::SignInResult(crate::SignInOutcome {
                    token: None,
                    error: Some(message),
                }),
                _ => Event::SignInResult(crate::SignInOutcome {
                    token: None,
                    error: Some("unexpected outcome".into()),
                }),
            })
        }
        Event::SignInResult(outcome) => {
            if outcome.token.is_some() {
                model.phase = Phase::Connected;
                render()
            } else {
                model.phase = Phase::NeedsSignIn;
                model.error = outcome.error;
                render()
            }
        }
        Event::ConnectResult(outcome) => {
            if outcome.ok.is_some() {
                model.phase = Phase::Connected;
                render()
            } else {
                model.error = outcome.err;
                render()
            }
        }
        Event::NewChat => {
            model.conversation_id = None;
            model.messages.clear();
            model.conversation_docs.clear();
            model.scan_active = false;
            render()
        }
        Event::OpenHistory => {
            model.history_open = true;
            Command::request_from_shell(PentestOperation::ListConversations).then_send(|out| {
                match out {
                    PentestOutcome::Conversations { list } => {
                        Event::ConversationsResult(crate::ConversationsOutcome {
                            conversations: Some(list),
                            error: None,
                        })
                    }
                    PentestOutcome::Error { message } => {
                        Event::ConversationsResult(crate::ConversationsOutcome {
                            conversations: None,
                            error: Some(message),
                        })
                    }
                    _ => Event::ConversationsResult(crate::ConversationsOutcome {
                        conversations: None,
                        error: Some("unexpected outcome".into()),
                    }),
                }
            })
        }
        Event::CloseHistory => {
            model.history_open = false;
            render()
        }
        Event::ConversationsResult(outcome) => {
            if let Some(list) = outcome.conversations {
                model.history = list;
                render()
            } else {
                model.error = outcome.error;
                render()
            }
        }
        Event::SelectConversation(id) => {
            model.conversation_id = Some(id.clone());
            model.history_open = false;
            Command::request_from_shell(PentestOperation::LoadConversation {
                conversation_id: id,
            })
            .then_send(|out| match out {
                PentestOutcome::LoadedMessages { messages } => {
                    Event::LoadConversationResult(crate::LoadConversationOutcome {
                        messages: Some(messages),
                        error: None,
                    })
                }
                PentestOutcome::Error { message } => {
                    Event::LoadConversationResult(crate::LoadConversationOutcome {
                        messages: None,
                        error: Some(message),
                    })
                }
                _ => Event::LoadConversationResult(crate::LoadConversationOutcome {
                    messages: None,
                    error: Some("unexpected outcome".into()),
                }),
            })
        }
        Event::LoadConversationResult(outcome) => {
            if let Some(msgs) = outcome.messages {
                model.messages = msgs;
                render()
            } else {
                model.error = outcome.error;
                render()
            }
        }
        Event::OpenDocument(id) => {
            model.opening_document_id = Some(id.clone());
            let conv = model.conversation_id.clone().unwrap_or_default();
            Command::request_from_shell(PentestOperation::GetDocumentContent {
                document_id: id.clone(),
                conversation_id: conv,
            })
            .then_send(move |out| match out {
                PentestOutcome::DocumentContent { markdown } => {
                    Event::DocumentContentResult(crate::DocumentContentOutcome {
                        content: Some(markdown),
                        error: None,
                    })
                }
                PentestOutcome::Error { message } => {
                    Event::DocumentContentResult(crate::DocumentContentOutcome {
                        content: None,
                        error: Some(message),
                    })
                }
                _ => Event::DocumentContentResult(crate::DocumentContentOutcome {
                    content: None,
                    error: Some("unexpected outcome".into()),
                }),
            })
        }
        Event::DocumentContentResult(outcome) => {
            if let Some(markdown) = outcome.content {
                let doc_id = model.opening_document_id.clone().unwrap_or_default();
                let title = model
                    .conversation_docs
                    .iter()
                    .chain(model.all_documents.iter())
                    .find(|d| d.id == doc_id)
                    .map(|d| d.title.clone())
                    .unwrap_or_else(|| "Report".into());
                let blocks = crate::markdown::parse_markdown(&markdown);
                model.open_document = Some(crate::view::DocView {
                    id: doc_id,
                    title,
                    markdown_body: markdown,
                    blocks,
                    share_url: None,
                });
                render()
            } else {
                model.error = outcome.error;
                render()
            }
        }
        Event::CloseDocument => {
            model.open_document = None;
            render()
        }
        Event::CreateShareLink(doc_id) => {
            let conv = model.conversation_id.clone().unwrap_or_default();
            Command::request_from_shell(PentestOperation::CreateSharedLink {
                conversation_id: conv,
                document_id: doc_id,
            })
            .then_send(|out| match out {
                PentestOutcome::SharedLink { url } => {
                    Event::ShareLinkResult(crate::ShareLinkOutcome {
                        url: Some(url),
                        error: None,
                    })
                }
                PentestOutcome::Error { message } => {
                    Event::ShareLinkResult(crate::ShareLinkOutcome {
                        url: None,
                        error: Some(message),
                    })
                }
                _ => Event::ShareLinkResult(crate::ShareLinkOutcome {
                    url: None,
                    error: Some("unexpected outcome".into()),
                }),
            })
        }
        Event::ShareLinkResult(outcome) => {
            if let Some(url) = outcome.url {
                if let Some(doc) = model.open_document.as_mut() {
                    doc.share_url = Some(url);
                }
                render()
            } else {
                model.error = outcome.error;
                render()
            }
        }
        Event::DismissError => {
            model.error = None;
            render()
        }
    }
}

fn delta_event(out: PentestOutcome) -> Event {
    match out {
        PentestOutcome::Delta(d) => Event::Delta(crate::DeltaOutcome {
            delta: Some(d),
            error: None,
        }),
        PentestOutcome::Error { message } => Event::Delta(crate::DeltaOutcome {
            delta: None,
            error: Some(message),
        }),
        _ => Event::Delta(crate::DeltaOutcome {
            delta: None,
            error: Some("unexpected outcome".into()),
        }),
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
        assert!(app.view(&model).show_scan_card, "fresh model shows card");
        let mut cmd = app.update(Event::StartScan, &mut model);
        assert!(model.scan_active);
        assert!(!app.view(&model).show_scan_card, "card hidden after StartScan");
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
        let mut cmd = app.update(
            Event::ScanResult(crate::ScanOutcome {
                conversation_id: Some("conv-1".into()),
                error: None,
            }),
            &mut model,
        );
        assert_eq!(model.conversation_id.as_deref(), Some("conv-1"));
        let op = match cmd.effects().next().unwrap() {
            Effect::Pentest(op) => op.operation,
            _ => panic!("expected Pentest effect"),
        };
        assert!(
            matches!(op, PentestOperation::PollConversation { conversation_id } if conversation_id == "conv-1")
        );
    }

    #[test]
    fn non_final_delta_merges_and_reloops() {
        let app = PickApp;
        let mut model = Model {
            conversation_id: Some("conv-1".into()),
            ..Default::default()
        };
        let delta = ConversationDelta {
            messages: vec![MessageView {
                sender: "pentest-connector".into(),
                kind: crate::view::MessageKind::AgentText,
                markdown: "scanning...".into(),
                blocks: vec![],
                tool: None,
            }],
            tool_calls: vec![],
            done: false,
        };
        let mut cmd = app.update(
            Event::Delta(crate::DeltaOutcome {
                delta: Some(delta),
                error: None,
            }),
            &mut model,
        );
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
        let mut model = Model {
            conversation_id: Some("conv-1".into()),
            ..Default::default()
        };
        let delta = ConversationDelta {
            messages: vec![],
            tool_calls: vec![],
            done: true,
        };
        let mut cmd = app.update(
            Event::Delta(crate::DeltaOutcome {
                delta: Some(delta),
                error: None,
            }),
            &mut model,
        );
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
        let _ = app.update(
            Event::SignInResult(crate::SignInOutcome {
                token: None,
                error: Some("nope".into()),
            }),
            &mut model,
        );
        assert_eq!(model.phase, crate::model::Phase::NeedsSignIn);
        assert!(app.view(&model).needs_sign_in);
    }

    #[test]
    fn open_document_requests_content_and_share() {
        let app = PickApp;
        let mut model = Model {
            conversation_id: Some("conv-1".into()),
            conversation_docs: vec![crate::view::DocRef {
                id: "doc-1".into(),
                title: "Test Report".into(),
                conversation_id: "conv-1".into(),
            }],
            ..Default::default()
        };
        let mut cmd = app.update(Event::OpenDocument("doc-1".into()), &mut model);
        assert_eq!(model.opening_document_id.as_deref(), Some("doc-1"));
        let op = match cmd.effects().next().unwrap() {
            Effect::Pentest(op) => op.operation,
            _ => panic!("expected Pentest effect"),
        };
        assert!(
            matches!(op, PentestOperation::GetDocumentContent { document_id, conversation_id }
                if document_id == "doc-1" && conversation_id == "conv-1")
        );
        let _ = app.update(
            Event::DocumentContentResult(crate::DocumentContentOutcome {
                content: Some("# Test\nContent".into()),
                error: None,
            }),
            &mut model,
        );
        let vm = app.view(&model);
        assert!(vm.open_document.is_some());
        let doc = vm.open_document.unwrap();
        assert_eq!(doc.id, "doc-1");
        assert_eq!(doc.title, "Test Report");
        let mut cmd = app.update(Event::CreateShareLink("doc-1".into()), &mut model);
        let op = match cmd.effects().next().unwrap() {
            Effect::Pentest(op) => op.operation,
            _ => panic!("expected Pentest effect"),
        };
        assert!(
            matches!(op, PentestOperation::CreateSharedLink { document_id, conversation_id }
                if document_id == "doc-1" && conversation_id == "conv-1")
        );
        let _ = app.update(
            Event::ShareLinkResult(crate::ShareLinkOutcome {
                url: Some("https://share.example/abc".into()),
                error: None,
            }),
            &mut model,
        );
        let vm = app.view(&model);
        assert_eq!(
            vm.open_document.unwrap().share_url.as_deref(),
            Some("https://share.example/abc")
        );
    }

    #[test]
    fn tool_call_delta_exposes_tool_rows() {
        let app = PickApp;
        let mut model = Model {
            conversation_id: Some("conv-1".into()),
            ..Default::default()
        };
        let delta = ConversationDelta {
            messages: vec![],
            tool_calls: vec![crate::view::ToolCallView {
                name: "nmap".into(),
                status: crate::view::ToolStatus::Running,
            }],
            done: false,
        };
        let _ = app.update(
            Event::Delta(crate::DeltaOutcome {
                delta: Some(delta),
                error: None,
            }),
            &mut model,
        );
        let vm = app.view(&model);
        assert_eq!(vm.tool_calls.len(), 1);
        assert_eq!(vm.tool_calls[0].name, "nmap");
        assert_eq!(vm.tool_calls[0].status, crate::view::ToolStatus::Running);
    }

    #[test]
    fn view_is_pure_function_of_model() {
        let app = PickApp;
        let m1 = Model::default();
        let m2 = Model {
            phase: crate::model::Phase::NeedsSignIn,
            messages: vec![MessageView {
                sender: "user".into(),
                kind: crate::view::MessageKind::User,
                markdown: "test".into(),
                blocks: vec![],
                tool: None,
            }],
            ..Default::default()
        };
        let vm1a = app.view(&m1);
        let vm1b = app.view(&m1);
        assert_eq!(vm1a, vm1b, "view() called twice on same model should be equal");
        let vm2 = app.view(&m2);
        assert_ne!(
            vm1a.screen, vm2.screen,
            "different models should produce different screens"
        );
        assert_ne!(
            vm1a.needs_sign_in, vm2.needs_sign_in,
            "different models should produce different needs_sign_in"
        );
    }
}
