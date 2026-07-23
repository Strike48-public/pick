use crate::effect::{PentestOperation, PentestOutcome};
use crate::model::{Model, Phase};
use crate::{Effect, Event, PickApp};
use crux_core::{render::render, Command};

pub fn update(_app: &PickApp, event: Event, model: &mut Model) -> Command<Effect, Event> {
    match event {
        Event::StartScan => {
            model.scan_active = true;
            model.error = None;
            model.notice = None;
            model.next_steps.clear();
            // Optimistic local echo: show the user's action immediately (before
            // the first poll) so the chat isn't empty while the scan spins up.
            // The scan prompt is a long block of agent instructions, so echo a
            // short human label instead of the raw prompt. The next Delta REPLACES
            // model.messages with the server's snapshot (which carries the real
            // user message), naturally reconciling this echo.
            model.messages.push(user_echo("Scan my network"));
            model.activity = crate::view::AgentActivity::Thinking;
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
            model.notice = None;
            model.next_steps.clear();
            // Optimistic local echo of the sent message (see StartScan) so it
            // appears instantly; the next Delta replaces messages with the
            // server snapshot. Show the status line immediately too.
            model.messages.push(user_echo(&text));
            model.activity = crate::view::AgentActivity::Thinking;
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
                // Contextual next-step chips from the last successful tool call
                // (computed by the middleware). Refreshed every delta so they
                // track the newest tool result; empty when none apply.
                model.next_steps = delta.next_steps;
                // The agent backend errored (incl. token/rate-limit exhaustion):
                // the middleware built a notice from tokenUsageStats. Surface it,
                // stop the scan, and stop polling — this is terminal, but unlike
                // a plain `done` we DON'T fetch documents (there is no report).
                if let Some(notice) = delta.notice {
                    model.notice = Some(notice);
                    model.scan_active = false;
                    model.activity = crate::view::AgentActivity::Idle;
                    return render();
                }
                // A successful delta clears any stale notice.
                model.notice = None;
                // Reflect what the agent is doing (Thinking/RunningTools/...) so
                // the shell shows an animated status line; clear it once done.
                model.activity = if delta.done {
                    crate::view::AgentActivity::Idle
                } else {
                    delta.activity
                };
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
                    // Render the just-merged snapshot AND keep polling. Without
                    // the render, the runtime never emits a view update between
                    // polls, so the shell only sees the final state (spinner
                    // until done). Emitting both streams each poll to the UI.
                    //
                    // Termination is driven entirely by the agent's own state:
                    // `done` (terminal agent_status) ends the scan cleanly, and a
                    // mid-stream failure is surfaced via the durable
                    // `stream_error` message metadata (see the middleware poll).
                    // We do NOT second-guess a "quiet" poll with a timer — a long
                    // report-generation turn looks quiet to the poller while the
                    // LLM is actively streaming server-side, and a timeout there
                    // kills a scan that's about to succeed.
                    let conv = model.conversation_id.clone().unwrap_or_default();
                    Command::all([
                        render(),
                        Command::request_from_shell(PentestOperation::PollConversation {
                            conversation_id: conv,
                        })
                        .then_send(delta_event),
                    ])
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
                // Order newest-first (ISO-8601 timestamps sort lexically =
                // chronologically) and drop duplicate ids, mirroring the Dioxus
                // Reports list. Without this the list is unordered with dupes
                // (repeated scans each write a fresh document).
                let all = dedup_newest_first(docs);
                model.conversation_docs = all
                    .iter()
                    .filter(|d| d.conversation_id == conv)
                    .cloned()
                    .collect();
                model.all_documents = all;
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
            model.notice = None;
            model.next_steps.clear();
            render()
        }
        Event::OpenDocuments => {
            // Fetch all documents on demand (no agent filter -> workspace-wide),
            // so the Reports list is populated even without a just-finished scan.
            Command::request_from_shell(PentestOperation::ListDocuments { agent_id: None })
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
                // Resume polling the selected conversation: if its agent is still
                // working, output streams in; if it's already done, the first
                // poll returns done=true and the loop stops. Render now so the
                // loaded history shows immediately.
                if let Some(conv) = model.conversation_id.clone() {
                    Command::all([
                        render(),
                        Command::request_from_shell(PentestOperation::PollConversation {
                            conversation_id: conv,
                        })
                        .then_send(delta_event),
                    ])
                } else {
                    render()
                }
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
                    preview_url: None,
                    social_links: vec![],
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
            // The title feeds the social compose text (e.g. X's pre-filled tweet);
            // pull it from the open document, falling back to the doc lists.
            let title = model
                .open_document
                .as_ref()
                .filter(|d| d.id == doc_id)
                .map(|d| d.title.clone())
                .or_else(|| {
                    model
                        .conversation_docs
                        .iter()
                        .chain(model.all_documents.iter())
                        .find(|d| d.id == doc_id)
                        .map(|d| d.title.clone())
                })
                .unwrap_or_default();
            Command::request_from_shell(PentestOperation::CreateSharedLink {
                conversation_id: conv,
                document_id: doc_id,
                title,
            })
            .then_send(|out| match out {
                PentestOutcome::SharedLink {
                    url,
                    preview_url,
                    social_links,
                } => Event::ShareLinkResult(crate::ShareLinkOutcome {
                    url: Some(url),
                    preview_url: Some(preview_url),
                    social_links,
                    error: None,
                }),
                PentestOutcome::Error { message } => {
                    Event::ShareLinkResult(crate::ShareLinkOutcome {
                        url: None,
                        preview_url: None,
                        social_links: vec![],
                        error: Some(message),
                    })
                }
                _ => Event::ShareLinkResult(crate::ShareLinkOutcome {
                    url: None,
                    preview_url: None,
                    social_links: vec![],
                    error: Some("unexpected outcome".into()),
                }),
            })
        }
        Event::ShareLinkResult(outcome) => {
            if let Some(url) = outcome.url {
                if let Some(doc) = model.open_document.as_mut() {
                    doc.share_url = Some(url);
                    doc.preview_url = outcome.preview_url;
                    doc.social_links = outcome.social_links;
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
        Event::SeedSettings { telemetry_enabled } => {
            // Startup: apply the shell's persisted opt-out choice to both the
            // model (so Settings reflects it) and the live telemetry client.
            model.telemetry_enabled = telemetry_enabled;
            pentest_core::telemetry::set_enabled(telemetry_enabled);
            render()
        }
        Event::SetTelemetryEnabled(enabled) => {
            // Runtime toggle from Settings: flip the flag and enable/disable the
            // Sentry client immediately (off = client fully closed). The shell
            // persists the new value natively.
            model.telemetry_enabled = enabled;
            pentest_core::telemetry::set_enabled(enabled);
            render()
        }
        Event::Logout => {
            // Clear in-core session/conversation state and return to sign-in.
            // The shell clears its persisted token separately.
            model.phase = Phase::NeedsSignIn;
            model.conversation_id = None;
            model.messages.clear();
            model.conversation_docs.clear();
            model.all_documents.clear();
            model.history.clear();
            model.open_document = None;
            model.scan_active = false;
            model.notice = None;
            model.next_steps.clear();
            model.error = None;
            render()
        }
    }
}

/// Build a synthetic user message for the optimistic local echo. Sender "You",
/// a single Text part (and legacy flattened markdown/blocks) parsed from `text`,
/// mirroring how the middleware maps a real user ChatMessage.
fn user_echo(text: &str) -> crate::view::MessageView {
    let blocks = crate::markdown::parse_markdown(text);
    crate::view::MessageView {
        sender: "You".into(),
        kind: crate::view::MessageKind::User,
        parts: vec![crate::view::MessagePartView::Text {
            blocks: blocks.clone(),
        }],
        markdown: text.to_string(),
        blocks,
        tool: None,
    }
}

/// Sort documents newest-first by ISO-8601 `timestamp` (lexical compare =
/// chronological) and drop duplicate ids, keeping the first (newest) occurrence.
/// Mirrors the Dioxus Reports list dedup/ordering.
fn dedup_newest_first(mut docs: Vec<crate::view::DocRef>) -> Vec<crate::view::DocRef> {
    docs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    let mut seen = std::collections::HashSet::new();
    docs.retain(|d| seen.insert(d.id.clone()));
    docs
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
    fn telemetry_defaults_on_and_toggles() {
        let app = PickApp;
        let mut model = Model::default();
        // Opt-out: on by default, surfaced in the ViewModel settings.
        assert!(model.telemetry_enabled);
        assert!(app.view(&model).settings.telemetry_enabled);

        let _ = app.update(Event::SetTelemetryEnabled(false), &mut model);
        assert!(!model.telemetry_enabled);
        assert!(!app.view(&model).settings.telemetry_enabled);

        let _ = app.update(Event::SetTelemetryEnabled(true), &mut model);
        assert!(model.telemetry_enabled);
    }

    #[test]
    fn seed_settings_applies_persisted_choice() {
        let app = PickApp;
        let mut model = Model::default();
        let _ = app.update(
            Event::SeedSettings {
                telemetry_enabled: false,
            },
            &mut model,
        );
        assert!(!model.telemetry_enabled);
        assert!(!app.view(&model).settings.telemetry_enabled);
    }

    #[test]
    fn logout_resets_session_and_shows_sign_in() {
        let app = PickApp;
        let mut model = Model {
            conversation_id: Some("c1".into()),
            scan_active: true,
            ..Default::default()
        };
        model.messages.push(super::user_echo("hi"));
        let _ = app.update(Event::Logout, &mut model);
        assert!(model.conversation_id.is_none());
        assert!(model.messages.is_empty());
        assert!(!model.scan_active);
        assert!(app.view(&model).needs_sign_in);
    }

    #[test]
    fn start_scan_emits_send_scan_and_hides_card() {
        let app = PickApp;
        let mut model = Model::default();
        assert!(app.view(&model).show_scan_card, "fresh model shows card");
        let mut cmd = app.update(Event::StartScan, &mut model);
        assert!(model.scan_active);
        assert!(
            !app.view(&model).show_scan_card,
            "card hidden after StartScan"
        );
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
                parts: vec![],
                markdown: "scanning...".into(),
                blocks: vec![],
                tool: None,
            }],
            tool_calls: vec![],
            done: false,
            activity: Default::default(),
            notice: None,
            next_steps: vec![],
        };
        let mut cmd = app.update(
            Event::Delta(crate::DeltaOutcome {
                delta: Some(delta),
                error: None,
            }),
            &mut model,
        );
        assert_eq!(model.messages.len(), 1);
        // A non-final delta now emits BOTH a Render (so the shell streams the
        // just-merged snapshot) AND the next PollConversation. Find the Pentest
        // op among the effects.
        let mut effects = cmd.effects();
        let poll_op = effects.find_map(|e| match e {
            Effect::Pentest(op) => Some(op.operation),
            _ => None,
        });
        assert!(
            matches!(poll_op, Some(PentestOperation::PollConversation { .. })),
            "non-final delta should re-emit PollConversation"
        );
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
            activity: Default::default(),
            notice: None,
            next_steps: vec![],
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
    fn error_delta_surfaces_notice_and_stops_without_documents() {
        let app = PickApp;
        let mut model = Model {
            conversation_id: Some("conv-1".into()),
            scan_active: true,
            ..Default::default()
        };
        let notice = crate::view::NoticeView {
            kind: crate::view::NoticeKind::TokenLimit,
            title: "Token limit reached".into(),
            detail: "Daily token limit reached.".into(),
            studio_url: Some("https://s/studio/#/".into()),
        };
        let delta = ConversationDelta {
            messages: vec![],
            tool_calls: vec![],
            // Even a `done=true` error delta must NOT fetch documents; the notice
            // is what makes it terminal-with-explanation.
            done: true,
            activity: Default::default(),
            notice: Some(notice.clone()),
            next_steps: vec![],
        };
        let mut cmd = app.update(
            Event::Delta(crate::DeltaOutcome {
                delta: Some(delta),
                error: None,
            }),
            &mut model,
        );
        assert!(!model.scan_active, "error stops the scan");
        assert_eq!(model.notice, Some(notice));
        // The App should render, NOT request documents (there is no report).
        let requested_docs = cmd.effects().any(|e| {
            matches!(
                e,
                Effect::Pentest(op) if matches!(op.operation, PentestOperation::ListDocuments { .. })
            )
        });
        assert!(!requested_docs, "error delta must not fetch documents");
        // The surfaced notice projects into the ViewModel.
        assert!(app.view(&model).notice.is_some());
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
                timestamp: String::new(),
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
            matches!(op, PentestOperation::CreateSharedLink { document_id, conversation_id, .. }
                if document_id == "doc-1" && conversation_id == "conv-1")
        );
        let _ = app.update(
            Event::ShareLinkResult(crate::ShareLinkOutcome {
                url: Some("https://share.example/abc".into()),
                preview_url: Some("https://share.example/abc?preview=1".into()),
                social_links: vec![crate::view::SocialLink {
                    label: "X".into(),
                    url: "https://twitter.com/intent/tweet?url=https%3A%2F%2Fshare.example%2Fabc"
                        .into(),
                }],
                error: None,
            }),
            &mut model,
        );
        let vm = app.view(&model);
        let doc = vm.open_document.unwrap();
        assert_eq!(doc.share_url.as_deref(), Some("https://share.example/abc"));
        assert_eq!(
            doc.preview_url.as_deref(),
            Some("https://share.example/abc?preview=1")
        );
        assert_eq!(doc.social_links.len(), 1);
        assert_eq!(doc.social_links[0].label, "X");
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
                arguments: None,
                result: None,
                error: None,
            }],
            done: false,
            activity: Default::default(),
            notice: None,
            next_steps: vec![],
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
    fn start_scan_echoes_user_bubble_and_shows_thinking() {
        let app = PickApp;
        let mut model = Model::default();
        let _ = app.update(Event::StartScan, &mut model);
        // A synthetic user bubble appears immediately (before any poll).
        assert_eq!(model.messages.len(), 1);
        assert_eq!(model.messages[0].kind, crate::view::MessageKind::User);
        assert_eq!(model.messages[0].sender, "You");
        assert_eq!(model.messages[0].markdown, "Scan my network");
        // The status line reflects activity right away.
        assert_eq!(model.activity, crate::view::AgentActivity::Thinking);
    }

    #[test]
    fn send_message_echoes_user_bubble() {
        let app = PickApp;
        let mut model = Model {
            conversation_id: Some("conv-1".into()),
            ..Default::default()
        };
        let _ = app.update(Event::SendMessage("hello there".into()), &mut model);
        assert_eq!(model.messages.len(), 1);
        assert_eq!(model.messages[0].markdown, "hello there");
        assert_eq!(model.messages[0].kind, crate::view::MessageKind::User);
        assert_eq!(model.activity, crate::view::AgentActivity::Thinking);
    }

    #[test]
    fn documents_result_orders_newest_first_and_dedups() {
        let app = PickApp;
        let mut model = Model {
            conversation_id: Some("conv-1".into()),
            ..Default::default()
        };
        let mk = |id: &str, ts: &str, conv: &str| crate::view::DocRef {
            id: id.into(),
            title: id.into(),
            conversation_id: conv.into(),
            timestamp: ts.into(),
        };
        let _ = app.update(
            Event::DocumentsResult(crate::DocumentsOutcome {
                documents: Some(vec![
                    mk("a", "2026-07-20T10:00:00Z", "conv-1"),
                    mk("b", "2026-07-21T10:00:00Z", "conv-2"),
                    mk("a", "2026-07-20T10:00:00Z", "conv-1"), // duplicate id
                ]),
                error: None,
            }),
            &mut model,
        );
        let vm = app.view(&model);
        // Newest first, dupes removed.
        assert_eq!(vm.all_documents.len(), 2);
        assert_eq!(vm.all_documents[0].id, "b");
        assert_eq!(vm.all_documents[1].id, "a");
        // Conversation docs filtered to conv-1.
        assert_eq!(vm.conversation_docs.len(), 1);
        assert_eq!(vm.conversation_docs[0].id, "a");
    }

    #[test]
    fn delta_next_steps_project_and_clear_on_send() {
        let app = PickApp;
        let mut model = Model {
            conversation_id: Some("conv-1".into()),
            ..Default::default()
        };
        let delta = ConversationDelta {
            messages: vec![],
            tool_calls: vec![],
            done: false,
            activity: Default::default(),
            notice: None,
            next_steps: vec![crate::view::QuickActionView {
                label: "Detailed Scan".into(),
                message: "Run a detailed scan".into(),
            }],
        };
        let _ = app.update(
            Event::Delta(crate::DeltaOutcome {
                delta: Some(delta),
                error: None,
            }),
            &mut model,
        );
        assert_eq!(app.view(&model).next_steps.len(), 1);
        // Sending a follow-up clears the chips.
        let _ = app.update(Event::SendMessage("go".into()), &mut model);
        assert!(app.view(&model).next_steps.is_empty());
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
                parts: vec![],
                markdown: "test".into(),
                blocks: vec![],
                tool: None,
            }],
            ..Default::default()
        };
        let vm1a = app.view(&m1);
        let vm1b = app.view(&m1);
        assert_eq!(
            vm1a, vm1b,
            "view() called twice on same model should be equal"
        );
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
