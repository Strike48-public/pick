import SwiftUI
import WebKit

/// Renders a Mermaid diagram in a `WKWebView`, mirroring the Dioxus app which
/// loads mermaid.js from a CDN and renders with the dark theme. The diagram
/// source comes pre-extracted from the SHARED markdown parser (```mermaid
/// fenced blocks surface as `MarkdownBlock.mermaid`).
///
/// The web view reports its rendered content height back so the SwiftUI layout
/// can size the block to fit (no internal scrolling, no fixed guess).
struct MermaidView: View {
    let code: String
    @State private var height: CGFloat = 80

    var body: some View {
        MermaidWebView(code: code, height: $height)
            .frame(height: height)
            .background(Theme.subtleFill, in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct MermaidWebView: UIViewRepresentable {
    let code: String
    @Binding var height: CGFloat

    func makeCoordinator() -> Coordinator { Coordinator(height: $height) }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.userContentController.add(context.coordinator, name: "heightHandler")
        let web = WKWebView(frame: .zero, configuration: config)
        web.scrollView.isScrollEnabled = false
        web.isOpaque = false
        web.backgroundColor = .clear
        web.scrollView.backgroundColor = .clear
        web.loadHTMLString(html(for: code), baseURL: nil)
        return web
    }

    func updateUIView(_ web: WKWebView, context: Context) {
        // Reload only when the diagram source actually changes.
        if context.coordinator.lastCode != code {
            context.coordinator.lastCode = code
            web.loadHTMLString(html(for: code), baseURL: nil)
        }
    }

    /// Build a minimal HTML page that renders the diagram and posts its height.
    private func html(for code: String) -> String {
        // Embed the diagram as a JSON string so any characters are safe.
        let json = (try? String(
            data: JSONSerialization.data(withJSONObject: [code], options: []),
            encoding: .utf8
        )) ?? "[\"\"]"
        return """
        <!doctype html>
        <html>
        <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          html, body { margin: 0; padding: 8px; background: transparent; }
          #d { display: flex; justify-content: center; }
          svg { max-width: 100%; height: auto; }
        </style>
        <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
        </head>
        <body>
        <div id="d"></div>
        <script>
          var src = (\(json))[0];
          function reportHeight() {
            var h = document.body.scrollHeight;
            window.webkit.messageHandlers.heightHandler.postMessage(h);
          }
          mermaid.initialize({ startOnLoad: false, theme: 'dark' });
          mermaid.render('m0', src).then(function (r) {
            document.getElementById('d').innerHTML = r.svg;
            setTimeout(reportHeight, 50);
          }).catch(function (e) {
            document.getElementById('d').innerText = String(e);
            setTimeout(reportHeight, 50);
          });
        </script>
        </body>
        </html>
        """
    }

    final class Coordinator: NSObject, WKScriptMessageHandler {
        @Binding var height: CGFloat
        var lastCode: String = ""

        init(height: Binding<CGFloat>) { _height = height }

        func userContentController(
            _ controller: WKUserContentController,
            didReceive message: WKScriptMessage
        ) {
            guard message.name == "heightHandler",
                  let h = message.body as? NSNumber else { return }
            let value = CGFloat(truncating: h)
            if value > 0 { height = value }
        }
    }
}
