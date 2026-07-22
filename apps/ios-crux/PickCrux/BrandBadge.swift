import SwiftUI

/// The sage rounded-square "S" brand badge. Draws the spec's stroke path
/// (viewBox 0 0 32 32) as a SwiftUI Path, scaled to the requested size.
struct BrandBadge: View {
    var size: CGFloat = 30

    var body: some View {
        RoundedRectangle(cornerRadius: Theme.radiusBadge * (size / 30))
            .fill(Theme.brand)
            .frame(width: size, height: size)
            .overlay(
                SGlyph()
                    .stroke(
                        Theme.onBrand,
                        style: StrokeStyle(lineWidth: 3.2 * (size / 32), lineCap: .round, lineJoin: .round)
                    )
                    .frame(width: size, height: size)
            )
    }
}

/// The "S" stroke path from the design spec, expressed in the 0..32 viewBox and
/// scaled into the view's rect.
private struct SGlyph: Shape {
    func path(in rect: CGRect) -> Path {
        let sx = rect.width / 32.0
        let sy = rect.height / 32.0
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: rect.minX + x * sx, y: rect.minY + y * sy)
        }
        var path = Path()
        // M23 9 C23 6 19 5 16 5 C12 5 9 7 9 10 C9 16 23 14 23 21 C23 25 19 27 15 27 C11 27 8 25 8 22
        path.move(to: p(23, 9))
        path.addCurve(to: p(16, 5), control1: p(23, 6), control2: p(19, 5))
        path.addCurve(to: p(9, 10), control1: p(12, 5), control2: p(9, 7))
        path.addCurve(to: p(23, 21), control1: p(9, 16), control2: p(23, 14))
        path.addCurve(to: p(15, 27), control1: p(23, 25), control2: p(19, 27))
        path.addCurve(to: p(8, 22), control1: p(11, 27), control2: p(8, 25))
        return path
    }
}
