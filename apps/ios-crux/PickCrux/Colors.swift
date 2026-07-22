import SwiftUI

/// Sage-dark theme tokens mirroring the Dioxus Easy Mode `--em-*` CSS variables.
/// Single source of truth for the SwiftUI shell; do NOT use default iOS blue.
enum Theme {
    // Brand
    static let brand = Color(hex: 0x9cbfae)          // sage primary
    static let brandDeep = Color(hex: 0x7fa894)      // pressed / hover
    static let onBrand = Color(hex: 0x17201b)        // dark ink on sage fills

    // Surfaces
    static let background = Color(hex: 0x1c1c1c)      // page background (neutral near-black)
    static let surface = Color(hex: 0x242b27)         // elevated cards / rows

    // Text
    static let text = Color(hex: 0xe9eeeb)
    static let muted = Color(hex: 0xe9eeeb, alpha: 0.6)

    // Fills / washes
    static let subtleFill = Color(hex: 0xe9eeeb, alpha: 0.08)
    static let faintWash = Color(hex: 0xe9eeeb, alpha: 0.03)

    // Borders
    static let hairline = Color(hex: 0xe9eeeb, alpha: 0.12)
    static let strongBorder = Color(hex: 0xe9eeeb, alpha: 0.22)
    static let rowSeparator = Color(hex: 0xe9eeeb, alpha: 0.08)

    // Status
    static let error = Color(hex: 0xd99a9a)
    static let success = Color(hex: 0x8fc4ab)
    static let warning = Color(hex: 0xd9b07c)

    // Radii (Material 3 shape scale)
    static let radiusCard: CGFloat = 16
    static let radiusControl: CGFloat = 12
    static let radiusBadge: CGFloat = 9
}

extension Color {
    init(hex: UInt32, alpha: Double = 1.0) {
        let r = Double((hex >> 16) & 0xff) / 255.0
        let g = Double((hex >> 8) & 0xff) / 255.0
        let b = Double(hex & 0xff) / 255.0
        self.init(.sRGB, red: r, green: g, blue: b, opacity: alpha)
    }
}
