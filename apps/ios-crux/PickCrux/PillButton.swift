import SwiftUI

/// Full-rounded sage "pill" button matching the Easy Mode CTA style.
struct SagePillButtonStyle: ButtonStyle {
    var enabled: Bool = true

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 16, weight: .semibold))
            .foregroundStyle(Theme.onBrand)
            .background(
                Capsule().fill(
                    enabled ? (configuration.isPressed ? Theme.brandDeep : Theme.brand)
                            : Theme.brand.opacity(0.5)
                )
            )
            .contentShape(Capsule())
    }
}
