# UI Features and Customization

This document describes the user interface features and customization options available in the Pick connector.

## Themes

### Built-in Themes

Pick includes 8 pre-built themes:

| Theme | Style | Description |
|-------|-------|-------------|
| **Dark** | Dark mode | Default dark theme with blue accents |
| **Light** | Light mode | Clean light theme with subtle colors |
| **Dracula** | Dark | Popular purple and pink color scheme |
| **Gruvbox** | Dark/Warm | Retro warm colors inspired by Gruvbox |
| **Tokyo Night** | Dark/Cool | Modern cool blue-purple palette |
| **Matrix** | Dark/Green | Hacker aesthetic with green-on-black |
| **Cyberpunk** | Dark/Neon | High-contrast neon accents |
| **Nord** | Light/Frost | Arctic-inspired frost palette |

### Changing Themes

#### Via Settings
1. Navigate to **Settings** (press `6` or click sidebar)
2. Scroll to **Appearance** section
3. Select theme from dropdown

#### Via Keyboard Shortcuts
Press `Ctrl+Shift+[1-8]` for instant theme switching:

- `Ctrl+Shift+1` → Dark
- `Ctrl+Shift+2` → Light
- `Ctrl+Shift+3` → Dracula
- `Ctrl+Shift+4` → Gruvbox
- `Ctrl+Shift+5` → Tokyo Night
- `Ctrl+Shift+6` → Matrix
- `Ctrl+Shift+7` → Cyberpunk
- `Ctrl+Shift+8` → Nord

#### Random Theme
Click the **🎲 dice button** next to the theme dropdown for a random theme.

### Theme Transitions

All theme changes include smooth 300ms animated transitions. Colors fade smoothly between themes for a polished experience.

## Shape Customization

### Border Radius

Control the roundness of UI elements:

- **Sharp** (0px) - Rectangular, no rounded corners
- **Minimal** (4px) - Slightly rounded
- **Rounded** (8px) - Default, moderately rounded
- **Soft** (16px) - Very rounded
- **Pill** (999px) - Fully rounded ends

### Density

Adjust spacing and padding:

- **Compact** - Dense layout, minimal spacing
- **Normal** - Default, balanced spacing
- **Comfortable** - Spacious layout, generous padding

## Custom Themes

### Creating Custom Themes

1. Create a CSS file with your theme colors
2. Use OKLCH color format for perceptual uniformity
3. Define all required CSS variables (see `themes/example-custom.css`)

Example theme file:
```css
/*
name: My Custom Theme
author: Your Name
description: A beautiful custom theme
version: 1.0.0
*/

:root {
  /* Background colors */
  --background: oklch(0.2 0.01 240);
  --foreground: oklch(0.95 0.01 240);

  /* Primary colors */
  --primary: oklch(0.6 0.2 280);
  --primary-foreground: oklch(0.98 0.01 280);

  /* Add all other required variables... */
}
```

### Importing Custom Themes

1. Go to **Settings → Appearance**
2. Expand **Advanced** section
3. Enter path to your `.css` file
4. Click **Import Theme**

The theme will be copied to `~/.config/pentest-connector/themes/` and validated for security.

### Security Restrictions

Custom themes are validated to prevent security issues:

- ❌ No external resources (no `url(http://...)`)
- ❌ No JavaScript URLs
- ❌ No CSS imports
- ❌ No font loading
- ❌ No data URLs
- ✅ Only local CSS properties and colors

See `themes/README.md` for complete documentation.

## Keyboard Shortcuts

### Navigation

| Key | Action |
|-----|--------|
| `?` | Toggle help modal |
| `1` | Dashboard |
| `2` | Tools |
| `3` | Files |
| `4` | Shell |
| `5` | Logs |
| `6` | Settings |
| `c` | Chat |
| `Esc` | Close modal/panel |

### Theme Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+Shift+1-8` | Switch to theme 1-8 |

### Easter Eggs

**Konami Code**: ↑ ↑ ↓ ↓ ← → ← → B A

Activates a special Matrix-themed easter egg with animated rain effect.

## Accessibility

### Reduced Motion

If you have "Reduce Motion" enabled in your OS accessibility settings:
- Theme transitions are instant (no animation)
- Toast notifications appear without animation
- Text fade effects are disabled

### Keyboard Navigation

All UI features are fully keyboard accessible:
- Tab navigation through all interactive elements
- Arrow keys in lists and menus
- Keyboard shortcuts for quick actions

## Toast Notifications

Toast notifications appear in the top-right corner for important events:

- **Success** (green) - Operation completed
- **Error** (red) - Something went wrong
- **Info** (blue) - Informational message
- **Warning** (yellow) - Caution required

Toasts auto-dismiss after 3 seconds or can be clicked to dismiss immediately.

## Tips

- **Quick Theme Switching**: Use keyboard shortcuts (`Ctrl+Shift+1-8`) for rapid theme previewing
- **Dark Mode at Night**: Dark/Matrix/Dracula themes reduce eye strain
- **Light Mode in Sunlight**: Light/Nord themes improve visibility in bright environments
- **Random Inspiration**: Click the dice button when you need a change
- **Create Your Own**: Make a custom theme that matches your terminal or IDE

## Troubleshooting

### Keyboard Shortcuts Not Working

The app auto-focuses on load, but if shortcuts don't work:
- Click anywhere in the app window
- Shortcuts should work immediately after

### Theme Not Changing

- Check browser console for errors
- Ensure you're using a supported browser
- Try refreshing the page

### Custom Theme Import Failed

Common issues:
- File too large (max 100KB)
- Invalid CSS syntax
- Contains blocked properties (external URLs, imports)
- File extension is not `.css`

See error message for specific issue and check `themes/README.md` for requirements.

---

For technical details on theme implementation, see:
- `themes/README.md` - Custom theme creation guide
- `crates/ui/src/theme.rs` - Theme system implementation
- `crates/core/src/theme_loader.rs` - Theme loading and validation
