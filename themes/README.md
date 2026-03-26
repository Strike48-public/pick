# Custom Themes

This directory contains custom theme files for the Pick pentest connector.

## Creating a Custom Theme

Custom themes are CSS files with special metadata comments. Here's the basic structure:

```css
/* Theme: My Theme Name */
/* Author: Your Name */
/* Version: 1.0.0 */
/* Description: A brief description */

:root {
    /* Your CSS variables here */
    --background: oklch(0.1 0 0);
    --foreground: oklch(0.9 0 0);
    /* ... more variables ... */
}

/* Optional: Custom component styles */
.dashboard-card {
    border: 2px solid var(--primary);
}
```

## Required Metadata

- `/* Theme: ... */` - Theme name (REQUIRED)
- `/* Author: ... */` - Author name (optional)
- `/* Version: ... */` - Version string (optional)
- `/* Description: ... */` - Brief description (optional)

## Required CSS Variables

Your theme MUST define these CSS variables in the `:root` block:

### Base Colors
- `--background` - Main background color
- `--foreground` - Main text color
- `--card` - Card background
- `--popover` - Popover background
- `--primary` - Primary action color
- `--primary-foreground` - Text on primary color
- `--secondary` - Secondary background
- `--secondary-foreground` - Text on secondary
- `--muted` - Muted background
- `--muted-foreground` - Muted text
- `--accent` - Accent color
- `--accent-foreground` - Text on accent
- `--destructive` - Danger/error color
- `--border` - Border color
- `--input` - Input background
- `--ring` - Focus ring color

### Sidebar Colors
- `--sidebar` - Sidebar background
- `--sidebar-foreground` - Sidebar text
- `--sidebar-primary` - Sidebar primary color
- `--sidebar-primary-foreground` - Text on sidebar primary
- `--sidebar-accent` - Sidebar accent
- `--sidebar-accent-foreground` - Text on sidebar accent
- `--sidebar-border` - Sidebar border
- `--sidebar-ring` - Sidebar focus ring

### Chart Colors (for data visualization)
- `--chart-1` through `--chart-5` - Five distinct colors

### Status Colors
- `--success` - Success state color
- `--warning` - Warning state color
- `--info` - Info state color

## Color Format: OKLCH

We recommend using the OKLCH color space for better perceptual uniformity:

```css
/* OKLCH format: oklch(lightness chroma hue) */
--primary: oklch(0.70 0.25 280);
/*              L=70%  C=0.25 H=280° (blue) */
```

- **Lightness (L)**: 0.0 (black) to 1.0 (white)
- **Chroma (C)**: 0 (gray) to ~0.4 (vibrant)
- **Hue (H)**: 0-360 degrees (red=0, yellow=90, green=150, cyan=180, blue=280, magenta=330)

## Optional: Custom Component Styles

After the `:root` block, you can add custom CSS for components:

```css
.dashboard-card {
    border-radius: 12px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}

button:hover {
    transform: translateY(-2px);
    transition: transform 0.2s;
}
```

## Security Restrictions

For security, custom themes are validated and these are **NOT ALLOWED**:

- JavaScript URLs (`javascript:`)
- External resource loading (`http://`, `https://`, `@import`)
- HTML data URLs (`data:text/html`)
- CSS expressions (`expression()`)
- Script tags
- IE behaviors or Mozilla bindings

Only local paths and `data:image/` URLs are allowed in `url()` functions.

## Installing Custom Themes

1. Create your `.css` file in this directory
2. Go to Settings > Appearance
3. Click "Import Theme"
4. Select your custom theme file
5. The theme will be validated and loaded if safe

## Example Theme

See `example-custom.css` for a complete working example.

## Tips

- Use consistent color schemes (e.g., all blues, or complementary colors)
- Ensure sufficient contrast between foreground and background (WCAG AA: 4.5:1 ratio)
- Test your theme with actual UI components before finalizing
- Keep custom CSS minimal - CSS variables handle most styling
- Use `color-mix()` for hover states: `color-mix(in srgb, var(--primary) 80%, black)`
