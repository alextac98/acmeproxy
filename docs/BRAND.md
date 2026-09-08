# ACME Proxy brand

[View the visual brand sheet](../assets/brand/brand-sheet.svg).

ACME Proxy’s gateway-shaped A and cyan path express controlled access through a single gateway. The interface uses a blue palette adapted from the generated artwork, with quiet surfaces for administrative work.

## Color palette

| Color | Hex | CSS token | Use |
| --- | --- | --- | --- |
| Royal blue | `#0057E6` | `--brand-blue` | Primary actions, links, light-surface focus outlines |
| Hover blue | `#0044B8` | `--brand-blue-hover` | Primary button hover |
| Cyan | `#00CDDD` | `--brand-cyan` | Selected navigation indicator, focus on navy, decorative accents |
| Deep navy | `#071D49` | `--brand-navy` | Navigation background, key figures, pressed primary buttons |
| Ink | `#172B4D` | `--ink` | Body text and headings |
| Muted | `#566782` | `--muted` | Supporting text |
| Canvas | `#F4F7FD` | `--canvas` | Page background |
| White | `#FFFFFF` | `--surface` | Cards, forms, button text |
| Soft white | `#F8FAFF` | `--surface-soft` | Table headings and panel notes |
| Blue tint | `#EAF1FF` | `--brand-tint` | Informational callouts, badges, subtle hover backgrounds |
| Border | `#DCE4F2` | `--border` | Surface separators |
| Input border | `#A5B4CC` | `--input-border` | Form control boundaries |

The CSS custom properties in `web/style.css` are the implementation source of truth. Use tokens for interface colors rather than introducing component-specific hex values.

## Logo

Use [the full logo](../web/brand/logo.png) on white or light surfaces. On deep navy, pair [the icon](../web/brand/icon.png) with light live text, as in the app navigation. Preserve the original proportions and colors. Leave at least one quarter of the icon’s width as clear space around a standalone mark. Do not stretch, recolor, or add shadows to the artwork.

The supplied assets are transparent PNGs. The original generated artwork and prompts are retained in `assets/brand/`.

## Typography and components

Use the existing Inter-first system sans-serif stack; no external font download is required. Body text is 16 px, controls 14 px, and desktop page headings 32 px. Use medium or semibold weights for hierarchy. Use monospace for identifiers and configuration values. The logo wordmark remains artwork.

Keep spacing mainly in multiples of 4 px, 6 px corner radii for controls, 8 px for cards, and 12–14 px for dialogs and the sign-in card. Primary buttons use solid royal blue with white labels, hover blue on hover, and navy while pressed. Secondary actions use white or a pale blue hover surface. Selected navigation uses a lighter navy surface plus a cyan edge and light text.

## Readability and status

Use royal blue, ink, or muted text on light surfaces. Cyan is an accent, not small text on white. Focus outlines are royal blue on light surfaces and cyan on the navy navigation. Keep visible text labels for statuses and errors.

Semantic status colors remain distinct from branding: green `#227669` on `#E8F5F1` for success, amber `#896827` on `#FFF6DF` for pending work, and red `#AB2F44` on `#FFF2F4` for errors. Destructive buttons use red with white text. Informational callouts use the blue palette.
