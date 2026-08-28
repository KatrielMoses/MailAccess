# Brand assets

Identity kit v1. Full usage rules, palette, and typography: [docs/brand.md](../../docs/brand.md).

- **13 numbered assets** — lockups (01–06), profile and app marks (07–10), favicons (11–13).
- All vector, all paths. The wordmark is outlined, so **Jost does not need to be installed** for these to render correctly.
- Palette is three colours: `#0D0D0D` near-black, `#8A1C2B` maroon (`#D8455A` on dark UI), `#9AA0A6` cool gray.
- `swatch-*.svg` and `preview-*.svg` are documentation helpers, not brand assets. `preview-*` files have a background panel baked in so on-dark marks stay visible on a light docs page — never ship those.

Do not hand-edit these files. Regenerate them from the identity kit if the brand changes.

The kit source bundle lives at `assets/mailaccess Identity Kit.html` and is **gitignored** — it is a design
file, not a shipped asset, so it will not be present in a fresh clone. Keep a copy if you need to regenerate.
