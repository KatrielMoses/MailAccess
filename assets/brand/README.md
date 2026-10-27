# Brand assets

Identity kit in the mailaccess.pro design system colours. Full usage rules, palette, and typography: [docs/brand.md](../../docs/brand.md).

- **13 numbered assets**: lockups (01–06), profile and app marks (07–10), favicons (11–13).
- All vector, all paths. The wordmark is outlined, so **no font needs to be installed** for these to render correctly. The site and docs use Geist and Geist Mono (SIL OFL).
- The mark on dark: envelope `#EEEDEC`, stroke `#0B0A0B`, corner `#B86A73`. On paper: envelope `#151515`, stroke `#F3F2F0`, corner `#B86A73`.
- Palette: charcoal `#0B0A0B` / `#121113` / `#18171A`, text `#EEEDEC` / `#ABA9A8` / muted `#9A9796`, paper `#F3F2F0`, ink `#151515`, and one accent, dusty rose `#B86A73`, used on small marks only.
- `swatch-*.svg` and `preview-*.svg` are documentation helpers, not brand assets. `preview-*` files have a background panel baked in so the marks stay visible on any docs page. Never ship those.

Do not hand-edit the geometry of these files. Regenerate them from the identity kit if the shapes change.

The kit source bundle lives at `assets/mailaccess Identity Kit.html` and is **gitignored**. It is a design
file, not a shipped asset, so it will not be present in a fresh clone. Keep a copy if you need to regenerate.
