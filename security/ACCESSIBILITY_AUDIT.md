# Accessibility audit (WCAG 2.1 A/AA, automated)

Date: 2026-09-24. Target: the built React UI served by the real backend (Vite dev server used for the run because the production CSP correctly blocks injecting a scanner script).

## Method
- **axe-core 4.10.2**, rule sets `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, run against 12 real UI states: intake, each of the 3 sample cases x every result tab (Evidence, Relay path, URLs, Source & attachments), Case history, Gmail alerts, Connections graph.
- **Custom contrast pass**, because axe reports contrast as "incomplete" on this app's gradient background: computed effective foreground/background (including alpha and inherited opacity) for every visible text element and compared against 4.5:1 (3:1 for large text). Disabled controls skipped per WCAG. 1,226 text elements checked.
- **Reflow at 375 px** (phone width): checked every main view for horizontal page overflow.

## Result
| Check | Result |
|---|---|
| axe-core WCAG 2.1 A/AA violations | **0** across all 12 states |
| Text contrast failures (4.5:1 / 3:1 large) | **0** of 1,226 text elements, after the fix below |
| Horizontal overflow at 375 px | **None** on any view |

## Real finding, fixed
Attribution "not applied" rows were dimmed with `opacity: .65`, which dropped their text to about 2.9:1 (13 elements). Replaced the opacity with explicit muted colors (`#8b93a1`, about 6.4:1) in `frontend/src/ps-features.css`; the rows stay visually de-emphasised and now pass.

False positives correctly excluded: disabled buttons ("Analyze email", "Connect", "Record note", "Hold" before their inputs are filled) - WCAG exempts disabled controls from contrast requirements.

## Scope - what this does NOT prove
Automated tools catch roughly a third of accessibility problems. This is not a screen-reader walkthrough, a full keyboard-only usability test, or a WCAG conformance certification. Claim: "automated WCAG 2.1 A/AA audit clean, contrast verified, mobile reflow verified" - not "WCAG AA certified".
