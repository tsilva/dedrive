# Home page design QA

Date: 2026-10-01

final result: passed

## Laptop density adjustment

The user requested a smaller version of the same design, with the main content mostly above the fold on a MacBook. This supersedes the original mockup's typography and spacing scale. Content width is capped at 1160px, the headline at 72px, and the workflow heading at 38px. Short desktop viewports use tighter spacing and a 32px workflow heading. The three-column preview remains available down to 1101px; mobile still stacks its regions.

At a 1440 × 800 CSS viewport, the local page height decreased from 1154px to 852px (26%). The full hero, workflow tabs, photo preview, and safety note fit in the first viewport, ending at y748 even with the local OAuth configuration error visible. Footer details require a small scroll. At 1280 × 720 the full photo preview remains visible; the safety note extends slightly below the fold in the configuration-error state. Mobile was inspected at 390 × 844 with no horizontal overflow or clipped content. Production build and whitespace checks pass; this update only changes CSS.

Final viewport screenshot: `/Users/tsilva/.codex/visualizations/2026/10/01/01a0f699-f472-7e33-84e0-d0fa6aef9688/home-compact-laptop.png`.

## Comparison target and evidence

- Source visual truth: `/Users/tsilva/.codex/generated_images/01a0f699-f472-7e33-84e0-d0fa6aef9688/exec-119dfcd2-bc9b-4ea5-bca6-444cd27321e2.png` (third displayed ideation result).
- Implementation: `http://localhost:63130/`, initial read-only example selected.
- Final implementation screenshot: `/Users/tsilva/.codex/visualizations/2026/10/01/01a0f699-f472-7e33-84e0-d0fa6aef9688/implementation-desktop-final.png`.
- Desktop CSS viewport: 1422 × 1106; device pixel ratio 1. Source and final implementation pixels: 1422 × 1106. No scaling or density normalization required for final comparison.
- Full-view comparison: `/Users/tsilva/.codex/visualizations/2026/10/01/01a0f699-f472-7e33-84e0-d0fa6aef9688/comparison-final.jpg`. Both images were assembled into one comparison input and opened.
- Focused hero comparison: `/Users/tsilva/.codex/visualizations/2026/10/01/01a0f699-f472-7e33-84e0-d0fa6aef9688/comparison-hero-final.jpg`.
- Focused preview comparison: `/Users/tsilva/.codex/visualizations/2026/10/01/01a0f699-f472-7e33-84e0-d0fa6aef9688/comparison-preview-final.jpg`.
- Mobile evidence: `/Users/tsilva/.codex/visualizations/2026/10/01/01a0f699-f472-7e33-84e0-d0fa6aef9688/implementation-mobile.png`, CSS viewport 390 × 844, full page screenshot. Tablet evidence: `implementation-tablet.png` in the same directory, CSS viewport 1024 × 900. Full-page captures omit the reserved scrollbar column; DOM measurements confirmed no horizontal overflow.

## Findings

No actionable P0/P1/P2 findings remain in the home page.

### Required fidelity surfaces

- **Fonts and typography:** Self-hosted Inter variable font reproduces the heavy display hierarchy with a monospace wordmark and step numbers. The headline has the intended two-line structure, and the workflow heading stays on one line at the reference width. Body copy, tabs, captions, and reassurance remain readable at all inspected sizes. Font files are served locally with their OFL license.
- **Spacing and layout rhythm:** Header, split hero, three steps, comparison panel, safety strip, and two-column footer follow the selected composition. After correction, hero ends at approximately y393 and preview begins at approximately y581, matching the source. Photos retain 3:2 proportions. On tablet the reassurance becomes a full-width row; mobile stacks the hero and footer, preserving two duplicate photos side by side. No clipped controls or overlapping text were observed.
- **Colors and tokens:** Near-black page, graphite panel, muted gray secondary text, blue CTA/active step, and green keep status match the source's semantics. Visible focus outlines distinguish keyboard interaction. Slight source lighting and gradients are omitted; flat surfaces preserve the intended hierarchy.
- **Image quality and assets:** A generated 1536 × 1024 coastal photograph matches the sea, mountains, grassy foreground, and daisies. The same asset is reused twice and both images loaded successfully. Next Image supplies responsive optimized images. Unmodified Feather SVG assets provide standard UI icons; the Google mark reuses the existing app asset. No handcrafted icon or image substitutes were introduced.
- **Copy and content:** Main headline, workflow labels, example paths, reassurance, and safety statement match the mockup. The footer intentionally says that no files are uploaded to dedrive rather than claiming Drive files never leave the user's device. The preview is explicitly an example; it does not authenticate or alter real files. Moving copies to `_dupes` is not described as freeing storage.

## Comparison history

1. **Initial comparison — blocked:** Initial screenshot `implementation-desktop-initial.png` and combined evidence `comparison-initial.jpg` showed P2 typography and spacing drift: the display text was too narrow, the hero intro divider sat too far right, and preview/footer sections were about 26–34 px too low. Initial full-page capture was 1407 × 1139 because page height exceeded the viewport and reserved a scrollbar. Fix: self-host Inter; adjust headline scale and tracking, hero column ratio/padding, workflow gaps, CTA width, and safety strip padding.
2. **Revised comparison — blocked:** `comparison-revised.jpg` showed corrected section rhythm and matching 1422 × 1106 frames, but display headings remained too narrow. Fix: increase headline and workflow heading scale, relax tracking, and increase file-path text size. Separately, mobile inspection found the hidden GitHub label left the icon link unnamed; add an explicit accessible label.
3. **Final comparison — passed:** `comparison-final.jpg`, `comparison-hero-final.jpg`, and `comparison-preview-final.jpg` were opened together with both source and implementation in each input. Display hierarchy, region alignment, photo proportions, and visible copy now preserve the selected design. No actionable P0/P1/P2 differences remain.

## Interaction and browser checks

- Clicking the review tab selects it and updates its title/reassurance.
- ArrowRight moves keyboard focus/selection to the move tab and updates the move label and explanatory text.
- Home returns focus/selection to the read-only tab.
- How it works scrolls the workflow section to its intended offset.
- Find duplicates requests Google sign-in from its click handler and enters `/app` only after read-only access is granted. Regression tests verify cancellation/retry and reuse of the in-memory session in the app without a second access request.
- GitHub destination and accessible name inspected; no external write actions taken.
- Mobile and tablet images load; measured document widths do not exceed the available viewport.
- Browser logs checked: no errors or warnings; development HMR and React DevTools messages only.
- All 76 regression tests pass. Production build passes.

## Secure-app entry correction

Removed the redundant introduction, feature cards, entry banner, and workflow navigation before sign-in. The compact entry screen retains the Google sign-in gate and read-only access explanation. Regression coverage verifies that scan settings appear after sign-in and that entering the app does not request write access or start a scan. Browser evidence: `/Users/tsilva/.codex/visualizations/2026/10/01/01a0f699-f472-7e33-84e0-d0fa6aef9688/secure-signin-fixed.png`.

The home-page CTA now opens Google directly, bypassing the app's signed-out fallback. Both routes use the Script `onReady` callback so a previously loaded Google script initializes after navigation. Browser evidence of the current home-page configuration-error state: `/Users/tsilva/.codex/visualizations/2026/10/01/01a0f699-f472-7e33-84e0-d0fa6aef9688/home-direct-signin.png`.

## Test gap

Google OAuth cannot be completed in this checkout because `NEXT_PUBLIC_GOOGLE_CLIENT_ID` is absent. The home page displays the configuration error and disables the sign-in CTA. Successful sign-in, navigation, cancellation/retry, and session reuse are covered with mocked Google access in the regression suite; no real Drive access or file moves were attempted.

## Implementation checklist

- [x] Implement selected home page in the existing Next.js project.
- [x] Use the generated photo and locally served, licensed font/icons.
- [x] Connect CTA and add accessible, keyboard-operable example steps.
- [x] Check desktop/tablet/mobile rendering and console logs.
- [x] Fix blocking visual drift and compare again.
- [x] Update README.

## Follow-up polish

P3 only: the standard Feather GitHub and shield silhouettes differ slightly from the mockup, the coastal photo is a matching regeneration rather than an identical original, and the blue ambient lighting is omitted. The Next.js development indicator is preview infrastructure and does not appear in production.
