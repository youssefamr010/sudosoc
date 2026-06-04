---
name: sudosoc-design
description: Use this skill to generate well-branded interfaces and assets for SudoSOC — a Hybrid AI-Powered IDS/IPS Security Operations Console — either for production or throwaway prototypes/mocks. Contains essential design guidelines, colors, type, fonts, assets, and a console UI kit for prototyping in the tactical red-on-black SOC aesthetic.
user-invocable: true
---

Read the `README.md` file within this skill, and explore the other available files.

If creating visual artifacts (slides, mocks, throwaway prototypes, etc), copy assets out and create static
HTML files for the user to view. If working on production code, you can copy assets and read the rules here
to become an expert in designing with this brand.

If the user invokes this skill without any other guidance, ask them what they want to build or design, ask
some questions, and act as an expert designer who outputs HTML artifacts _or_ production code, depending on
the need.

## Quick map
- `colors_and_type.css` — all design tokens (color, type, spacing, radii, shadow/glow, motion). Import first.
- `README.md` — product context, content fundamentals, visual foundations, iconography, file index.
- `assets/` — logo (full + dark/light wordmark cutouts).
- `preview/` — design-system specimen cards (color, type, spacing, components, brand).
- `ui_kits/console/` — interactive recreation of the SudoSOC console; reusable React components.

## The one-line brief
Tactical SOC console: black canvas, **red `#DB2223`** as the single loud color, neutrals everywhere else.
Space Grotesk display · IBM Plex Sans UI · JetBrains Mono data. Lucide icons. Alive with motion (radar
sweeps, streaming alerts, count-ups, glow). Calm precise SOC-analyst voice. Never emoji.
