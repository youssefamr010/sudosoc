# SudoSOC — Design System

> **SudoSOC** is a Hybrid AI-Powered IDS/IPS (Intrusion Detection & Prevention System) for 2026 — a
> **Security Operations Console** that watches network traffic in real time, decides what is hostile, and
> blocks it automatically. This repository is its **brand + design system**: tokens, type, color, assets,
> and high-fidelity UI-kit recreations of the product's console.

---

## What the product actually is

SudoSOC runs a **3-layer hybrid detection engine**:

1. **Rule / signature layer** — fast deterministic matches (Sigma & Suricata rules, port heuristics).
2. **Ensemble ML layer** — Random Forest + XGBoost combined via stacking; ~**95%+ detection accuracy**
   across DDoS/DoS, port scanning, brute-force, and encrypted-channel anomalies.
3. **LLM contextual layer** — Llama 3.3 / Qwen (via **Groq** + **HuggingFace** APIs) writes SOC-analyst
   threat summaries, maps alerts to **MITRE ATT&CK**, and auto-generates detection rules.

Key behaviors the UI must express:
- **Automated IPS response** — confirmed attacks trigger `iptables` rule injection to block the attacker IP
  within seconds. Response tiers: `AUTO_BLOCK` · `ISOLATE` · `RATE_LIMIT` · `LOG`.
- **Encrypted-traffic detection without decryption** — entropy analysis + packet-timing + connection-behavior
  signatures flag suspicious TLS/SSL flows.
- **Online-learning feedback loop** + **Concept Drift Monitor** — detects baseline shifts and triggers
  selective model retraining. Analysts can label alerts (false/true positive) to tune the model live.
- **MITRE ATT&CK mapping** — every alert carries a tactic (e.g. `TA0043 Reconnaissance`) and technique
  (e.g. `T1046 Network Service Scanning`).

### Attack classes in the vocabulary
`Port Scan` · `SYN Flood` · `ICMP Flood` · `SQL Injection` · `XSS Attempt` · `Path Traversal` ·
`Shell Injection` · `Netcat Reverse Shell` · `Encoded PowerShell` · `NOP-Sled / Shellcode` ·
`UDP Amplification` · `DoS / DDoS` · `Brute Force (ACCESS)` · `Trusted Agency` (whitelisted).

### The one product surface
SudoSOC ships as a **single web console** (originally a Streamlit dashboard). It is the only product, so
this system contains **one UI kit**: `ui_kits/console/`. The console has: live KPI header, real-time alert
feed, network-flow analytics, a real-time flow-prediction tool, and the "Adaptive Security Intelligence"
tabs (Online Learning · MITRE ATT&CK · Generated Rules · Encrypted Traffic).

---

## Sources used to build this system

- **GitHub:** [`youssefamr010/sudosoc`](https://github.com/youssefamr010/sudosoc) — the engine + Streamlit
  dashboard. The visual recreations here are derived from `dashboard.py` (layout, metrics, tabs, charts),
  `llm_analyzer.py` (MITRE map, attack types, rule generation), and `DEPLOYMENT_GUIDE.md`.
  **Explore this repo further** to build more accurate or deeper designs against the real engine output.
- **Logo:** `uploads/sudosoc_logo.png` (provided). Brand red sampled directly: **`#DB2223`**.

> The original dashboard uses default Streamlit styling + emoji. The **red/black tactical console aesthetic
> here is an intentional brand direction** layered on top of that functionality (requested: "red and black,
> dynamic and interactive with animations"). Layout, data model, and vocabulary stay faithful to the code.

---

## CONTENT FUNDAMENTALS

How SudoSOC speaks. The voice is a **calm, precise SOC analyst** — never alarmist, even about critical
threats. Authority through specificity.

- **Person:** System-as-operator. It reports in the **third person about traffic/threats** ("Source
  185.220.101.4 flagged — Port Scan") and gives the analyst **direct imperatives** for actions
  ("Block source IP", "Confirm true positive"). It rarely says "I".
- **Tone:** Clinical, confident, fast. States verdicts and confidence, not opinions. "ATTACK DETECTED —
  confidence 0.96" not "This might be bad."
- **Casing:**
  - **Kickers / labels / status** → `UPPERCASE` with wide tracking (`CRITICAL`, `AUTO_BLOCK`, `LIVE`,
    `TLS 1.3`). This is the signature treatment.
  - **Headings** → Title Case or sentence case ("Real-time flow prediction").
  - **Data** → verbatim mono (IPs, ports, SIDs, hashes, `T1046`).
- **Numbers & units:** Always concrete and mono. Percentages to one decimal in metrics (`95.4%`),
  confidence as `0.00–1.00` or `%`, latency in `ms`, throughput in `pps` / `Mbps`, bytes humanized
  (`8.2 KB`). Tabular figures everywhere.
- **Verbs:** Action-first and decisive — *Block, Isolate, Rate-limit, Quarantine, Confirm, Suppress,
  Retrain, Flag, Trace, Whitelist.*
- **Emoji:** The source Streamlit app leans on emoji (🛡️🚨📊). **The design system replaces these with a
  line-icon set** (see ICONOGRAPHY). Do not use emoji in branded output.
- **Vibe:** A war-room console at 3am. Quiet black, telemetry humming, one red light when something's wrong.
  Think Bloomberg-terminal density meets cyber-defense restraint — *not* consumer-friendly, *not* playful.

**Sample copy:**
- KPI: `TOTAL FLOWS 1,284,902` · `ATTACKS 3,417` · `BLOCKED 3,390` · `ACCURACY 95.4%`
- Alert row: `14:22:07 · CRITICAL · SYN Flood · 185.220.101.4:443 → 10.0.0.12:80 · conf 0.97 · BLOCKED`
- LLM summary: "High-confidence SYN flood from a known Tor exit. Maps to T1498.001 (Direct Network Flood).
  Recommend immediate AUTO_BLOCK and upstream rate-limit."
- Empty state: "No alerts in window. Engine nominal — baseline within drift threshold."

---

## VISUAL FOUNDATIONS

The look is a **tactical SOC console**: black canvas, red as the single loud color, everything else
neutral and quiet so that *threat* reads instantly.

- **Color strategy:** Black/near-black surfaces (`--void #08080A` → `--panel-3 #1D1D23`) layered by
  elevation. **Red (`#DB2223`) is reserved** for brand, active state, and danger — never decorative.
  Semantic status colors (orange `ISOLATE`, blue `RATE_LIMIT`, green `LOG/NORMAL`, cyan `encrypted`)
  appear only in badges, charts, and tier indicators — small doses against the neutral field.
- **Type:** `Space Grotesk` for display/headings (geometric, engineered), `IBM Plex Sans` for UI/body,
  `JetBrains Mono` for all data (IPs, ports, timestamps, metrics, rules, code). Mono + tabular figures
  give the "instrument readout" feel. Kickers are mono uppercase with `0.18em` tracking.
- **Backgrounds:** Flat black, never gradient-as-decoration. Texture comes from a faint **grid/graticule**
  (1px lines at low opacity), occasional **scanline** overlays, and a soft **radial red vignette/glow**
  behind focal panels. No photography. No illustration. No noise-for-noise's-sake.
- **Cards / panels:** `--panel #111115` fill, `1px solid --line #26262E` border, radius `10–14px`,
  shadow `--sh-md`. A subtle top inset highlight (`--inset-top`). Active/alerting panels get a red left
  rule or `--glow-red` ring. Corners are modestly rounded (10–14px) — engineered, not soft/friendly.
- **Borders:** Hairline (`1px`) is the default everywhere — borders do the work, not heavy fills.
  `--line` for structure, `--line-soft` for quiet dividers, `--red` for danger/active.
- **Shadows & glow:** Shadows are deep and soft (dark theme). The signature elevation is **glow**, not
  drop-shadow: `--glow-red` (red ring + bloom) on active/critical elements; `--glow-soft` for hover.
- **Animation (this brand is *alive*):**
  - **Easing:** `--ease-out` (cubic-bezier .16,1,.3,1) for entrances; `--ease-snap` for toggles/badges.
  - **Signature motions:** pulsing **status dot** (live heartbeat), **radar sweep** on monitoring panels,
    **scanline** drift, **count-up** on metrics, **streaming** alert rows that slide in from the top,
    **threat flash** (brief red wash) when a critical alert lands, animated **bar/donut** chart fills,
    typing-cursor blink on the LLM summary. Durations 130–420ms; ambient loops 2–6s.
  - Fades + small translateY for entrances; **no bounce on layout**, snap only on small controls.
- **Hover states:** Surfaces lighten one step (`--panel` → `--panel-3`); borders brighten; red elements
  gain `--glow-soft`. Links/icons go `--fg-3 → --fg`. Always a `--t-fast` transition.
- **Press states:** Brief scale-down (`0.97`) + deeper color (`--red → --red-deep`); buttons lose glow on
  press then restore.
- **Transparency & blur:** Used for **overlays/modals** (backdrop `rgba(0,0,0,0.6)` + `blur(8px)`) and for
  status washes (10% color fills behind badges/rows). Glass/blur is for chrome, never primary content.
- **Imagery vibe:** N/A — this is a data console. "Imagery" = data viz: donuts, sparklines, bar charts,
  the network graticule, a radar sweep. All rendered cool/neutral with red highlights.
- **Layout rules:** Dense, grid-aligned, instrument-panel composition. Fixed top KPI/status bar; left
  rail nav; main content as a responsive panel grid (`gap` via fl/grid, never margins). 4pt spacing scale.
  Tabular data is king — generous row height (44px min hit target), tabular-nums, zebra-free (use hairlines).
- **Radii:** `3px` chips → `6px` inputs/buttons → `10–14px` cards → `999px` pills/status dots.

---

## ICONOGRAPHY

- **System:** [**Lucide**](https://lucide.dev) (linked from CDN: `unpkg.com/lucide`). Chosen for its
  consistent **1.75–2px stroke**, geometric grid, and deep security-relevant set
  (`shield`, `shield-alert`, `activity`, `scan-line`, `lock`, `network`, `radar`, `siren`, `cpu`,
  `git-branch`, `terminal`, `ban`, `eye`, `waves`). Stroke style matches the engineered red/black look.
- **Why a substitution:** the source Streamlit app uses **emoji** (🛡️🚨📊🧠🔐) as iconography. Emoji
  are inconsistent across platforms and clash with the tactical aesthetic, so this system **standardizes
  on Lucide** line icons. **⚑ Flag:** if you have a bespoke SudoSOC icon set, drop the SVGs in `assets/`
  and we'll swap them in.
- **Usage rules:** icons are monochrome — inherit `currentColor`. Default `--fg-3`; `--fg` on hover;
  `--red`/severity color only when conveying status. Size `16px` inline, `18–20px` in nav/buttons,
  `24px` for panel headers. Never two-tone, never filled unless indicating an active toggle.
- **Status dots** (not icons): solid `999px` circles in the severity color, often with a pulsing ring —
  the primary at-a-glance threat indicator.
- **Logo:** `assets/sudosoc_logo.png` (full, on light card). Wordmark cutouts with transparent
  backgrounds: `assets/logo_wordmark_dark.png` (white "sud" + red, for dark surfaces — **default**) and
  `assets/logo_wordmark_light.png` (for light surfaces). The mark is `sudo→soc` with a red arrow/link
  glyph joining the halves.

---

## Index — what's in this system

| Path | What it is |
|---|---|
| `colors_and_type.css` | All design tokens: color, type scale, spacing, radii, shadows/glow, motion. Import this first. |
| `assets/sudosoc_logo.png` | Full logo on light card (provided original). |
| `assets/logo_wordmark_dark.png` | Wordmark for dark surfaces (transparent bg) — **default**. |
| `assets/logo_wordmark_light.png` | Wordmark for light surfaces (transparent bg). |
| `preview/*.html` | Design-system cards (color, type, spacing, components) shown in the Design System tab. |
| `ui_kits/console/` | The SudoSOC console UI kit — `index.html` (interactive demo) + JSX components. See its own `README.md`. |
| `SKILL.md` | Agent-Skill manifest so this system can be used as a Claude Skill. |

**UI kits:** `ui_kits/console/` — the SudoSOC Security Operations Console (the product's only surface):
Overview, Flow Analytics, Predict, and Intelligence views with a live streaming alert feed and slide-in
alert drawer. Reusable React primitives live in `ui_kits/console/ui.jsx`.

**Start here:** import `colors_and_type.css`, read this README, then open `ui_kits/console/index.html`
for the live product recreation.
