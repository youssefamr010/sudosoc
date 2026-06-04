# SudoSOC Console — UI Kit

A high-fidelity, interactive recreation of the **SudoSOC Security Operations Console** — the product's
single web surface (originally the Streamlit `dashboard.py`). Built as a click-through React prototype in
the brand's tactical red-on-black aesthetic.

Open **`index.html`** for the live demo.

## What's here

| View | What it shows |
|---|---|
| **Overview** | Live KPI header (count-up metrics), streaming alert feed, radar live-monitor, response-tier donut, and a slide-in **alert detail drawer** with LLM analysis + Block/Isolate/FP actions. |
| **Flow Analytics** | Traffic sparkline, protocol-distribution donut, top-ports bar chart, ensemble feature-importance. |
| **Predict** | The real-time flow-prediction form → animated **verdict panel** with confidence bar + class probabilities. |
| **Intelligence** | Tabbed engine internals: Online Learning + Concept Drift Monitor, MITRE ATT&CK coverage, generated Sigma/Suricata rules, and decryption-free Encrypted-Traffic analysis. |

## Interactions to try
- Toggle **LIVE / PAUSED** in the top bar — the alert feed streams new alerts every ~3s.
- Click any **alert row** → detail drawer slides in; the LLM summary types out. Click **Block IP** → toast confirms `iptables` update.
- In **Predict**, change Payload entropy (>7.5) or Packets (>10k) and run a prediction to flip the verdict.
- Switch **Intelligence** tabs.

## Files
- `index.html` — scaffold: loads `colors_and_type.css`, React 18 + Babel, Lucide (CDN), then components.
- `data.js` — mock data model (attacks, alerts generator, KPIs, MITRE, encrypted flows) mirroring engine fields.
- `ui.jsx` — shared primitives: `Icon`, `Badge`, `StatusDot`, `Button`, `Panel`, `CountUp`, `BarRow`, `Donut`, `SEV`.
- `Chrome.jsx` — `TopBar` + `LeftRail`.
- `Overview.jsx` — `KpiHeader`, `AlertRow`, `AlertDrawer`, `Radar`, `Overview`.
- `Analytics.jsx` — `Analytics`, `Sparkline`.
- `Predict.jsx` — `Predict`, `Field`, `Verdict`.
- `Intelligence.jsx` — `IntelTabs` and the four tab panels.
- `app.jsx` — `App` shell: routing, live-feed loop, selection, action toast.

## Notes
- This is a **cosmetic recreation** — predictions, blocking, and rule generation are simulated client-side.
  The real engine (RF+XGBoost stack, Sigma/Suricata generation, `iptables` injection, mitmproxy sniffer)
  lives in [`youssefamr010/sudosoc`](https://github.com/youssefamr010/sudosoc).
- Icons are **Lucide** via CDN. Fonts are Google Fonts (Space Grotesk / IBM Plex Sans / JetBrains Mono).
- Components are modular — lift `Panel`, `Badge`, `Donut`, `BarRow`, `KpiHeader`, `AlertRow` into real designs.
