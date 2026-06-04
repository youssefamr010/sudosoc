/* SudoSOC console — chrome: TopBar + LeftRail */

function TopBar({ live, onToggleLive }) {
  return <header style={{
    height: 56, display: "flex", alignItems: "center", gap: 18, padding: "0 18px",
    borderBottom: "var(--bd)", background: "rgba(11,11,14,0.72)", backdropFilter: "blur(10px)",
    WebkitBackdropFilter: "blur(10px)", flex: "none", zIndex: 5,
  }}>
    <img src="../../assets/logo_wordmark_dark.png" alt="sudosoc" style={{ height: 22 }} />
    <div style={{ width: 1, height: 24, background: "var(--line)" }} />
    <div style={{
      display: "flex", alignItems: "center", gap: 8, background: "var(--panel-2)",
      border: "var(--bd)", borderRadius: "var(--r-sm)", padding: "7px 12px", width: 280, color: "var(--fg-4)",
    }}>
      <Icon name="search" size={15} />
      <input placeholder="Search IP, port, rule, SID…" style={{
        background: "transparent", border: "none", outline: "none", color: "var(--fg)",
        fontFamily: "var(--font-mono)", fontSize: 12.5, width: "100%",
      }} />
    </div>
    <div style={{ flex: 1 }} />
    <button onClick={onToggleLive} style={{
      display: "inline-flex", alignItems: "center", gap: 8, cursor: "pointer",
      fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600, letterSpacing: ".12em",
      color: live ? "var(--safe)" : "var(--fg-4)", background: "var(--panel-2)",
      border: "var(--bd)", borderRadius: 999, padding: "6px 12px",
    }}>
      <StatusDot color={live ? "var(--safe)" : "var(--fg-4)"} pulse={live} size={8} />
      {live ? "LIVE" : "PAUSED"}
    </button>
    <div style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--fg-3)" }}>
      <Icon name="bell" size={18} />
      <div style={{
        width: 30, height: 30, borderRadius: 999, background: "var(--red-900)",
        border: "1px solid rgba(219,34,35,.4)", color: "var(--red-hi)", display: "grid",
        placeItems: "center", fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 700,
      }}>YA</div>
    </div>
  </header>;
}

const NAV = [
  { id: "overview", label: "Overview", icon: "layout-dashboard" },
  { id: "analytics", label: "Flow Analytics", icon: "chart-no-axes-column" },
  { id: "predict", label: "Predict", icon: "zap" },
  { id: "intel", label: "Intelligence", icon: "brain" },
];

function LeftRail({ view, setView }) {
  return <nav style={{
    width: 210, flex: "none", borderRight: "var(--bd)", background: "rgba(11,11,14,0.55)",
    backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)",
    display: "flex", flexDirection: "column", padding: "14px 12px", gap: 4,
  }}>
    <div style={{ padding: "4px 10px 10px" }}><Kicker>Console</Kicker></div>
    {NAV.map(n => {
      const active = view === n.id;
      return <button key={n.id} onClick={() => setView(n.id)} style={{
        display: "flex", alignItems: "center", gap: 11, padding: "10px 12px", cursor: "pointer",
        borderRadius: "var(--r-sm)", border: "none", textAlign: "left",
        background: active ? "var(--red-wash)" : "transparent",
        color: active ? "var(--fg)" : "var(--fg-3)",
        fontFamily: "var(--font-ui)", fontSize: 13.5, fontWeight: active ? 600 : 500,
        boxShadow: active ? "inset 2px 0 0 var(--red)" : "none",
        transition: "all var(--t-fast)",
      }}
        onMouseEnter={e => { if (!active) e.currentTarget.style.background = "var(--panel-2)"; }}
        onMouseLeave={e => { if (!active) e.currentTarget.style.background = "transparent"; }}>
        <Icon name={n.icon} size={17} color={active ? "var(--red-hi)" : "currentColor"} />
        {n.label}
      </button>;
    })}
    <div style={{ flex: 1 }} />
    <div style={{ padding: 12, border: "var(--bd)", borderRadius: "var(--r-md)", background: "var(--panel)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <Icon name="cpu" size={15} color="var(--violet)" />
        <Kicker>Engine</Kicker>
      </div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--fg-3)", lineHeight: 1.7 }}>
        <div>Layer 1 · Signatures <span style={{ color: "var(--safe)" }}>OK</span></div>
        <div>Layer 2 · RF+XGB <span style={{ color: "var(--safe)" }}>OK</span></div>
        <div>Layer 3 · LLM/Groq <span style={{ color: "var(--safe)" }}>OK</span></div>
      </div>
    </div>
  </nav>;
}

Object.assign(window, { TopBar, LeftRail });
