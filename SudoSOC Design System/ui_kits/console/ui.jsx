/* SudoSOC console — shared UI primitives */
const { useState, useEffect, useRef } = React;

// Lucide icon that re-renders safely
function Icon({ name, size = 16, color, style, className }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current && window.lucide) {
      ref.current.innerHTML = "";
      const el = document.createElement("i");
      el.setAttribute("data-lucide", name);
      ref.current.appendChild(el);
      window.lucide.createIcons({ attrs: { width: size, height: size }, nameAttr: "data-lucide" });
    }
  }, [name, size]);
  return <span ref={ref} className={className}
    style={{ display: "inline-flex", color: color || "currentColor", lineHeight: 0, ...style }} />;
}

function Kicker({ children, red, style }) {
  return <span className={"kicker" + (red ? " kicker--red" : "")} style={style}>{children}</span>;
}

function StatusDot({ color = "var(--red)", pulse, size = 8 }) {
  return <span style={{
    width: size, height: size, borderRadius: 999, background: color, display: "inline-block",
    flex: "none", boxShadow: pulse ? `0 0 0 0 ${color}` : "none",
    animation: pulse ? "sds-pulse 1.6s infinite" : "none",
  }} data-dot-color={color} />;
}

const SEV = {
  critical: { c: "#FF6B6F", dot: "#FF3B40", wash: "rgba(255,59,64,.12)", bd: "rgba(255,59,64,.3)" },
  high:     { c: "#FFA266", dot: "#FF8A3D", wash: "rgba(255,138,61,.12)", bd: "rgba(255,138,61,.3)" },
  medium:   { c: "#FFD466", dot: "#FFC53D", wash: "rgba(255,197,61,.12)", bd: "rgba(255,197,61,.3)" },
  info:     { c: "#7FACF8", dot: "#3B82F6", wash: "rgba(59,130,246,.12)", bd: "rgba(59,130,246,.3)" },
  safe:     { c: "#5AD494", dot: "#25C26E", wash: "rgba(37,194,110,.12)", bd: "rgba(37,194,110,.3)" },
};

function Badge({ sev = "info", children, dot }) {
  const s = SEV[sev] || SEV.info;
  return <span style={{
    fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600, letterSpacing: ".07em",
    textTransform: "uppercase", padding: "4px 9px", borderRadius: "var(--r-xs)",
    background: s.wash, color: s.c, border: `1px solid ${s.bd}`,
    display: "inline-flex", alignItems: "center", gap: 7, whiteSpace: "nowrap",
  }}>
    {dot && <StatusDot color={s.dot} size={6} />}{children}
  </span>;
}

function Button({ children, variant = "primary", icon, onClick, style, type }) {
  const [hover, setHover] = useState(false);
  const base = {
    fontFamily: "var(--font-ui)", fontWeight: 600, fontSize: 13.5, borderRadius: "var(--r-sm)",
    padding: "9px 15px", display: "inline-flex", alignItems: "center", gap: 8, cursor: "pointer",
    border: "1px solid transparent", transition: "all var(--t-fast) var(--ease-out)", whiteSpace: "nowrap",
  };
  const variants = {
    primary: { background: hover ? "var(--red-bright)" : "var(--red)", color: "#fff", boxShadow: hover ? "var(--glow-soft)" : "none" },
    secondary: { background: hover ? "var(--panel-3)" : "var(--panel-2)", color: "var(--fg)", borderColor: hover ? "#34343e" : "var(--line)" },
    ghost: { background: hover ? "var(--panel-2)" : "transparent", color: hover ? "var(--fg)" : "var(--fg-3)" },
    block: { background: hover ? "#3a1112" : "var(--red-900)", color: "var(--red-hi)", borderColor: hover ? "var(--red)" : "rgba(219,34,35,.4)" },
  };
  return <button type={type || "button"} onClick={onClick}
    onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
    style={{ ...base, ...variants[variant], ...style }}>
    {icon && <Icon name={icon} size={16} />}{children}
  </button>;
}

function Panel({ children, title, kicker, icon, action, alert, style, bodyStyle }) {
  return <section style={{
    background: "var(--panel)", border: alert ? "1px solid rgba(219,34,35,.4)" : "var(--bd)",
    borderRadius: "var(--r-lg)", boxShadow: alert ? "var(--glow-soft)" : "var(--inset-top)",
    display: "flex", flexDirection: "column", overflow: "hidden", ...style,
  }}>
    {(title || kicker) && (
      <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "14px 16px", borderBottom: "var(--bd-soft)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {icon && <Icon name={icon} size={17} color="var(--red-hi)" />}
          <div>
            {kicker && <div style={{ marginBottom: title ? 3 : 0 }}><Kicker red>{kicker}</Kicker></div>}
            {title && <h3 className="h3" style={{ fontSize: 16 }}>{title}</h3>}
          </div>
        </div>
        {action}
      </header>
    )}
    <div style={{ padding: 16, flex: 1, ...bodyStyle }}>{children}</div>
  </section>;
}

// animated count-up number
function CountUp({ to, dur = 1300, fmt }) {
  const [v, setV] = useState(0);
  const ref = useRef();
  useEffect(() => {
    const t0 = performance.now();
    function step(t) {
      const k = Math.min(1, (t - t0) / dur);
      const e = 1 - Math.pow(1 - k, 3);
      setV(to * e);
      if (k < 1) ref.current = requestAnimationFrame(step);
    }
    ref.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(ref.current);
  }, [to]);
  return <>{fmt ? fmt(v) : Math.round(v).toLocaleString()}</>;
}

// horizontal bar (animated fill)
function BarRow({ label, value, max, color = "var(--red)", suffix }) {
  const pct = Math.max(2, (value / max) * 100);
  return <div style={{ display: "grid", gridTemplateColumns: "84px 1fr auto", gap: 12, alignItems: "center", padding: "5px 0" }}>
    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--fg-3)" }}>{label}</span>
    <div style={{ height: 8, background: "var(--panel-3)", borderRadius: 999, overflow: "hidden" }}>
      <div style={{ height: "100%", width: pct + "%", background: color, borderRadius: 999,
        transition: "width 1s var(--ease-out)" }} />
    </div>
    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--fg-2)", fontVariantNumeric: "tabular-nums" }}>
      {value.toLocaleString()}{suffix || ""}</span>
  </div>;
}

// donut chart (SVG, animated)
function Donut({ data, size = 132, thick = 16, center }) {
  const total = data.reduce((s, d) => s + d.v, 0);
  const r = (size - thick) / 2;
  const C = 2 * Math.PI * r;
  let acc = 0;
  const [grow, setGrow] = useState(false);
  useEffect(() => { const t = setTimeout(() => setGrow(true), 80); return () => clearTimeout(t); }, []);
  return <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)", flex: "none" }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="var(--panel-3)" strokeWidth={thick} />
      {data.map((d, i) => {
        const frac = d.v / total;
        const dash = grow ? C * frac : 0;
        const seg = <circle key={i} cx={size/2} cy={size/2} r={r} fill="none"
          stroke={d.c || "var(--red)"} strokeWidth={thick}
          strokeDasharray={`${dash} ${C}`} strokeDashoffset={-acc}
          style={{ transition: "stroke-dasharray .9s var(--ease-out)" }} />;
        acc += C * frac;
        return seg;
      })}
    </svg>
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      {center}
      {data.map((d, i) => <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <StatusDot color={d.c || "var(--red)"} size={8} />
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--fg-2)", minWidth: 96 }}>{d.k}</span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--fg-3)" }}>{d.v}%</span>
      </div>)}
    </div>
  </div>;
}

Object.assign(window, { Icon, Kicker, StatusDot, Badge, Button, Panel, CountUp, BarRow, Donut, SEV });
