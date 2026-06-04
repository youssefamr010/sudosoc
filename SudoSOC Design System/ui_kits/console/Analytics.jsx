/* SudoSOC console — Analytics view */

function Sparkline({ color = "var(--red)", h = 60 }) {
  const pts = useRef([...Array(40)].map(() => 20 + Math.random() * 70)).current;
  const w = 100, max = 100;
  const path = pts.map((p, i) => `${(i / (pts.length - 1)) * w},${h - (p / max) * h}`).join(" ");
  return <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ width: "100%", height: h, display: "block" }}>
    <defs><linearGradient id="spk" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stopColor="rgba(219,34,35,.35)" /><stop offset="100%" stopColor="rgba(219,34,35,0)" />
    </linearGradient></defs>
    <polygon points={`0,${h} ${path} ${w},${h}`} fill="url(#spk)" />
    <polyline points={path} fill="none" stroke={color} strokeWidth="1.5" vectorEffect="non-scaling-stroke"
      style={{ strokeDasharray: 400, strokeDashoffset: 400, animation: "sds-draw 1.6s var(--ease-out) forwards" }} />
  </svg>;
}

function Analytics() {
  const maxPort = Math.max(...SOC.TOP_PORTS.map(p => p.v));
  return <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
    <Panel title="Traffic volume" kicker="Last 60 minutes · pps" icon="trending-up">
      <Sparkline h={80} />
    </Panel>
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
      <Panel title="Protocol distribution" kicker="bidirectional flows" icon="network">
        <Donut data={[
          { k: "TCP", v: 68, c: "var(--red)" }, { k: "UDP", v: 24, c: "#FF8A3D" },
          { k: "ICMP", v: 6, c: "#3B82F6" }, { k: "Other", v: 2, c: "var(--fg-4)" },
        ]} size={128} thick={16} />
      </Panel>
      <Panel title="Top destination ports" kicker="most frequent" icon="chart-no-axes-column">
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {SOC.TOP_PORTS.map(p => <BarRow key={p.k} label={":" + p.k} value={p.v} max={maxPort}
            color={["443","80","22"].includes(p.k) ? "var(--red)" : "var(--panel-3)"} />)}
        </div>
      </Panel>
    </div>
    <Panel title="Feature importance" kicker="ensemble · RF + XGBoost stack" icon="cpu">
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 28px" }}>
        {[["bytes_per_pkt",0.21],["payload_entropy",0.18],["dst_port",0.14],["pkt_rate",0.12],
          ["duration_ms",0.09],["syn_ratio",0.08],["fanout",0.07],["payload_len_var",0.05]].map(([f,v])=>
          <BarRow key={f} label={f} value={Math.round(v*100)} max={21} color="var(--violet)" suffix="%" />)}
      </div>
    </Panel>
  </div>;
}

Object.assign(window, { Analytics, Sparkline });
