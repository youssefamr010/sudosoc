/* SudoSOC console — Predict view (real-time flow prediction) */

function Field({ label, value, onChange, type = "text", options }) {
  const [focus, setFocus] = useState(false);
  const common = {
    fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--fg)", background: "var(--panel-2)",
    border: `1px solid ${focus ? "var(--red)" : "var(--line)"}`, borderRadius: "var(--r-sm)",
    padding: "10px 12px", outline: "none", width: "100%", boxSizing: "border-box",
    boxShadow: focus ? "0 0 0 3px var(--red-wash)" : "none", transition: "all var(--t-fast)",
  };
  return <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
    <Kicker>{label}</Kicker>
    {options
      ? <select value={value} onChange={e => onChange(e.target.value)} onFocus={() => setFocus(true)} onBlur={() => setFocus(false)} style={common}>
          {options.map(o => <option key={o}>{o}</option>)}</select>
      : <input value={value} onChange={e => onChange(e.target.value)} onFocus={() => setFocus(true)} onBlur={() => setFocus(false)} style={common} />}
  </label>;
}

function Predict() {
  const [f, setF] = useState({ src: "185.220.101.4", dst: "10.0.0.12", dport: "80", proto: "TCP", pkts: "48210", ent: "7.9" });
  const [result, setResult] = useState(null);
  const set = k => v => setF(s => ({ ...s, [k]: v }));
  function run() {
    const ent = parseFloat(f.ent) || 0;
    const hostile = ent > 7.5 || ["4444","31337"].includes(f.dport) || parseInt(f.pkts) > 10000;
    const conf = hostile ? 0.9 + Math.random() * 0.09 : 0.55 + Math.random() * 0.25;
    setResult(null);
    setTimeout(() => setResult({
      verdict: hostile ? "ATTACK DETECTED" : "NORMAL TRAFFIC", hostile, conf,
      cls: hostile ? "SYN Flood" : "Benign",
      probs: hostile
        ? [{ k: "SYN Flood", v: conf }, { k: "DoS", v: 0.04 }, { k: "Port Scan", v: 0.03 }, { k: "Normal", v: 1 - conf - 0.07 }]
        : [{ k: "Normal", v: conf }, { k: "Trusted Agency", v: 0.18 }, { k: "Port Scan", v: 0.06 }, { k: "DoS", v: 1 - conf - 0.24 }],
    }), 120);
  }
  return <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, alignItems: "start" }}>
    <Panel title="Real-time flow prediction" kicker="3-layer hybrid engine" icon="zap">
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <Field label="Source IP" value={f.src} onChange={set("src")} />
        <Field label="Destination IP" value={f.dst} onChange={set("dst")} />
        <Field label="Destination port" value={f.dport} onChange={set("dport")} />
        <Field label="Protocol" value={f.proto} onChange={set("proto")} options={["TCP", "UDP", "ICMP"]} />
        <Field label="Packets" value={f.pkts} onChange={set("pkts")} />
        <Field label="Payload entropy" value={f.ent} onChange={set("ent")} />
      </div>
      <Button icon="search-code" onClick={run} style={{ marginTop: 16, width: "100%", justifyContent: "center" }}>Predict verdict</Button>
    </Panel>
    <div>
      {!result && <Panel style={{ minHeight: 280 }} bodyStyle={{ display: "grid", placeItems: "center", minHeight: 280 }}>
        <div style={{ textAlign: "center", color: "var(--fg-4)" }}>
          <Icon name="scan-search" size={34} />
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, marginTop: 12 }}>Enter flow details and run a prediction.</div>
        </div>
      </Panel>}
      {result && <Verdict r={result} />}
    </div>
  </div>;
}

function Verdict({ r }) {
  const [w, setW] = useState(0);
  useEffect(() => { setW(0); const t = setTimeout(() => setW(r.conf * 100), 120); return () => clearTimeout(t); }, [r]);
  const accent = r.hostile ? "var(--red)" : "var(--safe)";
  const accentHi = r.hostile ? "var(--red-hi)" : "#5AD494";
  return <section className="sds-pop" style={{
    background: "var(--panel)", border: `1px solid ${r.hostile ? "rgba(219,34,35,.45)" : "rgba(37,194,110,.4)"}`,
    borderRadius: "var(--r-lg)", boxShadow: r.hostile ? "var(--glow-soft)" : "none", overflow: "hidden",
  }}>
    <div style={{ height: 4, background: accent }} />
    <div style={{ padding: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <Icon name={r.hostile ? "shield-alert" : "shield-check"} size={26} color={accentHi} />
        <div>
          <div className="h2" style={{ fontSize: 22, color: accentHi }}>{r.verdict}</div>
          <Kicker>predicted class · {r.cls}</Kicker>
        </div>
      </div>
      <div style={{ marginTop: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--fg-3)", marginBottom: 6 }}>
          <span>MODEL CONFIDENCE</span><b style={{ color: accentHi, fontSize: 13 }}>{(r.conf * 100).toFixed(0)}%</b>
        </div>
        <div style={{ height: 8, background: "var(--panel-3)", borderRadius: 999, overflow: "hidden" }}>
          <div style={{ height: "100%", width: w + "%", background: accent, borderRadius: 999, transition: "width 1.2s var(--ease-out)" }} />
        </div>
      </div>
      <div style={{ marginTop: 18 }}>
        <Kicker>class probabilities</Kicker>
        <div style={{ marginTop: 8 }}>
          {r.probs.map(p => <BarRow key={p.k} label={p.k} value={Math.max(0, Math.round(p.v * 100))} max={100}
            color={p.k === r.cls ? accent : "var(--panel-3)"} suffix="%" />)}
        </div>
      </div>
    </div>
  </section>;
}

Object.assign(window, { Predict, Field });
