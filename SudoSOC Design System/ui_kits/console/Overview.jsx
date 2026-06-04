/* SudoSOC console — Overview view */

function Radar() {
  return <div style={{ position: "relative", width: 150, height: 150, margin: "0 auto",
    borderRadius: 999, border: "1px solid var(--line)", overflow: "hidden",
    background: "radial-gradient(circle, rgba(219,34,35,.06), transparent 70%)" }}>
    <div style={{ position: "absolute", inset: "24%", border: "1px solid var(--line-soft)", borderRadius: 999 }} />
    <div style={{ position: "absolute", inset: "44%", border: "1px solid var(--line-soft)", borderRadius: 999 }} />
    <div style={{ position: "absolute", left: 0, right: 0, top: "50%", height: 1, background: "var(--line-soft)" }} />
    <div style={{ position: "absolute", top: 0, bottom: 0, left: "50%", width: 1, background: "var(--line-soft)" }} />
    <div style={{ position: "absolute", inset: 0, borderRadius: 999,
      background: "conic-gradient(from 0deg, rgba(219,34,35,.5), transparent 60deg)",
      animation: "sds-spin 3s linear infinite" }} />
    {[[30,62,.4],[64,38,1.2],[48,72,2.1],[36,30,1.7]].map(([t,l,d],i) =>
      <span key={i} style={{ position: "absolute", top: t+"%", left: l+"%", width: 7, height: 7,
        borderRadius: 999, background: "var(--red)", boxShadow: "0 0 10px var(--red)",
        animation: `sds-blip 3s ${d}s infinite` }} />)}
  </div>;
}

function KpiHeader() {
  const K = SOC.KPI;
  const cards = [
    { lab: "Total flows", icon: "activity", to: K.flows, foot: "+12,840 / min", footC: "var(--safe)" },
    { lab: "Attacks", icon: "shield-alert", to: K.attacks, red: true, alert: true, foot: "last 24h", footC: "var(--fg-3)" },
    { lab: "Blocked", icon: "ban", to: K.blocked, foot: "99.2% automated", footC: "var(--red-hi)" },
    { lab: "Detection accuracy", icon: "target", to: K.accuracy, fmt: v => v.toFixed(1) + "%", foot: "across all classes", footC: "var(--fg-3)" },
  ];
  return <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12 }}>
    {cards.map((c, i) => <div key={i} style={{
      position: "relative", background: "var(--panel)", borderRadius: "var(--r-lg)",
      border: c.alert ? "1px solid rgba(219,34,35,.4)" : "var(--bd)", padding: 16,
      boxShadow: "var(--inset-top)",
    }}>
      <div style={{ position: "absolute", top: 14, right: 14, color: c.alert ? "var(--red-hi)" : "var(--fg-4)" }}>
        <Icon name={c.icon} size={18} />
      </div>
      <Kicker>{c.lab}</Kicker>
      <div className="metric" style={{ fontSize: 30, marginTop: 10, color: c.red ? "var(--red-hi)" : "var(--fg)" }}>
        <CountUp to={c.to} fmt={c.fmt} />
      </div>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: c.footC, marginTop: 5 }}>{c.foot}</div>
    </div>)}
  </div>;
}

function AlertRow({ a, onClick, isNew, selected }) {
  const s = SEV[a.severity];
  return <button onClick={onClick} className={isNew ? "sds-slidein" : ""} style={{
    display: "grid", gridTemplateColumns: "70px 90px 1fr auto", gap: 12, alignItems: "center",
    width: "100%", textAlign: "left", cursor: "pointer",
    background: selected ? "var(--panel-2)" : "var(--panel)",
    border: "var(--bd)", borderLeft: `3px solid ${s.dot}`, borderRadius: "var(--r-sm)",
    padding: "9px 13px", transition: "background var(--t-fast)",
  }}
    onMouseEnter={e => { if (!selected) e.currentTarget.style.background = "var(--panel-2)"; }}
    onMouseLeave={e => { if (!selected) e.currentTarget.style.background = "var(--panel)"; }}>
    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--fg-3)" }}>{a.ts}</span>
    <Badge sev={a.severity} dot>{a.severity}</Badge>
    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--fg-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
      <b style={{ color: "var(--fg)" }}>{a.attack_type}</b> · {a.src_ip} → {a.dst_ip}:{a.dst_port} · conf <b style={{ color: "var(--fg)" }}>{a.confidence.toFixed(2)}</b>
    </span>
    <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600, letterSpacing: ".05em",
      padding: "3px 8px", borderRadius: "var(--r-xs)",
      background: a.blocked ? "var(--red-900)" : "var(--panel-3)",
      color: a.blocked ? "var(--red-hi)" : "var(--fg-3)" }}>{a.blocked ? "BLOCKED" : a.tier}</span>
  </button>;
}

function AlertDrawer({ a, onClose, onAction }) {
  const [typed, setTyped] = useState("");
  useEffect(() => {
    if (!a) return;
    setTyped(""); let i = 0;
    const t = setInterval(() => { i++; setTyped(a.llm.slice(0, i)); if (i >= a.llm.length) clearInterval(t); }, 12);
    return () => clearInterval(t);
  }, [a && a.id]);
  if (!a) return null;
  const s = SEV[a.severity];
  return <div style={{ position: "absolute", inset: 0, zIndex: 20 }}>
    <div onClick={onClose} style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.6)", backdropFilter: "blur(4px)" }} />
    <div className="sds-drawer" style={{
      position: "absolute", top: 0, right: 0, bottom: 0, width: 420, background: "var(--panel)",
      borderLeft: "1px solid var(--line)", boxShadow: "var(--sh-lg)", display: "flex", flexDirection: "column",
    }}>
      <header style={{ padding: "16px 18px", borderBottom: "var(--bd)", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <Kicker red>{a.mitre_tactic} · {a.mitre_tname}</Kicker>
          <h3 className="h3" style={{ marginTop: 6, color: s.c }}>{a.attack_type}</h3>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--fg-3)", cursor: "pointer" }}><Icon name="x" size={20} /></button>
      </header>
      <div style={{ padding: 18, display: "flex", flexDirection: "column", gap: 16, overflowY: "auto", flex: 1 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          {[["Source", `${a.src_ip}:${a.src_port}`],["Destination", `${a.dst_ip}:${a.dst_port}`],
            ["Protocol", a.proto],["Confidence", a.confidence.toFixed(2)],
            ["Packets", a.pkts.toLocaleString()],["Volume", SOC.fmtBytes(a.bytes)]].map(([k,v],i)=>
            <div key={i} style={{ background: "var(--panel-2)", border: "var(--bd)", borderRadius: "var(--r-sm)", padding: "9px 11px" }}>
              <Kicker>{k}</Kicker>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--fg)", marginTop: 4 }}>{v}</div>
            </div>)}
        </div>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <Icon name="sparkles" size={14} color="var(--violet)" /><Kicker>LLM analysis · Llama 3.3</Kicker>
          </div>
          <div style={{ background: "var(--panel-2)", border: "var(--bd)", borderRadius: "var(--r-md)",
            padding: 13, fontFamily: "var(--font-mono)", fontSize: 12.5, lineHeight: 1.65, color: "var(--fg-2)" }}>
            {typed}<span className="sds-cursor">▋</span>
          </div>
        </div>
        <div>
          <Kicker>MITRE ATT&CK</Kicker>
          <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, padding: "6px 10px", borderRadius: "var(--r-xs)", background: "var(--panel-2)", border: "var(--bd)", color: "var(--fg-2)" }}><b style={{ color: "var(--red-hi)" }}>{a.mitre_tech}</b> {a.mitre_techn}</span>
          </div>
        </div>
      </div>
      <footer style={{ padding: 14, borderTop: "var(--bd)", display: "flex", gap: 8 }}>
        <Button variant="block" icon="ban" onClick={() => onAction("Blocked " + a.src_ip)} style={{ flex: 1, justifyContent: "center" }}>Block IP</Button>
        <Button variant="secondary" icon="shield-off" onClick={() => onAction("Isolated " + a.src_ip)} style={{ flex: 1, justifyContent: "center" }}>Isolate</Button>
        <Button variant="ghost" icon="check" onClick={() => onAction("Marked false positive")}>FP</Button>
      </footer>
    </div>
  </div>;
}

function Overview({ alerts, live, onSelect, selected }) {
  return <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
    <KpiHeader />
    <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 14, alignItems: "start" }}>
      <Panel title="Live alert feed" kicker="Real-time engine" icon="siren"
        action={<span style={{ display: "inline-flex", alignItems: "center", gap: 7, fontFamily: "var(--font-mono)", fontSize: 10.5, color: live ? "var(--safe)" : "var(--fg-4)", letterSpacing: ".1em" }}><StatusDot color={live ? "var(--safe)" : "var(--fg-4)"} pulse={live} size={7} />{live ? "STREAMING" : "PAUSED"}</span>}
        bodyStyle={{ padding: 12, display: "flex", flexDirection: "column", gap: 6, maxHeight: 360, overflowY: "auto" }}>
        {alerts.map((a, i) => <AlertRow key={a.id} a={a} isNew={i === 0 && live} selected={selected && selected.id === a.id} onClick={() => onSelect(a)} />)}
      </Panel>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <Panel title="Live monitor" kicker="Engine nominal" icon="radar">
          <Radar />
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 14, fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--fg-3)" }}>
            <span>{SOC.KPI.pps.toLocaleString()} pps</span><span>{SOC.KPI.sensors} sensors</span><span>drift {SOC.KPI.drift}</span>
          </div>
        </Panel>
        <Panel title="Response actions" kicker="iptables tiers" icon="git-branch">
          <Donut data={SOC.TIER_DIST} size={120} thick={15} />
        </Panel>
      </div>
    </div>
  </div>;
}

Object.assign(window, { Overview, AlertDrawer, Radar });
