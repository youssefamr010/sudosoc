/* SudoSOC console — Intelligence view (Online Learning · MITRE · Rules · Encrypted) */

const SIGMA = `title: SudoSOC Detection - SYN_Flood
id: sudosoc-20260529-0417
status: experimental
author: SudoSOC Adaptive Engine
tags:
  - attack.impact
  - T1498.001
logsource:
  category: network_connection
  product: zeek
detection:
  selection:
    dst_port: 80
    syn_ratio: '>0.9'
  condition: selection
level: high`;

const SURICATA = `alert tcp any any -> any 80 (msg:"SudoSOC: SYN Flood";
  flow:stateless; flags:S; threshold:type both,track by_src,
  count 200,seconds 5; sid:4021337; rev:1;
  classtype:attempted-dos; priority:1;)`;

function IntelTabs() {
  const TABS = [
    { id: "ol", label: "Online Learning", icon: "refresh-cw" },
    { id: "mitre", label: "MITRE ATT&CK", icon: "crosshair" },
    { id: "rules", label: "Generated Rules", icon: "file-code" },
    { id: "enc", label: "Encrypted Traffic", icon: "lock" },
  ];
  const [tab, setTab] = useState("ol");
  return <Panel kicker="Adaptive Security Intelligence" title="Engine internals" icon="brain"
    bodyStyle={{ padding: 0 }}>
    <div style={{ display: "flex", gap: 2, padding: "0 12px", borderBottom: "var(--bd-soft)" }}>
      {TABS.map(t => {
        const on = tab === t.id;
        return <button key={t.id} onClick={() => setTab(t.id)} style={{
          display: "flex", alignItems: "center", gap: 8, padding: "13px 14px", cursor: "pointer",
          background: "none", border: "none", borderBottom: `2px solid ${on ? "var(--red)" : "transparent"}`,
          color: on ? "var(--fg)" : "var(--fg-3)", fontFamily: "var(--font-ui)", fontSize: 13, fontWeight: on ? 600 : 500,
          marginBottom: -1, transition: "color var(--t-fast)",
        }}>
          <Icon name={t.icon} size={15} color={on ? "var(--red-hi)" : "currentColor"} />{t.label}
        </button>;
      })}
    </div>
    <div style={{ padding: 18 }}>
      {tab === "ol" && <OnlineLearning />}
      {tab === "mitre" && <MitreView />}
      {tab === "rules" && <RulesView />}
      {tab === "enc" && <EncryptedView />}
    </div>
  </Panel>;
}

function OnlineLearning() {
  return <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12 }}>
      {[["Last retrain", "2026-05-29 03:14"], ["Retrain type", "incremental"], ["Training samples", "1.42M"], ["Pending feedback", "37"]].map(([k, v], i) =>
        <div key={i} style={{ background: "var(--panel-2)", border: "var(--bd)", borderRadius: "var(--r-md)", padding: 13 }}>
          <Kicker>{k}</Kicker><div style={{ fontFamily: "var(--font-mono)", fontSize: 14, color: "var(--fg)", marginTop: 6 }}>{v}</div>
        </div>)}
    </div>
    <div style={{ background: "var(--panel-2)", border: "var(--bd)", borderRadius: "var(--r-md)", padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <Icon name="waves" size={16} color="var(--cyan)" /><Kicker>Concept Drift Monitor</Kicker>
        </div>
        <Badge sev="safe" dot>within threshold</Badge>
      </div>
      <Sparkline color="var(--cyan)" h={56} />
      <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--fg-3)", marginTop: 8 }}>
        <span>baseline KL-div 0.04</span><span>threshold 0.15</span><span>retrain auto-trigger @ 0.15</span>
      </div>
    </div>
    <div style={{ display: "flex", gap: 10, alignItems: "center", padding: 14, background: "var(--red-wash)", border: "1px solid rgba(219,34,35,.25)", borderRadius: "var(--r-md)" }}>
      <Icon name="message-square-reply" size={18} color="var(--red-hi)" />
      <span style={{ fontFamily: "var(--font-ui)", fontSize: 13, color: "var(--fg-2)", flex: 1 }}>Analyst feedback tunes the model live — mark alerts as false/true positive to suppress repeats.</span>
      <Button variant="block" icon="thumbs-down">False positive</Button>
      <Button variant="secondary" icon="thumbs-up">Confirm</Button>
    </div>
  </div>;
}

function MitreView() {
  const max = Math.max(...SOC.MITRE.map(m => m.n));
  return <div>
    <Kicker red>Alerts per technique · last 24h</Kicker>
    <div style={{ marginTop: 12 }}>
      {SOC.MITRE.slice(0, 8).map(m => <div key={m.tech} style={{ display: "grid", gridTemplateColumns: "240px 1fr auto", gap: 12, alignItems: "center", padding: "5px 0" }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--fg-2)" }}>
          <b style={{ color: "var(--red-hi)" }}>{m.tech}</b> {m.techn}</span>
        <div style={{ height: 8, background: "var(--panel-3)", borderRadius: 999, overflow: "hidden" }}>
          <div style={{ height: "100%", width: (m.n / max * 100) + "%", background: "linear-gradient(90deg,var(--red-deep),var(--red))", borderRadius: 999, transition: "width 1s var(--ease-out)" }} />
        </div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--fg-3)" }}>{m.n}</span>
      </div>)}
    </div>
  </div>;
}

function RuleBlock({ title, lang, code }) {
  return <div style={{ background: "var(--panel-2)", border: "var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 13px", borderBottom: "var(--bd-soft)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}><Icon name="file-code" size={14} color="var(--red-hi)" /><Kicker>{title}</Kicker></div>
      <Icon name="copy" size={14} color="var(--fg-4)" />
    </div>
    <pre style={{ margin: 0, padding: 14, fontFamily: "var(--font-mono)", fontSize: 11.5, lineHeight: 1.6, color: "var(--fg-2)", overflowX: "auto", whiteSpace: "pre-wrap" }}>{code}</pre>
  </div>;
}

function RulesView() {
  return <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
    <RuleBlock title="Sigma · sigma_0417.yml" code={SIGMA} />
    <RuleBlock title="Suricata · suricata.rules" code={SURICATA} />
  </div>;
}

function EncryptedView() {
  return <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
    <div style={{ display: "flex", gap: 10, alignItems: "center", padding: "12px 14px", background: "var(--cyan-wash)", border: "1px solid rgba(34,211,216,.25)", borderRadius: "var(--r-md)" }}>
      <Icon name="lock" size={16} color="var(--cyan)" />
      <span style={{ fontFamily: "var(--font-ui)", fontSize: 13, color: "var(--fg-2)" }}>Flagged <b style={{ color: "var(--fg)" }}>without decryption</b> — entropy + packet-timing + connection-behavior signatures.</span>
    </div>
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 110px 90px 120px", gap: 12, padding: "0 13px 8px", borderBottom: "var(--bd-soft)" }}>
        {["Host / SNI", "TLS", "Entropy", "Verdict"].map(h => <Kicker key={h}>{h}</Kicker>)}
      </div>
      {SOC.ENC.map((e, i) => <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 110px 90px 120px", gap: 12, padding: "11px 13px", alignItems: "center", borderBottom: "var(--bd-soft)" }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--fg)" }}>{e.host}</span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: e.tls === "TLS 1.3" ? "var(--safe)" : e.tls === "TLS 1.0" ? "var(--red-hi)" : "var(--fg-3)" }}>{e.tls}</span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: e.ent > 7.95 ? "var(--red-hi)" : "var(--fg-3)" }}>{e.ent.toFixed(2)}</span>
        <Badge sev={e.verdict === "suspicious" ? "critical" : "safe"} dot>{e.verdict}</Badge>
      </div>)}
    </div>
  </div>;
}

Object.assign(window, { IntelTabs });
