/* SudoSOC console — main app */
function App() {
  const [view, setView] = useState("overview");
  const [live, setLive] = useState(true);
  const [alerts, setAlerts] = useState(() => SOC.seed(7));
  const [selected, setSelected] = useState(null);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    if (!live) return;
    const t = setInterval(() => {
      setAlerts(prev => [SOC.makeAlert(0), ...prev].slice(0, 14));
    }, 3200);
    return () => clearInterval(t);
  }, [live]);

  function action(msg) {
    setSelected(null);
    setToast(msg);
    setTimeout(() => setToast(null), 2600);
  }

  return <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: "transparent", position: "relative" }}>
    <TopBar live={live} onToggleLive={() => setLive(l => !l)} />
    <div style={{ display: "flex", flex: 1, overflow: "hidden", position: "relative" }}>
      <LeftRail view={view} setView={setView} />
      <main style={{ flex: 1, overflowY: "auto", padding: 18, position: "relative" }}>
        <div style={{ marginBottom: 16, display: "flex", alignItems: "baseline", justifyContent: "space-between" }}>
          <div>
            <Kicker red>{TITLE[view].k}</Kicker>
            <h1 className="h1" style={{ fontSize: 28, marginTop: 4 }}>{TITLE[view].t}</h1>
          </div>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--fg-4)" }}>{new Date().toISOString().slice(0, 10)} · UTC</span>
        </div>
        {view === "overview" && <Overview alerts={alerts} live={live} selected={selected} onSelect={setSelected} />}
        {view === "analytics" && <Analytics />}
        {view === "predict" && <Predict />}
        {view === "intel" && <IntelTabs />}
      </main>
      {view === "overview" && <AlertDrawer a={selected} onClose={() => setSelected(null)} onAction={action} />}
    </div>
    {toast && <div className="sds-toast" style={{
      position: "absolute", bottom: 22, left: "50%", transform: "translateX(-50%)", zIndex: 50,
      background: "var(--panel)", border: "1px solid var(--red)", borderRadius: "var(--r-md)",
      padding: "12px 18px", boxShadow: "var(--glow-soft)", display: "flex", alignItems: "center", gap: 10,
      fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--fg)",
    }}>
      <Icon name="check-circle-2" size={16} color="var(--red-hi)" />{toast}
      <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--fg-4)", marginLeft: 4 }}>· iptables updated</span>
    </div>}
  </div>;
}

const TITLE = {
  overview: { k: "Security Operations", t: "Overview" },
  analytics: { k: "Network telemetry", t: "Flow Analytics" },
  predict: { k: "Hybrid engine", t: "Real-time Prediction" },
  intel: { k: "Adaptive intelligence", t: "Intelligence" },
};

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
