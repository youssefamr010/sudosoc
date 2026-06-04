/* SudoSOC console — mock data model. Mirrors fields from realtime_ids.py / dashboard.py. */
window.SOC = (function () {
  const ATTACKS = [
    { type: "SYN Flood",        sev: "critical", tier: "AUTO_BLOCK", tactic: "TA0040", tname: "Impact",          tech: "T1498.001", techn: "Direct Network Flood" },
    { type: "Port Scan",        sev: "high",     tier: "ISOLATE",    tactic: "TA0043", tname: "Reconnaissance",  tech: "T1046",     techn: "Network Service Scanning" },
    { type: "Brute Force",      sev: "high",     tier: "RATE_LIMIT", tactic: "TA0006", tname: "Credential Access", tech: "T1110",   techn: "Brute Force" },
    { type: "SQL Injection",    sev: "critical", tier: "AUTO_BLOCK", tactic: "TA0001", tname: "Initial Access",  tech: "T1190",     techn: "Exploit Public-Facing App" },
    { type: "ICMP Flood",       sev: "medium",   tier: "RATE_LIMIT", tactic: "TA0040", tname: "Impact",          tech: "T1498.001", techn: "Direct Network Flood" },
    { type: "Shell Injection",  sev: "critical", tier: "AUTO_BLOCK", tactic: "TA0002", tname: "Execution",       tech: "T1059",     techn: "Command & Scripting Interpreter" },
    { type: "Encoded PowerShell", sev: "high",   tier: "ISOLATE",    tactic: "TA0002", tname: "Execution",       tech: "T1059.001", techn: "PowerShell" },
    { type: "UDP Amplification", sev: "medium",  tier: "RATE_LIMIT", tactic: "TA0040", tname: "Impact",          tech: "T1498.002", techn: "Reflection Amplification" },
    { type: "Netcat Reverse Shell", sev: "critical", tier: "AUTO_BLOCK", tactic: "TA0011", tname: "Command & Control", tech: "T1095", techn: "Non-Application Layer Protocol" },
  ];
  const HOSTILE_IPS = ["185.220.101.4","45.83.193.7","91.240.118.9","193.27.228.13","23.129.64.217","104.244.76.13","176.10.99.200","209.141.55.26"];
  const PROTOS = ["TCP","TCP","TCP","UDP","ICMP"];
  const SUMMARIES = {
    "SYN Flood": "High-confidence SYN flood from a known Tor exit node. Maps to T1498.001 (Direct Network Flood). Recommend immediate AUTO_BLOCK and upstream rate-limit.",
    "Port Scan": "Sequential connection attempts across 1k+ ports indicate active reconnaissance. Low payload, high fan-out. Isolate source and monitor for follow-on exploitation.",
    "Brute Force": "Repeated failed auth against SSH. Credential-access pattern (T1110). Rate-limit source and enforce lockout policy.",
    "SQL Injection": "Payload contains UNION-based injection markers against a public endpoint. High severity. AUTO_BLOCK and audit the target application.",
    "ICMP Flood": "Sustained ICMP echo volume above baseline. Likely volumetric DoS attempt. Rate-limit at the edge.",
    "Shell Injection": "Command-injection signature in request body. Execution-stage threat. Block immediately and capture payload for forensics.",
    "Encoded PowerShell": "Base64-encoded PowerShell detected in flow. Obfuscated execution attempt. Isolate host and inspect process tree.",
    "UDP Amplification": "Spoofed-source UDP with large response ratio — reflection/amplification. Rate-limit and verify upstream filtering.",
    "Netcat Reverse Shell": "Outbound connection to suspicious port matches reverse-shell behavior (T1095). C2 indicator. Block and quarantine host.",
  };
  function rint(a,b){return Math.floor(a+Math.random()*(b-a+1));}
  function pick(a){return a[rint(0,a.length-1)];}
  function ip(){return "10.0.0."+rint(2,40);}
  function ts(off){const d=new Date(Date.now()-off*1000);return d.toTimeString().slice(0,8);}
  let _seq = 0;
  function makeAlert(ageSec){
    const a = pick(ATTACKS);
    const proto = pick(PROTOS);
    const conf = (a.sev==="critical"? rint(90,99): a.sev==="high"? rint(78,94): rint(62,86))/100;
    const blocked = a.tier==="AUTO_BLOCK" || (a.tier==="ISOLATE" && Math.random()>0.4);
    return {
      id: ++_seq,
      ts: ts(ageSec||0),
      severity: a.sev, attack_type: a.type, tier: a.tier,
      src_ip: pick(HOSTILE_IPS), src_port: rint(1024,65000),
      dst_ip: ip(), dst_port: pick([22,80,443,3306,8080,53,4444]),
      proto, confidence: conf, blocked,
      pkts: rint(40,52000), bytes: rint(2000,9_000_000),
      mitre_tactic: a.tactic, mitre_tname: a.tname, mitre_tech: a.tech, mitre_techn: a.techn,
      llm: SUMMARIES[a.type],
    };
  }
  function seed(n){ const out=[]; for(let i=0;i<n;i++) out.push(makeAlert(i*7+rint(0,5))); return out; }
  const KPI = { flows: 1284902, attacks: 3417, blocked: 3390, accuracy: 95.4, sensors: 3, pps: 12840, drift: 0.04 };
  const PROTO_DIST = [{k:"TCP",v:68},{k:"UDP",v:24},{k:"ICMP",v:6},{k:"Other",v:2}];
  const TIER_DIST = [{k:"AUTO_BLOCK",v:41,c:"#FF3B40"},{k:"ISOLATE",v:23,c:"#FF8A3D"},{k:"RATE_LIMIT",v:21,c:"#3B82F6"},{k:"LOG",v:15,c:"#25C26E"}];
  const TOP_PORTS = [{k:"443",v:920},{k:"80",v:740},{k:"22",v:610},{k:"3306",v:280},{k:"53",v:190},{k:"4444",v:120},{k:"8080",v:95}];
  const MITRE = ATTACKS.map(a=>({tech:a.tech,techn:a.techn,tactic:a.tname,n:rint(8,140)})).sort((x,y)=>y.n-x.n);
  const ENC = [
    {host:"api.stripe.com", tls:"TLS 1.3", ent:7.9, verdict:"normal"},
    {host:"185.220.101.4", tls:"TLS 1.2", ent:7.99, verdict:"suspicious"},
    {host:"cdn.cloudflare.com", tls:"TLS 1.3", ent:7.7, verdict:"normal"},
    {host:"unknown-c2.xyz", tls:"TLS 1.0", ent:7.98, verdict:"suspicious"},
    {host:"login.microsoft.com", tls:"TLS 1.3", ent:7.6, verdict:"normal"},
  ];
  return { ATTACKS, makeAlert, seed, KPI, PROTO_DIST, TIER_DIST, TOP_PORTS, MITRE, ENC, fmtBytes, };
  function fmtBytes(b){ if(b>1e6) return (b/1e6).toFixed(1)+" MB"; if(b>1e3) return (b/1e3).toFixed(1)+" KB"; return b+" B"; }
})();
