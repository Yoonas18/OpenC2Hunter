import React, { useState, useEffect } from "react";
import {
  ShieldAlert, Activity, Terminal, Lock, Globe,
  ExternalLink, FileCode, CheckCircle2, AlertTriangle,
  User, LogOut, KeyRound, ShieldCheck
} from "lucide-react";

const API_TOKEN = import.meta.env.VITE_OPENC2_TOKEN || "";
const IS_DEMO_MODE = import.meta.env.VITE_DEMO_MODE === "true";

const DEMO_FLOWS = [
  {
    flow_key: "demo_1",
    process_name: "python3.exe",
    pid: 4812,
    exe_path: "C:\\Users\\Public\\ai_agent_sync.py",
    process_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    is_protected: 0,
    dst_ip: "185.220.101.45",
    dst_port: 8443,
    protocol: "TCP",
    session_count: 142,
    avg_iat: 60.2,
    jitter_pct: 4.8,
    dns_entropy: 4.12,
    is_dga: 1,
    dns_query: "x9k2m7p4q8z1w3.c2-routing.top",
    risk_score: 95,
    raw_preview: "1603010200010001fc0303a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4",
    intel: {
      shodan_ports: [80, 443, 8443],
      shodan_tags: ["c2", "self-signed"],
      threatfox_malware: "Sliver C2 / Autonomous Agent",
      vt_detections: "18/72"
    }
  },
  {
    flow_key: "demo_2",
    process_name: "svchost_sync",
    pid: 9104,
    exe_path: "/tmp/.X11-unix/svchost_sync",
    process_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    is_protected: 0,
    dst_ip: "149.154.167.220",
    dst_port: 443,
    protocol: "TCP",
    session_count: 64,
    avg_iat: 15.1,
    jitter_pct: 11.2,
    dns_entropy: 3.12,
    is_dga: 0,
    dns_query: "api.telegram.org",
    risk_score: 82,
    raw_preview: "504f5354202f626f743638323931303a4141482d78797a2f73656e64446f63",
    intel: {
      shodan_ports: [443],
      shodan_tags: ["cloud", "telegram"],
      threatfox_malware: "Dead-Drop Resolver Suspicion",
      vt_detections: "9/72"
    }
  },
  {
    flow_key: "demo_3",
    process_name: "chrome.exe",
    pid: 2140,
    exe_path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    process_sha256: "PROTECTED:chrome.exe:2140",
    is_protected: 1,
    dst_ip: "142.250.190.46",
    dst_port: 443,
    protocol: "UDP",
    session_count: 890,
    avg_iat: 1.4,
    jitter_pct: 84.5,
    dns_entropy: 2.65,
    is_dga: 0,
    dns_query: "www.google.com",
    risk_score: 5,
    raw_preview: "c300000001088394c8f03e5157080000449e7b9a2c",
    intel: {
      shodan_ports: [80, 443],
      shodan_tags: ["cdn", "google"],
      threatfox_malware: "None",
      vt_detections: "0/72"
    }
  }
];

export default function ThreatHunterDashboard() {
  const [flows, setFlows] = useState(DEMO_FLOWS);
  const [selectedFlow, setSelectedFlow] = useState(DEMO_FLOWS[0]);
  const [canaryAlerts, setCanaryAlerts] = useState([]);
  const [mitigatedIps, setMitigatedIps] = useState([]);
  const [sigmaModal, setSigmaModal] = useState(false);

  // Authentication states
  const [authToken, setAuthToken] = useState(() => localStorage.getItem("openc2_auth_token") || API_TOKEN || "");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState("superadmin");
  const [authChecking, setAuthChecking] = useState(true);

  // Login form states
  const [usernameInput, setUsernameInput] = useState("superadmin");
  const [passwordInput, setPasswordInput] = useState("");
  const [loginError, setLoginError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Verify existing token on initial load
  useEffect(() => {
    if (IS_DEMO_MODE) {
      setIsAuthenticated(true);
      setAuthChecking(false);
      return;
    }

    const tokenToVerify = authToken || API_TOKEN;
    if (!tokenToVerify) {
      setIsAuthenticated(false);
      setAuthChecking(false);
      return;
    }

    fetch("http://127.0.0.1:8000/api/v1/auth/verify", {
      headers: { "X-OpenC2-Token": tokenToVerify }
    })
      .then((res) => {
        if (res.ok) {
          setIsAuthenticated(true);
          setAuthToken(tokenToVerify);
          localStorage.setItem("openc2_auth_token", tokenToVerify);
        } else {
          setIsAuthenticated(false);
          localStorage.removeItem("openc2_auth_token");
        }
      })
      .catch(() => {
        setIsAuthenticated(false);
      })
      .finally(() => {
        setAuthChecking(false);
      });
  }, []);

  // Polling data when authenticated
  useEffect(() => {
    if (!isAuthenticated || IS_DEMO_MODE) return;
    const headers = { "X-OpenC2-Token": authToken };

    const interval = setInterval(async () => {
      try {
        const res = await fetch("http://127.0.0.1:8000/api/v1/graph-stats", { headers });
        if (res.status === 401 || res.status === 403) {
          handleLogout();
          return;
        }
        if (res.ok) {
          const data = await res.json();
          if (data.flows && data.flows.length > 0) {
            setFlows(data.flows);
          }
        }
        const cRes = await fetch("http://127.0.0.1:8000/api/v1/canary-alerts", { headers });
        if (cRes.ok) {
          const cData = await cRes.json();
          if (cData.alerts) setCanaryAlerts(cData.alerts);
        }
      } catch {
        // Handled silently
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [isAuthenticated, authToken]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoginError("");
    setIsSubmitting(true);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: usernameInput.trim(),
          password: passwordInput
        })
      });

      const data = await res.json();
      if (res.ok && data.token) {
        setAuthToken(data.token);
        localStorage.setItem("openc2_auth_token", data.token);
        setCurrentUser(data.username || "superadmin");
        setIsAuthenticated(true);
        setPasswordInput("");
      } else {
        setLoginError(data.detail || "Access Denied: Invalid credentials.");
      }
    } catch {
      setLoginError("Connection failed to backend API (http://127.0.0.1:8000). Ensure the backend is active.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleLogout = async () => {
    if (authToken) {
      try {
        await fetch("http://127.0.0.1:8000/api/v1/auth/logout", {
          method: "POST",
          headers: { "X-OpenC2-Token": authToken }
        });
      } catch {
        // Ignore
      }
    }
    localStorage.removeItem("openc2_auth_token");
    setAuthToken("");
    setIsAuthenticated(false);
  };

  const handleMitigate = async (flow) => {
    if (!IS_DEMO_MODE) {
      try {
        const pidParam = flow.is_protected ? "" : `&pid=${flow.pid}`;
        await fetch(`http://127.0.0.1:8000/api/v1/mitigate?dst_ip=${flow.dst_ip}${pidParam}`, {
          method: "POST",
          headers: { "X-OpenC2-Token": authToken }
        });
      } catch {
        // Handled
      }
    }
    setMitigatedIps((prev) => [...prev, flow.dst_ip]);
  };

  // If verifying session initially
  if (authChecking) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 font-mono">
        <div className="w-10 h-10 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin mb-4" />
        <p className="text-sm">Verifying Security Session...</p>
      </div>
    );
  }

  // Login Gate Screen
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 relative overflow-hidden font-sans">
        {/* Subtle cyber background grid */}
        <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-40" />
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative w-full max-w-md bg-slate-900/90 border border-slate-800 shadow-2xl rounded-2xl p-8 backdrop-blur-xl">
          {/* Header */}
          <div className="flex flex-col items-center text-center mb-6">
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-2xl mb-3 shadow-lg shadow-red-500/10">
              <ShieldAlert className="w-9 h-9 text-red-500" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">OpenC2Hunter</h1>
            <p className="text-xs font-mono text-emerald-400 tracking-wider uppercase mt-1">
              SOC Security Gateway
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Authenticate to access the live threat hunting workbench
            </p>
          </div>

          {/* Error Banner */}
          {loginError && (
            <div className="mb-4 p-3 bg-red-500/15 border border-red-500/40 rounded-lg flex items-center gap-2.5 text-xs text-red-300">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{loginError}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-mono uppercase text-slate-300 mb-1.5">
                Username / Role
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  required
                  value={usernameInput}
                  onChange={(e) => setUsernameInput(e.target.value)}
                  placeholder="superadmin"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-300 mb-1.5">
                Lab Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <KeyRound className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  required
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 font-mono"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 px-4 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-sm rounded-lg shadow-lg shadow-emerald-900/30 transition duration-150 flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isSubmitting ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Verifying Credentials...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Authenticate & Enter Lab</span>
                </>
              )}
            </button>
          </form>

          {/* Quick Info Box */}
          <div className="mt-6 p-3 bg-slate-950/70 border border-slate-800 rounded-lg text-[11px] text-slate-400 font-mono space-y-1">
            <div className="flex justify-between text-slate-300 font-semibold border-b border-slate-800 pb-1 mb-1">
              <span>Default Superadmin Credentials:</span>
              <span className="text-emerald-400">ROLE: SUPERADMIN</span>
            </div>
            <div>Username: <span className="text-slate-200">superadmin</span></div>
            <div>Password: <span className="text-slate-200">OpenC2Hunter@2026!</span></div>
            <p className="text-[10px] text-slate-500 pt-1">
              (Configurable via ADMIN_USERNAME & ADMIN_PASSWORD in .env)
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans p-4 select-none">
      <header className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-4 mb-4 gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-500/10 border border-red-500/30 rounded-lg">
            <ShieldAlert className="w-7 h-7 text-red-500" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">
              OpenC2Hunter
              <span className="text-xs font-mono bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded ml-2">
                {IS_DEMO_MODE ? "CLOUD DEMO MODE" : "LOCAL HARDENED ENGINE"}
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Session-Level C2 Beacon, Normalized DGA & Process-Hash Attribution Workbench
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="bg-slate-900 border border-slate-800 px-3.5 py-2 rounded-lg">
            <span className="text-xs text-slate-400 block">Critical Flows</span>
            <span className="text-lg font-bold text-red-400">
              {flows.filter((f) => f.risk_score >= 70).length} Active
            </span>
          </div>
          <div className="bg-slate-900 border border-slate-800 px-3.5 py-2 rounded-lg">
            <span className="text-xs text-slate-400 block">DGA / High Entropy</span>
            <span className="text-lg font-bold text-amber-400">
              {flows.filter((f) => f.is_dga).length} Flagged
            </span>
          </div>
          <div className="bg-slate-900 border border-slate-800 px-3.5 py-2 rounded-lg">
            <span className="text-xs text-slate-400 block">Security Status</span>
            <span className="text-sm font-semibold text-emerald-400 flex items-center gap-1 mt-1">
              <CheckCircle2 className="w-4 h-4" /> Lab Protected
            </span>
          </div>

          {/* Superadmin User Badge & Logout */}
          <div className="bg-slate-900 border border-emerald-500/30 px-3 py-1.5 rounded-lg flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <User className="w-4 h-4 text-emerald-400" />
            <div className="text-left">
              <span className="text-[10px] text-slate-400 block uppercase tracking-wider font-mono">Role</span>
              <span className="text-xs font-semibold text-emerald-300 font-mono">{currentUser}</span>
            </div>
          </div>

          <button
            onClick={handleLogout}
            className="bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
            title="Lock Laboratory Session"
          >
            <LogOut className="w-3.5 h-3.5" /> Lock Lab
          </button>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 mb-4">
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Globe className="w-4 h-4 text-sky-400" /> Direction-Verified Process-to-Socket Topology
            </h2>
            <span className="text-xs text-slate-400">Click any node to inspect telemetry</span>
          </div>

          <div className="relative h-64 bg-slate-950 rounded-lg border border-slate-800/80 overflow-hidden flex items-center justify-center">
            <svg className="w-full h-full" viewBox="0 0 650 240">
              <circle cx="90" cy="120" r="28" className="fill-sky-500/20 stroke-sky-400 stroke-2" />
              <text x="90" y="124" textAnchor="middle" className="fill-white text-[11px] font-bold">LOCAL HOST</text>

              {flows.slice(0, 3).map((flow, idx) => {
                const yPos = 45 + idx * 75;
                const isHighRisk = flow.risk_score >= 70;
                const isBlocked = mitigatedIps.includes(flow.dst_ip);
                const strokeColor = isBlocked ? "#64748b" : isHighRisk ? "#ef4444" : "#10b981";

                return (
                  <g
                    key={flow.flow_key}
                    className="cursor-pointer transition-opacity hover:opacity-90"
                    onClick={() => setSelectedFlow(flow)}
                  >
                    <line x1="118" y1="120" x2="260" y2={yPos} stroke="#334155" strokeWidth="2" />
                    <rect x="260" y={yPos - 16} width="125" height="32" rx="6" className="fill-slate-900 stroke-slate-600" />
                    <text x="322" y={yPos + 4} textAnchor="middle" className="fill-slate-200 text-[11px] font-mono">
                      {flow.process_name} ({flow.pid})
                    </text>
                    <line
                      x1="385"
                      y1={yPos}
                      x2="495"
                      y2={yPos}
                      stroke={strokeColor}
                      strokeWidth={selectedFlow.flow_key === flow.flow_key ? "3" : "1.8"}
                      strokeDasharray={isHighRisk && !isBlocked ? "5,4" : "none"}
                    />
                    <rect
                      x="495"
                      y={yPos - 18}
                      width="135"
                      height="36"
                      rx="6"
                      fill={isHighRisk ? "rgba(239, 68, 68, 0.15)" : "rgba(16, 185, 129, 0.12)"}
                      stroke={strokeColor}
                      strokeWidth="2"
                    />
                    <text x="562" y={yPos - 2} textAnchor="middle" className="fill-white text-[11px] font-mono font-bold">
                      {flow.dst_ip}:{flow.dst_port}
                    </text>
                    <text x="562" y={yPos + 12} textAnchor="middle" className="fill-slate-400 text-[9px]">
                      {isBlocked ? "BLOCKED IN FIREWALL" : `Risk: ${flow.risk_score}/100`}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-amber-400" /> Session Beacon Jitter vs. Normalized Entropy
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Measures TCP SYN / Session pulses & length-normalized DGA bits
            </p>
          </div>

          <div className="relative h-56 bg-slate-950 rounded-lg border border-slate-800 p-4 mt-2">
            <div className="absolute top-3 left-10 w-2/5 h-1/2 bg-red-500/10 border border-red-500/30 rounded p-1.5">
              <span className="text-[10px] font-mono text-red-400 uppercase font-semibold">
                C2 / AI Beacon Zone
              </span>
            </div>

            <svg className="w-full h-full overflow-visible" viewBox="0 0 300 160">
              <line x1="30" y1="10" x2="30" y2="140" stroke="#475569" strokeWidth="1" />
              <line x1="30" y1="140" x2="290" y2="140" stroke="#475569" strokeWidth="1" />
              <text x="160" y="156" textAnchor="middle" className="fill-slate-400 text-[10px]">
                Session Jitter (%) → (Left = Periodic Beacon)
              </text>
              {flows.map((f) => {
                const cx = 30 + Math.min(250, ((f.jitter_pct || 0) / 100) * 250);
                const cy = 140 - Math.min(125, ((f.dns_entropy || 0) / 5.0) * 125);
                return (
                  <g key={f.flow_key} onClick={() => setSelectedFlow(f)} className="cursor-pointer">
                    <circle
                      cx={cx}
                      cy={cy}
                      r={selectedFlow.flow_key === f.flow_key ? "8" : "6"}
                      className={f.risk_score >= 70 ? "fill-red-500 stroke-white stroke-1" : "fill-emerald-400"}
                    />
                    <text x={cx + 10} y={cy + 3} className="fill-slate-300 text-[10px] font-mono">
                      {f.process_name}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
            <div>
              <span className="text-xs uppercase font-mono text-slate-400">Selected Flow Attribution</span>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                {selectedFlow.process_name} → {selectedFlow.dst_ip}
                <span className={`text-xs px-2 py-0.5 rounded font-mono ${
                  selectedFlow.risk_score >= 70 ? "bg-red-500/20 text-red-400" : "bg-emerald-500/20 text-emerald-400"
                }`}>
                  Risk: {selectedFlow.risk_score}/100
                </span>
              </h3>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => setSigmaModal(!sigmaModal)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded-lg border border-slate-700 flex items-center gap-1.5"
              >
                <FileCode className="w-3.5 h-3.5 text-sky-400" /> Export Sigma
              </button>
              <button
                onClick={() => handleMitigate(selectedFlow)}
                disabled={mitigatedIps.includes(selectedFlow.dst_ip)}
                className="px-3 py-1.5 bg-red-600 hover:bg-red-500 disabled:bg-slate-800 disabled:text-slate-500 text-xs font-bold rounded-lg flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                {mitigatedIps.includes(selectedFlow.dst_ip)
                  ? "IP Blocked"
                  : selectedFlow.is_protected
                  ? "Block IP Only (Protected OS PID)"
                  : "Kill PID & Block IP"}
              </button>
            </div>
          </div>

          <div className="space-y-2 text-xs">
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800/80">
              <span className="text-slate-400 block mb-0.5">Local Binary Path & Process Identity:</span>
              <code className="text-sky-300 font-mono block truncate">{selectedFlow.exe_path}</code>
              <code className="text-slate-400 font-mono text-[11px] block truncate mt-0.5">
                ID / SHA256: {selectedFlow.process_sha256}
              </code>
            </div>

            <div className="grid grid-cols-3 gap-2 pt-1">
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[11px]">VirusTotal Ratio</span>
                <span className="text-sm font-bold text-red-400 font-mono">
                  {selectedFlow.intel?.vt_detections || "Unqueried"}
                </span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[11px]">Abuse.ch ThreatFox</span>
                <span className="text-xs font-bold text-amber-400 block truncate">
                  {selectedFlow.intel?.threatfox_malware || "Clean"}
                </span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[11px]">Shodan InternetDB</span>
                <span className="text-xs font-mono text-emerald-400 block truncate">
                  Ports: {(selectedFlow.intel?.shodan_ports || []).join(", ") || "N/A"}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-2">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" /> Session Telemetry & Hex Inspector
            </h3>
            <span className="text-xs font-mono text-slate-400">
              Sessions: {selectedFlow.session_count} | Mean IAT: {selectedFlow.avg_iat}s | Jitter: {selectedFlow.jitter_pct}%
            </span>
          </div>

          {sigmaModal ? (
            <div className="bg-slate-950 p-3 rounded-lg border border-sky-500/40 font-mono text-[11px] text-sky-300 overflow-x-auto">
              <pre>{`title: Suspicious C2 Beacon from ${selectedFlow.process_name}
status: experimental
logsource:
  category: network_connection
detection:
  selection:
    Image|endswith: '${selectedFlow.process_name}'
    DestinationIp: '${selectedFlow.dst_ip}'
    DestinationPort: ${selectedFlow.dst_port}
  condition: selection
level: critical`}</pre>
            </div>
          ) : (
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs space-y-1.5">
              <div className="text-slate-300">
                <span className="text-slate-500">DNS Query: </span>
                {selectedFlow.dns_query || "N/A"}{" "}
                <span className="text-amber-400">
                  (Entropy: {selectedFlow.dns_entropy} | DGA: {selectedFlow.is_dga ? "YES" : "NO"})
                </span>
              </div>
              <div className="pt-1">
                <span className="text-slate-500 block text-[10px]">FIRST 48 BYTES PAYLOAD HEX PREVIEW:</span>
                <div className="bg-slate-900 p-2 rounded text-[11px] text-emerald-400 break-all border border-slate-800 mt-0.5">
                  {selectedFlow.raw_preview || "No raw payload captured"}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
