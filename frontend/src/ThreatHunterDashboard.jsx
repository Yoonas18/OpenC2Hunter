import React, { useState, useEffect, useRef } from "react";
import {
  ShieldAlert, Activity, Terminal, Lock, Globe,
  ExternalLink, FileCode, CheckCircle2, AlertTriangle,
  User, LogOut, KeyRound, ShieldCheck,
  UploadCloud, Volume2, VolumeX, Bell, Radio,
  Cpu, Download, Copy, Check, RadioTower, Flame, X, Database
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
  const [mitigatedIps, setMitigatedIps] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("openc2_mitigated_ips") || "[]");
    } catch {
      return [];
    }
  });

  // Sound Engine
  const [soundEnabled, setSoundEnabled] = useState(() => {
    return localStorage.getItem("openc2_sound_enabled") !== "false";
  });

  // Modals & Tabs
  const [pcapModalOpen, setPcapModalOpen] = useState(false);
  const [pcapFile, setPcapFile] = useState(null);
  const [pcapUploading, setPcapUploading] = useState(false);
  const [pcapResult, setPcapResult] = useState(null);

  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [exportTab, setExportTab] = useState("sigma"); // "sigma" | "stix" | "yara"
  const [stixData, setStixData] = useState(null);
  const [yaraData, setYaraData] = useState(null);
  const [copiedKey, setCopiedKey] = useState(null);

  const [honeypotModalOpen, setHoneypotModalOpen] = useState(false);
  const [canaryTraps, setCanaryTraps] = useState([]);
  const [newTrapPort, setNewTrapPort] = useState("");
  const [newTrapService, setNewTrapService] = useState("");
  const [webhookUrlInput, setWebhookUrlInput] = useState("");
  const [webhookPlatform, setWebhookPlatform] = useState("discord");
  const [webhookStatus, setWebhookStatus] = useState(null);

  const [inspectorTab, setInspectorTab] = useState("telemetry"); // "telemetry" | "memory"
  const [memoryStrings, setMemoryStrings] = useState(null);
  const [memoryLoading, setMemoryLoading] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);

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

  // Synthesizes high-tech cyber radar beeps via Web Audio API
  const playTacticalAlert = (freq = 880, duration = 0.28, type = "sine") => {
    if (!soundEnabled) return;
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(0.12, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + duration);
    } catch {
      // Audio autoplay limitations handled
    }
  };

  const toggleSound = () => {
    setSoundEnabled((prev) => {
      const next = !prev;
      localStorage.setItem("openc2_sound_enabled", String(next));
      if (next) playTacticalAlert(920, 0.2);
      return next;
    });
  };

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

  // WebSockets real-time push connection
  useEffect(() => {
    if (!isAuthenticated || IS_DEMO_MODE) return;
    let ws = null;
    let reconnectTimeout = null;

    const connectWS = () => {
      try {
        ws = new WebSocket(`ws://127.0.0.1:8000/ws/telemetry?token=${authToken}`);
        ws.onopen = () => {
          setWsConnected(true);
        };
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.event === "canary_alert") {
              playTacticalAlert(520, 0.45, "sawtooth");
              setCanaryAlerts((prev) => [msg.data, ...prev]);
            } else if (msg.event === "pcap_analyzed") {
              playTacticalAlert(1040, 0.25, "sine");
            }
          } catch {
            // Non-JSON packet
          }
        };
        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWS, 4000);
        };
        ws.onerror = () => {
          ws.close();
        };
      } catch {
        reconnectTimeout = setTimeout(connectWS, 4000);
      }
    };

    connectWS();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, [isAuthenticated, authToken]);

  // Polling data fallback
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
          if (data.blocked_ips) {
            setMitigatedIps((prev) => {
              const merged = Array.from(new Set([...prev, ...data.blocked_ips]));
              localStorage.setItem("openc2_mitigated_ips", JSON.stringify(merged));
              return merged;
            });
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

  // Fetch memory strings when tab changes
  useEffect(() => {
    if (inspectorTab === "memory" && selectedFlow && selectedFlow.pid > 0 && !IS_DEMO_MODE) {
      setMemoryLoading(true);
      fetch(`http://127.0.0.1:8000/api/v1/process-memory-strings?pid=${selectedFlow.pid}`, {
        headers: { "X-OpenC2-Token": authToken }
      })
        .then((r) => r.json())
        .then((data) => {
          setMemoryStrings(data);
        })
        .catch(() => {
          setMemoryStrings(null);
        })
        .finally(() => setMemoryLoading(false));
    }
  }, [inspectorTab, selectedFlow, authToken]);

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
        playTacticalAlert(880, 0.2);
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
    const targetIp = flow.dst_ip;
    playTacticalAlert(440, 0.35, "sawtooth");
    setMitigatedIps((prev) => {
      const updated = Array.from(new Set([...prev, targetIp]));
      localStorage.setItem("openc2_mitigated_ips", JSON.stringify(updated));
      return updated;
    });

    if (!IS_DEMO_MODE) {
      try {
        const pidParam = flow.is_protected ? "" : `&pid=${flow.pid}`;
        await fetch(`http://127.0.0.1:8000/api/v1/mitigate?dst_ip=${targetIp}${pidParam}`, {
          method: "POST",
          headers: { "X-OpenC2-Token": authToken }
        });
      } catch {
        // Handled
      }
    }
  };

  // PCAP Forensic Upload
  const handlePcapUpload = async (e) => {
    e.preventDefault();
    if (!pcapFile) return;
    setPcapUploading(true);
    setPcapResult(null);

    const formData = new FormData();
    formData.append("file", pcapFile);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/forensics/upload-pcap", {
        method: "POST",
        headers: { "X-OpenC2-Token": authToken },
        body: formData
      });
      const data = await res.json();
      if (res.ok) {
        setPcapResult(data);
        playTacticalAlert(1040, 0.3);
      } else {
        alert(data.detail || "PCAP processing error");
      }
    } catch {
      alert("Failed to communicate with forensics engine");
    } finally {
      setPcapUploading(false);
    }
  };

  // Open Export Modal & Load STIX / YARA
  const openExportModal = async () => {
    setExportModalOpen(true);
    setStixData(null);
    setYaraData(null);

    try {
      const [stixRes, yaraRes] = await Promise.all([
        fetch(`http://127.0.0.1:8000/api/v1/export/stix?dst_ip=${selectedFlow.dst_ip}&proc_name=${selectedFlow.process_name}`, {
          headers: { "X-OpenC2-Token": authToken }
        }),
        fetch(`http://127.0.0.1:8000/api/v1/export/yara?dst_ip=${selectedFlow.dst_ip}&proc_name=${selectedFlow.process_name}&dns=${selectedFlow.dns_query || ""}&hex_preview=${selectedFlow.raw_preview || ""}`, {
          headers: { "X-OpenC2-Token": authToken }
        })
      ]);

      if (stixRes.ok) setStixData(await stixRes.json());
      if (yaraRes.ok) setYaraData((await yaraRes.json()).rule);
    } catch {
      // Handled
    }
  };

  // Honeypot Traps Manager
  const openHoneypotModal = async () => {
    setHoneypotModalOpen(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/canary/traps", {
        headers: { "X-OpenC2-Token": authToken }
      });
      if (res.ok) {
        const data = await res.json();
        setCanaryTraps(data.traps || []);
      }
    } catch {
      // Fallback
    }
  };

  const handleAddTrap = async (e) => {
    e.preventDefault();
    if (!newTrapPort || !newTrapService) return;
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/canary/add-trap", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-OpenC2-Token": authToken },
        body: JSON.stringify({
          port: parseInt(newTrapPort),
          service_name: newTrapService
        })
      });
      if (res.ok) {
        setNewTrapPort("");
        setNewTrapService("");
        openHoneypotModal();
        playTacticalAlert(960, 0.2);
      } else {
        alert("Could not start trap on specified port");
      }
    } catch {
      alert("Error adding honeypot trap");
    }
  };

  const handleTestWebhook = async () => {
    if (!webhookUrlInput) return;
    setWebhookStatus("testing");
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/webhooks/test", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-OpenC2-Token": authToken },
        body: JSON.stringify({
          webhook_url: webhookUrlInput,
          platform: webhookPlatform
        })
      });
      if (res.ok) {
        setWebhookStatus("success");
      } else {
        setWebhookStatus("failed");
      }
    } catch {
      setWebhookStatus("failed");
    }
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadFile = (content, filename, type = "text/plain") => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

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
        <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-40" />
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative w-full max-w-md bg-slate-900/90 border border-slate-800 shadow-2xl rounded-2xl p-8 backdrop-blur-xl">
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

          {loginError && (
            <div className="mb-4 p-3 bg-red-500/15 border border-red-500/40 rounded-lg flex items-center gap-2.5 text-xs text-red-300">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{loginError}</span>
            </div>
          )}

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
              className="w-full py-2.5 px-4 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-sm rounded-lg shadow-lg shadow-emerald-900/30 transition duration-150 flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
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

  const activeCriticalCount = flows.filter(
    (f) => f.risk_score >= 70 && !mitigatedIps.includes(f.dst_ip) && !f.is_blocked
  ).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans p-4 select-none">
      {/* Top Header */}
      <header className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-4 mb-4 gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-500/10 border border-red-500/30 rounded-lg">
            <ShieldAlert className="w-7 h-7 text-red-500" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight text-white">OpenC2Hunter</h1>
              <span className="text-xs font-mono bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded">
                ENTERPRISE SOC SUITE
              </span>
              <span className={`text-[11px] font-mono flex items-center gap-1 px-2 py-0.5 rounded ${
                wsConnected ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" : "bg-amber-500/10 text-amber-400"
              }`}>
                <Radio className={`w-3 h-3 ${wsConnected ? "animate-pulse text-emerald-400" : ""}`} />
                {wsConnected ? "LIVE PUSH (WS)" : "POLL (HTTP)"}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Autonomous AI-Traffic, C2 Beacon & Pre-Compromise Network Threat Hunter
            </p>
          </div>
        </div>

        {/* Global Action Toolbar */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Forensic PCAP Upload */}
          <button
            onClick={() => setPcapModalOpen(true)}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-sky-400 border border-sky-500/30 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
          >
            <UploadCloud className="w-4 h-4 text-sky-400" /> Replay PCAP
          </button>

          {/* Honeypot Traps Manager */}
          <button
            onClick={openHoneypotModal}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-amber-400 border border-amber-500/30 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
          >
            <RadioTower className="w-4 h-4 text-amber-400" /> Decoy Traps
          </button>

          {/* Audio Alert Toggle */}
          <button
            onClick={toggleSound}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border flex items-center gap-1.5 transition cursor-pointer ${
              soundEnabled
                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                : "bg-slate-900 text-slate-500 border-slate-800"
            }`}
            title="Toggle Tactical Audio Radar Alerts"
          >
            {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
            <span>Audio {soundEnabled ? "ON" : "MUTE"}</span>
          </button>

          {/* User Badge */}
          <div className="bg-slate-900 border border-emerald-500/30 px-3 py-1 rounded-lg flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <User className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-semibold text-emerald-300 font-mono">{currentUser}</span>
          </div>

          <button
            onClick={handleLogout}
            className="bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
            title="Lock Laboratory Session"
          >
            <LogOut className="w-3.5 h-3.5" /> Lock
          </button>
        </div>
      </header>

      {/* Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        <div className="bg-slate-900 border border-slate-800 px-3.5 py-2.5 rounded-xl">
          <span className="text-xs text-slate-400 block font-mono">CRITICAL BEACONS</span>
          <span className={`text-xl font-bold ${activeCriticalCount > 0 ? "text-red-400" : "text-emerald-400"}`}>
            {activeCriticalCount} Active
          </span>
        </div>
        <div className="bg-slate-900 border border-slate-800 px-3.5 py-2.5 rounded-xl">
          <span className="text-xs text-slate-400 block font-mono">CONTAINED THREATS</span>
          <span className="text-xl font-bold text-sky-400">
            {mitigatedIps.length} Blocked
          </span>
        </div>
        <div className="bg-slate-900 border border-slate-800 px-3.5 py-2.5 rounded-xl">
          <span className="text-xs text-slate-400 block font-mono">DGA DOMAINS</span>
          <span className="text-xl font-bold text-amber-400">
            {flows.filter((f) => f.is_dga).length} Flagged
          </span>
        </div>
        <div className="bg-slate-900 border border-slate-800 px-3.5 py-2.5 rounded-xl">
          <span className="text-xs text-slate-400 block font-mono">CANARY ALERTS</span>
          <span className="text-xl font-bold text-rose-400">
            {canaryAlerts.length} Captured
          </span>
        </div>
      </div>

      {/* Main Top Row: Topology & Scatter */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 mb-4">
        {/* Topology */}
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Globe className="w-4 h-4 text-sky-400" /> Direction-Verified Process-to-Socket Topology
            </h2>
            <span className="text-xs text-slate-400 font-mono">Click node to inspect</span>
          </div>

          <div className="relative h-64 bg-slate-950 rounded-lg border border-slate-800/80 overflow-hidden flex items-center justify-center">
            <svg className="w-full h-full" viewBox="0 0 650 240">
              <circle cx="90" cy="120" r="28" className="fill-sky-500/20 stroke-sky-400 stroke-2" />
              <text x="90" y="124" textAnchor="middle" className="fill-white text-[11px] font-bold">LOCAL HOST</text>

              {flows.slice(0, 3).map((flow, idx) => {
                const yPos = 45 + idx * 75;
                const isBlocked = mitigatedIps.includes(flow.dst_ip) || Boolean(flow.is_blocked);
                const isHighRisk = flow.risk_score >= 70 && !isBlocked;
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
                      strokeDasharray={isHighRisk ? "5,4" : "none"}
                    />
                    <rect
                      x="495"
                      y={yPos - 18}
                      width="135"
                      height="36"
                      rx="6"
                      fill={isBlocked ? "rgba(71, 85, 105, 0.25)" : isHighRisk ? "rgba(239, 68, 68, 0.15)" : "rgba(16, 185, 129, 0.12)"}
                      stroke={strokeColor}
                      strokeWidth="2"
                    />
                    <text x="562" y={yPos - 2} textAnchor="middle" className={`text-[11px] font-mono font-bold ${isBlocked ? "fill-slate-400" : "fill-white"}`}>
                      {flow.dst_ip}:{flow.dst_port}
                    </text>
                    <text x="562" y={yPos + 12} textAnchor="middle" className={`text-[9px] font-mono ${isBlocked ? "fill-sky-400 font-semibold" : "fill-slate-400"}`}>
                      {isBlocked ? "CONTAINED / BLOCKED" : `Risk: ${flow.risk_score}/100`}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* Scatter Plot */}
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
                const isFlowBlocked = mitigatedIps.includes(f.dst_ip) || Boolean(f.is_blocked);

                return (
                  <g key={f.flow_key} onClick={() => setSelectedFlow(f)} className="cursor-pointer">
                    <circle
                      cx={cx}
                      cy={cy}
                      r={selectedFlow.flow_key === f.flow_key ? "8" : "6"}
                      className={
                        isFlowBlocked
                          ? "fill-slate-500 stroke-slate-400 stroke-1 opacity-70"
                          : f.risk_score >= 70
                          ? "fill-red-500 stroke-white stroke-1"
                          : "fill-emerald-400"
                      }
                    />
                    <text x={cx + 10} y={cy + 3} className={`text-[10px] font-mono ${isFlowBlocked ? "fill-slate-500 line-through" : "fill-slate-300"}`}>
                      {f.process_name} {isFlowBlocked && "(Contained)"}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>
      </div>

      {/* Bottom Row: Attribution & Multi-Tab Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Selected Flow Card */}
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
            <div>
              <span className="text-xs uppercase font-mono text-slate-400">Selected Flow Attribution</span>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                {selectedFlow.process_name} → {selectedFlow.dst_ip}
                {(() => {
                  const isSelectedBlocked = mitigatedIps.includes(selectedFlow.dst_ip) || Boolean(selectedFlow.is_blocked);
                  return (
                    <span className={`text-xs px-2 py-0.5 rounded font-mono ${
                      isSelectedBlocked
                        ? "bg-sky-500/20 text-sky-300 border border-sky-500/30"
                        : selectedFlow.risk_score >= 70
                        ? "bg-red-500/20 text-red-400"
                        : "bg-emerald-500/20 text-emerald-400"
                    }`}>
                      {isSelectedBlocked ? "CONTAINED / FIREWALL BLOCKED" : `Risk: ${selectedFlow.risk_score}/100`}
                    </span>
                  );
                })()}
              </h3>
            </div>

            <div className="flex gap-2">
              <button
                onClick={openExportModal}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded-lg border border-slate-700 flex items-center gap-1.5 cursor-pointer text-sky-300"
              >
                <FileCode className="w-3.5 h-3.5 text-sky-400" /> Export Intel
              </button>
              {(() => {
                const isSelectedBlocked = mitigatedIps.includes(selectedFlow.dst_ip) || Boolean(selectedFlow.is_blocked);
                return (
                  <button
                    onClick={() => handleMitigate(selectedFlow)}
                    disabled={isSelectedBlocked}
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-500 disabled:bg-slate-800 disabled:border disabled:border-slate-700 disabled:text-sky-300 text-xs font-bold rounded-lg flex items-center gap-1.5 transition cursor-pointer"
                  >
                    {isSelectedBlocked ? (
                      <>
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Threat Neutralized (Blocked)</span>
                      </>
                    ) : (
                      <>
                        <Lock className="w-3.5 h-3.5" />
                        <span>{selectedFlow.is_protected ? "Block Outbound IP Only" : "Kill PID & Block IP"}</span>
                      </>
                    )}
                  </button>
                );
              })()}
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
                <span className="text-xs text-sky-400 block truncate">
                  Ports: {selectedFlow.intel?.shodan_ports?.join(", ") || "None"}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Tabbed Inspector: Session Telemetry VS Process Memory Strings */}
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
            <div className="flex gap-2">
              <button
                onClick={() => setInspectorTab("telemetry")}
                className={`px-2.5 py-1 text-xs font-medium rounded-lg transition cursor-pointer flex items-center gap-1.5 ${
                  inspectorTab === "telemetry"
                    ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-semibold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Terminal className="w-3.5 h-3.5" /> Session Telemetry
              </button>
              <button
                onClick={() => setInspectorTab("memory")}
                className={`px-2.5 py-1 text-xs font-medium rounded-lg transition cursor-pointer flex items-center gap-1.5 ${
                  inspectorTab === "memory"
                    ? "bg-sky-500/20 text-sky-400 border border-sky-500/30 font-semibold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Cpu className="w-3.5 h-3.5" /> Process Memory & Strings
              </button>
            </div>

            <span className="text-xs font-mono text-slate-400">
              Sessions: {selectedFlow.session_count} | Mean IAT: {selectedFlow.avg_iat}s | Jitter: {selectedFlow.jitter_pct}%
            </span>
          </div>

          {inspectorTab === "telemetry" ? (
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
          ) : (
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs space-y-2 overflow-y-auto max-h-40">
              {memoryLoading ? (
                <div className="flex items-center justify-center py-6 text-slate-400">
                  <div className="w-4 h-4 border-2 border-sky-400 border-t-transparent rounded-full animate-spin mr-2" />
                  Scanning process memory pages & binary strings...
                </div>
              ) : memoryStrings ? (
                <>
                  {memoryStrings.discovered_urls?.length > 0 && (
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase font-bold text-amber-400">Discovered URLs in Memory:</span>
                      <div className="space-y-0.5 mt-0.5">
                        {memoryStrings.discovered_urls.map((u, i) => (
                          <div key={i} className="text-sky-300 text-[11px] truncate bg-slate-900 px-1.5 py-0.5 rounded">
                            {u}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {memoryStrings.c2_indicators?.length > 0 && (
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase font-bold text-red-400">Suspicious Command Markers:</span>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {memoryStrings.c2_indicators.map((c, i) => (
                          <span key={i} className="bg-red-500/20 text-red-300 border border-red-500/30 px-1.5 py-0.5 rounded text-[10px]">
                            {c}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Strings Extracted: {memoryStrings.strings_extracted_count}</span>
                    <div className="text-slate-400 text-[10px] truncate mt-0.5">
                      Sample: {memoryStrings.sample_strings?.slice(0, 8).join(" | ")}
                    </div>
                  </div>
                </>
              ) : (
                <div className="text-slate-500 text-center py-4">
                  Process memory inspection requires an active local PID. Select a running host process to inspect memory.
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Modal 1: PCAP Forensic Replay */}
      {pcapModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 relative shadow-2xl">
            <button
              onClick={() => setPcapModalOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-sky-500/10 border border-sky-500/30 rounded-lg">
                <UploadCloud className="w-6 h-6 text-sky-400" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Offline PCAP Forensic Replay</h3>
                <p className="text-xs text-slate-400">Analyze Wireshark / tcpdump packet captures offline</p>
              </div>
            </div>

            <form onSubmit={handlePcapUpload} className="space-y-4">
              <div className="border-2 border-dashed border-slate-700 hover:border-sky-500 rounded-xl p-6 text-center cursor-pointer transition">
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  onChange={(e) => setPcapFile(e.target.files[0])}
                  className="hidden"
                  id="pcap-upload-input"
                />
                <label htmlFor="pcap-upload-input" className="cursor-pointer">
                  <FileCode className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                  <span className="text-sm text-slate-300 block font-medium">
                    {pcapFile ? pcapFile.name : "Select .pcap or .pcapng file"}
                  </span>
                  <span className="text-xs text-slate-500 block mt-1">Supports captures up to 50MB</span>
                </label>
              </div>

              <button
                type="submit"
                disabled={!pcapFile || pcapUploading}
                className="w-full py-2.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold rounded-lg text-sm transition flex items-center justify-center gap-2 cursor-pointer"
              >
                {pcapUploading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    <span>Reconstructing Network Flows...</span>
                  </>
                ) : (
                  <>
                    <UploadCloud className="w-4 h-4" />
                    <span>Replay & Extract C2 Threats</span>
                  </>
                )}
              </button>
            </form>

            {pcapResult && (
              <div className="mt-4 p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs space-y-1.5">
                <div className="text-emerald-400 font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" /> Forensics Analysis Completed
                </div>
                <div className="grid grid-cols-2 gap-2 text-slate-300 pt-1">
                  <div>Packets: <span className="text-white font-bold">{pcapResult.total_packets}</span></div>
                  <div>Flows Found: <span className="text-white font-bold">{pcapResult.flows_discovered}</span></div>
                  <div>DNS Queries: <span className="text-white font-bold">{pcapResult.dns_queries_analyzed}</span></div>
                  <div>DGA Flagged: <span className="text-amber-400 font-bold">{pcapResult.dga_detections}</span></div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Modal 2: Multi-Format Threat Intel Exporter */}
      {exportModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 relative shadow-2xl">
            <button
              onClick={() => setExportModalOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2.5">
                <FileCode className="w-5 h-5 text-sky-400" />
                <h3 className="text-base font-bold text-white">Threat Intelligence Exporter</h3>
              </div>
              <div className="flex gap-1.5">
                <button
                  onClick={() => setExportTab("sigma")}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold cursor-pointer ${
                    exportTab === "sigma" ? "bg-sky-500/20 text-sky-400 border border-sky-500/30" : "text-slate-400"
                  }`}
                >
                  Sigma Rule (YAML)
                </button>
                <button
                  onClick={() => setExportTab("stix")}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold cursor-pointer ${
                    exportTab === "stix" ? "bg-sky-500/20 text-sky-400 border border-sky-500/30" : "text-slate-400"
                  }`}
                >
                  STIX 2.1 (JSON)
                </button>
                <button
                  onClick={() => setExportTab("yara")}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold cursor-pointer ${
                    exportTab === "yara" ? "bg-sky-500/20 text-sky-400 border border-sky-500/30" : "text-slate-400"
                  }`}
                >
                  YARA Rule
                </button>
              </div>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto max-h-72 text-slate-200">
              {exportTab === "sigma" && (
                <pre>{`title: Suspicious C2 Beacon from ${selectedFlow.process_name}
id: ${selectedFlow.process_sha256?.slice(0, 16) || "openc2-detection"}
status: experimental
description: Auto-generated Sigma rule for high-confidence C2 beacon activity.
author: OpenC2Hunter Autonomous SOC
references:
  - https://github.com/Yoonas18/OpenC2Hunter
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Image|endswith: '${selectedFlow.process_name}'
    DestinationIp: '${selectedFlow.dst_ip}'
    DestinationPort: ${selectedFlow.dst_port}
  condition: selection
fields:
  - Image
  - DestinationIp
  - DestinationPort
level: critical`}</pre>
              )}

              {exportTab === "stix" && (
                <pre>{JSON.stringify(stixData || { message: "Generating STIX 2.1 bundle..." }, null, 2)}</pre>
              )}

              {exportTab === "yara" && (
                <pre>{yaraData || "// Generating YARA endpoint detection rule..."}</pre>
              )}
            </div>

            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={() => {
                  const content =
                    exportTab === "sigma"
                      ? `title: Suspicious C2 Beacon from ${selectedFlow.process_name}\nDestinationIp: '${selectedFlow.dst_ip}'`
                      : exportTab === "stix"
                      ? JSON.stringify(stixData, null, 2)
                      : yaraData;
                  copyToClipboard(content, exportTab);
                }}
                className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
              >
                {copiedKey === exportTab ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                {copiedKey === exportTab ? "Copied!" : "Copy Rule"}
              </button>
              <button
                onClick={() => {
                  const ext = exportTab === "sigma" ? "yml" : exportTab === "stix" ? "json" : "yar";
                  const content =
                    exportTab === "sigma"
                      ? `title: Suspicious C2 Beacon from ${selectedFlow.process_name}`
                      : exportTab === "stix"
                      ? JSON.stringify(stixData, null, 2)
                      : yaraData;
                  downloadFile(content, `OpenC2Hunter_${selectedFlow.process_name}_${exportTab}.${ext}`);
                }}
                className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
              >
                <Download className="w-4 h-4" /> Download
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal 3: Decoy Honeypot Traps & Webhook Manager */}
      {honeypotModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 relative shadow-2xl">
            <button
              onClick={() => setHoneypotModalOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                <RadioTower className="w-6 h-6 text-amber-400" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Canary Deception Traps & Webhooks</h3>
                <p className="text-xs text-slate-400">Configure listening decoy ports and SOC channel webhooks</p>
              </div>
            </div>

            {/* Active Traps Grid */}
            <div className="mb-4">
              <span className="text-xs font-mono uppercase text-slate-400 block mb-2 font-bold">Active Decoy Listeners</span>
              <div className="grid grid-cols-2 gap-2 max-h-36 overflow-y-auto">
                {canaryTraps.map((trap, idx) => (
                  <div key={idx} className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between text-xs">
                    <div>
                      <span className="text-white font-mono font-bold block">Port {trap.port}</span>
                      <span className="text-slate-400 text-[11px]">{trap.service}</span>
                    </div>
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  </div>
                ))}
              </div>
            </div>

            {/* Add Custom Trap */}
            <form onSubmit={handleAddTrap} className="border-t border-slate-800 pt-3 mb-4">
              <span className="text-xs font-mono uppercase text-slate-400 block mb-2 font-bold">Add Custom Decoy Port</span>
              <div className="flex gap-2">
                <input
                  type="number"
                  placeholder="Port (e.g. 3389)"
                  value={newTrapPort}
                  onChange={(e) => setNewTrapPort(e.target.value)}
                  className="w-1/3 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
                />
                <input
                  type="text"
                  placeholder="Service Name (e.g. RDP Trap)"
                  value={newTrapService}
                  onChange={(e) => setNewTrapService(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
                />
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white font-semibold rounded-lg text-xs transition cursor-pointer"
                >
                  Deploy
                </button>
              </div>
            </form>

            {/* Webhook Dispatch Test */}
            <div className="border-t border-slate-800 pt-3">
              <span className="text-xs font-mono uppercase text-slate-400 block mb-2 font-bold">SOC Webhook Notification (Discord / Slack)</span>
              <div className="flex gap-2 mb-2">
                <select
                  value={webhookPlatform}
                  onChange={(e) => setWebhookPlatform(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-white"
                >
                  <option value="discord">Discord</option>
                  <option value="slack">Slack</option>
                </select>
                <input
                  type="text"
                  placeholder="https://discord.com/api/webhooks/..."
                  value={webhookUrlInput}
                  onChange={(e) => setWebhookUrlInput(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
                />
                <button
                  type="button"
                  onClick={handleTestWebhook}
                  disabled={!webhookUrlInput || webhookStatus === "testing"}
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold rounded-lg text-xs transition cursor-pointer"
                >
                  {webhookStatus === "testing" ? "Testing..." : "Test"}
                </button>
              </div>
              {webhookStatus === "success" && (
                <span className="text-xs text-emerald-400 font-mono">✅ Alert dispatched successfully to webhook!</span>
              )}
              {webhookStatus === "failed" && (
                <span className="text-xs text-red-400 font-mono">❌ Failed to deliver webhook. Check URL.</span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
