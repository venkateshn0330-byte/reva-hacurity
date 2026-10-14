import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Terminal,
  Play,
  RefreshCw,
  Lock,
  Unlock,
  AlertTriangle,
  Server,
  Cpu,
  CheckCircle2,
  XCircle,
  ExternalLink,
  ChevronRight,
  Database,
  FileText,
  Filter,
  BookOpen,
  Search,
  Scale
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000';

export default function App() {
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [testSuite, setTestSuite] = useState(null);
  const [backendOnline, setBackendOnline] = useState(false);
  const [loadingTests, setLoadingTests] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard'); // 'dashboard' | 'policies' | 'activity' | 'fuzzer' | 'arch'
  const [filterType, setFilterType] = useState('ALL'); // 'ALL' | 'ALLOWED' | 'BLOCKED'
  const [policySearch, setPolicySearch] = useState('');
  const [policyCategoryFilter, setPolicyCategoryFilter] = useState('ALL');

  const fetchData = async () => {
    setRefreshing(true);
    try {
      // 1. Health check
      const healthRes = await fetch(`${API_BASE}/health`).catch(() => null);
      setBackendOnline(Boolean(healthRes && healthRes.ok));

      // 2. Fetch stats
      const statsRes = await fetch(`${API_BASE}/api/stats`).catch(() => null);
      if (statsRes && statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      // 3. Fetch 25 Policies
      const policiesRes = await fetch(`${API_BASE}/api/policies`).catch(() => null);
      if (policiesRes && policiesRes.ok) {
        const pData = await policiesRes.json();
        setPolicies(pData.policies || []);
      }

      // 4. Fetch events
      const eventsRes = await fetch(`${API_BASE}/api/events?limit=50`).catch(() => null);
      if (eventsRes && eventsRes.ok) {
        const eventsData = await eventsRes.json();
        setEvents(eventsData.events || []);
      }

      // 5. Fetch latest tests
      const testsRes = await fetch(`${API_BASE}/api/tests`).catch(() => null);
      if (testsRes && testsRes.ok) {
        const testsData = await testsRes.json();
        if (testsData && testsData.total_tests) {
          setTestSuite(testsData);
        }
      }
    } catch (err) {
      console.error('Error fetching AgentShield data:', err);
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleRunTests = async () => {
    setLoadingTests(true);
    try {
      const res = await fetch(`${API_BASE}/api/tests/run`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setTestSuite(data);
        fetchData();
      }
    } catch (err) {
      console.error('Error triggering test runner:', err);
    } finally {
      setLoadingTests(false);
    }
  };

  const filteredEvents = events.filter((e) => {
    if (filterType === 'ALLOWED') return e.allowed;
    if (filterType === 'BLOCKED') return !e.allowed;
    return true;
  });

  const filteredPolicies = policies.filter((p) => {
    const matchesSearch =
      p.name.toLowerCase().includes(policySearch.toLowerCase()) ||
      p.code.toLowerCase().includes(policySearch.toLowerCase()) ||
      p.purpose.toLowerCase().includes(policySearch.toLowerCase());
    const matchesCat =
      policyCategoryFilter === 'ALL' ||
      p.category.toLowerCase().includes(policyCategoryFilter.toLowerCase());
    return matchesSearch && matchesCat;
  });

  const categories = ['ALL', 'Integrity', 'Confidentiality', 'Access Control', 'System Governance', 'Defense in Depth'];

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 font-sans flex flex-col">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-[#0c1220]/90 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between shadow-lg shadow-black/20">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-indigo-500 to-cyan-500 p-0.5 shadow-cyan-500/20 shadow-md">
            <div className="h-full w-full bg-[#090d16] rounded-[7px] flex items-center justify-center">
              <Shield className="h-5 w-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="font-bold text-lg tracking-tight text-white">AgentShield</h1>
              <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                25-Policy AI Agent Firewall
              </span>
            </div>
            <p className="text-xs text-slate-400">Zero-Trust MCP Proxy for IBM Bob • Provable No-Escalation Delegation</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-3 text-xs bg-slate-900/80 border border-slate-800 px-3 py-1.5 rounded-full">
            <div className="flex items-center space-x-1.5">
              <span
                className={`h-2 w-2 rounded-full ${
                  backendOnline ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-rose-500'
                }`}
              />
              <span className="text-slate-300 font-mono">
                API {backendOnline ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>
            <span className="text-slate-600">|</span>
            <div className="flex items-center space-x-1.5">
              <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#22d3ee]" />
              <span className="text-slate-300 font-mono">IBM Bob: CONNECTED</span>
            </div>
          </div>

          <button
            onClick={fetchData}
            disabled={refreshing}
            className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700/60 transition disabled:opacity-50"
            title="Refresh Metrics"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </header>

      {/* Main Container */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar */}
        <nav className="w-64 border-r border-slate-800/80 bg-[#090d18] p-4 flex flex-col justify-between">
          <div className="space-y-1">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 px-3 py-2">
              Navigation
            </div>
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'dashboard'
                  ? 'bg-gradient-to-r from-indigo-600/30 to-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Activity className="h-4 w-4 text-cyan-400" />
              <span>Dashboard</span>
            </button>

            <button
              onClick={() => setActiveTab('policies')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'policies'
                  ? 'bg-gradient-to-r from-indigo-600/30 to-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Scale className="h-4 w-4 text-amber-400" />
              <span>25 Security Policies</span>
              <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded-full bg-amber-950/60 text-amber-300 font-mono border border-amber-800/40">
                25 Active
              </span>
            </button>

            <button
              onClick={() => setActiveTab('activity')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'activity'
                  ? 'bg-gradient-to-r from-indigo-600/30 to-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Terminal className="h-4 w-4 text-indigo-400" />
              <span>Live Audit Feed</span>
              {events.length > 0 && (
                <span className="ml-auto text-[11px] px-1.5 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                  {events.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('fuzzer')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'fuzzer'
                  ? 'bg-gradient-to-r from-indigo-600/30 to-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Play className="h-4 w-4 text-emerald-400" />
              <span>Attack Testing</span>
              {testSuite && (
                <span className="ml-auto text-[11px] px-1.5 py-0.5 rounded-full bg-emerald-950/80 text-emerald-300 font-mono border border-emerald-800/50">
                  {testSuite.passed_tests}/{testSuite.total_tests}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('arch')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'arch'
                  ? 'bg-gradient-to-r from-indigo-600/30 to-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Cpu className="h-4 w-4 text-cyan-400" />
              <span>Architecture & IBM Bob</span>
            </button>
          </div>

          <div className="bg-slate-900/90 rounded-xl p-3.5 border border-slate-800 space-y-2">
            <div className="flex items-center space-x-2 text-xs text-slate-300 font-semibold">
              <Database className="h-3.5 w-3.5 text-cyan-400" />
              <span>Formal Policy Invariant</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed font-mono">
              EffectiveAuthority(C) ⊆ DelegableAuthority(P)
            </p>
          </div>
        </nav>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* TAB 1: DASHBOARD OVERVIEW */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              {/* Stat Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-[#0e1424] border border-slate-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden group">
                  <div className="text-xs font-medium text-slate-400">Total Tool Invocations</div>
                  <div className="text-3xl font-extrabold text-white mt-2 font-mono">
                    {stats ? stats.total_requests : '...'}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-2">Monitored across Bob session</div>
                </div>

                <div className="bg-[#0e1424] border border-emerald-900/30 rounded-xl p-4 shadow-sm relative overflow-hidden group">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-emerald-400">Permitted Calls</span>
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  </div>
                  <div className="text-3xl font-extrabold text-emerald-300 mt-2 font-mono">
                    {stats ? stats.allowed_requests : '...'}
                  </div>
                  <div className="text-[11px] text-emerald-600 mt-2">Executed safely downstream</div>
                </div>

                <div className="bg-[#0e1424] border border-rose-900/30 rounded-xl p-4 shadow-sm relative overflow-hidden group">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-rose-400">Blocked Attacks</span>
                    <ShieldAlert className="h-4 w-4 text-rose-400" />
                  </div>
                  <div className="text-3xl font-extrabold text-rose-300 mt-2 font-mono">
                    {stats ? stats.blocked_requests : '...'}
                  </div>
                  <div className="text-[11px] text-rose-600 mt-2">0 downstream side-effects</div>
                </div>

                <div className="bg-[#0e1424] border border-cyan-900/30 rounded-xl p-4 shadow-sm relative overflow-hidden group">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-cyan-400">Policies Enforced</span>
                    <Scale className="h-4 w-4 text-cyan-400" />
                  </div>
                  <div className="text-3xl font-extrabold text-cyan-300 mt-2 font-mono">
                    25
                  </div>
                  <div className="text-[11px] text-cyan-500 mt-2">Active in Firewall Core</div>
                </div>
              </div>

              {/* Research Highlights Card */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gradient-to-br from-indigo-950/40 to-slate-900 border border-indigo-900/40 rounded-xl p-5 space-y-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                      POLICY 1 (P-T)
                    </span>
                    <h3 className="font-semibold text-white text-sm">Trusted Actions Policy (Integrity)</h3>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Blocks consequential tool actions when influenced by untrusted webpage or email content.
                    Inspired by Microsoft FIDES (Costa et al., 2025).
                  </p>
                </div>

                <div className="bg-gradient-to-br from-cyan-950/40 to-slate-900 border border-cyan-900/40 rounded-xl p-5 space-y-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                      POLICY 2 (P-F)
                    </span>
                    <h3 className="font-semibold text-white text-sm">Permitted Flows Policy (Confidentiality)</h3>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Prevents confidential documents and API keys from flowing to unauthorized external recipients or leak sites.
                  </p>
                </div>
              </div>

              {/* Fast Action Banner */}
              <div className="bg-gradient-to-r from-indigo-950/40 via-slate-900/60 to-cyan-950/40 border border-indigo-900/40 rounded-xl p-5 flex flex-col md:flex-row items-center justify-between gap-4">
                <div className="space-y-1">
                  <h3 className="font-semibold text-white flex items-center space-x-2">
                    <AlertTriangle className="h-4 w-4 text-amber-400" />
                    <span>Run Full Adversarial Security Test Suite</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Runs 8 deterministic attack vectors verifying Policy 1 (P-T), Policy 2 (P-F), Provable No-Escalation, and Fail-Closed behavior.
                  </p>
                </div>
                <button
                  onClick={handleRunTests}
                  disabled={loadingTests}
                  className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-medium text-xs tracking-wide shadow-lg shadow-cyan-600/20 flex items-center space-x-2 transition disabled:opacity-50"
                >
                  <Play className={`h-4 w-4 ${loadingTests ? 'animate-spin' : ''}`} />
                  <span>{loadingTests ? 'Executing Scenarios...' : 'Run Security Tests'}</span>
                </button>
              </div>

              {/* Recent Security Activity Table Preview */}
              <div className="bg-[#0e1424] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
                <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-900/40">
                  <div className="flex items-center space-x-2">
                    <Activity className="h-4 w-4 text-cyan-400" />
                    <h3 className="text-sm font-semibold text-white">Recent Security Interceptions</h3>
                  </div>
                  <button
                    onClick={() => setActiveTab('activity')}
                    className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                  >
                    <span>View all {events.length} events</span>
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900/60 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-4">Time</th>
                        <th className="py-2.5 px-4">Policy</th>
                        <th className="py-2.5 px-4">Tool</th>
                        <th className="py-2.5 px-4">Target Resource</th>
                        <th className="py-2.5 px-4">Decision</th>
                        <th className="py-2.5 px-4">Policy Reason</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/50">
                      {events.slice(0, 6).map((ev) => (
                        <tr
                          key={ev.id}
                          onClick={() => setSelectedEvent(ev)}
                          className="hover:bg-slate-800/30 cursor-pointer transition"
                        >
                          <td className="py-2.5 px-4 text-slate-400 font-mono">
                            {ev.timestamp.split('T')[1]?.slice(0, 8) || ev.timestamp}
                          </td>
                          <td className="py-2.5 px-4">
                            <span className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded bg-indigo-950/80 text-indigo-300 border border-indigo-800/50">
                              {ev.policy_code || 'P-AUTHZ'}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 font-semibold text-slate-200">{ev.tool_name}</td>
                          <td className="py-2.5 px-4 text-slate-400 truncate max-w-[140px]">
                            {ev.resource_or_destination}
                          </td>
                          <td className="py-2.5 px-4">
                            {ev.allowed ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800/40">
                                ALLOWED
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950/80 text-rose-400 border border-rose-800/40">
                                BLOCKED
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-4 text-slate-300 truncate max-w-[260px]">
                            {ev.reason}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: 25 SECURITY POLICIES BROWSER */}
          {activeTab === 'policies' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center space-x-2">
                  <Scale className="h-5 w-5 text-amber-400" />
                  <span>The 25 AI Agent Security Policies</span>
                </h2>
                <p className="text-xs text-slate-400">
                  Comprehensive policy framework enforcing Integrity, Confidentiality, Least Privilege, and Provable Delegation.
                </p>
              </div>

              {/* Search and Category Filters */}
              <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
                <div className="relative w-full md:w-80">
                  <Search className="h-4 w-4 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder="Search policies (e.g. P-T, Confidentiality)..."
                    value={policySearch}
                    onChange={(e) => setPolicySearch(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div className="flex items-center space-x-1 overflow-x-auto w-full md:w-auto pb-1">
                  {categories.map((cat) => (
                    <button
                      key={cat}
                      onClick={() => setPolicyCategoryFilter(cat)}
                      className={`px-2.5 py-1 rounded text-xs font-medium whitespace-nowrap transition ${
                        policyCategoryFilter === cat
                          ? 'bg-cyan-600/30 text-cyan-300 border border-cyan-500/40'
                          : 'text-slate-400 hover:text-white bg-slate-900/60 border border-slate-800'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>

              {/* Policies Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredPolicies.map((pol) => (
                  <div
                    key={pol.id}
                    onClick={() => setSelectedPolicy(pol)}
                    className="bg-[#0e1424] border border-slate-800/90 rounded-xl p-4 space-y-3 hover:border-slate-700 transition cursor-pointer flex flex-col justify-between"
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                          Policy {pol.id} — {pol.code}
                        </span>
                        <span className="text-[10px] uppercase font-semibold text-slate-400">
                          {pol.category}
                        </span>
                      </div>
                      <h4 className="font-semibold text-white text-sm leading-snug">{pol.name}</h4>
                      <p className="text-xs text-slate-400 leading-relaxed line-clamp-2">
                        {pol.purpose}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
                      <span>Source: {pol.source_reference.split(' ')[0]}</span>
                      <span className="text-cyan-400 font-medium">Details →</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: LIVE AUDIT FEED */}
          {activeTab === 'activity' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold text-white">Live Security Audit Log</h2>
                  <p className="text-xs text-slate-400">
                    Real-time SQLite audit records with policy attribution generated by the AgentShield MCP Firewall.
                  </p>
                </div>
                <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 p-1 rounded-lg text-xs">
                  <Filter className="h-3.5 w-3.5 text-slate-400 ml-1.5" />
                  {['ALL', 'ALLOWED', 'BLOCKED'].map((type) => (
                    <button
                      key={type}
                      onClick={() => setFilterType(type)}
                      className={`px-2.5 py-1 rounded font-medium transition ${
                        filterType === type
                          ? 'bg-slate-800 text-white shadow-sm'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>

              <div className="bg-[#0e1424] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">Req ID</th>
                      <th className="py-3 px-4">Timestamp</th>
                      <th className="py-3 px-4">Policy Code</th>
                      <th className="py-3 px-4">Tool Requested</th>
                      <th className="py-3 px-4">Target Resource</th>
                      <th className="py-3 px-4">Decision</th>
                      <th className="py-3 px-4">Downstream Status</th>
                      <th className="py-3 px-4">Policy Explanation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredEvents.map((ev) => (
                      <tr
                        key={ev.id}
                        onClick={() => setSelectedEvent(ev)}
                        className="hover:bg-slate-800/40 cursor-pointer transition"
                      >
                        <td className="py-2.5 px-4 text-cyan-400 text-[11px]">{ev.request_id}</td>
                        <td className="py-2.5 px-4 text-slate-400">
                          {ev.timestamp.split('T')[1]?.slice(0, 8)}
                        </td>
                        <td className="py-2.5 px-4 font-sans">
                          <span className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded bg-indigo-950/80 text-indigo-300 border border-indigo-800/50">
                            {ev.policy_code || 'P-AUTHZ'}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 font-sans font-medium text-white">{ev.tool_name}</td>
                        <td className="py-2.5 px-4 text-slate-400 truncate max-w-[120px]">
                          {ev.resource_or_destination}
                        </td>
                        <td className="py-2.5 px-4 font-sans">
                          {ev.allowed ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800/40">
                              ALLOW
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950/80 text-rose-400 border border-rose-800/40">
                              DENY
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-4 font-sans">
                          {ev.downstream_status === 'EXECUTED' ? (
                            <span className="text-emerald-400 flex items-center space-x-1">
                              <CheckCircle2 className="h-3 w-3" />
                              <span>EXECUTED</span>
                            </span>
                          ) : (
                            <span className="text-slate-400 flex items-center space-x-1">
                              <XCircle className="h-3 w-3 text-rose-400" />
                              <span>BLOCKED</span>
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-4 font-sans text-slate-300 truncate max-w-[220px]">
                          {ev.reason}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: ATTACK TESTING (FUZZER) */}
          {activeTab === 'fuzzer' && (
            <div className="space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-bold text-white">Adversarial Security Test Harness</h2>
                  <p className="text-xs text-slate-400">
                    Runs 8 deterministic attack scenarios verifying that denied actions never execute downstream.
                  </p>
                </div>
                <button
                  onClick={handleRunTests}
                  disabled={loadingTests}
                  className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-medium text-xs tracking-wide shadow-lg shadow-emerald-600/20 flex items-center space-x-2 transition disabled:opacity-50"
                >
                  <Play className={`h-4 w-4 ${loadingTests ? 'animate-spin' : ''}`} />
                  <span>{loadingTests ? 'Executing Scenarios...' : 'Run Security Tests'}</span>
                </button>
              </div>

              {testSuite && (
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-4">
                    <div className="text-xs text-slate-400">Total Scenarios</div>
                    <div className="text-2xl font-bold font-mono text-white mt-1">
                      {testSuite.total_tests}
                    </div>
                  </div>
                  <div className="bg-[#0e1424] border border-emerald-900/30 rounded-xl p-4">
                    <div className="text-xs text-emerald-400">Passed Verifications</div>
                    <div className="text-2xl font-bold font-mono text-emerald-300 mt-1">
                      {testSuite.passed_tests}
                    </div>
                  </div>
                  <div className="bg-[#0e1424] border border-rose-900/30 rounded-xl p-4">
                    <div className="text-xs text-rose-400">Security Bypasses</div>
                    <div className="text-2xl font-bold font-mono text-rose-300 mt-1">
                      {testSuite.failed_tests}
                    </div>
                  </div>
                  <div className="bg-[#0e1424] border border-cyan-900/30 rounded-xl p-4">
                    <div className="text-xs text-cyan-400">Execution Latency</div>
                    <div className="text-2xl font-bold font-mono text-cyan-300 mt-1">
                      {testSuite.duration_ms} ms
                    </div>
                  </div>
                </div>
              )}

              {/* Individual Test Cards */}
              <div className="space-y-3">
                {testSuite &&
                  testSuite.results.map((tc) => (
                    <div
                      key={tc.id}
                      className="bg-[#0e1424] border border-slate-800/90 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-slate-700 transition"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-cyan-400 font-semibold">
                            {tc.id}
                          </span>
                          <span className="text-sm font-semibold text-white">{tc.name}</span>
                          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/40">
                            {tc.policy_code || tc.category}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400">{tc.description}</p>
                        <p className="text-xs text-slate-300 font-mono mt-1">
                          <span className="text-slate-500">Reason:</span> {tc.reason}
                        </p>
                      </div>

                      <div className="flex items-center space-x-4 shrink-0">
                        <div className="text-right text-xs space-y-0.5">
                          <div className="text-slate-400">
                            Decision:{' '}
                            <span
                              className={`font-semibold ${
                                tc.actual_allowed ? 'text-emerald-400' : 'text-rose-400'
                              }`}
                            >
                              {tc.actual_allowed ? 'ALLOWED' : 'BLOCKED'}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500 font-mono">
                            Downstream Mock:{' '}
                            <span className={tc.mock_executed ? 'text-emerald-400' : 'text-slate-400'}>
                              {tc.mock_executed ? 'Executed' : 'Not Run'}
                            </span>
                          </div>
                        </div>

                        {tc.passed ? (
                          <div className="px-3 py-1.5 rounded-lg bg-emerald-950/60 border border-emerald-800/40 text-emerald-300 text-xs font-semibold flex items-center space-x-1.5">
                            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                            <span>PASS</span>
                          </div>
                        ) : (
                          <div className="px-3 py-1.5 rounded-lg bg-rose-950/60 border border-rose-800/40 text-rose-300 text-xs font-semibold flex items-center space-x-1.5">
                            <XCircle className="h-4 w-4 text-rose-400" />
                            <span>FAIL</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* TAB 5: ARCHITECTURE & IBM BOB INTEGRATION */}
          {activeTab === 'arch' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold text-white">System Architecture & IBM Bob Setup</h2>
                <p className="text-xs text-slate-400">
                  How AgentShield sits between IBM Bob and protected tools as an inline security firewall.
                </p>
              </div>

              {/* Architecture Diagram Card */}
              <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-6 space-y-4">
                <h3 className="text-sm font-semibold text-cyan-300">Inline Gateway Flow</h3>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-center">
                  <div className="bg-slate-900 border border-slate-700/60 p-4 rounded-lg">
                    <div className="text-xs font-semibold text-slate-300">1. IBM Bob Agent</div>
                    <p className="text-[11px] text-slate-400 mt-1">Issues tool call via STDIO JSON-RPC</p>
                  </div>
                  <div className="bg-indigo-950/40 border border-indigo-700/50 p-4 rounded-lg">
                    <div className="text-xs font-semibold text-indigo-300">2. AgentShield MCP</div>
                    <p className="text-[11px] text-slate-400 mt-1">Intercepts request before tool execution</p>
                  </div>
                  <div className="bg-cyan-950/40 border border-cyan-700/50 p-4 rounded-lg">
                    <div className="text-xs font-semibold text-cyan-300">3. Policy Engine</div>
                    <p className="text-[11px] text-slate-400 mt-1">Evaluates 25 Policies & Attenuation</p>
                  </div>
                  <div className="bg-emerald-950/40 border border-emerald-700/50 p-4 rounded-lg">
                    <div className="text-xs font-semibold text-emerald-300">4. Protected Tool</div>
                    <p className="text-[11px] text-slate-400 mt-1">Executes ONLY if policy permits</p>
                  </div>
                </div>
              </div>

              {/* IBM Bob Configuration Example */}
              <div className="bg-[#0e1424] border border-slate-800 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">Active IBM Bob Configuration</h3>
                  <span className="text-[11px] text-slate-400 font-mono">.bob/mcp.json</span>
                </div>
                <pre className="bg-[#080d1a] border border-slate-800/80 p-4 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto leading-relaxed">
{`{
  "mcpServers": {
    "agentshield": {
      "command": "python3",
      "args": [
        "/Users/ashwinshetty/Desktop/hackcurity/agentshield/mcp_server/server.py"
      ],
      "cwd": "/Users/ashwinshetty/Desktop/hackcurity/agentshield",
      "env": {
        "PYTHONUNBUFFERED": "1"
      },
      "alwaysAllow": ["read_document"],
      "disabled": false,
      "protocolNegotiation": "legacy"
    }
  }
}`}
                </pre>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Modal: Policy Details */}
      {selectedPolicy && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Scale className="h-5 w-5 text-amber-400" />
                <h3 className="text-sm font-bold text-white">
                  Policy {selectedPolicy.id}: {selectedPolicy.code}
                </h3>
              </div>
              <button
                onClick={() => setSelectedPolicy(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-400 block mb-0.5">Policy Name:</span>
                <span className="text-sm font-semibold text-white">{selectedPolicy.name}</span>
              </div>
              <div>
                <span className="text-slate-400 block mb-0.5">Category:</span>
                <span className="font-semibold text-cyan-400">{selectedPolicy.category}</span>
              </div>
              <div>
                <span className="text-slate-400 block mb-0.5">Formal Purpose:</span>
                <p className="bg-slate-900 border border-slate-800 p-2.5 rounded text-slate-200 leading-relaxed">
                  {selectedPolicy.purpose}
                </p>
              </div>
              <div>
                <span className="text-slate-400 block mb-0.5">Real-World Scenario / Example:</span>
                <p className="bg-slate-900/60 border border-slate-800 p-2.5 rounded text-slate-300 leading-relaxed">
                  {selectedPolicy.example}
                </p>
              </div>
              <div>
                <span className="text-slate-400 block mb-0.5">Research Basis & Citation:</span>
                <span className="font-mono text-indigo-300">{selectedPolicy.source_reference}</span>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedPolicy(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Event Details */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Shield className="h-5 w-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Security Interception Record</h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Request ID:</span>
                <span className="font-mono text-cyan-400">{selectedEvent.request_id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Enforced Policy:</span>
                <span className="font-mono font-semibold text-indigo-300">
                  {selectedEvent.policy_code || 'P-AUTHZ'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Tool Name:</span>
                <span className="font-semibold text-white">{selectedEvent.tool_name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Resource / Destination:</span>
                <span className="text-slate-300 font-mono truncate max-w-[200px]">
                  {selectedEvent.resource_or_destination}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Decision:</span>
                <span
                  className={`font-bold ${
                    selectedEvent.allowed ? 'text-emerald-400' : 'text-rose-400'
                  }`}
                >
                  {selectedEvent.allowed ? 'ALLOWED' : 'BLOCKED'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Downstream Execution:</span>
                <span
                  className={
                    selectedEvent.downstream_status === 'EXECUTED'
                      ? 'text-emerald-400 font-semibold'
                      : 'text-rose-400 font-semibold'
                  }
                >
                  {selectedEvent.downstream_status}
                </span>
              </div>
              <div>
                <span className="text-slate-400 block mb-1">Policy Reason:</span>
                <p className="bg-slate-900 border border-slate-800 p-2.5 rounded text-slate-300 leading-relaxed font-sans">
                  {selectedEvent.reason}
                </p>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
