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
  Scale,
  FolderKanban,
  Key,
  Copy,
  Plus,
  Trash2,
  RotateCw,
  UserCheck,
  Radio,
  Check,
  Code,
  Sparkles,
  Globe,
  ArrowRight,
  LogOut
} from 'lucide-react';
import LandingPage from './components/LandingPage';
import LoginPage from './components/LoginPage';

const getApiBase = () => {
  if (typeof window === 'undefined') return 'http://127.0.0.1:8000';
  if (import.meta.env?.VITE_API_BASE) return import.meta.env.VITE_API_BASE;
  const { protocol, hostname } = window.location;
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return `${protocol}//${hostname}:8000`;
  }
  return window.location.origin;
};

const API_BASE = getApiBase();

export default function App() {
  // Global Dashboard & Security State
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [projects, setProjects] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [testSuite, setTestSuite] = useState(null);
  const [backendOnline, setBackendOnline] = useState(false);
  const [loadingTests, setLoadingTests] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard'); // 'dashboard' | 'projects' | 'connect' | 'policies' | 'activity' | 'fuzzer' | 'arch'
  const [viewMode, setViewMode] = useState('landing'); // 'landing' | 'login' | 'dashboard'
  const [filterType, setFilterType] = useState('ALL'); // 'ALL' | 'ALLOWED' | 'BLOCKED'
  const [policySearch, setPolicySearch] = useState('');
  const [policyCategoryFilter, setPolicyCategoryFilter] = useState('ALL');

  // Tenant & Developer Session State
  const [session, setSession] = useState(null);
  const [selectedProjectId, setSelectedProjectId] = useState(() => {
    return localStorage.getItem('agentshield_selected_project') || 'proj_default';
  });
  const [connectInfo, setConnectInfo] = useState(null);
  const [credentials, setCredentials] = useState([]);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [copiedEndpoint, setCopiedEndpoint] = useState(false);

  // Modals
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [creatingProject, setCreatingProject] = useState(false);

  const [showKeyModal, setShowKeyModal] = useState(false);
  const [newKeyAgentId, setNewKeyAgentId] = useState('');
  const [generatingKey, setGeneratingKey] = useState(false);
  const [newlyCreatedKey, setNewlyCreatedKey] = useState(null); // Displayed strictly ONCE

  // Upstream Server Proxy State
  const [upstreamInfo, setUpstreamInfo] = useState(null);
  const [showUpstreamModal, setShowUpstreamModal] = useState(false);
  const [upstreamName, setUpstreamName] = useState('');
  const [upstreamUrl, setUpstreamUrl] = useState('');
  const [upstreamToken, setUpstreamToken] = useState('');
  const [upstreamPrefix, setUpstreamPrefix] = useState('upstream_');
  const [savingUpstream, setSavingUpstream] = useState(false);
  const [testingUpstream, setTestingUpstream] = useState(false);
  const [upstreamStatusMsg, setUpstreamStatusMsg] = useState(null);

  // Helper to extract session and CSRF tokens for state-changing or authenticated calls
  const getAuthHeaders = (includeCsrf = false) => {
    const headers = {};
    const token = session?.session_token || localStorage.getItem('agentshield_session_token');
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
      headers['X-Session-Token'] = token;
    }
    const csrf = session?.csrf_token || localStorage.getItem('agentshield_csrf_token');
    if (includeCsrf && csrf) {
      headers['X-CSRF-Token'] = csrf;
    }
    return headers;
  };

  // Ensure Developer Session & Fetch Core Data (supports silent background polling)
  const ensureSessionAndFetchData = async (targetProjectId = null, activeSessionOverride = null, isSilent = false) => {
    if (!isSilent) setRefreshing(true);
    try {
      // 1. Health check
      const healthRes = await fetch(`${API_BASE}/health`, { credentials: 'include' }).catch(() => null);
      const isOnline = Boolean(healthRes && healthRes.ok);
      setBackendOnline(isOnline);
      if (!isOnline) {
        if (!isSilent) setRefreshing(false);
        return;
      }

      // 2. Developer Session verification
      let sessionData = activeSessionOverride;
      const storedToken = localStorage.getItem('agentshield_session_token');
      const initialHeaders = storedToken ? { 'Authorization': `Bearer ${storedToken}`, 'X-Session-Token': storedToken } : {};

      if (!sessionData) {
        let sessionRes = await fetch(`${API_BASE}/api/auth/session`, { 
          headers: initialHeaders,
          credentials: 'include' 
        }).catch(() => null);
        sessionData = sessionRes && sessionRes.ok ? await sessionRes.json() : null;
      }

      if (!sessionData || !sessionData.authenticated) {
        setSession(null);
        setRefreshing(false);
        return;
      }

      if (sessionData && sessionData.authenticated) {
        if (sessionData.session_token) localStorage.setItem('agentshield_session_token', sessionData.session_token);
        if (sessionData.csrf_token) localStorage.setItem('agentshield_csrf_token', sessionData.csrf_token);
      }
      setSession(sessionData);

      const activeAuthHeaders = sessionData?.session_token 
        ? { 'Authorization': `Bearer ${sessionData.session_token}`, 'X-Session-Token': sessionData.session_token }
        : initialHeaders;

      // 3. Projects List
      let currentProjId = targetProjectId !== null ? targetProjectId : selectedProjectId;
      const projectsRes = await fetch(`${API_BASE}/api/projects`, { 
        headers: activeAuthHeaders,
        credentials: 'include' 
      }).catch(() => null);
      if (projectsRes && projectsRes.ok) {
        const pList = await projectsRes.json();
        const projs = pList.projects || [];
        setProjects(projs);
        if (projs.length > 0 && currentProjId !== 'all' && (!currentProjId || !projs.find(p => p.project_id === currentProjId))) {
          const defProj = projs.find(p => p.project_id === 'proj_default');
          currentProjId = defProj ? 'proj_default' : projs[0].project_id;
          setSelectedProjectId(currentProjId);
        }
      }

      // 4. Scoped Stats for Selected Project or All
      const statsUrl = currentProjId && currentProjId !== 'all' ? `${API_BASE}/api/stats?project_id=${currentProjId}` : `${API_BASE}/api/stats`;
      const statsRes = await fetch(statsUrl, { 
        headers: activeAuthHeaders,
        credentials: 'include' 
      }).catch(() => null);
      if (statsRes && statsRes.ok) {
        const sData = await statsRes.json();
        setStats(sData);
      }

      // 5. Scoped Policies for Selected Project
      const policiesUrl = currentProjId ? `${API_BASE}/api/projects/${currentProjId}/policies` : `${API_BASE}/api/policies`;
      const policiesRes = await fetch(policiesUrl, { 
        headers: activeAuthHeaders,
        credentials: 'include' 
      }).catch(() => null);
      if (policiesRes && policiesRes.ok) {
        const pData = await policiesRes.json();
        setPolicies(pData.policies || []);
      } else {
        // Fallback to global policies if project-specific route fails
        const fallbackRes = await fetch(`${API_BASE}/api/policies`, { 
          headers: activeAuthHeaders,
          credentials: 'include' 
        }).catch(() => null);
        if (fallbackRes && fallbackRes.ok) {
          const fbData = await fallbackRes.json();
          setPolicies(fbData.policies || []);
        }
      }

      // 6. Scoped Events for Selected Project or All
      const eventsUrl = currentProjId && currentProjId !== 'all' ? `${API_BASE}/api/projects/${currentProjId}/events?limit=50` : `${API_BASE}/api/events?limit=50`;
      const eventsRes = await fetch(eventsUrl, { 
        headers: activeAuthHeaders,
        credentials: 'include' 
      }).catch(() => null);
      if (eventsRes && eventsRes.ok) {
        const eData = await eventsRes.json();
        setEvents(eData.events || []);
      }

      // 7. Developer Connect Metadata
      if (currentProjId) {
        const connectRes = await fetch(`${API_BASE}/api/projects/${currentProjId}/connect`, { 
          headers: activeAuthHeaders,
          credentials: 'include' 
        }).catch(() => null);
        if (connectRes && connectRes.ok) {
          const cData = await connectRes.json();
          setConnectInfo(cData);
        }

        // 8. Credentials List (Masked)
        const credsRes = await fetch(`${API_BASE}/api/projects/${currentProjId}/credentials`, { 
          headers: activeAuthHeaders,
          credentials: 'include' 
        }).catch(() => null);
        if (credsRes && credsRes.ok) {
          const credData = await credsRes.json();
          setCredentials(credData.credentials || []);
        }

        // 8.5 Upstream Server Proxy Configuration
        const upstreamRes = await fetch(`${API_BASE}/api/projects/${currentProjId}/upstream`, { 
          headers: activeAuthHeaders,
          credentials: 'include' 
        }).catch(() => null);
        if (upstreamRes && upstreamRes.ok) {
          const upData = await upstreamRes.json();
          setUpstreamInfo(upData);
        } else {
          setUpstreamInfo(null);
        }
      }

      // 9. Tests run status
      const testsRes = await fetch(`${API_BASE}/api/tests`, { 
        headers: activeAuthHeaders,
        credentials: 'include' 
      }).catch(() => null);
      if (testsRes && testsRes.ok) {
        const tData = await testsRes.json();
        if (tData && tData.total_tests) {
          setTestSuite(tData);
        }
      }
    } catch (err) {
      console.error('Error fetching AgentShield data:', err);
    } finally {
      if (!isSilent) setRefreshing(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: 'POST',
        headers: getAuthHeaders(true),
        credentials: 'include'
      }).catch(() => null);
    } finally {
      localStorage.removeItem('agentshield_session_token');
      localStorage.removeItem('agentshield_csrf_token');
      setSession(null);
      setViewMode('landing');
    }
  };

  useEffect(() => {
    const checkAuthOnMount = async () => {
      const storedToken = localStorage.getItem('agentshield_session_token');
      let activeSession = null;
      if (storedToken) {
        const headers = { 'Authorization': `Bearer ${storedToken}`, 'X-Session-Token': storedToken };
        const res = await fetch(`${API_BASE}/api/auth/session`, { headers, credentials: 'include' }).catch(() => null);
        if (res && res.ok) {
          const sData = await res.json();
          if (sData?.authenticated) {
            activeSession = sData;
            setSession(sData);
          }
        }
      }

      // Check URL query parameters or hash to determine initial view
      const params = new URLSearchParams(window.location.search);
      const urlView = params.get('view') || (window.location.hash ? window.location.hash.replace('#', '') : null);

      if (urlView === 'dashboard') {
        setViewMode('dashboard');
        if (activeSession) {
          await ensureSessionAndFetchData(selectedProjectId, activeSession);
        }
      } else if (urlView === 'login') {
        setViewMode('login');
      } else {
        // Default entry view is the public Landing Page
        setViewMode('landing');
      }
    };
    checkAuthOnMount();
  }, []);

  useEffect(() => {
    if (viewMode !== 'dashboard' || !session?.authenticated) return;
    const interval = setInterval(() => {
      ensureSessionAndFetchData(selectedProjectId, null, true);
    }, 2000);
    return () => clearInterval(interval);
  }, [selectedProjectId, viewMode, session]);

  const handleSelectProject = (projId) => {
    setSelectedProjectId(projId);
    localStorage.setItem('agentshield_selected_project', projId);
    ensureSessionAndFetchData(projId);
  };

  const handleCreateProject = async (e) => {
    e.preventDefault();
    if (!newProjectName.trim()) return;
    setCreatingProject(true);
    try {
      const res = await fetch(`${API_BASE}/api/projects`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders(true)
        },
        body: JSON.stringify({ name: newProjectName.trim() }),
        credentials: 'include'
      });
      if (res.ok) {
        const created = await res.json();
        setNewProjectName('');
        setShowCreateModal(false);
        setSelectedProjectId(created.project_id);
        await ensureSessionAndFetchData(created.project_id);
        setActiveTab('connect');
      } else {
        const err = await res.json();
        alert(`Failed to create project: ${err.error || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Error creating project:', err);
      alert('Error creating project. Please check backend connection.');
    } finally {
      setCreatingProject(false);
    }
  };

  const handleGenerateKey = async (e) => {
    e.preventDefault();
    if (!selectedProjectId) return;
    setGeneratingKey(true);
    try {
      const agentId = newKeyAgentId.trim() || `${selectedProjectId}-agent`;
      const res = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/credentials`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders(true)
        },
        body: JSON.stringify({ agent_id: agentId, role: 'agent' }),
        credentials: 'include'
      });
      if (res.ok) {
        const credData = await res.json();
        setNewlyCreatedKey(credData);
        setShowKeyModal(false);
        setNewKeyAgentId('');
        // Refresh masked credential list
        const listRes = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/credentials`, { 
          headers: getAuthHeaders(false),
          credentials: 'include' 
        });
        if (listRes.ok) {
          const listData = await listRes.json();
          setCredentials(listData.credentials || []);
        }
      } else {
        const err = await res.json();
        alert(`Failed to generate key: ${err.error || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Error generating key:', err);
      alert('Error generating credential.');
    } finally {
      setGeneratingKey(false);
    }
  };

  const handleRevokeKey = async (keyId) => {
    if (!confirm(`Are you sure you want to revoke credential ${keyId}? Any agent currently using this key will be disconnected immediately.`)) {
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/credentials/${keyId}/revoke`, {
        method: 'POST',
        headers: getAuthHeaders(true),
        credentials: 'include'
      });
      if (res.ok) {
        const listRes = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/credentials`, { 
          headers: getAuthHeaders(false),
          credentials: 'include' 
        });
        if (listRes.ok) {
          const listData = await listRes.json();
          setCredentials(listData.credentials || []);
        }
      } else {
        const err = await res.json();
        alert(`Failed to revoke: ${err.error}`);
      }
    } catch (err) {
      console.error('Error revoking key:', err);
    }
  };

  const handleRotateKey = async (keyId) => {
    if (!confirm(`Rotate credential ${keyId}? This will invalidate the previous key and generate a fresh agent key.`)) {
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/credentials/${keyId}/rotate`, {
        method: 'POST',
        headers: getAuthHeaders(true),
        credentials: 'include'
      });
      if (res.ok) {
        const newCred = await res.json();
        setNewlyCreatedKey(newCred);
        const listRes = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/credentials`, { 
          headers: getAuthHeaders(false),
          credentials: 'include' 
        });
        if (listRes.ok) {
          const listData = await listRes.json();
          setCredentials(listData.credentials || []);
        }
      } else {
        const err = await res.json();
        alert(`Failed to rotate: ${err.error}`);
      }
    } catch (err) {
      console.error('Error rotating key:', err);
    }
  };

  const openConfigureUpstreamModal = () => {
    if (upstreamInfo?.server) {
      setUpstreamName(upstreamInfo.server.name || '');
      setUpstreamUrl(upstreamInfo.server.upstream_url || '');
      setUpstreamToken('');
      setUpstreamPrefix(upstreamInfo.server.tool_prefix || 'upstream_');
    } else {
      setUpstreamName('Production Tools Server');
      setUpstreamUrl('https://');
      setUpstreamToken('');
      setUpstreamPrefix('upstream_');
    }
    setUpstreamStatusMsg(null);
    setShowUpstreamModal(true);
  };

  const handleSaveUpstream = async (e) => {
    e.preventDefault();
    if (!selectedProjectId) return;
    setSavingUpstream(true);
    setUpstreamStatusMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/upstream`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders(true)
        },
        body: JSON.stringify({
          name: upstreamName.trim(),
          upstream_url: upstreamUrl.trim(),
          auth_token: upstreamToken.trim(),
          tool_prefix: upstreamPrefix.trim() || 'upstream_'
        }),
        credentials: 'include'
      });
      const data = await res.json();
      if (res.ok) {
        setUpstreamInfo({ configured: true, server: data.server });
        setShowUpstreamModal(false);
        if (data.warning) {
          alert(`Upstream saved with warning: ${data.warning}`);
        }
        await ensureSessionAndFetchData(selectedProjectId);
      } else {
        setUpstreamStatusMsg({ type: 'error', text: data.error || 'Failed to save upstream configuration.' });
      }
    } catch (err) {
      console.error('Error saving upstream:', err);
      setUpstreamStatusMsg({ type: 'error', text: 'Network error saving upstream configuration.' });
    } finally {
      setSavingUpstream(false);
    }
  };

  const handleTestUpstream = async () => {
    if (!selectedProjectId) return;
    setTestingUpstream(true);
    try {
      const res = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/upstream/test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders(true)
        },
        credentials: 'include'
      });
      const data = await res.json();
      if (res.ok) {
        alert(`Upstream connection verified! Discovered ${data.tools_count} external tools:\n${data.tools.map(t => t.name).join(', ')}`);
        await ensureSessionAndFetchData(selectedProjectId);
      } else {
        alert(`Upstream test failed: ${data.error || 'Could not connect'}`);
      }
    } catch (err) {
      alert(`Upstream test error: ${err.message}`);
    } finally {
      setTestingUpstream(false);
    }
  };

  const handleDeleteUpstream = async () => {
    if (!selectedProjectId) return;
    if (!confirm('Are you sure you want to disconnect this upstream MCP server? Discovered tools will no longer be available to AI agents.')) return;
    try {
      const res = await fetch(`${API_BASE}/api/projects/${selectedProjectId}/upstream`, {
        method: 'DELETE',
        headers: getAuthHeaders(true),
        credentials: 'include'
      });
      if (res.ok) {
        setUpstreamInfo({ configured: false, server: null });
        await ensureSessionAndFetchData(selectedProjectId);
      } else {
        const err = await res.json();
        alert(`Failed to remove upstream: ${err.error || 'Unknown error'}`);
      }
    } catch (err) {
      alert(`Error removing upstream: ${err.message}`);
    }
  };

  const handleRunTests = async () => {
    setLoadingTests(true);
    try {
      const res = await fetch(`${API_BASE}/api/tests/run`, {
        method: 'POST',
        headers: getAuthHeaders(true),
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setTestSuite(data);
        ensureSessionAndFetchData(selectedProjectId);
      }
    } catch (err) {
      console.error('Error triggering test runner:', err);
    } finally {
      setLoadingTests(false);
    }
  };

  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    if (type === 'key') {
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    } else if (type === 'snippet') {
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2000);
    } else if (type === 'endpoint') {
      setCopiedEndpoint(true);
      setTimeout(() => setCopiedEndpoint(false), 2000);
    }
  };

  const filteredEvents = events.filter((e) => {
    const isRealMcp = e.event_source === 'mcp_live' || (e.agent_id !== 'demo-agent' && e.agent_id !== 'suite-agent');
    if (filterType === 'REAL_MCP') return isRealMcp;
    if (filterType === 'FUZZER') return !isRealMcp;
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

  const currentProject = projects.find(p => p.project_id === selectedProjectId) || {
    project_id: selectedProjectId,
    name: 'Default Workspace',
    owner_identity: session?.developer_identity || 'external-developer'
  };

  const categories = ['ALL', 'Integrity', 'Confidentiality', 'Access Control', 'System Governance', 'Defense in Depth'];

  if (viewMode === 'landing') {
    return (
      <LandingPage
        onGetStarted={() => setViewMode(session?.authenticated ? 'dashboard' : 'login')}
        onGoToDashboard={() => setViewMode('dashboard')}
        isAuthenticated={Boolean(session?.authenticated)}
        onLogout={handleLogout}
      />
    );
  }

  if (viewMode === 'login') {
    return (
      <LoginPage
        onLoginSuccess={(loginData) => {
          setSession(loginData);
          setViewMode('dashboard');
          ensureSessionAndFetchData(selectedProjectId, loginData);
        }}
        onBackToHome={() => setViewMode('landing')}
        apiBase={API_BASE}
      />
    );
  }

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 font-sans flex flex-col">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-[#0c1220]/90 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between shadow-lg shadow-black/20">
        <div 
          onClick={() => {
            if (window.location.hash === '#dashboard') {
              window.history.pushState(null, '', window.location.pathname);
            }
            setViewMode('landing');
          }}
          className="flex items-center space-x-4 cursor-pointer hover:opacity-90 transition group"
          title="Return to Public Landing Page"
        >
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-indigo-500 to-cyan-500 p-0.5 shadow-cyan-500/20 shadow-md group-hover:shadow-cyan-500/40 transition">
            <div className="h-full w-full bg-[#090d16] rounded-[7px] flex items-center justify-center">
              <Shield className="h-5 w-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="font-bold text-lg tracking-tight text-white group-hover:text-cyan-300 transition">AgentShield</h1>
              <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                Remote MCP Security Gateway
              </span>
            </div>
            <p className="text-xs text-slate-400">Zero-Trust MCP Proxy • Streamable HTTP • Provable 25-Policy Enforcement</p>
          </div>
        </div>

        {/* Project Selector & System Status */}
        <div className="flex items-center space-x-3">
          {/* Active Project Dropdown */}
          <div className="flex items-center space-x-2 bg-slate-900/90 border border-slate-700/80 px-3 py-1.5 rounded-lg shadow-inner">
            <FolderKanban className="h-4 w-4 text-cyan-400" />
            <span className="text-xs text-slate-400 font-medium">Project:</span>
            <select
              value={selectedProjectId}
              onChange={(e) => handleSelectProject(e.target.value)}
              className="bg-transparent text-xs font-semibold text-white focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-slate-900 text-cyan-300 font-semibold">
                🌐 All Projects (Global MCP Feed)
              </option>
              {projects.map((p) => (
                <option key={p.project_id} value={p.project_id} className="bg-slate-900 text-white">
                  {p.name} ({p.project_id})
                </option>
              ))}
            </select>
          </div>

          {/* Developer Session Badge */}
          <div className="flex items-center space-x-2 text-xs bg-indigo-950/40 border border-indigo-800/50 px-3 py-1.5 rounded-lg text-indigo-300">
            <UserCheck className="h-3.5 w-3.5 text-indigo-400" />
            <span className="font-mono text-[11px]">{session?.developer_identity || (session === null ? 'connecting...' : 'unauthenticated')}</span>
            <span className="text-[10px] uppercase px-1.5 py-0.2 rounded bg-indigo-900/60 text-indigo-300 font-semibold border border-indigo-700/50">
              {session?.role || (session === null ? 'CONNECTING' : 'GUEST')}
            </span>
          </div>

          {/* Backend Status */}
          <div className="flex items-center space-x-2 text-xs bg-slate-900/80 border border-slate-800 px-3 py-1.5 rounded-full">
            <span
              className={`h-2 w-2 rounded-full ${
                backendOnline ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-rose-500'
              }`}
            />
            <span className="text-slate-300 font-mono text-[11px]">
              API {backendOnline ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>

          <button
            onClick={() => ensureSessionAndFetchData(selectedProjectId)}
            disabled={refreshing}
            className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700/60 transition disabled:opacity-50"
            title="Refresh All Data"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>

          <button
            onClick={() => {
              if (window.location.hash === '#dashboard') {
                window.history.pushState(null, '', window.location.pathname);
              }
              setViewMode('landing');
            }}
            className="px-3.5 py-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/40 hover:bg-cyan-900/50 text-cyan-300 text-xs font-medium transition flex items-center space-x-1.5 cursor-pointer shadow-sm shadow-cyan-500/10"
            title="View Public Landing Page"
          >
            <Globe className="h-3.5 w-3.5 text-cyan-400" />
            <span>Landing Page</span>
          </button>

          <button
            onClick={handleLogout}
            className="px-3 py-1.5 rounded-lg border border-rose-900/50 bg-rose-950/20 hover:bg-rose-900/40 text-rose-300 text-xs font-medium transition flex items-center space-x-1.5 cursor-pointer"
            title="Sign out of developer session"
          >
            <LogOut className="h-3.5 w-3.5 text-rose-400" />
            <span>Sign Out</span>
          </button>
        </div>
      </header>

      {/* Main Container */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar */}
        <nav className="w-64 border-r border-slate-800/80 bg-[#090d18] p-4 flex flex-col justify-between">
          <div className="space-y-1">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 px-3 py-2">
              Gateway Management
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
              <span>Security Overview</span>
            </button>

            <button
              onClick={() => setActiveTab('projects')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'projects'
                  ? 'bg-gradient-to-r from-indigo-600/30 to-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <FolderKanban className="h-4 w-4 text-indigo-400" />
              <span>Projects & Tenancy</span>
              {projects.length > 0 && (
                <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded-full bg-indigo-950/80 text-indigo-300 font-mono border border-indigo-800/40">
                  {projects.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('connect')}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'connect'
                  ? 'bg-gradient-to-r from-indigo-600/30 to-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Key className="h-4 w-4 text-emerald-400" />
              <span>Developer Connect & MCP</span>
              <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-950/80 text-emerald-300 font-mono border border-emerald-800/40">
                HTTP
              </span>
            </button>

            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 px-3 pt-4 pb-2">
              Security & Compliance
            </div>

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
              <span>Project Audit Feed</span>
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
              <Play className="h-4 w-4 text-rose-400" />
              <span>Adversarial Testing</span>
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
              <span>Gateway Architecture</span>
            </button>
          </div>

          <div className="pt-4 border-t border-slate-800/80">
            <div className="bg-slate-900/90 rounded-lg p-3 border border-slate-800 text-xs space-y-1.5">
              <div className="text-slate-400 flex items-center justify-between">
                <span>Active Scope:</span>
                <span className="text-cyan-400 font-mono text-[11px]">{selectedProjectId}</span>
              </div>
              <div className="text-slate-400 flex items-center justify-between">
                <span>Developer:</span>
                <span className="text-slate-200 font-mono text-[11px]">{session?.email || session?.developer_identity || 'dev_primary'}</span>
              </div>
              <div className="text-slate-400 flex items-center justify-between">
                <span>Total Interceptions:</span>
                <span className="text-white font-mono font-bold">{stats?.total_intercepted ?? stats?.total_requests ?? 0}</span>
              </div>
              <button
                onClick={handleLogout}
                className="w-full mt-2 py-1.5 px-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] text-slate-400 hover:text-rose-400 flex items-center justify-center space-x-1.5 transition cursor-pointer"
              >
                <LogOut className="h-3 w-3" />
                <span>Sign Out</span>
              </button>
            </div>
          </div>
        </nav>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#080d19]">
          {/* TAB 1: SECURITY DASHBOARD OVERVIEW */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              {/* Scoped Project Banner */}
              <div className="bg-gradient-to-r from-slate-900 via-indigo-950/30 to-slate-900 border border-indigo-900/40 rounded-xl p-4 flex items-center justify-between shadow-lg">
                <div className="flex items-center space-x-3">
                  <div className="h-9 w-9 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center">
                    <FolderKanban className="h-5 w-5 text-indigo-400" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-indigo-300 font-medium uppercase tracking-wide">Monitoring Project Scope:</span>
                      <span className="text-sm font-bold text-white">{currentProject.name}</span>
                      <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
                        {currentProject.project_id}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Displaying real-time policy enforcements and audit logs restricted to this authenticated tenant.
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setActiveTab('connect')}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-medium flex items-center space-x-1.5 transition"
                >
                  <Key className="h-3.5 w-3.5" />
                  <span>Developer Connect & MCP</span>
                </button>
              </div>

              {/* Metric Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-[#0f172a]/90 border border-slate-800/80 rounded-xl p-4 shadow-sm hover:border-slate-700 transition">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-400">Total Intercepted</span>
                    <Activity className="h-4 w-4 text-cyan-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-white mt-2">
                    {stats?.total_intercepted ?? stats?.total_requests ?? 0}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">Remote MCP & STDIO tool calls</div>
                </div>

                <div className="bg-[#0f172a]/90 border border-slate-800/80 rounded-xl p-4 shadow-sm hover:border-slate-700 transition">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-400">Allowed Tool Calls</span>
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">
                    {stats?.allowed_count ?? stats?.allowed_requests ?? 0}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">Verified within permitted flows</div>
                </div>

                <div className="bg-[#0f172a]/90 border border-slate-800/80 rounded-xl p-4 shadow-sm hover:border-slate-700 transition">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-400">Policy Blocks Enforced</span>
                    <ShieldAlert className="h-4 w-4 text-rose-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-rose-400 mt-2">
                    {stats?.blocked_count ?? stats?.blocked_requests ?? 0}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">Violations actively contained</div>
                </div>

                <div className="bg-[#0f172a]/90 border border-slate-800/80 rounded-xl p-4 shadow-sm hover:border-slate-700 transition">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-400">Block Rate</span>
                    <Lock className="h-4 w-4 text-indigo-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-indigo-300 mt-2">
                    {stats?.block_rate ?? (stats?.total_requests ? `${Math.round(((stats.blocked_requests || stats.blocked_count || 0) / stats.total_requests) * 100)}%` : '0%')}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">Defense enforcement ratio</div>
                </div>
              </div>

              {/* Status & Gateway Summary */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-[#0f172a]/80 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <Terminal className="h-4 w-4 text-cyan-400" />
                      <h3 className="font-semibold text-sm text-white">Recent Project Interceptions</h3>
                    </div>
                    <button
                      onClick={() => setActiveTab('activity')}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center space-x-1"
                    >
                      <span>View Full Audit Feed</span>
                      <ChevronRight className="h-3 w-3" />
                    </button>
                  </div>

                  {events.length === 0 ? (
                    <div className="py-12 text-center text-slate-500 text-xs">
                      No tool interception events recorded yet for this project.
                      <div className="mt-2">
                        <button
                          onClick={() => setActiveTab('connect')}
                          className="text-cyan-400 hover:underline font-medium"
                        >
                          Connect an MCP AI client
                        </button>{' '}
                        or run attack tests to see live security enforcement.
                      </div>
                    </div>
                  ) : (
                    <div className="divide-y divide-slate-800/60 overflow-hidden">
                      {events.slice(0, 5).map((ev) => (
                        <div
                          key={ev.id || ev.request_id}
                          onClick={() => setSelectedEvent(ev)}
                          className="py-3 px-2 flex items-center justify-between hover:bg-slate-800/40 rounded cursor-pointer transition text-xs"
                        >
                          <div className="flex items-center space-x-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                                ev.allowed
                                  ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50'
                                  : 'bg-rose-950/80 text-rose-400 border border-rose-800/50'
                              }`}
                            >
                              {ev.allowed ? 'PERMIT' : 'BLOCKED'}
                            </span>
                            <span
                              className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase ${
                                ev.event_source === 'mcp_live' || (ev.agent_id !== 'demo-agent' && ev.agent_id !== 'suite-agent')
                                  ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/60'
                                  : 'bg-purple-950/80 text-purple-300 border border-purple-800/60'
                              }`}
                            >
                              {ev.event_source === 'mcp_live' || (ev.agent_id !== 'demo-agent' && ev.agent_id !== 'suite-agent') ? 'REAL MCP' : 'TEST'}
                            </span>
                            <div>
                              <span className="font-semibold text-white font-mono">{ev.tool_name}</span>
                              <span className="text-slate-400 ml-2">agent: {ev.agent_id}</span>
                            </div>
                          </div>
                          <div className="flex items-center space-x-3 text-slate-400">
                            <span className="font-mono text-[11px] text-indigo-300">{ev.policy_code || 'P-AUTHZ'}</span>
                            <span className="text-[11px]">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                            <ChevronRight className="h-3 w-3 text-slate-600" />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Gateway Connection Quick Status */}
                <div className="bg-[#0f172a]/80 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <Radio className="h-4 w-4 text-emerald-400" />
                      <h3 className="font-semibold text-sm text-white">MCP Gateway Status</h3>
                    </div>
                    <span
                      className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${
                        connectInfo?.status === 'ACTIVE'
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                      }`}
                    >
                      {connectInfo?.status || 'READY'}
                    </span>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div>
                      <span className="text-slate-400 block text-[11px]">Streamable HTTP Endpoint:</span>
                      <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 mt-1 font-mono text-[11px] text-cyan-300">
                        <span>{connectInfo?.mcp_endpoint || 'http://127.0.0.1:8000/mcp'}</span>
                        <button
                          onClick={() => copyToClipboard(connectInfo?.mcp_endpoint || 'http://127.0.0.1:8000/mcp', 'endpoint')}
                          className="text-slate-400 hover:text-white"
                        >
                          {copiedEndpoint ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-400 block text-[11px]">Transport Protocol:</span>
                      <span className="text-slate-200 font-mono text-[11px]">Streamable HTTP (JSON-RPC 2.0 / SSE)</span>
                    </div>

                    <div>
                      <span className="text-slate-400 block text-[11px]">Protected Sandbox Tools:</span>
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">read_document</span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">send_email</span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">export_data</span>
                      </div>
                    </div>

                    <div className="pt-2">
                      <button
                        onClick={() => setActiveTab('connect')}
                        className="w-full py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs transition flex items-center justify-center space-x-1.5"
                      >
                        <Key className="h-3.5 w-3.5" />
                        <span>Manage Credentials & SDK Snippet</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: PROJECTS & TENANT MANAGEMENT */}
          {activeTab === 'projects' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                    <FolderKanban className="h-6 w-6 text-indigo-400" />
                    <span>Authorized Projects & Tenancy</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Projects authorized for developer identity{' '}
                    <span className="font-mono text-cyan-300 bg-slate-800 px-1.5 py-0.5 rounded">
                      {session?.developer_identity || 'dev_primary'}
                    </span>
                    . Cross-project audit events and keys are strictly isolated.
                  </p>
                </div>
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition shadow-lg shadow-indigo-600/20"
                >
                  <Plus className="h-4 w-4" />
                  <span>Create New Project</span>
                </button>
              </div>

              {/* Projects Table */}
              <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-semibold border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">Project Name</th>
                      <th className="px-4 py-3">Project ID</th>
                      <th className="px-4 py-3">Owner Identity</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Created</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-sans">
                    {projects.map((proj) => {
                      const isSelected = proj.project_id === selectedProjectId;
                      return (
                        <tr
                          key={proj.project_id}
                          className={`hover:bg-slate-800/40 transition ${isSelected ? 'bg-indigo-950/20' : ''}`}
                        >
                          <td className="px-4 py-3.5">
                            <div className="font-semibold text-white flex items-center space-x-2">
                              <span>{proj.name}</span>
                              {isSelected && (
                                <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-1.5 py-0.2 rounded font-mono">
                                  ACTIVE SCOPE
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3 font-mono text-cyan-400">{proj.project_id}</td>
                          <td className="px-4 py-3 text-slate-300 font-mono">{proj.owner_identity}</td>
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">
                              {proj.status.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-slate-400 text-[11px]">
                            {new Date(proj.created_at).toLocaleString()}
                          </td>
                          <td className="px-4 py-3 text-right space-x-2">
                            <button
                              onClick={() => {
                                handleSelectProject(proj.project_id);
                                setActiveTab('connect');
                              }}
                              className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-medium transition"
                            >
                              Developer Connect
                            </button>
                            <button
                              onClick={() => {
                                handleSelectProject(proj.project_id);
                                setActiveTab('dashboard');
                              }}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium transition"
                            >
                              Inspect Scope
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: DEVELOPER CONNECT & CREDENTIAL MANAGEMENT */}
          {activeTab === 'connect' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              {/* Header Banner */}
              <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-900/50 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center space-x-3">
                    <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                      <Key className="h-5 w-5 text-emerald-400" />
                      <span>Developer Connect: {currentProject.name}</span>
                    </h2>
                    <span
                      className={`text-[11px] font-bold font-mono px-2.5 py-0.5 rounded-full flex items-center space-x-1.5 ${
                        connectInfo?.status === 'ACTIVE'
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                      }`}
                    >
                      <span className={`h-2 w-2 rounded-full ${connectInfo?.status === 'ACTIVE' ? 'bg-emerald-400 animate-pulse' : 'bg-cyan-400'}`} />
                      <span>{connectInfo?.status === 'ACTIVE' ? 'GATEWAY ACTIVE (Traffic Intercepted)' : 'READY FOR MCP CONNECTION'}</span>
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Project ID: <span className="font-mono text-cyan-300">{currentProject.project_id}</span> • Managed by developer:{' '}
                    <span className="font-mono text-slate-300">{currentProject.owner_identity}</span>
                  </p>
                </div>

                <button
                  onClick={() => setShowKeyModal(true)}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition shadow-lg shadow-emerald-600/20"
                >
                  <Plus className="h-4 w-4" />
                  <span>Generate Agent Key</span>
                </button>
              </div>

              {/* Endpoint Details & Integration Guide */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Connection Specs */}
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <Server className="h-4 w-4 text-cyan-400" />
                      <h3 className="font-bold text-sm text-white">Remote MCP Connection Configuration</h3>
                    </div>
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                      Streamable HTTP
                    </span>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div>
                      <span className="text-slate-400 block text-[11px] mb-1">MCP Endpoint URL:</span>
                      <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 font-mono text-cyan-300 text-xs">
                        <span>{connectInfo?.mcp_endpoint || 'http://127.0.0.1:8000/mcp'}</span>
                        <button
                          onClick={() => copyToClipboard(connectInfo?.mcp_endpoint || 'http://127.0.0.1:8000/mcp', 'endpoint')}
                          className="text-slate-400 hover:text-white flex items-center space-x-1"
                        >
                          {copiedEndpoint ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <span className="text-slate-400 block text-[11px]">Supported Transport:</span>
                        <span className="text-white font-mono font-medium">streamable-http</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[11px]">Protocol Versions:</span>
                        <span className="text-slate-300 font-mono text-[11px]">2025-11-25, 2024-11-05</span>
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-400 block text-[11px] mb-1.5">Available Protected Tools Intercepted:</span>
                      <div className="space-y-2">
                        {connectInfo?.protected_tools?.map((tool) => (
                          <div key={tool.name} className="bg-slate-900/80 border border-slate-800/80 p-2.5 rounded-lg">
                            <div className="flex items-center justify-between">
                              <span className="font-mono font-bold text-cyan-400">{tool.name}</span>
                              <span className="text-[10px] text-indigo-300 font-mono bg-indigo-950/60 px-1.5 py-0.2 rounded border border-indigo-800/40">
                                {tool.policy}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 mt-1">{tool.description}</p>
                          </div>
                        )) || (
                          <div className="text-slate-500">read_document, send_email, export_data</div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Tested Official MCP SDK Example */}
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <Code className="h-4 w-4 text-emerald-400" />
                      <h3 className="font-bold text-sm text-white">Tested MCP SDK Client Example</h3>
                    </div>
                    <button
                      onClick={() => copyToClipboard(connectInfo?.sdk_snippet || '', 'snippet')}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center space-x-1.5 transition"
                    >
                      {copiedSnippet ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                      <span>{copiedSnippet ? 'Copied!' : 'Copy Code'}</span>
                    </button>
                  </div>

                  <div className="text-xs text-slate-400">
                    Connect your AI agent using the official Model Context Protocol SDK (
                    <code className="text-cyan-400 font-mono">@modelcontextprotocol/sdk</code>):
                  </div>

                  <div className="bg-slate-950 border border-slate-800/90 rounded-lg p-3 font-mono text-[11px] text-slate-300 overflow-x-auto leading-relaxed max-h-[290px]">
                    <pre>{connectInfo?.sdk_snippet || `import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const transport = new StreamableHTTPClientTransport(
  new URL("http://127.0.0.1:8000/mcp"),
  {
    requestInit: {
      headers: {
        "Authorization": "Bearer YOUR_AGENT_KEY",
        "Accept": "application/json, text/event-stream"
      }
    }
  }
);

const client = new Client({ name: "my-ai-agent", version: "1.0.0" }, { capabilities: {} });
await client.connect(transport);

// Discover protected tools
const { tools } = await client.listTools();
console.log("Connected to AgentShield! Tools:", tools.map(t => t.name));

// Safely execute an approved tool
const result = await client.callTool({
  name: "read_document",
  arguments: { document_id: "doc_sample_001" }
});`}</pre>
                  </div>
                </div>
              </div>

              {/* UPSTREAM MCP SERVER PROXY CONFIGURATION */}
              <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
                <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-3 gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <Globe className="h-4 w-4 text-purple-400" />
                      <h3 className="font-bold text-sm text-white">Configurable Upstream MCP Proxy (Tool Server)</h3>
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                          upstreamInfo?.configured && upstreamInfo?.server?.is_active
                            ? 'bg-purple-950 text-purple-300 border border-purple-800'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {upstreamInfo?.configured && upstreamInfo?.server?.is_active
                          ? 'UPSTREAM CONNECTED & PROXIED'
                          : 'NO UPSTREAM CONFIGURED'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">
                      Connect an external MCP tool server through AgentShield. Your AI agents communicate with AgentShield; all upstream tool calls are intercepted, authenticated, policy-evaluated, and audited before forwarding.
                    </p>
                  </div>

                  <div className="flex items-center space-x-2 self-start md:self-auto">
                    {upstreamInfo?.configured ? (
                      <>
                        <button
                          onClick={handleTestUpstream}
                          disabled={testingUpstream}
                          className="px-3 py-1.5 rounded-lg bg-indigo-950 hover:bg-indigo-900 border border-indigo-800 text-indigo-300 text-xs font-medium flex items-center space-x-1.5 transition disabled:opacity-50"
                        >
                          <RefreshCw className={`h-3.5 w-3.5 ${testingUpstream ? 'animate-spin' : ''}`} />
                          <span>{testingUpstream ? 'Testing...' : 'Test & Sync'}</span>
                        </button>
                        <button
                          onClick={openConfigureUpstreamModal}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium transition"
                        >
                          Configure
                        </button>
                        <button
                          onClick={handleDeleteUpstream}
                          className="p-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 transition"
                          title="Disconnect Upstream"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </>
                    ) : (
                      <button
                        onClick={openConfigureUpstreamModal}
                        className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition shadow-lg shadow-purple-600/20"
                      >
                        <Plus className="h-3.5 w-3.5" />
                        <span>Connect Upstream MCP</span>
                      </button>
                    )}
                  </div>
                </div>

                {upstreamInfo?.configured && upstreamInfo?.server ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 bg-slate-950/70 border border-slate-800/80 rounded-lg p-3 text-xs">
                      <div>
                        <span className="text-slate-400 block text-[11px] mb-0.5">Upstream Server Name:</span>
                        <span className="font-semibold text-white">{upstreamInfo.server.name}</span>
                      </div>
                      <div className="md:col-span-2">
                        <span className="text-slate-400 block text-[11px] mb-0.5">Upstream Endpoint URL:</span>
                        <span className="font-mono text-purple-300 truncate block">{upstreamInfo.server.upstream_url}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[11px] mb-0.5">Tool Namespace Prefix:</span>
                        <span className="font-mono text-cyan-300">{upstreamInfo.server.tool_prefix || 'upstream_'}</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                      <div className="bg-slate-900/50 border border-slate-800/60 rounded-lg p-3">
                        <span className="text-slate-400 block text-[11px] mb-1">Encrypted Keystore Token:</span>
                        <span className="font-mono text-emerald-400 font-medium">
                          {upstreamInfo.server.has_auth_token ? 'Encrypted at rest (CTR+HMAC-SHA256)' : 'None (Public Endpoint)'}
                        </span>
                      </div>
                      <div className="bg-slate-900/50 border border-slate-800/60 rounded-lg p-3">
                        <span className="text-slate-400 block text-[11px] mb-1">SSRF Firewall Status:</span>
                        <span className="font-mono text-emerald-400 font-medium">Active (Private IPs & Cloud Metadata Blocked)</span>
                      </div>
                      <div className="bg-slate-900/50 border border-slate-800/60 rounded-lg p-3">
                        <span className="text-slate-400 block text-[11px] mb-1">Discovered External Tools:</span>
                        <span className="font-mono text-white font-bold">
                          {upstreamInfo.server.tools_count ?? (upstreamInfo.server.cached_tools?.length || 0)} tools proxied
                        </span>
                      </div>
                    </div>

                    {upstreamInfo.server.cached_tools && upstreamInfo.server.cached_tools.length > 0 && (
                      <div>
                        <span className="text-slate-400 block text-[11px] mb-2 font-medium">Proxied Tool Registry (Exposed to Calling Agent):</span>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {upstreamInfo.server.cached_tools.map((tool) => (
                            <div key={tool.name} className="bg-slate-900/80 border border-slate-800/90 rounded-lg p-2.5 flex items-start justify-between">
                              <div>
                                <span className="font-mono font-bold text-purple-300 text-xs">{tool.name}</span>
                                <p className="text-[11px] text-slate-400 mt-0.5">{tool.description || 'External upstream tool'}</p>
                              </div>
                              <span className="text-[10px] font-mono bg-purple-950/70 text-purple-300 px-1.5 py-0.5 rounded border border-purple-800/50 shrink-0 ml-2">
                                PROXIED
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-6 bg-slate-900/40 border border-dashed border-slate-800 rounded-lg text-center space-y-2">
                    <p className="text-xs text-slate-400">
                      No external MCP server is currently connected to this project. Connect an existing Streamable HTTP tool server to route external tool executions through AgentShield.
                    </p>
                    <button
                      onClick={openConfigureUpstreamModal}
                      className="px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium inline-flex items-center space-x-1.5 transition"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      <span>Configure Upstream Tool Server</span>
                    </button>
                  </div>
                )}
              </div>

              {/* Credential Management Section */}
              <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
                <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-3 gap-2">
                  <div>
                    <div className="flex items-center space-x-2">
                      <Key className="h-4 w-4 text-cyan-400" />
                      <h3 className="font-bold text-sm text-white">Project Credential Registry & Role Separation</h3>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Agent execution credentials execute tools through the remote MCP gateway. Developer management credentials allow project administration and key rotation.
                    </p>
                  </div>
                  <button
                    onClick={() => setShowKeyModal(true)}
                    className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center space-x-1.5 transition self-start"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>Generate Agent Key</span>
                  </button>
                </div>

                {/* Credentials Table */}
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-semibold border-b border-slate-800">
                      <tr>
                        <th className="px-4 py-2.5">Key ID</th>
                        <th className="px-4 py-2.5">Agent / Caller ID</th>
                        <th className="px-4 py-2.5">Role Separation</th>
                        <th className="px-4 py-2.5">Masked Credential</th>
                        <th className="px-4 py-2.5">Status</th>
                        <th className="px-4 py-2.5">Created At</th>
                        <th className="px-4 py-2.5 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-sans">
                      {credentials.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="px-4 py-6 text-center text-slate-500 text-xs">
                            No credentials generated for this project yet. Click &quot;Generate Agent Key&quot; to connect an AI client.
                          </td>
                        </tr>
                      ) : (
                        credentials.map((cred) => (
                          <tr key={cred.key_id} className="hover:bg-slate-800/30 transition">
                            <td className="px-4 py-3 font-mono font-medium text-white">{cred.key_id}</td>
                            <td className="px-4 py-3 text-slate-300 font-mono">{cred.agent_id}</td>
                            <td className="px-4 py-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                                  cred.role === 'developer_admin'
                                    ? 'bg-indigo-950 text-indigo-300 border border-indigo-800'
                                    : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                                }`}
                              >
                                {cred.role === 'developer_admin' ? 'DEVELOPER MANAGEMENT' : 'AGENT EXECUTION'}
                              </span>
                            </td>
                            <td className="px-4 py-3 font-mono text-slate-400 text-[11px]">
                              {cred.masked_key || `${cred.key_id}...****`}
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                                  cred.status === 'active'
                                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                    : 'bg-rose-950 text-rose-400 border border-rose-800'
                                }`}
                              >
                                {cred.status.toUpperCase()}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-slate-400 text-[11px]">
                              {new Date(cred.created_at).toLocaleDateString()}
                            </td>
                            <td className="px-4 py-3 text-right space-x-2">
                              {cred.status === 'active' ? (
                                <>
                                  <button
                                    onClick={() => handleRotateKey(cred.key_id)}
                                    className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                                    title="Rotate Key"
                                  >
                                    <RotateCw className="h-3.5 w-3.5 text-cyan-400" />
                                  </button>
                                  <button
                                    onClick={() => handleRevokeKey(cred.key_id)}
                                    className="p-1 rounded bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 transition"
                                    title="Revoke Key"
                                  >
                                    <Trash2 className="h-3.5 w-3.5" />
                                  </button>
                                </>
                              ) : (
                                <span className="text-[11px] text-slate-500 italic">Revoked</span>
                              )}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: 25 SECURITY POLICIES */}
          {activeTab === 'policies' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                    <Scale className="h-6 w-6 text-amber-400" />
                    <span>25 Enforced Security Policies</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Formal integrity, confidentiality, access control, and defense-in-depth policies enforced by the AgentShield engine.
                  </p>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="relative">
                    <Search className="h-4 w-4 text-slate-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Search policy name, code, purpose..."
                      value={policySearch}
                      onChange={(e) => setPolicySearch(e.target.value)}
                      className="bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-64"
                    />
                  </div>
                </div>
              </div>

              {/* Category Filter Pills */}
              <div className="flex flex-wrap gap-2">
                {categories.map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setPolicyCategoryFilter(cat)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                      policyCategoryFilter === cat
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>

              {/* Policy Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredPolicies.map((p) => (
                  <div
                    key={p.code}
                    onClick={() => setSelectedPolicy(p)}
                    className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 hover:border-slate-700 cursor-pointer transition flex flex-col justify-between space-y-3 group shadow-sm"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
                          {p.code}
                        </span>
                        <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
                          {p.category}
                        </span>
                      </div>
                      <h3 className="font-semibold text-white text-sm mt-2 group-hover:text-cyan-300 transition">
                        {p.name}
                      </h3>
                      <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                        {p.purpose}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
                      <div className="flex items-center space-x-2">
                        <span className="text-emerald-400">✓ {p.allowed_count || 0}</span>
                        <span className="text-rose-400">✕ {p.blocked_count || 0}</span>
                      </div>
                      <span className="text-cyan-400 flex items-center space-x-1 group-hover:translate-x-0.5 transition">
                        <span>Details</span>
                        <ChevronRight className="h-3 w-3" />
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 5: LIVE AUDIT FEED */}
          {activeTab === 'activity' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                    <Terminal className="h-6 w-6 text-indigo-400" />
                    <span>Project Audit Feed & Forensics</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Immutable append-only record of intercepted tool executions scoped to project{' '}
                    <span className="font-mono text-cyan-300">{selectedProjectId}</span>.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => setFilterType('ALL')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                      filterType === 'ALL'
                        ? 'bg-slate-700 text-white'
                        : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    All Events ({events.length})
                  </button>
                  <button
                    onClick={() => setFilterType('REAL_MCP')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                      filterType === 'REAL_MCP'
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                        : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    Real MCP Traffic ({events.filter(e => e.event_source === 'mcp_live' || (e.agent_id !== 'demo-agent' && e.agent_id !== 'suite-agent')).length})
                  </button>
                  <button
                    onClick={() => setFilterType('FUZZER')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                      filterType === 'FUZZER'
                        ? 'bg-purple-950 text-purple-300 border border-purple-800'
                        : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    Fuzzer Tests ({events.filter(e => e.event_source === 'fuzzer_test' || e.agent_id === 'demo-agent' || e.agent_id === 'suite-agent').length})
                  </button>
                  <button
                    onClick={() => setFilterType('ALLOWED')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                      filterType === 'ALLOWED'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    Allowed
                  </button>
                  <button
                    onClick={() => setFilterType('BLOCKED')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                      filterType === 'BLOCKED'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    Blocked
                  </button>
                </div>
              </div>

              <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-semibold border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">Timestamp</th>
                      <th className="px-4 py-3">Source</th>
                      <th className="px-4 py-3">Decision</th>
                      <th className="px-4 py-3">Tool Name</th>
                      <th className="px-4 py-3">Target Resource / Destination</th>
                      <th className="px-4 py-3">Enforced Policy</th>
                      <th className="px-4 py-3">Agent ID</th>
                      <th className="px-4 py-3 text-right">Downstream</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-sans">
                    {filteredEvents.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                          No audit events matching this filter.
                        </td>
                      </tr>
                    ) : (
                      filteredEvents.map((ev) => {
                        const isReal = ev.event_source === 'mcp_live' || (ev.agent_id !== 'demo-agent' && ev.agent_id !== 'suite-agent');
                        return (
                          <tr
                            key={ev.id || ev.request_id}
                            onClick={() => setSelectedEvent(ev)}
                            className="hover:bg-slate-800/40 cursor-pointer transition"
                          >
                            <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                              {new Date(ev.timestamp).toLocaleTimeString()}
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase ${
                                  isReal
                                    ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/60'
                                    : 'bg-purple-950/80 text-purple-300 border border-purple-800/60'
                                }`}
                              >
                                {isReal ? 'REAL MCP' : 'TEST'}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                                  ev.allowed
                                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                    : 'bg-rose-950 text-rose-400 border border-rose-800'
                                }`}
                              >
                                {ev.allowed ? 'ALLOWED' : 'BLOCKED'}
                              </span>
                            </td>
                            <td className="px-4 py-3 font-semibold text-white font-mono">{ev.tool_name}</td>
                            <td className="px-4 py-3 text-slate-300 font-mono truncate max-w-[200px]">
                              {ev.resource_or_destination || 'None'}
                            </td>
                            <td className="px-4 py-3 text-indigo-300 font-mono">{ev.policy_code || 'P-AUTHZ'}</td>
                            <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">{ev.agent_id}</td>
                            <td className="px-4 py-3 text-right">
                              <span
                                className={`text-[11px] font-mono font-medium ${
                                  ev.downstream_status === 'EXECUTED' ? 'text-emerald-400' : 'text-rose-400'
                                }`}
                              >
                                {ev.downstream_status}
                              </span>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: ADVERSARIAL TESTING & FUZZER */}
          {activeTab === 'fuzzer' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                    <Play className="h-6 w-6 text-rose-400" />
                    <span>Adversarial Testing & Attack Verification</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Execute real adversarial attack payloads against the gateway to verify policy containment and fail-closed security.
                  </p>
                </div>
                <button
                  onClick={handleRunTests}
                  disabled={loadingTests}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center space-x-2 transition shadow-lg shadow-indigo-600/20"
                >
                  <Play className={`h-4 w-4 ${loadingTests ? 'animate-spin' : ''}`} />
                  <span>{loadingTests ? 'Executing Security Tests...' : 'Run Security Tests'}</span>
                </button>
              </div>

              {testSuite && (
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                      <h3 className="font-semibold text-sm text-white">Test Suite Results</h3>
                    </div>
                    <span className="text-xs font-mono text-emerald-400 font-bold bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800/50">
                      {testSuite.passed_tests} / {testSuite.total_tests} PASSED ({testSuite.success_rate})
                    </span>
                  </div>

                  <div className="divide-y divide-slate-800/60">
                    {testSuite.results?.map((res, i) => (
                      <div key={i} className="py-3 flex items-start justify-between text-xs">
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span
                              className={`h-2 w-2 rounded-full ${
                                res.status === 'PASSED' ? 'bg-emerald-400' : 'bg-rose-500'
                              }`}
                            />
                            <span className="font-semibold text-white">{res.test_name}</span>
                            <span className="font-mono text-[10px] text-cyan-400 bg-cyan-950/60 px-1.5 py-0.2 rounded border border-cyan-800/40">
                              {res.policy_code}
                            </span>
                          </div>
                          <p className="text-slate-400 text-[11px]">{res.description}</p>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                            res.status === 'PASSED'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : 'bg-rose-950 text-rose-400 border border-rose-800'
                          }`}
                        >
                          {res.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 7: ARCHITECTURE & IBM BOB */}
          {activeTab === 'arch' && (
            <div className="space-y-6 max-w-7xl mx-auto">
              <div>
                <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                  <Cpu className="h-6 w-6 text-cyan-400" />
                  <span>AgentShield Architecture & Integration Specification</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  How AgentShield operates as an inline zero-trust proxy between AI agents and Model Context Protocol servers.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-3">
                  <h3 className="font-bold text-sm text-cyan-400">Streamable HTTP Transport</h3>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    AgentShield exposes a standardized MCP transport endpoint at <code className="text-cyan-300 font-mono">POST /mcp</code> supporting JSON-RPC 2.0 messages, SSE streaming, protocol negotiation, and session tracking. Remote AI clients authenticate with high-entropy project-scoped Bearer tokens.
                  </p>
                </div>

                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-3">
                  <h3 className="font-bold text-sm text-indigo-400">Tenant & Role Isolation</h3>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Developer management sessions are verified via HttpOnly cookies and restricted to project configuration. Agent execution keys have permission strictly to execute approved sandbox tools, with all client-supplied identity assertions stripped and replaced by server-verified metadata.
                  </p>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* MODAL: CREATE PROJECT */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-xl max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <FolderKanban className="h-5 w-5 text-indigo-400" />
                <h3 className="text-sm font-bold text-white">Create New Project</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateProject} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 block mb-1 font-medium">Project Name</label>
                <input
                  type="text"
                  placeholder="e.g. Customer Support AI Gateway"
                  value={newProjectName}
                  onChange={(e) => setNewProjectName(e.target.value)}
                  required
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-sans"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Owner Identity</label>
                <div className="bg-slate-900 border border-slate-800/80 rounded px-3 py-2 font-mono text-cyan-300">
                  {session?.developer_identity || 'dev_primary'}
                </div>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Project will be strictly isolated to your developer identity.
                </span>
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingProject}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold disabled:opacity-50"
                >
                  {creatingProject ? 'Creating...' : 'Create Project'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: GENERATE AGENT KEY */}
      {showKeyModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-xl max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Key className="h-5 w-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-white">Generate Agent Execution Credential</h3>
              </div>
              <button
                onClick={() => setShowKeyModal(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleGenerateKey} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 block mb-1 font-medium">Target Project</label>
                <div className="bg-slate-900 border border-slate-800 rounded px-3 py-2 font-mono text-cyan-300">
                  {currentProject.name} ({currentProject.project_id})
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-medium">Agent Identifier (Caller ID)</label>
                <input
                  type="text"
                  placeholder={`e.g. ${selectedProjectId}-production-agent`}
                  value={newKeyAgentId}
                  onChange={(e) => setNewKeyAgentId(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Identifies this AI client in the audit feed and policy logs.
                </span>
              </div>

              <div className="bg-amber-950/40 border border-amber-900/60 rounded-lg p-3 text-[11px] text-amber-300 space-y-1">
                <div className="font-semibold flex items-center space-x-1.5">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  <span>Role Separation Notice:</span>
                </div>
                <p className="text-slate-300">
                  This credential will be assigned the <span className="font-mono text-cyan-300">agent</span> role. It can execute protected tools via MCP, but cannot create projects or manage developer credentials.
                </p>
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowKeyModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generatingKey}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold disabled:opacity-50"
                >
                  {generatingKey ? 'Generating...' : 'Generate Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: ONE-TIME DISPLAY OF RAW CREDENTIAL */}
      {newlyCreatedKey && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-emerald-600/80 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl shadow-emerald-500/10">
            <div className="flex items-center space-x-3 border-b border-slate-800 pb-3">
              <div className="h-9 w-9 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center">
                <Key className="h-5 w-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Agent Execution Key Generated</h3>
                <span className="text-[11px] text-slate-400">Save this raw secret key immediately.</span>
              </div>
            </div>

            <div className="bg-rose-950/40 border border-rose-800/60 rounded-lg p-3 text-xs text-rose-300 space-y-1">
              <div className="font-bold flex items-center space-x-1.5">
                <AlertTriangle className="h-4 w-4" />
                <span>Security Notice: Displayed Strictly Once</span>
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                For zero-trust security, AgentShield only stores the cryptographic SHA-256 hash. This raw key cannot be recovered or viewed again once this dialog is closed.
              </p>
            </div>

            <div className="space-y-2">
              <label className="text-xs text-slate-400 font-medium">Raw Secret API Key (Bearer Token):</label>
              <div className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-emerald-400 select-all">
                <span className="break-all">{newlyCreatedKey.raw_key}</span>
                <button
                  onClick={() => copyToClipboard(newlyCreatedKey.raw_key, 'key')}
                  className="ml-3 px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-sans text-xs font-semibold flex items-center space-x-1 shrink-0 transition"
                >
                  {copiedKey ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copiedKey ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div className="text-xs space-y-1 bg-slate-900/60 border border-slate-800 p-3 rounded text-slate-300">
              <div className="flex justify-between">
                <span className="text-slate-400">Key ID:</span>
                <span className="font-mono text-white">{newlyCreatedKey.key_id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Agent ID:</span>
                <span className="font-mono text-cyan-300">{newlyCreatedKey.agent_id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Role:</span>
                <span className="font-mono text-indigo-300">{newlyCreatedKey.role}</span>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setNewlyCreatedKey(null)}
                className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg transition"
              >
                I Have Safely Saved My Key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: CONFIGURE UPSTREAM MCP TOOL SERVER */}
      {showUpstreamModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Globe className="h-5 w-5 text-purple-400" />
                <h3 className="text-sm font-bold text-white">Connect External MCP Tool Server</h3>
              </div>
              <button
                onClick={() => setShowUpstreamModal(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveUpstream} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 block mb-1 font-medium">Target Project</label>
                <div className="bg-slate-900 border border-slate-800 rounded px-3 py-2 font-mono text-cyan-300">
                  {currentProject.name} ({currentProject.project_id})
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-medium">Upstream Server Name</label>
                <input
                  type="text"
                  placeholder="e.g. Analytics MCP Server"
                  value={upstreamName}
                  onChange={(e) => setUpstreamName(e.target.value)}
                  required
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 font-sans"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-medium">Upstream Endpoint URL (Streamable HTTP)</label>
                <input
                  type="url"
                  placeholder="https://mcp-server.example.com/mcp"
                  value={upstreamUrl}
                  onChange={(e) => setUpstreamUrl(e.target.value)}
                  required
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono text-xs"
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Must be an accessible Streamable HTTP MCP server supporting JSON-RPC.
                </span>
              </div>

              <div className="bg-rose-950/30 border border-rose-900/50 rounded-lg p-2.5 text-[11px] text-rose-300 space-y-1">
                <div className="font-semibold flex items-center space-x-1.5">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  <span>SSRF Security Controls Enforced:</span>
                </div>
                <p className="text-slate-300 leading-normal">
                  Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback, link-local, and cloud metadata endpoints (169.254.169.254) are rejected by AgentShield.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 block mb-1 font-medium">Tool Collision Prefix</label>
                  <input
                    type="text"
                    placeholder="upstream_"
                    value={upstreamPrefix}
                    onChange={(e) => setUpstreamPrefix(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
                  />
                  <span className="text-[10px] text-slate-500 mt-0.5 block">
                    e.g. upstream_tool_name
                  </span>
                </div>
                <div>
                  <label className="text-slate-300 block mb-1 font-medium">Bearer Secret Token (Optional)</label>
                  <input
                    type="password"
                    placeholder={upstreamInfo?.server?.has_auth_token ? "Leave blank to keep existing" : "Bearer token"}
                    value={upstreamToken}
                    onChange={(e) => setUpstreamToken(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
                  />
                  <span className="text-[10px] text-slate-500 mt-0.5 block">
                    Encrypted at rest with keystore.
                  </span>
                </div>
              </div>

              {upstreamStatusMsg && (
                <div className="bg-rose-950/60 border border-rose-800 text-rose-300 p-2.5 rounded text-xs">
                  {upstreamStatusMsg.text}
                </div>
              )}

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowUpstreamModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingUpstream}
                  className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold disabled:opacity-50 flex items-center space-x-1.5"
                >
                  {savingUpstream ? (
                    <>
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      <span>Validating & Connecting...</span>
                    </>
                  ) : (
                    <span>Save & Discover Tools</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: POLICY DETAILS */}
      {selectedPolicy && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                  {selectedPolicy.code}
                </span>
                <h3 className="text-sm font-bold text-white">{selectedPolicy.name}</h3>
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

      {/* MODAL: EVENT DETAILS */}
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
                <span className="text-slate-400">Project ID:</span>
                <span className="font-mono text-indigo-300">{selectedEvent.project_id || selectedProjectId}</span>
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
