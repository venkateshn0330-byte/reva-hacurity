import React from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Lock,
  Terminal,
  ArrowRight,
  ExternalLink,
  Cpu,
  Database,
  Layers,
  Radio,
  Sparkles,
  Zap
} from 'lucide-react';

export default function LandingPage({ onGetStarted, onGoToDashboard, isAuthenticated, onLogout }) {
  const scrollToSection = (id) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 font-sans flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background cyber grid overlay */}
      <div className="fixed inset-0 cyber-grid pointer-events-none opacity-40 z-0" />
      <div className="fixed inset-0 bg-radial-gradient pointer-events-none z-0" 
           style={{ background: 'radial-gradient(ellipse at 50% -20%, rgba(14, 165, 233, 0.15), transparent 70%)' }} />

      {/* 1. Navbar */}
      <header className="relative z-20 border-b border-slate-800/80 bg-[#0c1220]/80 backdrop-blur-md sticky top-0 px-6 py-4 flex items-center justify-between shadow-lg shadow-black/20">
        <div className="flex items-center space-x-3 cursor-pointer" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-indigo-500 to-cyan-500 p-0.5 shadow-cyan-500/20 shadow-md">
            <div className="h-full w-full bg-[#090d16] rounded-[7px] flex items-center justify-center">
              <Shield className="h-5 w-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-tight text-white">AgentShield</span>
              <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                MCP Gateway
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">Zero-Trust AI Tool Firewall</p>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="hidden md:flex items-center space-x-8 text-sm font-medium text-slate-300">
          <button
            onClick={() => scrollToSection('features')}
            className="hover:text-cyan-400 transition cursor-pointer"
          >
            Features
          </button>
          <button
            onClick={() => scrollToSection('how-it-works')}
            className="hover:text-cyan-400 transition cursor-pointer"
          >
            How It Works
          </button>
        </nav>

        {/* CTAs */}
        <div className="flex items-center space-x-3">
          {isAuthenticated ? (
            <>
              <button
                onClick={onGoToDashboard}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white text-xs font-semibold flex items-center space-x-2 shadow-lg shadow-cyan-500/20 transition cursor-pointer"
              >
                <span>Dashboard</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={onLogout}
                className="px-3 py-2 rounded-lg border border-slate-700/80 bg-slate-900/60 hover:bg-slate-800 text-slate-300 text-xs font-medium transition cursor-pointer"
              >
                Sign Out
              </button>
            </>
          ) : (
            <button
              onClick={onGetStarted}
              className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white text-xs font-semibold flex items-center space-x-2 shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 transition cursor-pointer"
            >
              <span>Get Started</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </header>

      {/* Main Container */}
      <main className="relative z-10 flex-1 flex flex-col">
        {/* 2. Hero Section */}
        <section className="relative px-6 pt-20 pb-24 md:pt-28 md:pb-32 text-center max-w-5xl mx-auto flex flex-col items-center">
          {/* Subtle Cyber Badge */}
          <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-[#0f172a]/90 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-8 shadow-sm shadow-cyan-500/10">
            <Radio className="h-3.5 w-3.5 text-cyan-400 animate-pulse" />
            <span>Next-Gen Model Context Protocol Security</span>
          </div>

          {/* Hero Headline */}
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight text-white leading-tight max-w-4xl">
            The Security Firewall for{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400">
              AI Agents
            </span>
          </h1>

          {/* Subheading */}
          <p className="mt-6 text-base sm:text-lg md:text-xl text-slate-300 max-w-3xl leading-relaxed font-normal">
            Protect every AI tool call with real-time policy enforcement, zero-trust access control, and complete audit visibility.
          </p>

          {/* Actions */}
          <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4 w-full sm:w-auto">
            <button
              onClick={onGetStarted}
              className="w-full sm:w-auto px-7 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-semibold text-sm flex items-center justify-center space-x-2 shadow-xl shadow-cyan-500/25 hover:shadow-cyan-500/40 transition-all cursor-pointer transform hover:-translate-y-0.5"
            >
              <span>{isAuthenticated ? 'Open Security Dashboard' : 'Get Started'}</span>
              <ArrowRight className="h-4 w-4" />
            </button>
            <button
              onClick={() => scrollToSection('features')}
              className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-[#0f172a]/90 hover:bg-slate-800/90 text-slate-200 border border-slate-700 font-medium text-sm transition cursor-pointer"
            >
              Explore Features
            </button>
          </div>

          {/* Trust Metrics Pill Bar */}
          <div className="mt-14 grid grid-cols-2 sm:grid-cols-4 gap-4 w-full max-w-3xl border border-slate-800/80 bg-[#0c1220]/60 backdrop-blur rounded-2xl p-4 text-left shadow-lg">
            <div className="px-3 border-r border-slate-800/80 last:border-r-0">
              <div className="text-xl font-bold font-mono text-cyan-400">25</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Enforced Policies</div>
            </div>
            <div className="px-3 border-r border-slate-800/80 last:border-r-0">
              <div className="text-xl font-bold font-mono text-emerald-400">&lt; 1ms</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Proxy Interception</div>
            </div>
            <div className="px-3 border-r border-slate-800/80 last:border-r-0">
              <div className="text-xl font-bold font-mono text-indigo-400">100%</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Default Deny</div>
            </div>
            <div className="px-3">
              <div className="text-xl font-bold font-mono text-white">Streamable</div>
              <div className="text-[11px] text-slate-400 mt-0.5">HTTP & STDIO MCP</div>
            </div>
          </div>
        </section>

        {/* 3. Three Feature Cards */}
        <section id="features" className="px-6 py-20 bg-[#090e1c]/60 border-t border-b border-slate-800/60 scroll-mt-20">
          <div className="max-w-6xl mx-auto">
            <div className="text-center max-w-2xl mx-auto mb-14">
              <div className="text-xs uppercase font-mono tracking-wider text-cyan-400 font-semibold mb-2">
                Core Capabilities
              </div>
              <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
                Zero-Trust Defense Built Specifically for Agents
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Feature 1 */}
              <div className="bg-[#0f172a]/80 border border-slate-800 hover:border-cyan-500/50 rounded-2xl p-6 shadow-lg shadow-black/40 transition-all duration-300 hover:-translate-y-1 group">
                <div className="h-12 w-12 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center mb-5 group-hover:scale-105 transition">
                  <ShieldAlert className="h-6 w-6 text-rose-400" />
                </div>
                <h3 className="text-lg font-bold text-white tracking-tight">
                  Real-Time Threat Blocking
                </h3>
                <p className="mt-3 text-sm text-slate-400 leading-relaxed">
                  Deterministic policy engine evaluates incoming tool calls in memory before execution. Intercepts prompt injection payloads, exfiltration destinations, and unauthorized file access with zero hallucination.
                </p>
                <div className="mt-5 pt-4 border-t border-slate-800/60 flex items-center text-xs text-rose-300/90 font-mono">
                  <span>Fail-Closed Enforcements</span>
                </div>
              </div>

              {/* Feature 2 */}
              <div className="bg-[#0f172a]/80 border border-slate-800 hover:border-cyan-500/50 rounded-2xl p-6 shadow-lg shadow-black/40 transition-all duration-300 hover:-translate-y-1 group">
                <div className="h-12 w-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mb-5 group-hover:scale-105 transition">
                  <Lock className="h-6 w-6 text-cyan-400" />
                </div>
                <h3 className="text-lg font-bold text-white tracking-tight">
                  Zero-Trust MCP Gateway
                </h3>
                <p className="mt-3 text-sm text-slate-400 leading-relaxed">
                  Universal proxy layer supporting official Model Context Protocol specifications over Streamable HTTP and STDIO. Provides cryptographically isolated agent keys and upstream server collision prevention.
                </p>
                <div className="mt-5 pt-4 border-t border-slate-800/60 flex items-center text-xs text-cyan-300/90 font-mono">
                  <span>Multi-Tenant Project Scoping</span>
                </div>
              </div>

              {/* Feature 3 */}
              <div className="bg-[#0f172a]/80 border border-slate-800 hover:border-cyan-500/50 rounded-2xl p-6 shadow-lg shadow-black/40 transition-all duration-300 hover:-translate-y-1 group">
                <div className="h-12 w-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center mb-5 group-hover:scale-105 transition">
                  <Activity className="h-6 w-6 text-indigo-400" />
                </div>
                <h3 className="text-lg font-bold text-white tracking-tight">
                  Live Security Monitoring
                </h3>
                <p className="mt-3 text-sm text-slate-400 leading-relaxed">
                  Immutable forensic audit trail capturing full JSON-RPC payloads, policy decision codes, and timestamps. Built-in 67-vector adversarial security fuzzer automatically validates gateway posture.
                </p>
                <div className="mt-5 pt-4 border-t border-slate-800/60 flex items-center text-xs text-indigo-300/90 font-mono">
                  <span>Tamper-Evident SQLite Ledger</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 4. Architecture Section */}
        <section id="how-it-works" className="px-6 py-24 max-w-5xl mx-auto scroll-mt-20">
          <div className="text-center max-w-2xl mx-auto mb-16">
            <div className="text-xs uppercase font-mono tracking-wider text-cyan-400 font-semibold mb-2">
              Architecture & Data Flow
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              AI Agent → AgentShield → Protected Tools
            </h2>
            <p className="mt-3 text-sm text-slate-400">
              AgentShield sits inline between the model agent and host execution surfaces, screening every tool invocation before handoff.
            </p>
          </div>

          {/* Simple Visual Flow */}
          <div className="bg-[#0c1220]/90 border border-slate-800 rounded-2xl p-6 sm:p-10 shadow-2xl relative overflow-hidden">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center relative z-10">
              {/* Node 1: AI Agent */}
              <div className="bg-[#090d16] border border-slate-700/80 rounded-xl p-5 text-center flex flex-col items-center">
                <div className="h-12 w-12 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center mb-3">
                  <Cpu className="h-6 w-6 text-sky-400" />
                </div>
                <div className="font-bold text-white text-sm">AI Agent</div>
                <div className="text-xs text-slate-400 mt-1">IBM Bob, Claude, Cursor, LangChain</div>
                <div className="mt-3 inline-block px-2.5 py-1 rounded bg-slate-800 text-[11px] font-mono text-slate-300">
                  tools/call (JSON-RPC)
                </div>
              </div>

              {/* Node 2: AgentShield Gateway */}
              <div className="bg-gradient-to-b from-indigo-950/40 to-[#090d16] border-2 border-cyan-500/60 rounded-xl p-6 text-center flex flex-col items-center shadow-lg shadow-cyan-500/15 relative">
                <div className="absolute -top-3 px-3 py-0.5 rounded-full bg-cyan-500 text-black text-[10px] font-bold uppercase tracking-wider">
                  Firewall Gateway
                </div>
                <div className="h-14 w-14 rounded-xl bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center mb-3 mt-1">
                  <Shield className="h-7 w-7 text-cyan-300 animate-pulse" />
                </div>
                <div className="font-bold text-white text-base">AgentShield Gateway</div>
                <div className="text-xs text-cyan-300 mt-1">Real-Time Policy Engine</div>
                <div className="mt-3 space-y-1 w-full text-left text-[11px] font-mono text-slate-300 bg-slate-900/90 p-2.5 rounded border border-slate-800">
                  <div className="text-emerald-400 flex items-center space-x-1">
                    <ShieldCheck className="h-3 w-3 inline" />
                    <span>✓ 25 Policy Rules</span>
                  </div>
                  <div className="text-cyan-400 flex items-center space-x-1">
                    <Lock className="h-3 w-3 inline" />
                    <span>✓ Project Auth Check</span>
                  </div>
                  <div className="text-indigo-300 flex items-center space-x-1">
                    <Activity className="h-3 w-3 inline" />
                    <span>✓ Tamper-Evident Audit</span>
                  </div>
                </div>
              </div>

              {/* Node 3: Protected Tools */}
              <div className="bg-[#090d16] border border-slate-700/80 rounded-xl p-5 text-center flex flex-col items-center">
                <div className="h-12 w-12 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mb-3">
                  <Database className="h-6 w-6 text-emerald-400" />
                </div>
                <div className="font-bold text-white text-sm">Protected Tools</div>
                <div className="text-xs text-slate-400 mt-1">Filesystems, DBs, Shell, Upstream MCP</div>
                <div className="mt-3 inline-block px-2.5 py-1 rounded bg-emerald-950/40 border border-emerald-800/40 text-[11px] font-mono text-emerald-300">
                  Verified Safe Execution
                </div>
              </div>
            </div>

            {/* Bottom Callout in Architecture */}
            <div className="mt-8 pt-6 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-400">
              <span className="font-mono text-slate-300">
                Protocol: <span className="text-cyan-400">Model Context Protocol (2024-11-05 & Streamable HTTP)</span>
              </span>
              <span className="mt-2 sm:mt-0 font-mono text-slate-400">
                Enforcement Model: <span className="text-rose-400">Strict Default-Deny</span>
              </span>
            </div>
          </div>
        </section>

        {/* Bottom CTA Banner */}
        <section className="px-6 pb-20 text-center">
          <div className="max-w-4xl mx-auto bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-900/40 rounded-2xl p-10 shadow-2xl">
            <h3 className="text-2xl font-bold text-white tracking-tight">
              Ready to secure your AI agent infrastructure?
            </h3>
            <p className="mt-3 text-sm text-slate-300 max-w-xl mx-auto">
              Launch AgentShield locally or in cloud production. Protect your tools against prompt injections and privilege escalation in minutes.
            </p>
            <div className="mt-6 flex justify-center">
              <button
                onClick={onGetStarted}
                className="px-8 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-semibold text-sm flex items-center space-x-2 shadow-xl shadow-cyan-500/25 transition cursor-pointer"
              >
                <span>{isAuthenticated ? 'Open Security Dashboard' : 'Get Started Now'}</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </section>
      </main>

      {/* 5. Minimal Footer */}
      <footer className="relative z-10 border-t border-slate-800/80 bg-[#060a12] px-6 py-8 text-xs text-slate-500">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="h-6 w-6 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Shield className="h-3.5 w-3.5 text-cyan-400" />
            </div>
            <span className="font-semibold text-slate-300">AgentShield</span>
            <span className="text-slate-600">|</span>
            <span>Enterprise MCP Tool Firewall</span>
          </div>

          <div className="flex items-center space-x-4 font-mono text-[11px]">
            <span className="flex items-center space-x-1.5 text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Gateway Online</span>
            </span>
            <span className="text-slate-600">•</span>
            <span>v0.1.0</span>
          </div>

          <div>
            <span>© 2026 AgentShield Security. All rights reserved.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
