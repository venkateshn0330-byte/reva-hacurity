import React, { useState } from 'react';
import {
  Shield,
  Lock,
  Mail,
  User,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  Eye,
  EyeOff,
  ArrowLeft,
  Sparkles,
  Key
} from 'lucide-react';

export default function LoginPage({ onLoginSuccess, onBackToHome, apiBase }) {
  const [mode, setMode] = useState('login'); // 'login' | 'register'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [developerIdentity, setDeveloperIdentity] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail || !cleanEmail.includes('@') || !cleanEmail.includes('.')) {
      setErrorMsg('Please enter a valid email address.');
      return;
    }
    if (!password || password.length < 8) {
      setErrorMsg('Password must be at least 8 characters long.');
      return;
    }

    setLoading(true);
    try {
      const endpoint = mode === 'login' ? `${apiBase}/api/auth/login` : `${apiBase}/api/auth/register`;
      const body = {
        email: cleanEmail,
        password: password
      };
      if (mode === 'register' && developerIdentity.trim()) {
        body.developer_identity = developerIdentity.trim();
      }

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'include'
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || (mode === 'login' ? 'Authentication failed. Please verify your credentials.' : 'Registration failed.'));
      }

      // Persist session tokens to localStorage for Authorization headers as well as cookies
      if (data.session_token) {
        localStorage.setItem('agentshield_session_token', data.session_token);
      }
      if (data.csrf_token) {
        localStorage.setItem('agentshield_csrf_token', data.csrf_token);
      }

      setSuccessMsg(mode === 'login' ? 'Authenticated successfully. Redirecting...' : 'Account created successfully. Redirecting...');
      setTimeout(() => {
        onLoginSuccess(data);
      }, 500);
    } catch (err) {
      setErrorMsg(err.message || 'Network error occurred while authenticating.');
    } finally {
      setLoading(false);
    }
  };

  const handleFillDemo = () => {
    setEmail('dev@agentshield.io');
    setPassword('AgentShield2026!');
    setMode('login');
    setErrorMsg(null);
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 font-sans flex flex-col justify-center items-center px-6 py-12 relative selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background cyber grid */}
      <div className="fixed inset-0 cyber-grid pointer-events-none opacity-40 z-0" />
      <div className="fixed inset-0 pointer-events-none z-0" 
           style={{ background: 'radial-gradient(circle at 50% 25%, rgba(14, 165, 233, 0.12), transparent 60%)' }} />

      {/* Back to Home Link */}
      <button
        onClick={onBackToHome}
        className="relative z-10 mb-6 flex items-center space-x-2 text-xs font-medium text-slate-400 hover:text-cyan-400 transition cursor-pointer"
      >
        <ArrowLeft className="h-4 w-4" />
        <span>Back to AgentShield Overview</span>
      </button>

      {/* Auth Card */}
      <div className="relative z-10 w-full max-w-md bg-[#0c1220]/95 border border-slate-800 rounded-2xl shadow-2xl shadow-black/80 p-8 backdrop-blur-xl">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-6">
          <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-indigo-500 to-cyan-500 p-0.5 shadow-cyan-500/25 shadow-lg mb-3">
            <div className="h-full w-full bg-[#090d16] rounded-[9px] flex items-center justify-center">
              <Shield className="h-6 w-6 text-cyan-400" />
            </div>
          </div>
          <h2 className="text-xl font-bold tracking-tight text-white">
            {mode === 'login' ? 'Sign in to AgentShield' : 'Create Developer Account'}
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Zero-Trust Gateway • Scoped Projects • 25 Policies
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="grid grid-cols-2 gap-1 p-1 bg-slate-900/90 border border-slate-800 rounded-xl mb-6">
          <button
            type="button"
            onClick={() => { setMode('login'); setErrorMsg(null); }}
            className={`py-2 text-xs font-semibold rounded-lg transition cursor-pointer ${
              mode === 'login'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setMode('register'); setErrorMsg(null); }}
            className={`py-2 text-xs font-semibold rounded-lg transition cursor-pointer ${
              mode === 'register'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Create Account
          </button>
        </div>

        {/* Initial Account Callout / Safe Seed */}
        <div className="mb-5 p-3 rounded-xl bg-[#090f1d] border border-cyan-500/20 text-xs">
          <div className="flex items-center justify-between text-[11px] font-semibold text-cyan-300 mb-1">
            <span className="flex items-center space-x-1.5">
              <Key className="h-3.5 w-3.5 text-cyan-400" />
              <span>Initial Developer Account</span>
            </span>
            <button
              type="button"
              onClick={handleFillDemo}
              className="text-[10px] text-cyan-400 hover:text-cyan-300 font-mono underline cursor-pointer"
            >
              Auto-fill
            </button>
          </div>
          <div className="font-mono text-[11px] text-slate-400 flex flex-col space-y-0.5">
            <div>Email: <span className="text-slate-200">dev@agentshield.io</span></div>
            <div>Password: <span className="text-slate-200">AgentShield2026!</span></div>
          </div>
        </div>

        {/* Error Alert */}
        {errorMsg && (
          <div className="mb-5 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start space-x-2.5">
            <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
            <span className="leading-snug">{errorMsg}</span>
          </div>
        )}

        {/* Success Alert */}
        {successMsg && (
          <div className="mb-5 p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center space-x-2.5">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {mode === 'register' && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Developer Identity / Handle (Optional)
              </label>
              <div className="relative">
                <User className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="text"
                  value={developerIdentity}
                  onChange={(e) => setDeveloperIdentity(e.target.value)}
                  placeholder="e.g. sec_engineer"
                  className="w-full bg-slate-900/90 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="developer@corp.com"
                className="w-full bg-slate-900/90 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="At least 8 characters"
                className="w-full bg-slate-900/90 border border-slate-700 rounded-lg pl-9 pr-10 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 cursor-pointer"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <p className="text-[10px] text-slate-500 mt-1">
              Hashed via PBKDF2-HMAC-SHA256 with cryptographically random salt.
            </p>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/20 transition cursor-pointer"
          >
            {loading ? (
              <span>Authenticating...</span>
            ) : (
              <>
                <span>{mode === 'login' ? 'Sign In to Dashboard' : 'Create Account & Sign In'}</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </>
            )}
          </button>
        </form>

        {/* Security Footer Note */}
        <div className="mt-6 pt-4 border-t border-slate-800 text-center text-[11px] text-slate-500">
          <span>Protected by HttpOnly session cookies & CSRF verification.</span>
        </div>
      </div>
    </div>
  );
}
