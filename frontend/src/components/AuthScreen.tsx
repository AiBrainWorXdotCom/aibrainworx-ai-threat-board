import { FormEvent, useEffect, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Text } from '@astryxdesign/core/Text';
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  ShieldCheck,
  Smartphone,
  UserPlus,
} from 'lucide-react';
import { ApiError, api } from '../api';
import type { AuthStatusResponse } from '../types';

interface AuthScreenProps {
  authStatus: AuthStatusResponse;
  onAuthenticated: () => Promise<void>;
}

function evaluatePasswordStrength(pw: string): {
  score: number;
  label: string;
  color: string;
} {
  if (!pw) return { score: 0, label: 'Minimum 10 characters', color: '#64748b' };
  let score = 0;
  if (pw.length >= 10) score += 1;
  if (pw.length >= 14) score += 1;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 1;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score += 1;
  if (pw.length < 10) return { score: 1, label: 'Too short (<10 chars)', color: '#ef4444' };
  if (score <= 2) return { score: 2, label: 'Fair — add symbols or length', color: '#f59e0b' };
  if (score === 3) return { score: 3, label: 'Strong', color: '#38bdf8' };
  return { score: 4, label: 'Hardened', color: '#66efab' };
}

export function AuthScreen({ authStatus, onAuthenticated }: AuthScreenProps) {
  const isSetup = authStatus.setup_required;

  const [mode, setMode] = useState<'password' | 'token'>(
    authStatus.token_auth_enabled && !isSetup ? 'password' : 'password'
  );
  const [username, setUsername] = useState(isSetup ? 'admin' : '');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);

  const [totpStep, setTotpStep] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [tokenInput, setTokenInput] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [lockoutSecs, setLockoutSecs] = useState<number>(0);

  useEffect(() => {
    if (lockoutSecs <= 0) return;
    const id = window.setInterval(() => {
      setLockoutSecs((s) => (s > 1 ? s - 1 : 0));
    }, 1000);
    return () => window.clearInterval(id);
  }, [lockoutSecs]);

  const strength = evaluatePasswordStrength(password);

  const handleSetupSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    const cleanUser = username.trim();
    if (cleanUser.length < 3) {
      setErrorMsg('Username must be at least 3 characters.');
      return;
    }
    if (password.length < 10) {
      setErrorMsg('Password must be at least 10 characters long.');
      return;
    }
    if (password !== confirmPassword) {
      setErrorMsg('Passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      await api.setupAdmin({
        username: cleanUser,
        display_name: displayName.trim() || cleanUser,
        password,
      });
      setPassword('');
      setConfirmPassword('');
      await onAuthenticated();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed creating admin account.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleLoginSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (lockoutSecs > 0) return;
    setErrorMsg(null);

    if (mode === 'token') {
      if (!tokenInput.trim()) {
        setErrorMsg('Enter your server access token.');
        return;
      }
      setSubmitting(true);
      try {
        await api.login({ token: tokenInput.trim() });
        setTokenInput('');
        await onAuthenticated();
      } catch (err) {
        if (err instanceof ApiError && err.retryAfterSecs) {
          setLockoutSecs(err.retryAfterSecs);
        }
        setErrorMsg(err instanceof Error ? err.message : 'Invalid access token.');
      } finally {
        setSubmitting(false);
      }
      return;
    }

    if (!username.trim() || !password) {
      setErrorMsg('Enter your username and password.');
      return;
    }
    if (totpStep && !totpCode.trim()) {
      setErrorMsg('Enter your 6-digit authenticator code or a recovery code.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await api.login({
        username: username.trim(),
        password,
        totp_code: totpStep ? totpCode.trim() : undefined,
        remember_me: rememberMe,
      });
      if (res.requires_totp && !res.authenticated) {
        setTotpStep(true);
        setErrorMsg(null);
        return;
      }
      if (res.authenticated) {
        setPassword('');
        setTotpCode('');
        setTotpStep(false);
        await onAuthenticated();
      }
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.retryAfterSecs) setLockoutSecs(err.retryAfterSecs);
        if (err.requiresTotp) setTotpStep(true);
      }
      setErrorMsg(err instanceof Error ? err.message : 'Authentication failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="abw-auth-backdrop">
      <div className="abw-auth-grid" aria-hidden="true" />
      <div className="abw-auth-glow" aria-hidden="true" />

      <div className="abw-auth-shell">
        {/* Header Brand Lockup */}
        <div className="abw-auth-brand">
          <img
            src={`${import.meta.env.BASE_URL}aibrainworx-logo.png`}
            alt="AiBrainWorX"
            className="abw-auth-logo"
          />
          <div className="abw-auth-subtitle">
            AI CYBERSECURITY THREAT ANALYSIS BOARD
          </div>
          <div className="abw-auth-badges">
            <Badge variant="success" label="LOCAL ARGON2ID AUTH" />
            {authStatus.wallboard_mode && <Badge variant="neutral" label="WALLBOARD READ-ONLY" />}
            {authStatus.offline_mode && <Badge variant="warning" label="AIR-GAPPED OFFLINE" />}
          </div>
        </div>

        {/* Main Glass Auth Card */}
        <section className="abw-auth-card">
          <div className="abw-auth-card-head">
            <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
              {isSetup ? (
                <UserPlus size={16} color="#66efab" />
              ) : totpStep ? (
                <Smartphone size={16} color="#38bdf8" />
              ) : (
                <Lock size={16} color="#66efab" />
              )}
              <span className="abw-auth-card-title">
                {isSetup
                  ? 'First-Run Local Admin Setup'
                  : totpStep
                    ? 'Two-Factor Verification'
                    : 'SOC Command Sign In'}
              </span>
            </div>
            <span className="abw-auth-sec-chip">
              <ShieldCheck size={12} color="#66efab" />
              HttpOnly
            </span>
          </div>

          <div className="abw-auth-card-body">
            {isSetup ? (
              <form onSubmit={(e) => void handleSetupSubmit(e)} className="abw-auth-form">
                <Text type="supporting" size="sm">
                  Create your local administrator account to protect this Threat Board. Credentials are hashed with <strong>Argon2id</strong> and stored strictly in local SQLite — nothing ever leaves your machine.
                </Text>

                <label className="abw-auth-field">
                  <span className="abw-auth-label">ADMIN USERNAME</span>
                  <input
                    type="text"
                    autoComplete="username"
                    autoFocus
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="admin"
                    className="abw-auth-input"
                  />
                </label>

                <label className="abw-auth-field">
                  <span className="abw-auth-label">DISPLAY NAME (OPTIONAL)</span>
                  <input
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="Lead SOC Analyst"
                    className="abw-auth-input"
                  />
                </label>

                <label className="abw-auth-field">
                  <span className="abw-auth-label">PASSWORD (MIN 10 CHARACTERS)</span>
                  <div className="abw-auth-pw-wrap">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter a strong passphrase..."
                      className="abw-auth-input"
                    />
                    <button
                      type="button"
                      className="abw-auth-eye"
                      onClick={() => setShowPassword((v) => !v)}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                  <div className="abw-strength-row">
                    {[1, 2, 3, 4].map((seg) => (
                      <span
                        key={seg}
                        className="abw-strength-seg"
                        style={{
                          background:
                            strength.score >= seg ? strength.color : 'rgba(148,163,184,0.18)',
                        }}
                      />
                    ))}
                  </div>
                  <span className="abw-strength-label" style={{ color: strength.color }}>
                    {strength.label}
                  </span>
                </label>

                <label className="abw-auth-field">
                  <span className="abw-auth-label">CONFIRM PASSWORD</span>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Re-enter password..."
                    className="abw-auth-input"
                  />
                </label>

                {errorMsg && (
                  <div className="abw-auth-error" role="alert">
                    <AlertTriangle size={14} />
                    <span>{errorMsg}</span>
                  </div>
                )}

                <Button
                  type="submit"
                  label={submitting ? 'Creating Hardened Account...' : 'Create Admin & Launch War Room'}
                  variant="primary"
                  isLoading={submitting}
                  icon={<CheckCircle2 size={14} />}
                />
              </form>
            ) : (
              <form onSubmit={(e) => void handleLoginSubmit(e)} className="abw-auth-form">
                {authStatus.token_auth_enabled && !totpStep && (
                  <div className="abw-auth-tabs" role="tablist">
                    <button
                      type="button"
                      className={`abw-auth-tab ${mode === 'password' ? 'active' : ''}`}
                      onClick={() => {
                        setMode('password');
                        setErrorMsg(null);
                      }}
                    >
                      <Lock size={13} />
                      Local Account
                    </button>
                    <button
                      type="button"
                      className={`abw-auth-tab ${mode === 'token' ? 'active' : ''}`}
                      onClick={() => {
                        setMode('token');
                        setErrorMsg(null);
                      }}
                    >
                      <KeyRound size={13} />
                      Access Token
                    </button>
                  </div>
                )}

                {mode === 'token' ? (
                  <>
                    <Text type="supporting" size="sm">
                      Enter the server <code>AUTH_TOKEN</code> for headless or API-token session access.
                    </Text>
                    <label className="abw-auth-field">
                      <span className="abw-auth-label">SERVER ACCESS TOKEN</span>
                      <input
                        type="password"
                        autoFocus
                        value={tokenInput}
                        onChange={(e) => setTokenInput(e.target.value)}
                        placeholder="Paste AUTH_TOKEN..."
                        className="abw-auth-input abw-mono"
                      />
                    </label>
                  </>
                ) : totpStep ? (
                  <>
                    <Text type="supporting" size="sm">
                      Enter the 6-digit verification code from your authenticator app for{' '}
                      <strong>{username}</strong>, or enter a single-use recovery code.
                    </Text>
                    <label className="abw-auth-field">
                      <span className="abw-auth-label">AUTHENTICATOR OR RECOVERY CODE</span>
                      <input
                        type="text"
                        inputMode="numeric"
                        autoFocus
                        autoComplete="one-time-code"
                        value={totpCode}
                        onChange={(e) => setTotpCode(e.target.value)}
                        placeholder="123456 or XXXXX-XXXXX"
                        className="abw-auth-input abw-mono"
                        style={{ letterSpacing: '0.18em', fontSize: 16, textAlign: 'center' }}
                      />
                    </label>
                    <button
                      type="button"
                      className="abw-auth-link"
                      onClick={() => {
                        setTotpStep(false);
                        setTotpCode('');
                        setErrorMsg(null);
                      }}
                    >
                      <ArrowLeft size={13} />
                      Back to username &amp; password
                    </button>
                  </>
                ) : (
                  <>
                    <label className="abw-auth-field">
                      <span className="abw-auth-label">USERNAME</span>
                      <input
                        type="text"
                        autoComplete="username"
                        autoFocus
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="Enter username"
                        className="abw-auth-input"
                      />
                    </label>

                    <label className="abw-auth-field">
                      <span className="abw-auth-label">PASSWORD</span>
                      <div className="abw-auth-pw-wrap">
                        <input
                          type={showPassword ? 'text' : 'password'}
                          autoComplete="current-password"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          placeholder="Enter password"
                          className="abw-auth-input"
                        />
                        <button
                          type="button"
                          className="abw-auth-eye"
                          onClick={() => setShowPassword((v) => !v)}
                          aria-label={showPassword ? 'Hide password' : 'Show password'}
                        >
                          {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                        </button>
                      </div>
                    </label>

                    <label className="abw-auth-remember">
                      <input
                        type="checkbox"
                        checked={rememberMe}
                        onChange={(e) => setRememberMe(e.target.checked)}
                      />
                      <span>Keep session active for 24 hours on this browser</span>
                    </label>
                  </>
                )}

                {lockoutSecs > 0 && (
                  <div className="abw-auth-error" role="alert">
                    <AlertTriangle size={14} />
                    <span>
                      Brute-force protection active. Retry allowed in <strong>{lockoutSecs}s</strong>.
                    </span>
                  </div>
                )}

                {errorMsg && lockoutSecs === 0 && (
                  <div className="abw-auth-error" role="alert">
                    <AlertTriangle size={14} />
                    <span>{errorMsg}</span>
                  </div>
                )}

                <Button
                  type="submit"
                  label={
                    submitting
                      ? 'Verifying...'
                      : totpStep
                        ? 'Verify 2FA & Unlock'
                        : 'Unlock Threat Board'
                  }
                  variant="primary"
                  isLoading={submitting}
                  isDisabled={lockoutSecs > 0}
                  icon={<Lock size={14} />}
                />
              </form>
            )}
          </div>
        </section>

        {/* Security Assurance Footer */}
        <div className="abw-auth-footer">
          <span>Argon2id · 256-bit CSPRNG Session · SameSite=Strict · Brute-Force Lockout</span>
          <span>
            Local recovery: launch with <code>--reset-auth</code> (or <code>--no-auth</code> on 127.0.0.1)
          </span>
        </div>
      </div>
    </div>
  );
}
