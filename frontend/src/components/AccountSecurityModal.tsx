import { FormEvent, useEffect, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Text } from '@astryxdesign/core/Text';
import {
  Check,
  Copy,
  KeyRound,
  LogOut,
  Monitor,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  X,
} from 'lucide-react';
import { api } from '../api';
import type { AuthSessionPublic, AuthStatusResponse, TotpEnrollResponse } from '../types';

interface AccountSecurityModalProps {
  open: boolean;
  authStatus: AuthStatusResponse;
  onClose: () => void;
  onRefreshAuth: () => Promise<void>;
  onLogout: () => Promise<void>;
}

export function AccountSecurityModal({
  open,
  authStatus,
  onClose,
  onRefreshAuth,
  onLogout,
}: AccountSecurityModalProps) {
  const [sessions, setSessions] = useState<AuthSessionPublic[]>([]);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Change password state
  const [curPw, setCurPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [pwBusy, setPwBusy] = useState(false);

  // TOTP 2FA state
  const [enrollData, setEnrollData] = useState<TotpEnrollResponse | null>(null);
  const [totpVerifyCode, setTotpVerifyCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copiedRecovery, setCopiedRecovery] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [disablePw, setDisablePw] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [totpBusy, setTotpBusy] = useState(false);

  const loadSessions = async () => {
    try {
      const list = await api.listSessions();
      setSessions(list);
    } catch {
      // ignore if token-only session
    }
  };

  useEffect(() => {
    if (!open) return;
    setStatusMsg(null);
    setErrorMsg(null);
    void loadSessions();
  }, [open]);

  if (!open) return null;

  const isLocalUser = Boolean(authStatus.username);

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setStatusMsg(null);
    if (newPw.length < 10) {
      setErrorMsg('New password must be at least 10 characters.');
      return;
    }
    if (newPw !== confirmPw) {
      setErrorMsg('New passwords do not match.');
      return;
    }
    setPwBusy(true);
    try {
      const res = await api.changePassword(curPw, newPw);
      setCurPw('');
      setNewPw('');
      setConfirmPw('');
      setStatusMsg(
        `Password updated cleanly (Argon2id). Revoked ${res.other_sessions_revoked} other active session(s).`
      );
      await loadSessions();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed updating password.');
    } finally {
      setPwBusy(false);
    }
  };

  const handleStartEnroll = async () => {
    setErrorMsg(null);
    setStatusMsg(null);
    setRecoveryCodes(null);
    setTotpBusy(true);
    try {
      const data = await api.enrollTotp();
      setEnrollData(data);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed starting 2FA enrollment.');
    } finally {
      setTotpBusy(false);
    }
  };

  const handleVerifyEnroll = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setTotpBusy(true);
    try {
      const res = await api.verifyTotp(totpVerifyCode.trim());
      setRecoveryCodes(res.recovery_codes);
      setEnrollData(null);
      setTotpVerifyCode('');
      setStatusMsg('TOTP Two-Factor Authentication is now ACTIVE. Save your one-time recovery codes below!');
      await onRefreshAuth();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Invalid 6-digit authenticator code.');
    } finally {
      setTotpBusy(false);
    }
  };

  const handleDisableTotp = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setStatusMsg(null);
    setTotpBusy(true);
    try {
      await api.disableTotp(disablePw, disableCode.trim());
      setDisablePw('');
      setDisableCode('');
      setRecoveryCodes(null);
      setStatusMsg('TOTP 2FA has been disabled for your account.');
      await onRefreshAuth();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed disabling 2FA.');
    } finally {
      setTotpBusy(false);
    }
  };

  const handleRevokeOthers = async () => {
    setErrorMsg(null);
    setStatusMsg(null);
    try {
      const res = await api.revokeOtherSessions();
      setStatusMsg(`Signed out ${res.revoked} other browser session(s).`);
      await loadSessions();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed revoking sessions.');
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Account Security & 2FA Settings"
      className="abw-modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="abw-modal-card" style={{ maxWidth: 680 }}>
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <ShieldCheck size={15} color="#66efab" />
            Account Security, TOTP 2FA &amp; Active Sessions
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Badge
              variant={authStatus.totp_enabled ? 'success' : 'warning'}
              label={authStatus.totp_enabled ? '2FA ENABLED' : '2FA OFF'}
            />
            <button
              type="button"
              onClick={onClose}
              aria-label="Close security modal"
              style={{
                background: 'transparent',
                border: '1px solid var(--soc-border)',
                color: 'var(--soc-text)',
                width: 28,
                height: 28,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
              }}
            >
              <X size={14} />
            </button>
          </div>
        </div>

        <div className="abw-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {statusMsg && (
            <div style={{ border: '1px solid #166534', background: 'rgba(22,101,52,0.18)', padding: '9px 12px', fontSize: 12.5, color: '#86efac' }}>
              {statusMsg}
            </div>
          )}
          {errorMsg && (
            <div style={{ border: '1px solid #991b1b', background: 'rgba(153,27,27,0.2)', padding: '9px 12px', fontSize: 12.5, color: '#fca5a5' }}>
              {errorMsg}
            </div>
          )}

          {/* Signed-in Identity Bar */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 12,
              padding: '10px 12px',
              background: 'var(--soc-surface-elevated)',
              border: '1px solid var(--soc-border)',
            }}
          >
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--soc-text)' }}>
                {authStatus.display_name || authStatus.username || 'Token Session'}
                {authStatus.username && (
                  <span style={{ marginLeft: 8, fontFamily: 'ui-monospace, monospace', fontSize: 11.5, color: '#66efab' }}>
                    @{authStatus.username}
                  </span>
                )}
              </div>
              <Text type="supporting" size="xsm">
                Local SQLite Argon2id identity · Random 256-bit HttpOnly SameSite=Strict session
              </Text>
            </div>
            <Button
              label="Lock / Sign Out"
              variant="destructive"
              size="sm"
              icon={<LogOut size={13} />}
              onClick={() => void onLogout()}
            />
          </div>

          {isLocalUser && (
            <>
              {/* TOTP 2FA Section */}
              <section className="abw-panel">
                <div className="abw-panel-head">
                  <span className="abw-panel-title">
                    <Smartphone size={14} color="#38bdf8" />
                    Authenticator App 2FA (RFC 6238 TOTP)
                  </span>
                  {authStatus.totp_enabled && (
                    <Badge
                      variant="info"
                      label={`${authStatus.recovery_codes_remaining} Recovery Codes Left`}
                    />
                  )}
                </div>
                <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {recoveryCodes && (
                    <div
                      style={{
                        border: '1px solid rgba(102,239,171,0.45)',
                        background: 'rgba(102,239,171,0.08)',
                        padding: 12,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 10,
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <strong style={{ fontSize: 12.5, color: '#66efab' }}>
                          Save Your One-Time Recovery Codes (Shown Once Only)
                        </strong>
                        <Button
                          label={copiedRecovery ? 'Copied!' : 'Copy All'}
                          size="sm"
                          variant="secondary"
                          icon={copiedRecovery ? <Check size={12} /> : <Copy size={12} />}
                          onClick={() => {
                            void navigator.clipboard.writeText(recoveryCodes.join('\n'));
                            setCopiedRecovery(true);
                            window.setTimeout(() => setCopiedRecovery(false), 2000);
                          }}
                        />
                      </div>
                      <div
                        style={{
                          display: 'grid',
                          gridTemplateColumns: 'repeat(4, 1fr)',
                          gap: 6,
                          fontFamily: 'ui-monospace, monospace',
                          fontSize: 12,
                        }}
                      >
                        {recoveryCodes.map((c) => (
                          <div
                            key={c}
                            style={{
                              padding: '5px 8px',
                              background: 'var(--soc-surface)',
                              border: '1px solid var(--soc-border)',
                              textAlign: 'center',
                              color: '#f8fafc',
                            }}
                          >
                            {c}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {!authStatus.totp_enabled ? (
                    enrollData ? (
                      <div style={{ display: 'grid', gridTemplateColumns: '216px 1fr', gap: 16, alignItems: 'start' }}>
                        <div
                          style={{
                            background: '#ffffff',
                            padding: 6,
                            borderRadius: 6,
                            width: 216,
                            height: 216,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                        >
                          <img
                            src={enrollData.qr_svg_data_uri}
                            alt="Offline TOTP QR Code"
                            style={{ width: 204, height: 204, display: 'block' }}
                          />
                        </div>
                        <form onSubmit={(e) => void handleVerifyEnroll(e)} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                          <Text type="supporting" size="xsm">
                            Scan this locally generated QR code with 1Password, Bitwarden, Authy, or Google Authenticator. Zero external requests are made.
                          </Text>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <code
                              style={{
                                flex: 1,
                                fontSize: 11.5,
                                padding: '6px 8px',
                                background: 'var(--soc-surface)',
                                border: '1px solid var(--soc-border)',
                                wordBreak: 'break-all',
                                color: '#66efab',
                              }}
                            >
                              {enrollData.secret_b32}
                            </code>
                            <Button
                              type="button"
                              label={copiedSecret ? 'Copied' : 'Copy'}
                              size="sm"
                              variant="secondary"
                              onClick={() => {
                                void navigator.clipboard.writeText(enrollData.secret_b32);
                                setCopiedSecret(true);
                                window.setTimeout(() => setCopiedSecret(false), 1800);
                              }}
                            />
                          </div>
                          <input
                            type="text"
                            inputMode="numeric"
                            value={totpVerifyCode}
                            onChange={(e) => setTotpVerifyCode(e.target.value)}
                            placeholder="Enter 6-digit code to activate"
                            className="abw-auth-input abw-mono"
                          />
                          <div style={{ display: 'flex', gap: 8 }}>
                            <Button
                              type="submit"
                              label={totpBusy ? 'Verifying...' : 'Verify & Enable 2FA'}
                              variant="primary"
                              size="sm"
                              isLoading={totpBusy}
                            />
                            <Button
                              type="button"
                              label="Cancel"
                              variant="secondary"
                              size="sm"
                              onClick={() => setEnrollData(null)}
                            />
                          </div>
                        </form>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                        <Text type="supporting" size="xsm">
                          Protect your SOC board with offline RFC 6238 authenticator codes and 8 single-use recovery codes.
                        </Text>
                        <Button
                          label={totpBusy ? 'Generating...' : 'Enable 2FA'}
                          variant="primary"
                          size="sm"
                          isLoading={totpBusy}
                          onClick={() => void handleStartEnroll()}
                        />
                      </div>
                    )
                  ) : (
                    <form onSubmit={(e) => void handleDisableTotp(e)} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <Text type="supporting" size="xsm">
                        2FA is actively enforced at sign-in with replay protection. To disable 2FA, confirm your password and a valid authenticator or recovery code:
                      </Text>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 8 }}>
                        <input
                          type="password"
                          value={disablePw}
                          onChange={(e) => setDisablePw(e.target.value)}
                          placeholder="Current password"
                          className="abw-auth-input"
                        />
                        <input
                          type="text"
                          value={disableCode}
                          onChange={(e) => setDisableCode(e.target.value)}
                          placeholder="6-digit or recovery code"
                          className="abw-auth-input abw-mono"
                        />
                        <Button
                          type="submit"
                          label="Disable 2FA"
                          variant="destructive"
                          size="sm"
                          isLoading={totpBusy}
                        />
                      </div>
                    </form>
                  )}
                </div>
              </section>

              {/* Change Password Section */}
              <section className="abw-panel">
                <div className="abw-panel-head">
                  <span className="abw-panel-title">
                    <KeyRound size={14} color="#66efab" />
                    Rotate Local Password
                  </span>
                </div>
                <form
                  onSubmit={(e) => void handleChangePassword(e)}
                  className="abw-panel-body"
                  style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
                >
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                    <input
                      type="password"
                      value={curPw}
                      onChange={(e) => setCurPw(e.target.value)}
                      placeholder="Current password"
                      className="abw-auth-input"
                    />
                    <input
                      type="password"
                      value={newPw}
                      onChange={(e) => setNewPw(e.target.value)}
                      placeholder="New password (10+ chars)"
                      className="abw-auth-input"
                    />
                    <input
                      type="password"
                      value={confirmPw}
                      onChange={(e) => setConfirmPw(e.target.value)}
                      placeholder="Confirm new password"
                      className="abw-auth-input"
                    />
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <Button
                      type="submit"
                      label={pwBusy ? 'Updating...' : 'Update Password & Revoke Other Sessions'}
                      variant="secondary"
                      size="sm"
                      isLoading={pwBusy}
                    />
                  </div>
                </form>
              </section>

              {/* Active Sessions Section */}
              <section className="abw-panel">
                <div className="abw-panel-head">
                  <span className="abw-panel-title">
                    <Monitor size={14} color="#a78bfa" />
                    Active Browser Sessions ({sessions.length})
                  </span>
                  <Button
                    label="Sign Out Other Sessions"
                    variant="secondary"
                    size="sm"
                    icon={<ShieldAlert size={12} />}
                    isDisabled={sessions.length <= 1}
                    onClick={() => void handleRevokeOthers()}
                  />
                </div>
                <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {sessions.length === 0 ? (
                    <Text type="supporting" size="xsm">
                      No active SQLite sessions found.
                    </Text>
                  ) : (
                    sessions.map((s) => (
                      <div
                        key={s.id_preview}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: 10,
                          padding: '7px 10px',
                          background: 'var(--soc-surface)',
                          border: '1px solid var(--soc-border)',
                          fontSize: 11.5,
                        }}
                      >
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ color: 'var(--soc-text)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {s.user_agent}
                          </div>
                          <div style={{ color: 'var(--soc-muted)', fontFamily: 'ui-monospace, monospace', fontSize: 10.5 }}>
                            ID {s.id_preview}… · Last seen {new Date(s.last_seen_at).toLocaleString()} · Expires {new Date(s.expires_at).toLocaleString()}
                          </div>
                        </div>
                        {s.is_current && (
                          <div style={{ flexShrink: 0 }}>
                            <Badge variant="success" label="CURRENT" />
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
