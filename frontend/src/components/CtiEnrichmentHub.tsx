import { useEffect, useState } from 'react';
import { useToast } from '@astryxdesign/core';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Switch } from '@astryxdesign/core/Switch';
import { Text } from '@astryxdesign/core/Text';
import { Timestamp } from '@astryxdesign/core/Timestamp';
import {
  Database,
  ExternalLink,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Trash2,
} from 'lucide-react';
import { api, safeExternalUrl } from '../api';
import type { CtiConfigPublic, CtiProviderId, CtiProviderStatusPublic } from '../types';

interface CtiEnrichmentHubProps {
  readOnly?: boolean;
  onUpdated?: () => void;
}

export function CtiEnrichmentHub({ readOnly = false, onUpdated }: CtiEnrichmentHubProps) {
  const toast = useToast();
  const [cfg, setCfg] = useState<CtiConfigPublic | null>(null);
  const [keyInputs, setKeyInputs] = useState<Record<CtiProviderId, string>>({
    otx: '',
    greynoise: '',
    abuseipdb: '',
    virustotal: '',
  });
  const [busyProv, setBusyProv] = useState<string | null>(null);
  const [testMsgs, setTestMsgs] = useState<Record<string, { ok: boolean; msg: string }>>({});
  const [syncingOtx, setSyncingOtx] = useState(false);
  const [otxMsg, setOtxMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const loadConfig = async () => {
    try {
      const c = await api.getCtiConfig();
      setCfg(c);
    } catch {
      // ignore initial error
    }
  };

  useEffect(() => {
    void loadConfig();
  }, []);

  const toggleProvider = async (id: CtiProviderId, enabled: boolean) => {
    if (readOnly) return;
    setBusyProv(id);
    try {
      const payload =
        id === 'otx'
          ? { otx_enabled: enabled }
          : id === 'greynoise'
            ? { greynoise_enabled: enabled }
            : id === 'abuseipdb'
              ? { abuseipdb_enabled: enabled }
              : { virustotal_enabled: enabled };
      const updated = await api.updateCtiConfig(payload);
      setCfg(updated);
      onUpdated?.();
    } catch (err) {
      toast({ type: 'error', body: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusyProv(null);
    }
  };

  const saveProviderKey = async (id: CtiProviderId) => {
    const val = keyInputs[id].trim();
    if (readOnly || !val) return;
    setBusyProv(`save:${id}`);
    try {
      const payload =
        id === 'otx'
          ? { otx_api_key: val, otx_enabled: true }
          : id === 'greynoise'
            ? { greynoise_api_key: val, greynoise_enabled: true }
            : id === 'abuseipdb'
              ? { abuseipdb_api_key: val, abuseipdb_enabled: true }
              : { virustotal_api_key: val, virustotal_enabled: true };
      const updated = await api.updateCtiConfig(payload);
      setCfg(updated);
      setKeyInputs((prev) => ({ ...prev, [id]: '' }));
      toast({ type: 'info', body: `Saved ${id.toUpperCase()} API key in server memory${updated.save_keys_to_keychain ? ' & OS Keychain' : ''}.` });
      onUpdated?.();
    } catch (err) {
      toast({ type: 'error', body: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusyProv(null);
    }
  };

  const clearProviderKey = async (id: CtiProviderId) => {
    if (readOnly) return;
    setBusyProv(`clear:${id}`);
    try {
      const payload =
        id === 'otx'
          ? { clear_otx_key: true }
          : id === 'greynoise'
            ? { clear_greynoise_key: true }
            : id === 'abuseipdb'
              ? { clear_abuseipdb_key: true }
              : { clear_virustotal_key: true };
      const updated = await api.updateCtiConfig(payload);
      setCfg(updated);
      toast({ type: 'info', body: `Cleared ${id.toUpperCase()} API key.` });
    } catch (err) {
      toast({ type: 'error', body: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusyProv(null);
    }
  };

  const testProvider = async (id: CtiProviderId) => {
    if (readOnly) return;
    setBusyProv(`test:${id}`);
    try {
      const candidateKey = keyInputs[id].trim() || undefined;
      const res = await api.testCtiProvider(id, candidateKey);
      setTestMsgs((prev) => ({
        ...prev,
        [id]: { ok: res.ok, msg: `${res.message} (${res.latency_ms} ms)` },
      }));
    } catch (err) {
      setTestMsgs((prev) => ({
        ...prev,
        [id]: { ok: false, msg: err instanceof Error ? err.message : String(err) },
      }));
    } finally {
      setBusyProv(null);
    }
  };

  const handleSyncOtx = async () => {
    if (readOnly || syncingOtx) return;
    setSyncingOtx(true);
    setOtxMsg(null);
    try {
      const res = await api.syncOtxPulses();
      setOtxMsg({
        ok: true,
        text: `${res.message} (${res.ip_count} IPs · ${res.domain_count} domains · ${res.hash_count} hashes · ${res.latency_ms} ms)`,
      });
      await loadConfig();
      onUpdated?.();
    } catch (err) {
      setOtxMsg({
        ok: false,
        text: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setSyncingOtx(false);
    }
  };

  const handleToggleKeychain = async (checked: boolean) => {
    if (readOnly) return;
    const updated = await api.updateCtiConfig({ save_keys_to_keychain: checked });
    setCfg(updated);
    toast({
      type: 'info',
      body: checked
        ? 'CTI API keys will persist in your native OS Keychain (never SQLite).'
        : 'Switched to RAM-only mode and cleared OS Keychain CTI entries.',
    });
  };

  const handleToggleOtxAutoSync = async (checked: boolean) => {
    if (readOnly) return;
    const updated = await api.updateCtiConfig({ otx_sync_pulses: checked });
    setCfg(updated);
  };

  const handleClearCache = async () => {
    if (readOnly) return;
    const res = await api.clearCtiCache();
    toast({ type: 'info', body: `Cleared ${res.cleared} cached CTI enrichment lookup(s) from SQLite.` });
    await loadConfig();
  };

  if (!cfg) return null;

  const otxProv = cfg.providers.find((p) => p.id === 'otx');

  return (
    <section className="abw-panel">
      <div className="abw-panel-head">
        <span className="abw-panel-title">
          <Sparkles size={14} color="#66efab" />
          Optional BYO CTI Enrichment Hub (OTX · GreyNoise · AbuseIPDB · VirusTotal)
        </span>
        <div className="abw-flex-wrap" style={{ gap: 6 }}>
          <Badge variant="success" label="ZERO-KEY DEFAULT · KEYS NEVER IN SQLITE" />
          <Badge
            variant="cyan"
            label={`SQLITE CACHE: ${cfg.otx_indicator_count.toLocaleString()} OTX IOCs · ${cfg.cached_enrichment_count} ENRICHMENTS (24H)`}
          />
          {cfg.cached_enrichment_count > 0 && (
            <Button
              label="Clear Cache"
              size="sm"
              variant="secondary"
              icon={<Trash2 size={11} />}
              isDisabled={readOnly}
              onClick={() => void handleClearCache()}
            />
          )}
        </div>
      </div>

      <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div
          className="abw-flex-wrap"
          style={{
            justifyContent: 'space-between',
            padding: '8px 10px',
            border: '1px solid var(--soc-border)',
            background: 'var(--soc-surface)',
          }}
        >
          <div style={{ flex: '1 1 380px' }}>
            <Text size="xsm" display="block">
              <strong style={{ color: 'var(--soc-text)' }}>Privacy Guard &amp; SQLite Caching:</strong>{' '}
              Private/RFC1918/internal IPs and <code>.local</code>/<code>.internal</code> domains are strictly blocked from leaving your machine. Synced OTX Pulses and on-demand enrichment verdicts (24h TTL) are cached locally in <code>data/threat_board.db</code> to save API quota; API keys remain strictly in RAM or your optional OS Keychain.
            </Text>
          </div>
          {cfg.keychain_available && (
            <Switch
              label="Persist keys in OS Keychain"
              value={cfg.save_keys_to_keychain}
              isDisabled={readOnly}
              onChange={(c) => void handleToggleKeychain(c)}
            />
          )}
        </div>

        {/* 4 Provider Cards */}
        <div className="abw-grid-2">
          {cfg.providers.map((p: CtiProviderStatusPublic) => {
            const safeSignup = safeExternalUrl(p.signup_url);
            const testRes = testMsgs[p.id];
            return (
              <div
                key={p.id}
                style={{
                  border: '1px solid var(--soc-border-strong)',
                  background: 'var(--soc-surface)',
                  padding: 12,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                <div className="abw-flex-wrap" style={{ justifyContent: 'space-between' }}>
                  <div className="abw-flex-wrap">
                    <KeyRound size={13} color={p.enabled ? '#66efab' : '#64748b'} />
                    <strong style={{ fontSize: 13 }}>{p.name}</strong>
                    {p.has_key ? (
                      <Badge
                        variant="success"
                        label={
                          p.env_key_present
                            ? `ENV: ${p.key_masked}`
                            : p.keychain_has_key
                              ? `KEYCHAIN: ${p.key_masked}`
                              : `RAM: ${p.key_masked}`
                        }
                      />
                    ) : p.key_optional ? (
                      <Badge variant="cyan" label="KEY OPTIONAL" />
                    ) : (
                      <Badge variant="neutral" label="NO KEY" />
                    )}
                  </div>
                  <Switch
                    label="Enabled"
                    value={p.enabled}
                    isDisabled={readOnly || busyProv === p.id}
                    onChange={(c) => void toggleProvider(p.id, c)}
                  />
                </div>

                <Text type="supporting" size="xsm" display="block">
                  {p.description}
                </Text>

                <div className="abw-flex-wrap" style={{ gap: 4 }}>
                  {p.supports.map((s) => (
                    <Badge key={s} variant="neutral" label={s} />
                  ))}
                  {safeSignup && (
                    <a
                      href={safeSignup}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="abw-a2ui-ext-link"
                      style={{ marginLeft: 'auto' }}
                    >
                      Get Free Key <ExternalLink size={11} />
                    </a>
                  )}
                </div>

                <div className="abw-flex-wrap" style={{ gap: 6 }}>
                  <input
                    type="password"
                    autoComplete="off"
                    className="abw-select"
                    disabled={readOnly}
                    placeholder={`Enter ${p.env_var}...`}
                    value={keyInputs[p.id]}
                    onChange={(e) =>
                      setKeyInputs((prev) => ({ ...prev, [p.id]: e.target.value }))
                    }
                    style={{ flex: '1 1 170px', fontFamily: 'ui-monospace, monospace' }}
                  />
                  <Button
                    label="Save Key"
                    size="sm"
                    variant="primary"
                    isLoading={busyProv === `save:${p.id}`}
                    isDisabled={readOnly || !keyInputs[p.id].trim()}
                    onClick={() => void saveProviderKey(p.id)}
                  />
                  <Button
                    label="Test"
                    size="sm"
                    variant="secondary"
                    icon={<ShieldCheck size={12} />}
                    isLoading={busyProv === `test:${p.id}`}
                    isDisabled={readOnly || (!p.has_key && !p.key_optional && !keyInputs[p.id].trim())}
                    onClick={() => void testProvider(p.id)}
                  />
                  {p.has_key && !p.env_key_present && (
                    <Button
                      label="Clear"
                      size="sm"
                      variant="ghost"
                      isLoading={busyProv === `clear:${p.id}`}
                      isDisabled={readOnly}
                      onClick={() => void clearProviderKey(p.id)}
                    />
                  )}
                </div>

                {testRes && (
                  <Text
                    size="xsm"
                    display="block"
                    style={{ color: testRes.ok ? '#66efab' : '#fca5a5' }}
                  >
                    {testRes.ok ? '✓ ' : '✗ '}
                    {testRes.msg}
                  </Text>
                )}
              </div>
            );
          })}
        </div>

        {/* Private Local OTX Subscribed Pulse Sync Bar */}
        <div
          style={{
            border: '1px solid rgba(102, 239, 171, 0.32)',
            borderLeft: '3px solid #66efab',
            background: 'rgba(102, 239, 171, 0.05)',
            padding: '10px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
          }}
        >
          <div className="abw-flex-wrap" style={{ justifyContent: 'space-between' }}>
            <div>
              <div className="abw-flex-wrap" style={{ marginBottom: 2 }}>
                <Database size={13} color="#66efab" />
                <strong style={{ fontSize: 12.5 }}>
                  AlienVault / LevelBlue OTX — 100% Private Local Pulse Sync (SQLite)
                </strong>
                <Badge
                  variant={cfg.otx_indicator_count > 0 ? 'success' : 'neutral'}
                  label={`${cfg.otx_pulse_count} PULSES · ${cfg.otx_indicator_count.toLocaleString()} IOCs`}
                />
              </div>
              <Text type="supporting" size="xsm" display="block">
                Pulls subscribed OTX Pulses down into <code>data/threat_board.db</code> so Network IOCs and Wireshark PCAP captures match OTX campaigns locally without transmitting internal IPs.
                {cfg.otx_last_synced_at && (
                  <>
                    {' '}
                    Last synced <Timestamp value={cfg.otx_last_synced_at} format="relative" />.
                  </>
                )}
              </Text>
            </div>
            <div className="abw-flex-wrap" style={{ gap: 8 }}>
              <Switch
                label="Auto-sync hourly"
                value={cfg.otx_sync_pulses}
                isDisabled={readOnly || !otxProv?.has_key}
                onChange={(c) => void handleToggleOtxAutoSync(c)}
              />
              <Button
                label="Sync OTX Pulses Now"
                size="sm"
                variant="primary"
                icon={<RefreshCw size={12} />}
                isLoading={syncingOtx}
                isDisabled={readOnly || !otxProv?.has_key}
                onClick={() => void handleSyncOtx()}
              />
            </div>
          </div>

          {otxMsg && (
            <Text size="xsm" display="block" style={{ color: otxMsg.ok ? '#66efab' : '#fca5a5' }}>
              {otxMsg.text}
            </Text>
          )}

          {cfg.otx_pulses_preview.length > 0 && (
            <div className="abw-flex-wrap" style={{ gap: 6 }}>
              {cfg.otx_pulses_preview.slice(0, 6).map((p) => (
                <Badge
                  key={p.id || p.name}
                  variant="info"
                  label={`${p.name.slice(0, 38)} (${p.indicator_count})`}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
