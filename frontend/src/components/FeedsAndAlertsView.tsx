import { useEffect, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { EmptyState } from '@astryxdesign/core/EmptyState';
import { StatusDot } from '@astryxdesign/core/StatusDot';
import { Switch } from '@astryxdesign/core/Switch';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import { Timestamp } from '@astryxdesign/core/Timestamp';
import {
  BellRing,
  CheckCheck,
  Download,
  ExternalLink,
  Plus,
  Rss,
  Save,
  Send,
  Trash2,
  Upload,
  Webhook,
} from 'lucide-react';
import { api, safeExternalUrl, severityBadgeVariant } from '../api';
import type {
  AlertRules,
  CustomFeedConfig,
  CustomFeedKind,
  FeedHealth,
  FeedSettings,
  Severity,
  SnapshotImportResult,
  ThreatAlert,
  WebhookKind,
  WebhookTargetPublic,
} from '../types';
import { redactDisplayText } from '../utils/opsec';

interface FeedsAndAlertsViewProps {
  alerts: ThreatAlert[];
  feeds: FeedHealth[];
  readOnly?: boolean;
  opsecMode?: boolean;
  onAckAlert: (id: string) => void;
  onAckAll: () => void;
  onTriggerTestAlert: () => void;
  onSelectVulnId: (id: string) => void;
  onRulesUpdated: () => void;
}

export function FeedsAndAlertsView({
  alerts,
  feeds,
  readOnly = false,
  opsecMode = false,
  onAckAlert,
  onAckAll,
  onTriggerTestAlert,
  onSelectVulnId,
  onRulesUpdated,
}: FeedsAndAlertsViewProps) {
  const [rules, setRules] = useState<AlertRules | null>(null);
  const [keywordsText, setKeywordsText] = useState('');
  const [saving, setSaving] = useState(false);
  const [savedBanner, setSavedBanner] = useState(false);

  const [feedSettings, setFeedSettings] = useState<FeedSettings>({
    disabled_feeds: [],
    custom_feeds: [],
  });
  const [cfName, setCfName] = useState('');
  const [cfUrl, setCfUrl] = useState('');
  const [cfKind, setCfKind] = useState<CustomFeedKind>('rss_atom');
  const [cfError, setCfError] = useState<string | null>(null);

  const [webhooks, setWebhooks] = useState<WebhookTargetPublic[]>([]);
  const [whName, setWhName] = useState('');
  const [whKind, setWhKind] = useState<WebhookKind>('slack');
  const [whUrl, setWhUrl] = useState('');
  const [whMinSev, setWhMinSev] = useState<Severity>('HIGH');
  const [whKevOnly, setWhKevOnly] = useState(false);
  const [whStackOnly, setWhStackOnly] = useState(false);
  const [whSecret, setWhSecret] = useState('');
  const [whError, setWhError] = useState<string | null>(null);
  const [whTestMsg, setWhTestMsg] = useState<string | null>(null);

  const [snapshotStatus, setSnapshotStatus] = useState<string | null>(null);
  const [snapshotErr, setSnapshotErr] = useState<string | null>(null);

  const reloadSettingsAndHooks = () => {
    api.getFeeds().then((res) => {
      if (res.feed_settings) setFeedSettings(res.feed_settings);
    });
    api.listWebhooks().then(setWebhooks).catch(() => {});
  };

  useEffect(() => {
    api.getRules().then((r) => {
      setRules(r);
      setKeywordsText(r.watchlist_keywords.join(', '));
    });
    reloadSettingsAndHooks();
  }, []);

  const saveRules = async () => {
    if (!rules || readOnly) return;
    setSaving(true);
    setSavedBanner(false);
    try {
      const updated: AlertRules = {
        ...rules,
        watchlist_keywords: keywordsText
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      };
      const res = await api.updateRules(updated);
      setRules(res);
      setSavedBanner(true);
      onRulesUpdated();
    } finally {
      setSaving(false);
    }
  };

  const handleToggleBuiltInFeed = async (feedId: string, enabled: boolean) => {
    if (readOnly) return;
    const next = await api.updateFeedConfig(feedId, enabled);
    setFeedSettings(next);
    onRulesUpdated();
  };

  const handleAddCustomFeed = async () => {
    if (readOnly || !cfName.trim() || !cfUrl.trim()) return;
    setCfError(null);
    try {
      await api.createCustomFeed({
        name: cfName.trim(),
        url: cfUrl.trim(),
        kind: cfKind,
        enabled: true,
      });
      setCfName('');
      setCfUrl('');
      reloadSettingsAndHooks();
      onRulesUpdated();
    } catch (e) {
      setCfError(e instanceof Error ? e.message : String(e));
    }
  };

  const handleDeleteCustomFeed = async (id: string) => {
    if (readOnly) return;
    await api.deleteCustomFeed(id);
    reloadSettingsAndHooks();
    onRulesUpdated();
  };

  const handleCreateWebhook = async () => {
    if (readOnly || !whName.trim() || !whUrl.trim()) return;
    setWhError(null);
    setWhTestMsg(null);
    try {
      await api.createWebhook({
        name: whName.trim(),
        kind: whKind,
        url: whUrl.trim(),
        enabled: true,
        min_severity: whMinSev,
        kev_only: whKevOnly,
        stack_only: whStackOnly,
        signing_secret: whSecret.trim() || undefined,
      });
      setWhName('');
      setWhUrl('');
      setWhSecret('');
      reloadSettingsAndHooks();
    } catch (e) {
      setWhError(e instanceof Error ? e.message : String(e));
    }
  };

  const handleToggleWebhook = async (hook: WebhookTargetPublic, enabled: boolean) => {
    if (readOnly) return;
    await api.updateWebhook(hook.id, { enabled });
    reloadSettingsAndHooks();
  };

  const handleTestWebhook = async (hook: WebhookTargetPublic) => {
    if (readOnly) return;
    setWhTestMsg(null);
    const res = await api.testWebhook(hook.id);
    setWhTestMsg(`${hook.name}: ${res.ok ? 'OK' : 'FAILED'} — ${res.message} (${res.latency_ms} ms)`);
    reloadSettingsAndHooks();
  };

  const handleDeleteWebhook = async (id: string) => {
    if (readOnly) return;
    await api.deleteWebhook(id);
    reloadSettingsAndHooks();
  };

  const handleSnapshotUpload = async (file: File | undefined) => {
    if (!file || readOnly) return;
    setSnapshotStatus(null);
    setSnapshotErr(null);
    if (file.size > 10 * 1024 * 1024) {
      setSnapshotErr('Snapshot exceeds 10 MB limit.');
      return;
    }
    try {
      const text = await file.text();
      const res: SnapshotImportResult = await api.importSnapshot(text);
      setSnapshotStatus(
        `Verified SHA-256 & imported ${res.vulnerabilities_imported} CVEs + ${res.news_imported} news reports (exported ${new Date(res.snapshot_exported_at).toLocaleString()}).`
      );
      onRulesUpdated();
    } catch (e) {
      setSnapshotErr(e instanceof Error ? e.message : String(e));
    }
  };

  const feedsOk = feeds.filter((f) => f.status === 'OK').length;
  const isFeedEnabled = (f: FeedHealth) =>
    !feedSettings.disabled_feeds.some(
      (d) => d.toLowerCase() === f.id.toLowerCase() || d.toLowerCase() === f.name.toLowerCase()
    );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Top Row: Alert Center + Rules Engine */}
      <div className="abw-grid-asymmetric">
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              Real-Time Vulnerability Alert Log ({alerts.length})
            </span>
            <div className="abw-flex-wrap">
              <Button
                label="Simulate New Alert"
                size="sm"
                variant="primary"
                icon={<BellRing size={13} />}
                isDisabled={readOnly}
                onClick={onTriggerTestAlert}
              />
              <Button
                label="Acknowledge All"
                size="sm"
                variant="secondary"
                icon={<CheckCheck size={13} />}
                isDisabled={readOnly}
                onClick={onAckAll}
              />
            </div>
          </div>

          {alerts.length === 0 ? (
            <div className="abw-panel-body">
              <EmptyState
                title="No alerts recorded yet"
                description="Click 'Simulate New Alert' to verify live SSE alert delivery, or wait for new hourly vulnerability disclosures."
              />
            </div>
          ) : (
            <div className="abw-scroll-list" style={{ maxHeight: 440 }}>
              {alerts.map((a) => (
                <div
                  key={a.id}
                  className="abw-list-row"
                  style={{
                    opacity: a.acknowledged ? 0.68 : 1,
                    borderLeft: a.acknowledged ? '2px solid transparent' : '2px solid #ef4444',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 8,
                      flexWrap: 'wrap',
                    }}
                  >
                    <div className="abw-flex-wrap">
                      <Badge variant={severityBadgeVariant(a.severity)} label={a.severity} />
                      <Badge variant="cyan" label={a.alert_type} />
                      <Badge variant="neutral" label={a.source} />
                      {a.acknowledged && <Badge variant="success" label="ACKED" />}
                    </div>
                    <Text type="supporting" size="xsm">
                      <Timestamp value={a.created_at} format="date_time" />
                    </Text>
                  </div>

                  <Text weight="semibold" size="sm" display="block">
                    {redactDisplayText(a.title, opsecMode)}
                  </Text>
                  <Text type="supporting" size="sm" display="block">
                    {redactDisplayText(a.summary, opsecMode)}
                  </Text>

                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 8,
                      flexWrap: 'wrap',
                    }}
                  >
                    <div className="abw-flex-wrap">
                      {a.cve_ids.map((cve) => (
                        <button
                          key={cve}
                          type="button"
                          className="abw-cve-chip"
                          onClick={() => onSelectVulnId(cve)}
                        >
                          {cve}
                        </button>
                      ))}
                      {a.matched_reasons.map((r) => (
                        <Badge key={r} variant="purple" label={r} />
                      ))}
                    </div>
                    <div className="abw-flex-wrap">
                      {safeExternalUrl(a.url) && (
                        <Button
                          label="Source"
                          size="sm"
                          variant="ghost"
                          href={safeExternalUrl(a.url)}
                          target="_blank"
                          rel="noopener noreferrer"
                          icon={<ExternalLink size={12} />}
                        />
                      )}
                      {!a.acknowledged && (
                        <Button
                          label="Acknowledge"
                          size="sm"
                          variant="secondary"
                          isDisabled={readOnly}
                          onClick={() => onAckAlert(a.id)}
                        />
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">Hourly Watchdog & Alert Rules</span>
          </div>
          <div className="abw-panel-body">
            <Text type="supporting" size="xsm">
              Configure what triggers immediate alerts during hourly background sweeps.
            </Text>

            {rules && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div>
                  <Text weight="medium" size="xsm" display="block" style={{ marginBottom: 6 }}>
                    MINIMUM SEVERITY THRESHOLD
                  </Text>
                  <select
                    className="abw-select"
                    style={{ width: '100%' }}
                    disabled={readOnly}
                    value={rules.min_severity}
                    onChange={(e) =>
                      setRules({ ...rules, min_severity: e.target.value as Severity })
                    }
                  >
                    <option value="CRITICAL">CRITICAL only</option>
                    <option value="HIGH">HIGH & CRITICAL</option>
                    <option value="MEDIUM">MEDIUM, HIGH & CRITICAL</option>
                    <option value="LOW">LOW and above</option>
                  </select>
                </div>

                <Switch
                  label="Alert on any new CISA KEV addition"
                  description="Trigger immediately whenever a CVE enters CISA Known Exploited Vulnerabilities"
                  value={rules.alert_on_any_kev}
                  onChange={(checked) => !readOnly && setRules({ ...rules, alert_on_any_kev: checked })}
                />

                <Switch
                  label="Alert on breaking vulnerability news"
                  description="Trigger when news feeds publish zero-day, RCE, or CVE disclosures"
                  value={rules.alert_on_vuln_news}
                  onChange={(checked) =>
                    !readOnly && setRules({ ...rules, alert_on_vuln_news: checked })
                  }
                />

                <Switch
                  label="Alert on AI / LLM supply-chain CVEs"
                  description="Monitor PyTorch, LangChain, vLLM, MCP, Transformers & MLOps"
                  value={rules.alert_on_ai_threats}
                  onChange={(checked) =>
                    !readOnly && setRules({ ...rules, alert_on_ai_threats: checked })
                  }
                />

                <div>
                  <Text weight="medium" size="xsm" display="block" style={{ marginBottom: 6 }}>
                    WATCHLIST KEYWORDS (COMMA-SEPARATED)
                  </Text>
                  <TextInput
                    label="Watchlist keywords"
                    isLabelHidden
                    value={keywordsText}
                    onChange={setKeywordsText}
                    width="100%"
                  />
                </div>

                <div>
                  <Text weight="medium" size="xsm" display="block" style={{ marginBottom: 6 }}>
                    COLLECTION INTERVAL
                  </Text>
                  <select
                    className="abw-select"
                    style={{ width: '100%' }}
                    disabled={readOnly}
                    value={String(rules.poll_interval_secs)}
                    onChange={(e) =>
                      setRules({ ...rules, poll_interval_secs: Number(e.target.value) })
                    }
                  >
                    <option value="3600">Every 1 Hour (3600s · Default)</option>
                    <option value="1800">Every 30 Minutes (1800s)</option>
                    <option value="900">Every 15 Minutes (900s)</option>
                    <option value="300">Every 5 Minutes (300s)</option>
                  </select>
                </div>

                <div className="abw-flex-wrap">
                  <Button
                    label="Save Watchdog Rules"
                    variant="primary"
                    icon={<Save size={13} />}
                    isLoading={saving}
                    isDisabled={readOnly}
                    onClick={() => void saveRules()}
                  />
                  {savedBanner && <Badge variant="success" label="Rules saved" />}
                </div>
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Webhooks & BYO Custom Threat Feeds */}
      <div className="abw-grid-2">
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              <Webhook size={14} color="#66efab" />
              Outbound Alert Webhooks ({webhooks.length})
            </span>
            <Badge variant="info" label="SSRF-PINNED HTTPS" />
          </div>
          <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <Text type="supporting" size="xsm">
              Dispatch signed real-time alerts to Slack, Discord, Microsoft Teams, or any generic HTTPS webhook. URLs are strictly validated against SSRF and never echoed after creation.
            </Text>

            <div className="abw-flex-wrap" style={{ gap: 6 }}>
              <input
                className="abw-select"
                placeholder="Target Name (e.g. SOC Slack)"
                disabled={readOnly}
                value={whName}
                onChange={(e) => setWhName(e.target.value)}
                style={{ flex: '1 1 140px' }}
              />
              <select
                className="abw-select"
                disabled={readOnly}
                value={whKind}
                onChange={(e) => setWhKind(e.target.value as WebhookKind)}
              >
                <option value="slack">Slack</option>
                <option value="discord">Discord</option>
                <option value="teams">Microsoft Teams</option>
                <option value="generic">Generic JSON</option>
              </select>
              <select
                className="abw-select"
                disabled={readOnly}
                value={whMinSev}
                onChange={(e) => setWhMinSev(e.target.value as Severity)}
              >
                <option value="CRITICAL">CRITICAL+</option>
                <option value="HIGH">HIGH+</option>
                <option value="MEDIUM">MEDIUM+</option>
              </select>
            </div>

            <TextInput
              label="HTTPS Webhook URL"
              isLabelHidden
              type="password"
              value={whUrl}
              onChange={setWhUrl}
              placeholder="https://hooks.slack.com/services/..."
              width="100%"
            />

            <div className="abw-flex-wrap" style={{ gap: 12, fontSize: 12 }}>
              <label style={{ display: 'inline-flex', gap: 5, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={whKevOnly}
                  disabled={readOnly}
                  onChange={(e) => setWhKevOnly(e.target.checked)}
                />
                KEV Only
              </label>
              <label style={{ display: 'inline-flex', gap: 5, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={whStackOnly}
                  disabled={readOnly}
                  onChange={(e) => setWhStackOnly(e.target.checked)}
                />
                My Stack Hits Only
              </label>
              <input
                className="abw-select"
                type="password"
                disabled={readOnly}
                value={whSecret}
                onChange={(e) => setWhSecret(e.target.value)}
                placeholder="Optional HMAC-SHA256 Secret"
                style={{ flex: '1 1 160px' }}
              />
              <Button
                label="Add Webhook"
                size="sm"
                variant="primary"
                icon={<Plus size={12} />}
                isDisabled={readOnly}
                onClick={() => void handleCreateWebhook()}
              />
            </div>

            {whError && <Text size="xsm" style={{ color: '#fca5a5' }}>{whError}</Text>}
            {whTestMsg && <Text size="xsm" style={{ color: '#66efab' }}>{whTestMsg}</Text>}

            {webhooks.length > 0 && (
              <div style={{ border: '1px solid var(--soc-border)' }}>
                {webhooks.map((hook) => (
                  <div key={hook.id} className="abw-list-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <div style={{ minWidth: 0 }}>
                      <div className="abw-flex-wrap">
                        <strong>{hook.name}</strong>
                        <Badge variant="cyan" label={hook.kind.toUpperCase()} />
                        <Badge variant="neutral" label={`${hook.min_severity}+`} />
                        {hook.kev_only && <Badge variant="error" label="KEV" />}
                        {hook.stack_only && <Badge variant="warning" label="STACK" />}
                        {hook.has_signing_secret && <Badge variant="success" label="HMAC" />}
                      </div>
                      <Text type="code" size="xsm" display="block">
                        {hook.url_masked} {hook.last_status ? `· ${hook.last_status}` : ''}
                      </Text>
                    </div>
                    <div className="abw-flex-wrap" style={{ gap: 6 }}>
                      <Switch
                        label=""
                        value={hook.enabled}
                        onChange={(checked) => void handleToggleWebhook(hook, checked)}
                      />
                      <Button
                        label="Test"
                        size="sm"
                        variant="secondary"
                        icon={<Send size={12} />}
                        isDisabled={readOnly}
                        onClick={() => void handleTestWebhook(hook)}
                      />
                      <Button
                        label="Delete"
                        size="sm"
                        variant="ghost"
                        isIconOnly
                        isDisabled={readOnly}
                        icon={<Trash2 size={13} />}
                        onClick={() => void handleDeleteWebhook(hook.id)}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              <Rss size={14} color="#38bdf8" />
              BYO Custom Threat Feeds & Offline Air-Gapped Snapshots
            </span>
          </div>
          <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="abw-flex-wrap" style={{ gap: 6 }}>
              <input
                className="abw-select"
                placeholder="Feed Name"
                disabled={readOnly}
                value={cfName}
                onChange={(e) => setCfName(e.target.value)}
                style={{ flex: '1 1 130px' }}
              />
              <select
                className="abw-select"
                disabled={readOnly}
                value={cfKind}
                onChange={(e) => setCfKind(e.target.value as CustomFeedKind)}
              >
                <option value="rss_atom">RSS / Atom</option>
                <option value="ioc_text">IOC Text List</option>
                <option value="stix21">STIX 2.1 Bundle</option>
                <option value="misp_json">MISP Event JSON</option>
              </select>
            </div>
            <div className="abw-flex-wrap" style={{ gap: 6 }}>
              <div style={{ flex: 1 }}>
                <TextInput
                  label="Custom feed URL"
                  isLabelHidden
                  value={cfUrl}
                  onChange={setCfUrl}
                  placeholder="https://intel.example.org/feed.json"
                  width="100%"
                />
              </div>
              <Button
                label="Add Feed"
                size="sm"
                variant="primary"
                icon={<Plus size={12} />}
                isDisabled={readOnly}
                onClick={() => void handleAddCustomFeed()}
              />
            </div>
            {cfError && <Text size="xsm" style={{ color: '#fca5a5' }}>{cfError}</Text>}

            {feedSettings.custom_feeds.length > 0 && (
              <div style={{ border: '1px solid var(--soc-border)' }}>
                {feedSettings.custom_feeds.map((cf: CustomFeedConfig) => (
                  <div key={cf.id} className="abw-list-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <div style={{ minWidth: 0 }}>
                      <div className="abw-flex-wrap">
                        <strong>{cf.name}</strong>
                        <Badge variant="info" label={cf.kind.toUpperCase()} />
                        {cf.last_status && <Badge variant="neutral" label={cf.last_status} />}
                      </div>
                      <Text type="code" size="xsm" maxLines={1}>
                        {opsecMode ? redactDisplayText(cf.url, true) : cf.url}
                      </Text>
                    </div>
                    <Button
                      label="Delete"
                      size="sm"
                      variant="ghost"
                      isIconOnly
                      isDisabled={readOnly}
                      icon={<Trash2 size={13} />}
                      onClick={() => void handleDeleteCustomFeed(cf.id)}
                    />
                  </div>
                ))}
              </div>
            )}

            <div style={{ borderTop: '1px solid var(--soc-border)', paddingTop: 10 }}>
              <Text weight="semibold" size="xsm" display="block" style={{ marginBottom: 6 }}>
                AIR-GAPPED SNAPSHOT SYNC (SECRET-STRIPPED & SHA-256 VERIFIED)
              </Text>
              <div className="abw-flex-wrap" style={{ gap: 8 }}>
                <Button
                  label="Export Snapshot (.json)"
                  size="sm"
                  variant="secondary"
                  icon={<Download size={13} />}
                  onClick={() => void api.exportSnapshot()}
                />
                <label
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '5px 10px',
                    border: '1px solid var(--soc-border)',
                    background: 'var(--soc-surface-elevated)',
                    cursor: readOnly ? 'not-allowed' : 'pointer',
                    fontSize: 12,
                  }}
                >
                  <Upload size={13} />
                  Import Verified Snapshot
                  <input
                    type="file"
                    accept=".json,application/json"
                    disabled={readOnly}
                    style={{ display: 'none' }}
                    onChange={(e) => void handleSnapshotUpload(e.target.files?.[0])}
                  />
                </label>
              </div>
              {snapshotStatus && (
                <Text size="xsm" display="block" style={{ marginTop: 6, color: '#66efab' }}>
                  {snapshotStatus}
                </Text>
              )}
              {snapshotErr && (
                <Text size="xsm" display="block" style={{ marginTop: 6, color: '#fca5a5' }}>
                  {snapshotErr}
                </Text>
              )}
            </div>
          </div>
        </section>
      </div>

      {/* Bottom: 25-Source Public Data Feed Health Matrix with Per-Feed Toggle */}
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            Open Public Data Sources Telemetry ({feedsOk}/{feeds.length} Healthy)
          </span>
          <Badge variant="success" label={`${feedsOk} ONLINE`} />
        </div>

        <div className="abw-table-wrap">
          <table className="abw-table">
            <thead>
              <tr>
                <th>Enabled</th>
                <th>Status</th>
                <th>Feed Source</th>
                <th>Category</th>
                <th>HTTP</th>
                <th>Latency</th>
                <th>Records</th>
                <th>Last Synced</th>
                <th>Endpoint</th>
              </tr>
            </thead>
            <tbody>
              {feeds.map((f) => {
                const enabled = isFeedEnabled(f);
                return (
                  <tr key={f.id}>
                    <td>
                      <Switch
                        label=""
                        value={enabled}
                        onChange={(checked) => void handleToggleBuiltInFeed(f.id, checked)}
                      />
                    </td>
                    <td>
                      <div className="abw-flex-wrap">
                        <StatusDot
                          variant={
                            f.status === 'OK'
                              ? 'success'
                              : f.status === 'ERROR'
                                ? 'error'
                                : f.status === 'DISABLED'
                                  ? 'neutral'
                                  : 'warning'
                          }
                          label={f.status}
                        />
                        <Badge
                          variant={
                            f.status === 'OK'
                              ? 'success'
                              : f.status === 'ERROR'
                                ? 'error'
                                : f.status === 'DISABLED'
                                  ? 'neutral'
                                  : 'warning'
                          }
                          label={f.status}
                        />
                      </div>
                    </td>
                    <td>
                      <strong>{f.name}</strong>
                      {f.last_error && (
                        <Text type="supporting" size="xsm" display="block">
                          {f.last_error}
                        </Text>
                      )}
                    </td>
                    <td>
                      <Badge variant="neutral" label={f.category} />
                    </td>
                    <td className="abw-mono">{f.http_status ?? '—'}</td>
                    <td className="abw-mono">{f.latency_ms} ms</td>
                    <td className="abw-mono">{f.items_fetched.toLocaleString()}</td>
                    <td>
                      {f.last_success_at ? (
                        <Text type="supporting" size="xsm">
                          <Timestamp value={f.last_success_at} format="relative" />
                        </Text>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>
                      {safeExternalUrl(f.url) ? (
                        <a
                          href={safeExternalUrl(f.url)}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ color: 'var(--soc-cyan)', fontSize: 12 }}
                        >
                          {f.url}
                        </a>
                      ) : (
                        <span style={{ fontSize: 12 }}>{f.url}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
