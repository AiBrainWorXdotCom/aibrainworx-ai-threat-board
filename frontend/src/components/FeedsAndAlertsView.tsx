import { useEffect, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { EmptyState } from '@astryxdesign/core/EmptyState';
import { StatusDot } from '@astryxdesign/core/StatusDot';
import { Switch } from '@astryxdesign/core/Switch';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import { Timestamp } from '@astryxdesign/core/Timestamp';
import { BellRing, CheckCheck, ExternalLink, Save } from 'lucide-react';
import { api, safeExternalUrl, severityBadgeVariant } from '../api';
import type { AlertRules, FeedHealth, Severity, ThreatAlert } from '../types';

interface FeedsAndAlertsViewProps {
  alerts: ThreatAlert[];
  feeds: FeedHealth[];
  onAckAlert: (id: string) => void;
  onAckAll: () => void;
  onTriggerTestAlert: () => void;
  onSelectVulnId: (id: string) => void;
  onRulesUpdated: () => void;
}

export function FeedsAndAlertsView({
  alerts,
  feeds,
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

  useEffect(() => {
    api.getRules().then((r) => {
      setRules(r);
      setKeywordsText(r.watchlist_keywords.join(', '));
    });
  }, []);

  const saveRules = async () => {
    if (!rules) return;
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

  const feedsOk = feeds.filter((f) => f.status === 'OK').length;

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
                onClick={onTriggerTestAlert}
              />
              <Button
                label="Acknowledge All"
                size="sm"
                variant="secondary"
                icon={<CheckCheck size={13} />}
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
                    {a.title}
                  </Text>
                  <Text type="supporting" size="sm" display="block">
                    {a.summary}
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
                  onChange={(checked) => setRules({ ...rules, alert_on_any_kev: checked })}
                />

                <Switch
                  label="Alert on breaking vulnerability news"
                  description="Trigger when news feeds publish zero-day, RCE, or CVE disclosures"
                  value={rules.alert_on_vuln_news}
                  onChange={(checked) => setRules({ ...rules, alert_on_vuln_news: checked })}
                />

                <Switch
                  label="Alert on AI / LLM supply-chain CVEs"
                  description="Monitor PyTorch, LangChain, vLLM, MCP, Transformers & MLOps"
                  value={rules.alert_on_ai_threats}
                  onChange={(checked) => setRules({ ...rules, alert_on_ai_threats: checked })}
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
                    onClick={() => void saveRules()}
                  />
                  {savedBanner && <Badge variant="success" label="Rules saved" />}
                </div>
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Bottom: 25-Source Public Data Feed Health Matrix */}
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
              {feeds.map((f) => (
                <tr key={f.id}>
                  <td>
                    <div className="abw-flex-wrap">
                      <StatusDot
                        variant={f.status === 'OK' ? 'success' : f.status === 'ERROR' ? 'error' : 'warning'}
                        label={f.status}
                      />
                      <Badge
                        variant={f.status === 'OK' ? 'success' : f.status === 'ERROR' ? 'error' : 'warning'}
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
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
