import { useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import { Copy, Download, EyeOff, Globe, Search, ShieldAlert } from 'lucide-react';
import { api } from '../api';
import type { BulkIocResponse, IocLookupResult, NetworkTelemetry } from '../types';
import {
  defangIp,
  defangUrl,
  redactDisplayText,
  redactHostname,
  redactIp,
  redactUrl,
} from '../utils/opsec';

interface NetworkIocViewProps {
  telemetry: NetworkTelemetry;
  opsecMode: boolean;
  onSelectVulnId: (id: string) => void;
}

export function NetworkIocView({ telemetry, opsecMode, onSelectVulnId }: NetworkIocViewProps) {
  const [iocQuery, setIocQuery] = useState('');
  const [lookupResult, setLookupResult] = useState<IocLookupResult | null>(null);
  const [checking, setChecking] = useState(false);

  const [bulkInput, setBulkInput] = useState('');
  const [bulkResult, setBulkResult] = useState<BulkIocResponse | null>(null);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [copiedMsg, setCopiedMsg] = useState<string | null>(null);

  const runLookup = async (override?: string) => {
    const q = (override ?? iocQuery).trim();
    if (!q) return;
    setChecking(true);
    try {
      const res = await api.getIocs(q);
      setLookupResult(res.lookup_result);
    } finally {
      setChecking(false);
    }
  };

  const runBulkLookup = async () => {
    const lines = bulkInput
      .split(/[\r\n,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (lines.length === 0) return;
    setBulkLoading(true);
    try {
      const res = await api.bulkLookupIocs(lines);
      setBulkResult(res);
    } finally {
      setBulkLoading(false);
    }
  };

  const copyDefangedMatches = async () => {
    if (!bulkResult) return;
    const hits = bulkResult.results
      .filter((r) => r.matched)
      .map((r) => (r.query.includes('://') ? defangUrl(r.query) : defangIp(r.query)));
    if (hits.length === 0) return;
    await navigator.clipboard.writeText(hits.join('\n')).catch(() => {});
    setCopiedMsg(`Copied ${hits.length} defanged hits`);
    setTimeout(() => setCopiedMsg(null), 2500);
  };

  const displayIp = (ip: string) => (opsecMode ? redactIp(ip) : ip);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {opsecMode && (
        <div className="abw-alert-bar" style={{ borderLeftColor: '#66efab', background: 'var(--soc-mint-soft)' }}>
          <div className="abw-flex-wrap">
            <EyeOff size={15} color="#66efab" />
            <Text size="sm" weight="semibold">
              OPSEC Redact Mode Active: Public attacker IPs, C2 endpoints, and phishing domains are masked for safe screen sharing.
            </Text>
          </div>
        </div>
      )}

      {/* Firewall Blocklist Exports + Instant IOC Verifier */}
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <Globe size={14} color="#66efab" />
            Live IOC Reputation & Firewall Blocklist Exports
          </span>
          <div className="abw-flex-wrap" style={{ gap: 6 }}>
            <Button
              label="EDL (.txt)"
              size="sm"
              variant="secondary"
              icon={<Download size={12} />}
              onClick={() => void api.exportIocs('edl')}
            />
            <Button
              label="nftables"
              size="sm"
              variant="secondary"
              icon={<Download size={12} />}
              onClick={() => void api.exportIocs('nftables')}
            />
            <Button
              label="pf Table"
              size="sm"
              variant="secondary"
              icon={<Download size={12} />}
              onClick={() => void api.exportIocs('pf')}
            />
            <Button
              label="CSV"
              size="sm"
              variant="secondary"
              icon={<Download size={12} />}
              onClick={() => void api.exportIocs('csv')}
            />
          </div>
        </div>
        <div className="abw-panel-body">
          <Text type="supporting" size="sm">
            Check any IPv4 address, hostname, defanged IOC, or domain against SANS ISC Top Attackers, abuse.ch Feodo Botnet C2s, OpenPhish, and Emerging Threats Compromised IPs ({telemetry.compromised_ips_total_count.toLocaleString()} hosts).
          </Text>

          <div className="abw-flex-wrap" style={{ gap: 8 }}>
            <div style={{ flex: '1 1 320px' }}>
              <TextInput
                label="IOC lookup"
                isLabelHidden
                value={iocQuery}
                onChange={setIocQuery}
                onEnter={() => void runLookup()}
                placeholder="Enter IP (e.g. 198.51.100.14 or 198.51.100[.]14) or domain..."
                startIcon={<Search size={14} />}
                hasClear
                width="100%"
              />
            </div>
            <Button
              label="Verify IOC"
              variant="primary"
              isLoading={checking}
              onClick={() => void runLookup()}
            />
            {telemetry.top_attacking_ips[0] && (
              <Button
                label={`Sample Top Attacker (${displayIp(telemetry.top_attacking_ips[0].ip)})`}
                variant="secondary"
                size="sm"
                onClick={() => {
                  const sample = telemetry.top_attacking_ips[0].ip;
                  setIocQuery(opsecMode ? redactIp(sample) : sample);
                  void runLookup(sample);
                }}
              />
            )}
          </div>

          {lookupResult && (
            <div
              className="abw-alert-bar"
              style={{
                borderColor: lookupResult.matched
                  ? 'rgba(239, 68, 68, 0.55)'
                  : 'rgba(102, 239, 171, 0.45)',
                borderLeftColor: lookupResult.matched ? '#ef4444' : '#66efab',
                background: lookupResult.matched
                  ? 'var(--soc-red-bg)'
                  : 'var(--soc-mint-soft)',
              }}
            >
              <div>
                <div className="abw-mono" style={{ fontWeight: 700, fontSize: 12.5, marginBottom: 3 }}>
                  {redactDisplayText(lookupResult.query, opsecMode)} — {lookupResult.risk_verdict}
                </div>
                <Text type="supporting" size="xsm">
                  {lookupResult.matched
                    ? redactDisplayText(
                        lookupResult.hits
                          .map((h) => `[${h.feed}] ${h.indicator_type}: ${h.detail}`)
                          .join(' | '),
                        opsecMode
                      )
                    : 'Indicator not present in active public blocklists or C2 sensors.'}
                </Text>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Bulk Batch IOC Lookup */}
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <ShieldAlert size={14} color="#38bdf8" />
            Bulk IOC Triage (Up to 200 IPs / Domains / Defanged URLs)
          </span>
          <div className="abw-flex-wrap" style={{ gap: 6 }}>
            {bulkResult && bulkResult.matched_count > 0 && (
              <Button
                label={copiedMsg ?? 'Copy Defanged Hits'}
                size="sm"
                variant="secondary"
                icon={<Copy size={12} />}
                onClick={() => void copyDefangedMatches()}
              />
            )}
            <Button
              label={bulkLoading ? 'Checking...' : 'Check Batch'}
              size="sm"
              variant="primary"
              isLoading={bulkLoading}
              onClick={() => void runBulkLookup()}
            />
          </div>
        </div>
        <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <textarea
            rows={3}
            value={bulkInput}
            onChange={(e) => setBulkInput(e.target.value)}
            placeholder="Paste firewall log IPs, domains, or defanged URLs (one per line or comma-separated)..."
            style={{
              width: '100%',
              background: 'var(--soc-surface)',
              border: '1px solid var(--soc-border)',
              color: 'var(--soc-text)',
              padding: 8,
              fontFamily: 'ui-monospace, monospace',
              fontSize: 12,
            }}
          />
          {bulkResult && (
            <div>
              <div className="abw-flex-wrap" style={{ marginBottom: 8 }}>
                <Badge variant="info" label={`Checked ${bulkResult.checked}`} />
                <Badge
                  variant={bulkResult.matched_count > 0 ? 'error' : 'success'}
                  label={`${bulkResult.matched_count} Malicious Hits`}
                />
              </div>
              {bulkResult.results.filter((r) => r.matched).length > 0 && (
                <div className="abw-table-wrap" style={{ maxHeight: 200, overflowY: 'auto' }}>
                  <table className="abw-table">
                    <thead>
                      <tr>
                        <th>Indicator (Defanged)</th>
                        <th>Verdict</th>
                        <th>Sensor Matches</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bulkResult.results
                        .filter((r) => r.matched)
                        .map((r) => (
                          <tr key={r.query}>
                            <td className="abw-mono">
                              {opsecMode
                                ? redactDisplayText(r.query, true)
                                : r.query.includes('://')
                                  ? defangUrl(r.query)
                                  : defangIp(r.query)}
                            </td>
                            <td>
                              <Badge variant="error" label="FLAGGED" />
                            </td>
                            <td style={{ fontSize: 12 }}>
                              {redactDisplayText(
                                r.hits.map((h) => `[${h.feed}] ${h.detail}`).join('; '),
                                opsecMode
                              )}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </section>

      {/* Top Row: Feodo Botnet C2s + SANS Top Attackers */}
      <div className="abw-grid-2">
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              abuse.ch Feodo Botnet C2 Servers ({telemetry.botnet_c2s.length})
            </span>
            <Badge variant="error" label="ACTIVE C2" />
          </div>
          <div className="abw-table-wrap" style={{ maxHeight: 340, overflowY: 'auto' }}>
            <table className="abw-table">
              <thead>
                <tr>
                  <th>IP : Port</th>
                  <th>Malware</th>
                  <th>Country / ASN</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {telemetry.botnet_c2s.slice(0, 40).map((c2) => (
                  <tr key={`${c2.ip_address}:${c2.port}`}>
                    <td className="abw-mono">
                      {displayIp(c2.ip_address)}:{c2.port}
                    </td>
                    <td>
                      <Badge variant="purple" label={c2.malware} />
                    </td>
                    <td>
                      <Text size="xsm">
                        {c2.country ?? '--'} {c2.as_name ? `· ${c2.as_name}` : ''}
                      </Text>
                    </td>
                    <td>
                      <Badge
                        variant={c2.status === 'online' ? 'error' : 'neutral'}
                        label={c2.status}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              SANS ISC Top Attacking Source IPs ({telemetry.top_attacking_ips.length})
            </span>
            <Badge variant="orange" label="HONEYPOT SENSORS" />
          </div>
          <div className="abw-table-wrap" style={{ maxHeight: 340, overflowY: 'auto' }}>
            <table className="abw-table">
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Attacks</th>
                  <th>Packets</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {telemetry.top_attacking_ips.map((ip) => (
                  <tr
                    key={ip.ip}
                    className="clickable"
                    onClick={() => {
                      setIocQuery(opsecMode ? redactIp(ip.ip) : ip.ip);
                      void runLookup(ip.ip);
                    }}
                  >
                    <td className="abw-mono">{displayIp(ip.ip)}</td>
                    <td className="abw-mono">{ip.attacks.toLocaleString()}</td>
                    <td className="abw-mono">{ip.count.toLocaleString()}</td>
                    <td className="abw-mono">{ip.last_seen}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {/* Bottom Row: OpenPhish (Defanged, Non-Clickable) + FIRST Global High EPSS */}
      <div className="abw-grid-2">
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">OpenPhish Live Phishing Campaigns (Defanged)</span>
            <Badge variant="warning" label={`${telemetry.phishing_total_count} ACTIVE URLS`} />
          </div>
          <div className="abw-scroll-list" style={{ maxHeight: 320 }}>
            {telemetry.phishing_urls.slice(0, 35).map((p, idx) => (
              <div key={idx} className="abw-list-row">
                <div className="abw-flex-wrap" style={{ justifyContent: 'space-between' }}>
                  <div className="abw-flex-wrap">
                    <strong className="abw-mono" style={{ fontSize: 12 }}>
                      {opsecMode ? redactHostname(p.domain) : defangIp(p.domain)}
                    </strong>
                    {p.suspected_brand && <Badge variant="orange" label={p.suspected_brand} />}
                  </div>
                  <Button
                    label="Copy"
                    size="sm"
                    variant="secondary"
                    onClick={() => void navigator.clipboard.writeText(defangUrl(p.url)).catch(() => {})}
                  />
                </div>
                <Text type="code" size="xsm" color="secondary" maxLines={1}>
                  {opsecMode ? redactUrl(p.url, true) : defangUrl(p.url)}
                </Text>
              </div>
            ))}
          </div>
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              FIRST.org Top Global EPSS Exploitation Probabilities
            </span>
            <Badge variant="cyan" label="EPSS v4" />
          </div>
          <div className="abw-table-wrap" style={{ maxHeight: 300, overflowY: 'auto' }}>
            <table className="abw-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>30d Exploit Prob</th>
                  <th>Percentile</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {telemetry.top_epss_global.map((e) => (
                  <tr
                    key={e.cve}
                    className="clickable"
                    onClick={() => onSelectVulnId(e.cve)}
                  >
                    <td className="abw-mono" style={{ fontWeight: 600 }}>
                      {e.cve}
                    </td>
                    <td className="abw-mono">{(e.epss * 100).toFixed(2)}%</td>
                    <td className="abw-mono">{(e.percentile * 100).toFixed(1)}th</td>
                    <td className="abw-mono">{e.date}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ padding: '10px 14px', borderTop: '1px solid var(--soc-border)' }}>
            <Text type="supporting" size="xsm" display="block">
              Emerging Threats Blocklist:{' '}
              <strong>{telemetry.compromised_ips_total_count.toLocaleString()}</strong> compromised IPv4 addresses indexed locally for zero-latency IOC matching.
            </Text>
          </div>
        </section>
      </div>
    </div>
  );
}
