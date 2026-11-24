import { useRef, useState } from 'react';
import { useToast } from '@astryxdesign/core';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Spinner } from '@astryxdesign/core/Spinner';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import {
  AlertTriangle,
  Bot,
  Copy,
  Download,
  ExternalLink,
  EyeOff,
  FileCode2,
  Filter,
  Globe,
  Network,
  RefreshCw,
  Search,
  ShieldAlert,
  Sparkles,
  Trash2,
  Upload,
} from 'lucide-react';
import { api, safeExternalUrl, severityBadgeVariant } from '../api';
import type {
  BulkIocResponse,
  CtiEnrichmentResponse,
  IocLookupResult,
  NavTab,
  NetworkTelemetry,
  PcapAnalysisReport,
} from '../types';
import {
  defangIp,
  defangUrl,
  redactDisplayText,
  redactHostname,
  redactIp,
  redactUrl,
  redactWiresharkFilter,
} from '../utils/opsec';
import { A2uiRenderer } from './A2uiRenderer';

interface NetworkIocViewProps {
  telemetry: NetworkTelemetry;
  opsecMode: boolean;
  readOnly?: boolean;
  onSelectVulnId: (id: string) => void;
  onNavigate?: (tab: NavTab) => void;
  onAskAnalyst?: (prompt: string) => void;
}

const MAX_PCAP_BYTES = 25 * 1024 * 1024;

export function NetworkIocView({
  telemetry,
  opsecMode,
  readOnly = false,
  onSelectVulnId,
  onNavigate,
  onAskAnalyst,
}: NetworkIocViewProps) {
  const toast = useToast();
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [iocQuery, setIocQuery] = useState('');
  const [lookupResult, setLookupResult] = useState<IocLookupResult | null>(null);
  const [checking, setChecking] = useState(false);

  const [ctiResult, setCtiResult] = useState<CtiEnrichmentResponse | null>(null);
  const [ctiLoading, setCtiLoading] = useState(false);
  const [ctiError, setCtiError] = useState<string | null>(null);
  const ctiPanelRef = useRef<HTMLDivElement | null>(null);

  const [bulkInput, setBulkInput] = useState('');
  const [bulkResult, setBulkResult] = useState<BulkIocResponse | null>(null);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [copiedMsg, setCopiedMsg] = useState<string | null>(null);

  const [pcapReport, setPcapReport] = useState<PcapAnalysisReport | null>(null);
  const [pcapLoading, setPcapLoading] = useState(false);
  const [pcapError, setPcapError] = useState<string | null>(null);
  const [draggingPcap, setDraggingPcap] = useState(false);

  const notify = (body: string, isError = false) => {
    toast({ type: isError ? 'error' : 'info', body });
  };

  const copyFilterText = async (rawFilter: string, label = 'Wireshark display filter') => {
    const text = opsecMode ? redactWiresharkFilter(rawFilter, true) : rawFilter;
    try {
      await navigator.clipboard.writeText(text);
      notify(`Copied ${label} to clipboard`);
    } catch {
      notify('Clipboard unavailable in this browser context', true);
    }
  };

  const copyLiveWiresharkFilter = async () => {
    try {
      const res = await api.getWiresharkFilter();
      await copyFilterText(
        res.filter,
        `live Wireshark filter (${res.c2_count} C2s + ${res.attacker_count} attackers)`
      );
    } catch (err) {
      notify(err instanceof Error ? err.message : String(err), true);
    }
  };

  const handlePcapFile = async (file: File) => {
    if (readOnly) {
      setPcapError('Read-only Wallboard Mode is active; PCAP upload is disabled.');
      return;
    }
    if (file.size > MAX_PCAP_BYTES) {
      setPcapError(`File "${file.name}" exceeds the 25 MB local triage limit.`);
      return;
    }
    setPcapLoading(true);
    setPcapError(null);
    try {
      const report = await api.analyzePcapFile(file);
      setPcapReport(report);
      notify(
        `Parsed ${report.packets_parsed.toLocaleString()} ${report.format} packets (${report.malicious_hits.length} IOC hits)`
      );
    } catch (err) {
      setPcapError(err instanceof Error ? err.message : String(err));
    } finally {
      setPcapLoading(false);
    }
  };

  const runSamplePcap = async () => {
    if (readOnly || pcapLoading) return;
    setPcapLoading(true);
    setPcapError(null);
    try {
      const report = await api.analyzePcapSample();
      setPcapReport(report);
      notify(
        `Analyzed sample capture (${report.packets_parsed} packets · ${report.malicious_hits.length} IOC hits · ${report.anomalies.length} anomalies)`
      );
    } catch (err) {
      setPcapError(err instanceof Error ? err.message : String(err));
    } finally {
      setPcapLoading(false);
    }
  };

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

  const runCtiEnrich = async (override?: string, forceRefresh = false) => {
    const q = (override ?? iocQuery).trim();
    if (!q || ctiLoading || readOnly) return;
    if (override) {
      setIocQuery(
        opsecMode
          ? /^\d{1,3}(\.\d{1,3}){3}$/.test(override)
            ? redactIp(override)
            : redactHostname(override)
          : override
      );
    }
    setCtiLoading(true);
    setCtiError(null);
    try {
      const res = await api.enrichIndicator(q, forceRefresh);
      setCtiResult(res);
      notify(
        `${res.overall_verdict}: ${res.findings.length} provider finding(s)${res.cached ? ' (SQLite 24h cache)' : ''}`
      );
      setTimeout(() => {
        ctiPanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 60);
    } catch (err) {
      setCtiError(err instanceof Error ? err.message : String(err));
      setCtiResult(null);
      setTimeout(() => {
        ctiPanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 60);
    } finally {
      setCtiLoading(false);
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
  const displayHost = (host: string) => (opsecMode ? redactHostname(host) : host);
  const displayFilter = (expr: string) => (opsecMode ? redactWiresharkFilter(expr, true) : expr);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {opsecMode && (
        <div
          className="abw-alert-bar"
          style={{ borderLeftColor: '#66efab', background: 'var(--soc-mint-soft)' }}
        >
          <div className="abw-flex-wrap">
            <EyeOff size={15} color="#66efab" />
            <Text size="sm" weight="semibold">
              OPSEC Redact Mode Active: Public attacker IPs, C2 endpoints, extracted PCAP hosts, and Wireshark filters are masked for safe screen sharing.
            </Text>
          </div>
        </div>
      )}

      {/* Firewall Blocklist & Wireshark Display Filter Exports + Instant IOC Verifier */}
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <Globe size={14} color="#66efab" />
            Live IOC Reputation, Firewall Blocklists &amp; Wireshark Filters
          </span>
          <div className="abw-flex-wrap" style={{ gap: 6 }}>
            <Button
              label="Copy WS Filter"
              size="sm"
              variant="primary"
              icon={<Filter size={12} />}
              onClick={() => void copyLiveWiresharkFilter()}
            />
            <Button
              label="Wireshark (.txt)"
              size="sm"
              variant="secondary"
              icon={<Download size={12} />}
              onClick={() => void api.exportIocs('wireshark')}
            />
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
            Check any IPv4 address, hostname, defanged IOC, or domain against SANS ISC Top Attackers, abuse.ch Feodo Botnet C2s, OpenPhish, and Emerging Threats Compromised IPs ({telemetry.compromised_ips_total_count.toLocaleString()} hosts), or export a ready-to-paste Wireshark display filter.
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
            <Button
              label="Enrich (OTX / GN / VT)"
              variant="secondary"
              icon={<Sparkles size={13} />}
              isLoading={ctiLoading}
              isDisabled={readOnly}
              onClick={() => void runCtiEnrich()}
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
              {lookupResult.matched && (
                <Button
                  label="Copy WS Filter"
                  size="sm"
                  variant="secondary"
                  icon={<Filter size={12} />}
                  onClick={() => {
                    const q = lookupResult.query.trim();
                    const expr = /^\d{1,3}(\.\d{1,3}){3}$/.test(q)
                      ? `ip.addr == ${q}`
                      : `dns.qry.name contains "${q}" || tls.handshake.extensions_server_name contains "${q}"`;
                    void copyFilterText(expr, `Wireshark filter for ${q}`);
                  }}
                />
              )}
            </div>
          )}

          {/* Optional BYO CTI On-Demand Enrichment Results (24h SQLite Cached) */}
          <div ref={ctiPanelRef}>
            {ctiError && (
              <div
                className="abw-alert-bar"
                style={{
                  borderColor: 'rgba(245, 158, 11, 0.5)',
                  borderLeftColor: '#f59e0b',
                  background: 'rgba(245, 158, 11, 0.08)',
                }}
              >
                <div style={{ flex: 1 }}>
                  <Text size="xsm" display="block">
                    {ctiError}
                  </Text>
                </div>
                {onNavigate && (
                  <Button
                    label="Configure OTX / GN / VT"
                    size="sm"
                    variant="secondary"
                    onClick={() => onNavigate('alerts')}
                  />
                )}
              </div>
            )}

            {ctiResult && (
              <section className="abw-a2ui-card" style={{ marginTop: 4 }}>
                <div className="abw-a2ui-card-head">
                  <div className="abw-flex-wrap">
                    <Sparkles size={13} color="#66efab" />
                    <span className="abw-a2ui-card-title">
                      BYO CTI Enrichment:{' '}
                      {opsecMode
                        ? ctiResult.indicator_type === 'ipv4' || ctiResult.indicator_type === 'ipv6'
                          ? redactIp(ctiResult.indicator)
                          : ctiResult.indicator_type === 'domain'
                            ? redactHostname(ctiResult.indicator)
                            : `${ctiResult.indicator.slice(0, 10)}••••`
                        : defangIp(ctiResult.indicator)}
                    </span>
                    <Badge
                      variant={
                        ctiResult.overall_verdict === 'MALICIOUS'
                          ? 'error'
                          : ctiResult.overall_verdict === 'SUSPICIOUS'
                            ? 'orange'
                            : ctiResult.overall_verdict.startsWith('BENIGN')
                              ? 'success'
                              : 'neutral'
                      }
                      label={ctiResult.overall_verdict}
                    />
                    <Badge
                      variant={ctiResult.cached ? 'cyan' : 'info'}
                      label={ctiResult.cached ? 'SQLITE CACHED (24H)' : 'LIVE LOOKUP · SAVED'}
                    />
                  </div>
                  <div className="abw-flex-wrap">
                    <Button
                      label="Force Refresh"
                      size="sm"
                      variant="secondary"
                      icon={<RefreshCw size={11} />}
                      isLoading={ctiLoading}
                      isDisabled={readOnly}
                      onClick={() => void runCtiEnrich(ctiResult.indicator, true)}
                    />
                    <Button
                      label="Dismiss"
                      size="sm"
                      variant="ghost"
                      onClick={() => setCtiResult(null)}
                    />
                  </div>
                </div>
                <div className="abw-a2ui-news-grid">
                  {ctiResult.findings.map((f) => {
                    const safeRef = safeExternalUrl(f.reference_url);
                    return (
                      <div key={f.provider} className="abw-a2ui-news-item">
                        <div
                          className="abw-flex-wrap"
                          style={{ justifyContent: 'space-between', marginBottom: 4 }}
                        >
                          <strong style={{ fontSize: 12.5 }}>{f.provider_name}</strong>
                          <div className="abw-flex-wrap">
                            <Badge
                              variant={
                                f.verdict === 'MALICIOUS'
                                  ? 'error'
                                  : f.verdict === 'SUSPICIOUS'
                                    ? 'orange'
                                    : f.verdict === 'BENIGN'
                                      ? 'success'
                                      : f.verdict === 'ERROR'
                                        ? 'warning'
                                        : 'neutral'
                              }
                              label={f.verdict}
                            />
                            <Badge variant="neutral" label={`${f.latency_ms} ms`} />
                          </div>
                        </div>
                        <Text type="supporting" size="xsm" display="block" style={{ marginBottom: 6 }}>
                          {redactDisplayText(f.summary, opsecMode)}
                        </Text>
                        <div
                          className="abw-flex-wrap"
                          style={{ justifyContent: 'space-between', marginTop: 'auto' }}
                        >
                          <div className="abw-flex-wrap">
                            {f.tags.slice(0, 4).map((t) => (
                              <Badge key={t} variant="info" label={t} />
                            ))}
                          </div>
                          {safeRef && !opsecMode && (
                            <a
                              href={safeRef}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="abw-a2ui-ext-link"
                            >
                              Report <ExternalLink size={11} />
                            </a>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}
          </div>
        </div>
      </section>

      {/* Wireshark Offline PCAP / PCAPNG Threat Triage */}
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <Network size={14} color="#38bdf8" />
            Wireshark Offline .pcap / .pcapng Threat Triage
          </span>
          <div className="abw-flex-wrap" style={{ gap: 6 }}>
            <Badge variant="success" label="PURE RUST · ZERO TSHARK" />
            <Badge variant="cyan" label="RAM-ONLY · MAX 25 MB" />
            {pcapReport && (
              <Button
                label="Clear"
                size="sm"
                variant="secondary"
                icon={<Trash2 size={12} />}
                onClick={() => {
                  setPcapReport(null);
                  setPcapError(null);
                }}
              />
            )}
          </div>
        </div>
        <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div
            className="abw-pcap-dropzone"
            data-dragging={draggingPcap}
            onDragOver={(e) => {
              e.preventDefault();
              if (!readOnly) setDraggingPcap(true);
            }}
            onDragLeave={() => setDraggingPcap(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDraggingPcap(false);
              const file = e.dataTransfer.files?.[0];
              if (file) void handlePcapFile(file);
            }}
          >
            <div style={{ flex: '1 1 340px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 3 }}>
                Drop a Wireshark <code>.pcap</code> or <code>.pcapng</code> capture here for instant local CTI correlation
              </div>
              <Text type="supporting" size="xsm" display="block">
                Extracts external IPs, TCP/UDP ports, DNS queries, TLS ClientHello SNIs, and cleartext HTTP hosts strictly in memory — correlates against Feodo C2s, SANS Attackers, Emerging Threats &amp; OpenPhish, and generates ready-to-paste Wireshark display filters.
              </Text>
            </div>
            <div className="abw-flex-wrap" style={{ gap: 8 }}>
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                style={{ display: 'none' }}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  e.target.value = '';
                  if (file) void handlePcapFile(file);
                }}
              />
              <Button
                label="Choose .pcap / .pcapng"
                size="sm"
                variant="primary"
                icon={<Upload size={12} />}
                isLoading={pcapLoading}
                isDisabled={readOnly}
                onClick={() => fileInputRef.current?.click()}
              />
              <Button
                label="Run Sample Capture"
                size="sm"
                variant="secondary"
                icon={<FileCode2 size={12} />}
                isLoading={pcapLoading}
                isDisabled={readOnly}
                onClick={() => void runSamplePcap()}
              />
            </div>
          </div>

          {pcapLoading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Spinner />
              <Text size="sm">
                Parsing capture frames in Rust, extracting DNS/TLS SNI/HTTP indicators, and correlating live threat feeds...
              </Text>
            </div>
          )}

          {pcapError && (
            <div className="abw-alert-bar" role="alert">
              <Text size="sm">{pcapError}</Text>
            </div>
          )}

          {pcapReport && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* A2UI 1.0 Interactive PCAP Incident Surface */}
              {pcapReport.a2ui && (
                <A2uiRenderer
                  surface={pcapReport.a2ui}
                  opsecMode={opsecMode}
                  readOnly={readOnly}
                  onOpenCve={onSelectVulnId}
                  onNavigate={onNavigate}
                  onNotify={(msg, tone) => notify(msg, tone === 'error')}
                />
              )}

              {/* Master Wireshark Display Filter Bar + AI Threat Analyst Handoff */}
              <div className="abw-ws-filter-bar">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: '1 1 360px', minWidth: 0 }}>
                  <span
                    className="abw-mono"
                    style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#94a3b8' }}
                  >
                    WIRESHARK DISPLAY FILTER (PASTE INTO WIRESHARK FILTER BAR)
                  </span>
                  <code className="abw-ws-filter-code">
                    {displayFilter(pcapReport.master_wireshark_filter)}
                  </code>
                </div>
                <div className="abw-flex-wrap" style={{ gap: 6 }}>
                  <Button
                    label="Copy WS Filter"
                    size="sm"
                    variant="primary"
                    icon={<Copy size={12} />}
                    onClick={() =>
                      void copyFilterText(
                        pcapReport.master_wireshark_filter,
                        'master Wireshark display filter'
                      )
                    }
                  />
                  {onAskAnalyst && (
                    <Button
                      label="Analyze PCAP with AI Analyst"
                      size="sm"
                      variant="secondary"
                      icon={<Bot size={12} />}
                      isDisabled={readOnly}
                      onClick={() =>
                        onAskAnalyst(
                          opsecMode
                            ? redactDisplayText(pcapReport.ai_prompt_summary, true)
                            : pcapReport.ai_prompt_summary
                        )
                      }
                    />
                  )}
                </div>
              </div>

              {/* Flagged Threat-Feed IOC Matches */}
              {pcapReport.malicious_hits.length > 0 && (
                <section className="abw-a2ui-card">
                  <div className="abw-a2ui-card-head">
                    <span className="abw-a2ui-card-title">
                      <ShieldAlert size={13} color="#ef4444" />
                      Flagged Malicious Indicators in Capture ({pcapReport.malicious_hits.length})
                    </span>
                    <Badge variant="error" label="LIVE FEED MATCH" />
                  </div>
                  <div style={{ overflowX: 'auto' }}>
                    <table className="abw-a2ui-table">
                      <thead>
                        <tr>
                          <th>Indicator</th>
                          <th>Severity / Type</th>
                          <th>Matched Feeds &amp; Context</th>
                          <th>Packets / Ports</th>
                          <th style={{ textAlign: 'right' }}>Wireshark</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pcapReport.malicious_hits.map((hit, idx) => (
                          <tr key={`${hit.indicator}-${idx}`}>
                            <td className="abw-mono" style={{ fontWeight: 700 }}>
                              {opsecMode
                                ? /^\d{1,3}(\.\d{1,3}){3}$/.test(hit.indicator) ||
                                  hit.indicator.includes(':')
                                  ? redactIp(hit.indicator)
                                  : redactHostname(hit.indicator)
                                : defangIp(hit.indicator)}
                            </td>
                            <td>
                              <div className="abw-flex-wrap">
                                <Badge variant={severityBadgeVariant(hit.severity)} label={hit.severity} />
                                <Badge variant="purple" label={hit.indicator_type} />
                              </div>
                            </td>
                            <td style={{ fontSize: 12 }}>
                              <div style={{ fontWeight: 600 }}>{hit.feeds.join(', ')}</div>
                              <div style={{ color: 'var(--soc-text-muted)', fontSize: 11.5 }}>
                                {redactDisplayText(hit.detail, opsecMode)}
                              </div>
                            </td>
                            <td className="abw-mono" style={{ fontSize: 11.5 }}>
                              <div>{hit.packets.toLocaleString()} pkts</div>
                              {hit.ports.length > 0 && (
                                <div style={{ color: 'var(--soc-text-muted)' }}>
                                  ports: {hit.ports.slice(0, 5).join(', ')}
                                </div>
                              )}
                            </td>
                            <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                              <div className="abw-flex-wrap" style={{ justifyContent: 'flex-end' }}>
                                <Button
                                  label="Enrich"
                                  size="sm"
                                  variant="secondary"
                                  icon={<Sparkles size={11} />}
                                  isDisabled={readOnly || ctiLoading}
                                  onClick={() => void runCtiEnrich(hit.indicator)}
                                />
                                <Button
                                  label="Copy Filter"
                                  size="sm"
                                  variant="secondary"
                                  icon={<Filter size={11} />}
                                  onClick={() =>
                                    void copyFilterText(
                                      hit.wireshark_filter,
                                      `Wireshark filter for ${hit.indicator}`
                                    )
                                  }
                                />
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}

              {/* Behavioral Anomalies */}
              {pcapReport.anomalies.length > 0 && (
                <section className="abw-a2ui-card">
                  <div className="abw-a2ui-card-head">
                    <span className="abw-a2ui-card-title">
                      <AlertTriangle size={13} color="#f97316" />
                      Behavioral Anomalies &amp; Heuristics ({pcapReport.anomalies.length})
                    </span>
                    <Badge variant="orange" label="PACKET HEURISTICS" />
                  </div>
                  <div className="abw-a2ui-card-body" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {pcapReport.anomalies.map((anom, idx) => (
                      <div key={`${anom.kind}-${idx}`} className="abw-a2ui-step">
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div className="abw-flex-wrap" style={{ marginBottom: 3 }}>
                            <Badge variant={severityBadgeVariant(anom.severity)} label={anom.severity} />
                            <Badge variant="neutral" label={anom.kind} />
                            <strong style={{ fontSize: 12.5 }}>
                              {redactDisplayText(anom.title, opsecMode)}
                            </strong>
                          </div>
                          <Text type="supporting" size="xsm" display="block">
                            {redactDisplayText(anom.detail, opsecMode)}
                          </Text>
                        </div>
                        <Button
                          label="Copy Filter"
                          size="sm"
                          variant="secondary"
                          icon={<Filter size={11} />}
                          onClick={() =>
                            void copyFilterText(anom.wireshark_filter, `${anom.kind} filter`)
                          }
                        />
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Extracted DNS / TLS SNI / HTTP Hosts + Top External Talkers */}
              <div className="abw-grid-2">
                <section className="abw-a2ui-card">
                  <div className="abw-a2ui-card-head">
                    <span className="abw-a2ui-card-title">
                      Observed DNS / TLS SNI / HTTP Hosts ({pcapReport.observed_hosts.length})
                    </span>
                  </div>
                  <div style={{ maxHeight: 240, overflowY: 'auto' }}>
                    {pcapReport.observed_hosts.length > 0 ? (
                      <table className="abw-a2ui-table">
                        <thead>
                          <tr>
                            <th>Hostname</th>
                            <th>Source</th>
                            <th>Hits</th>
                            <th style={{ textAlign: 'right' }}>Filter</th>
                          </tr>
                        </thead>
                        <tbody>
                          {pcapReport.observed_hosts.map((h) => (
                            <tr key={h.host}>
                              <td className="abw-mono" style={{ fontSize: 11.5, wordBreak: 'break-all' }}>
                                <div>{displayHost(h.host)}</div>
                                {h.is_flagged && <Badge variant="error" label="FLAGGED" />}
                                {!h.is_flagged && h.suspicious_reason && (
                                  <Badge variant="warning" label="SUSPECT" />
                                )}
                              </td>
                              <td>
                                <Badge variant="cyan" label={h.kind} />
                              </td>
                              <td className="abw-mono" style={{ fontSize: 11.5 }}>
                                {h.count}
                              </td>
                              <td style={{ textAlign: 'right' }}>
                                <Button
                                  label="WS"
                                  size="sm"
                                  variant="secondary"
                                  icon={<Filter size={10} />}
                                  onClick={() =>
                                    void copyFilterText(h.wireshark_filter, `filter for ${h.host}`)
                                  }
                                />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div className="abw-a2ui-card-body">
                        <Text type="supporting" size="xsm">
                          No DNS queries, TLS SNI extensions, or cleartext HTTP Host headers found in capture.
                        </Text>
                      </div>
                    )}
                  </div>
                </section>

                <section className="abw-a2ui-card">
                  <div className="abw-a2ui-card-head">
                    <span className="abw-a2ui-card-title">
                      Top External Talkers ({pcapReport.top_external_ips.length})
                    </span>
                  </div>
                  <div style={{ maxHeight: 240, overflowY: 'auto' }}>
                    {pcapReport.top_external_ips.length > 0 ? (
                      <table className="abw-a2ui-table">
                        <thead>
                          <tr>
                            <th>External IP</th>
                            <th>Packets</th>
                            <th>Ports</th>
                            <th style={{ textAlign: 'right' }}>Filter</th>
                          </tr>
                        </thead>
                        <tbody>
                          {pcapReport.top_external_ips.map((ep) => (
                            <tr key={ep.ip}>
                              <td className="abw-mono" style={{ fontSize: 11.5 }}>
                                <div className="abw-flex-wrap">
                                  <span>{displayIp(ep.ip)}</span>
                                  {ep.is_flagged && <Badge variant="error" label="FLAGGED" />}
                                </div>
                              </td>
                              <td className="abw-mono" style={{ fontSize: 11.5 }}>
                                {ep.packets.toLocaleString()}
                              </td>
                              <td className="abw-mono" style={{ fontSize: 11, color: 'var(--soc-text-muted)' }}>
                                {ep.ports.slice(0, 4).join(', ') || '—'}
                              </td>
                              <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                <div className="abw-flex-wrap" style={{ justifyContent: 'flex-end' }}>
                                  <Button
                                    label="Enrich"
                                    size="sm"
                                    variant="secondary"
                                    icon={<Sparkles size={10} />}
                                    isDisabled={readOnly || ctiLoading}
                                    onClick={() => void runCtiEnrich(ep.ip)}
                                  />
                                  <Button
                                    label="WS"
                                    size="sm"
                                    variant="secondary"
                                    icon={<Filter size={10} />}
                                    onClick={() =>
                                      void copyFilterText(ep.wireshark_filter, `filter for ${ep.ip}`)
                                    }
                                  />
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div className="abw-a2ui-card-body">
                        <Text type="supporting" size="xsm">
                          Only internal/RFC1918 traffic observed in this capture.
                        </Text>
                      </div>
                    )}
                  </div>
                </section>
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
                  <th style={{ textAlign: 'right' }}>WS Filter</th>
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
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <div className="abw-flex-wrap" style={{ justifyContent: 'flex-end' }}>
                        <Button
                          label="Enrich"
                          size="sm"
                          variant="secondary"
                          icon={<Sparkles size={10} />}
                          isDisabled={readOnly || ctiLoading}
                          onClick={() => void runCtiEnrich(c2.ip_address)}
                        />
                        <Button
                          label="WS"
                          size="sm"
                          variant="secondary"
                          icon={<Filter size={10} />}
                          onClick={() =>
                            void copyFilterText(
                              `ip.addr == ${c2.ip_address} && tcp.port == ${c2.port}`,
                              `C2 Wireshark filter (${c2.malware})`
                            )
                          }
                        />
                      </div>
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
                    onClick={() =>
                      void navigator.clipboard.writeText(defangUrl(p.url)).catch(() => {})
                    }
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
