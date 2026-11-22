import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Markdown } from '@astryxdesign/core/Markdown';
import { ProgressBar } from '@astryxdesign/core/ProgressBar';
import { Text } from '@astryxdesign/core/Text';
import { Timestamp } from '@astryxdesign/core/Timestamp';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  ExternalLink,
  Flame,
  Globe,
  Layers,
  Newspaper,
  ShieldAlert,
  Sparkles,
  TrendingUp,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from 'recharts';
import { api, safeExternalUrl, severityBadgeVariant } from '../api';
import type { DashboardPayload, NavTab, ThreatAlert, Vulnerability } from '../types';
import { redactDisplayText, sanitizeMarkdownClient } from '../utils/opsec';

interface OverviewViewProps {
  data: DashboardPayload;
  opsecMode: boolean;
  readOnly: boolean;
  onSelectVuln: (v: Vulnerability) => void;
  onSelectVulnId: (id: string) => void;
  onAckAlert: (id: string) => void;
  onDeltaReviewed: () => void;
  onNavigate: (tab: NavTab) => void;
}

function scoreClass(score: number): string {
  if (score >= 85) return 'abw-score-badge abw-score-crit';
  if (score >= 70) return 'abw-score-badge abw-score-high';
  if (score >= 45) return 'abw-score-badge abw-score-med';
  return 'abw-score-badge abw-score-low';
}

const CHART_TOOLTIP_STYLE = {
  background: '#0b0e13',
  border: '1px solid #2b3545',
  borderRadius: 0,
  fontSize: 12,
  fontFamily: 'ui-monospace, monospace',
};

export function OverviewView({
  data,
  opsecMode,
  readOnly,
  onSelectVuln,
  onSelectVulnId,
  onAckAlert,
  onDeltaReviewed,
  onNavigate,
}: OverviewViewProps) {
  const {
    ai_brief: brief,
    kpis,
    top_vulnerabilities,
    recent_news,
    telemetry,
    alerts,
    stack_summary,
    recent_epss_spikes,
    latest_delta,
  } = data;
  const activeAlert: ThreatAlert | undefined = alerts.find((a) => !a.acknowledged);

  const scatterData = top_vulnerabilities
    .filter((v) => v.cvss_score != null || v.epss_score != null)
    .slice(0, 35)
    .map((v) => ({
      id: v.id,
      cvss: Number((v.cvss_score ?? (v.severity === 'CRITICAL' ? 9.2 : 7.5)).toFixed(1)),
      epssPct: Number(((v.epss_score ?? 0.05) * 100).toFixed(1)),
      risk: v.ai_risk_score,
      isKev: v.is_kev,
      vendor: v.vendor ?? v.product ?? v.ecosystem ?? 'Advisory',
      vuln: v,
    }));

  const portChartData = telemetry.top_attacked_ports.slice(0, 8).map((p) => ({
    name: `${p.port}/${p.service_name}`,
    records: p.records,
    sources: p.sources,
  }));

  const vendorChartData = brief.top_targeted_vendors.slice(0, 7).map((v) => ({
    name: v.label.length > 16 ? `${v.label.slice(0, 15)}…` : v.label,
    fullName: v.label,
    count: v.count,
  }));

  const maxTacticCount = Math.max(1, ...brief.top_mitre_tactics.map((t) => t.count));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {activeAlert && (
        <div className="abw-alert-bar" role="alert">
          <div className="abw-alert-bar-body">
            <AlertTriangle size={16} color="#ef4444" style={{ marginTop: 2, flexShrink: 0 }} />
            <div style={{ minWidth: 0 }}>
              <div className="abw-flex-wrap" style={{ marginBottom: 3 }}>
                <Badge variant={severityBadgeVariant(activeAlert.severity)} label={activeAlert.severity} />
                <strong style={{ fontSize: 13 }}>{redactDisplayText(activeAlert.title, opsecMode)}</strong>
              </div>
              <Text type="supporting" size="xsm" display="block">
                {redactDisplayText(activeAlert.summary, opsecMode)} ({activeAlert.matched_reasons.join(' · ')})
              </Text>
            </div>
          </div>
          <div className="abw-flex-wrap">
            {activeAlert.cve_ids[0] && (
              <Button
                label="Inspect"
                size="sm"
                variant="primary"
                onClick={() => onSelectVulnId(activeAlert.cve_ids[0])}
              />
            )}
            <Button
              label="Acknowledge"
              size="sm"
              variant="secondary"
              icon={<Check size={13} />}
              isDisabled={readOnly}
              onClick={() => onAckAlert(activeAlert.id)}
            />
          </div>
        </div>
      )}

      {/* Exposed in Your Stack Banner */}
      {stack_summary?.configured && stack_summary.matched_vuln_count > 0 && (
        <div
          className="abw-alert-bar"
          style={{
            borderColor: 'rgba(249, 115, 22, 0.55)',
            borderLeftColor: '#f97316',
            background: 'rgba(249, 115, 22, 0.08)',
          }}
        >
          <div className="abw-alert-bar-body">
            <Layers size={16} color="#f97316" style={{ marginTop: 2, flexShrink: 0 }} />
            <div style={{ minWidth: 0 }}>
              <div className="abw-flex-wrap" style={{ marginBottom: 4 }}>
                <Badge variant="orange" label="MY STACK EXPOSURE" />
                <strong style={{ fontSize: 13 }}>
                  {stack_summary.matched_vuln_count} tracked CVEs ({stack_summary.matched_kev_count} CISA KEV) match your local SBOM / watchlist
                </strong>
              </div>
              <div className="abw-flex-wrap" style={{ gap: 6 }}>
                {stack_summary.top_matched_cves.slice(0, 6).map((cve) => (
                  <button
                    key={cve}
                    type="button"
                    className="abw-cve-chip"
                    onClick={() => onSelectVulnId(cve)}
                  >
                    {cve}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <Button
            label="Open My Stack"
            size="sm"
            variant="secondary"
            onClick={() => onNavigate('mystack')}
          />
        </div>
      )}

      {/* What Changed Since Last Sync & EPSS 24h Surges */}
      {(recent_epss_spikes.length > 0 || (latest_delta && !latest_delta.reviewed)) && (
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              <TrendingUp size={14} color="#f97316" />
              What Changed & Exploit Velocity Spikes
            </span>
            <div className="abw-flex-wrap" style={{ gap: 6 }}>
              {latest_delta && (
                <Badge
                  variant={latest_delta.reviewed ? 'neutral' : 'warning'}
                  label={
                    latest_delta.reviewed
                      ? 'Delta Reviewed'
                      : `${latest_delta.new_cves.length} New · ${latest_delta.new_kevs.length} KEV · ${latest_delta.epss_spikes.length} Spikes`
                  }
                />
              )}
              {latest_delta && !latest_delta.reviewed && (
                <Button
                  label="Mark Reviewed"
                  size="sm"
                  variant="secondary"
                  icon={<Check size={12} />}
                  isDisabled={readOnly}
                  onClick={() => void api.ackDelta().then(onDeltaReviewed)}
                />
              )}
            </div>
          </div>
          <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {recent_epss_spikes.length > 0 ? (
              <div className="abw-flex-wrap" style={{ gap: 6 }}>
                {recent_epss_spikes.slice(0, 6).map((spike) => (
                  <button
                    key={spike.cve_id}
                    type="button"
                    className="abw-cve-chip"
                    style={{ borderColor: 'rgba(249, 115, 22, 0.5)' }}
                    onClick={() => onSelectVulnId(spike.cve_id)}
                  >
                    <strong>{spike.cve_id}</strong> · {spike.current_epss_pct.toFixed(1)}% (+
                    {spike.delta_24h_pct.toFixed(1)}% 24h)
                    {spike.matched_stack.length > 0 ? ` [${spike.matched_stack[0]}]` : ''}
                  </button>
                ))}
              </div>
            ) : (
              <Text type="supporting" size="xsm">
                Latest sweep captured {latest_delta?.new_cves.length ?? 0} new CVEs,{' '}
                {latest_delta?.new_stack_hits.length ?? 0} My Stack matches, and{' '}
                {latest_delta?.new_alerts_count ?? 0} new watchlist alerts.
              </Text>
            )}
          </div>
        </section>
      )}

      {/* Unified 6-Column Seamless KPI Strip */}
      <div className="abw-kpi-strip">
        <div className="abw-kpi-cell accent-mint">
          <div className="abw-kpi-label-row">
            <span>AI Threat Index</span>
            <Activity size={13} color="#66efab" />
          </div>
          <div className="abw-kpi-value">{brief.global_threat_index}/100</div>
          <div className="abw-flex-wrap">
            <Badge
              variant={brief.global_threat_index >= 75 ? 'error' : 'warning'}
              label={brief.threat_level_label}
            />
            <span className="abw-kpi-sub">
              {kpis.feeds_ok}/{kpis.feeds_total} OK
            </span>
          </div>
        </div>

        <div className="abw-kpi-cell accent-red">
          <div className="abw-kpi-label-row">
            <span>Critical & High (7d)</span>
            <Flame size={13} color="#ef4444" />
          </div>
          <div className="abw-kpi-value">{kpis.critical_count_7d + kpis.high_count_7d}</div>
          <div className="abw-kpi-sub">
            {kpis.critical_count_7d} Crit · {kpis.total_vulnerabilities} total
          </div>
        </div>

        <div className="abw-kpi-cell accent-orange">
          <div className="abw-kpi-label-row">
            <span>CISA KEV Exploited</span>
            <ShieldAlert size={13} color="#f97316" />
          </div>
          <div className="abw-kpi-value">{kpis.kev_total_catalog.toLocaleString()}</div>
          <div className="abw-kpi-sub">{kpis.kev_added_7d} added past 7d</div>
        </div>

        <div className="abw-kpi-cell accent-amber">
          <div className="abw-kpi-label-row">
            <span>High-EPSS & AI CVEs</span>
            <Bot size={13} color="#f59e0b" />
          </div>
          <div className="abw-kpi-value">{kpis.high_epss_count}</div>
          <div className="abw-kpi-sub">
            Max {kpis.max_epss_pct.toFixed(0)}% · {kpis.ai_related_vulns} AI/ML
          </div>
        </div>

        <div className="abw-kpi-cell accent-cyan">
          <div className="abw-kpi-label-row">
            <span>News & Exploit Wire</span>
            <Newspaper size={13} color="#38bdf8" />
          </div>
          <div className="abw-kpi-value">{kpis.news_count_24h}</div>
          <div className="abw-kpi-sub">
            24h · {kpis.news_count_7d} 7d · {kpis.exploit_poc_count} PoCs
          </div>
        </div>

        <div className="abw-kpi-cell accent-mint">
          <div className="abw-kpi-label-row">
            <span>Live Network IOCs</span>
            <Globe size={13} color="#66efab" />
          </div>
          <div className="abw-kpi-value">
            {(kpis.botnet_c2_count + kpis.phishing_total_count).toLocaleString()}
          </div>
          <div className="abw-kpi-sub">
            {kpis.botnet_c2_count} C2s · {kpis.compromised_ips_count.toLocaleString()} Comp IPs
          </div>
        </div>
      </div>

      {/* AI Threat Posture Brief + MITRE Tactics */}
      <div className="abw-grid-asymmetric">
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              <Sparkles size={14} color="#66efab" />
              AI Threat Posture Briefing (Past 7 Days & 24h)
            </span>
            <Button
              label="Open AI Threat Analyst"
              size="sm"
              variant="secondary"
              onClick={() => onNavigate('analyst')}
            />
          </div>
          <div className="abw-panel-body">
            <Markdown density="compact">
              {sanitizeMarkdownClient(redactDisplayText(brief.executive_summary, opsecMode))}
            </Markdown>

            {brief.key_findings.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                <Text weight="semibold" size="xsm">
                  KEY INTELLIGENCE SIGNALS
                </Text>
                {brief.key_findings.map((finding, i) => (
                  <div
                    key={i}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 8,
                      fontSize: 12.5,
                      lineHeight: 1.45,
                    }}
                  >
                    <AlertTriangle size={13} color="#f59e0b" style={{ marginTop: 3, flexShrink: 0 }} />
                    <span>{finding}</span>
                  </div>
                ))}
              </div>
            )}

            {brief.remediation_priorities.length > 0 && (
              <div style={{ borderTop: '1px solid var(--soc-border)', paddingTop: 10 }}>
                <Text weight="semibold" size="xsm" display="block" style={{ marginBottom: 6 }}>
                  PRIORITIZED REMEDIATION QUEUE
                </Text>
                <div style={{ border: '1px solid var(--soc-border)' }}>
                  {brief.remediation_priorities.slice(0, 4).map((rem) => (
                    <div
                      key={rem.cve_id}
                      className="abw-list-row clickable"
                      style={{ padding: '7px 10px' }}
                      onClick={() => onSelectVulnId(rem.cve_id)}
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
                          <span className={scoreClass(rem.ai_risk_score)}>{rem.ai_risk_score}</span>
                          <strong className="abw-mono" style={{ fontSize: 12 }}>
                            {rem.cve_id}
                          </strong>
                          <Text size="sm" weight="medium">
                            {rem.vendor_product}
                          </Text>
                        </div>
                        <div className="abw-flex-wrap">
                          {rem.due_date && <Badge variant="warning" label={`Due ${rem.due_date}`} />}
                          <Badge
                            variant={rem.urgency === 'IMMEDIATE' ? 'error' : 'orange'}
                            label={rem.urgency}
                          />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">MITRE ATT&CK Tactics & Vectors (7d)</span>
          </div>
          <div className="abw-panel-body">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {brief.top_mitre_tactics.map((t) => (
                <ProgressBar
                  key={t.label}
                  label={t.label}
                  value={t.count}
                  max={maxTacticCount}
                  hasValueLabel
                  formatValueLabel={(v) => `${v} CVEs`}
                  variant={t.label.includes('Supply Chain') ? 'warning' : 'accent'}
                />
              ))}
            </div>

            <div style={{ borderTop: '1px solid var(--soc-border)', paddingTop: 10 }}>
              <Text weight="semibold" size="xsm" display="block" style={{ marginBottom: 8 }}>
                PRIMARY EXPLOITATION VECTORS
              </Text>
              <div className="abw-flex-wrap">
                {brief.top_attack_vectors.map((av) => (
                  <Badge key={av.label} variant="cyan" label={`${av.label} (${av.count})`} />
                ))}
              </div>
            </div>
          </div>
        </section>
      </div>

      {/* 2x2 Analytics Charts */}
      <div className="abw-grid-2">
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">7-Day Threat & Vulnerability Velocity</span>
            <Text type="supporting" size="xsm">
              CVEs · News · Exploits
            </Text>
          </div>
          <div className="abw-panel-body">
            <div style={{ width: '100%', height: 225 }}>
              <ResponsiveContainer>
                <AreaChart data={brief.velocity_7d}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" />
                  <XAxis dataKey="date" tick={{ fontSize: 10.5, fill: '#8b98a8' }} />
                  <YAxis tick={{ fontSize: 10.5, fill: '#8b98a8' }} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Area
                    type="monotone"
                    dataKey="cves"
                    name="CVEs"
                    stroke="#66efab"
                    fill="rgba(102,239,171,0.16)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="news"
                    name="News & Advisories"
                    stroke="#38bdf8"
                    fill="rgba(56,189,248,0.14)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="exploits"
                    name="Exploits / Zero-Days"
                    stroke="#ef4444"
                    fill="rgba(239,68,68,0.18)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">Exploit Risk Matrix (CVSS vs EPSS %)</span>
            <Text type="supporting" size="xsm">
              Red = CISA KEV Active
            </Text>
          </div>
          <div className="abw-panel-body">
            <div style={{ width: '100%', height: 225 }}>
              <ResponsiveContainer>
                <ScatterChart margin={{ top: 8, right: 12, bottom: 4, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" />
                  <XAxis
                    type="number"
                    dataKey="cvss"
                    name="CVSS"
                    domain={[0, 10]}
                    tick={{ fontSize: 10.5, fill: '#8b98a8' }}
                  />
                  <YAxis
                    type="number"
                    dataKey="epssPct"
                    name="EPSS %"
                    domain={[0, 100]}
                    tick={{ fontSize: 10.5, fill: '#8b98a8' }}
                  />
                  <ZAxis type="number" dataKey="risk" range={[45, 220]} />
                  <Tooltip
                    cursor={{ strokeDasharray: '3 3' }}
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const p = payload[0].payload as (typeof scatterData)[number];
                      return (
                        <div style={{ ...CHART_TOOLTIP_STYLE, padding: '8px 10px' }}>
                          <strong>{p.id}</strong> ({p.vendor})
                          <div>
                            CVSS {p.cvss} · EPSS {p.epssPct}% · AI Risk {p.risk}/100
                          </div>
                          {p.isKev && <div style={{ color: '#ef4444' }}>CISA KEV Actively Exploited</div>}
                        </div>
                      );
                    }}
                  />
                  <Scatter
                    data={scatterData}
                    onClick={(entry) => {
                      const p = entry as unknown as { vuln?: Vulnerability };
                      if (p?.vuln) onSelectVuln(p.vuln);
                    }}
                  >
                    {scatterData.map((entry, idx) => (
                      <Cell
                        key={idx}
                        fill={entry.isKev ? '#ef4444' : entry.risk >= 75 ? '#f59e0b' : '#66efab'}
                        fillOpacity={0.85}
                        style={{ cursor: 'pointer' }}
                      />
                    ))}
                  </Scatter>
                </ScatterChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">SANS ISC Live Top Attacked Ports</span>
            <Button
              label="Network IOCs"
              size="sm"
              variant="ghost"
              onClick={() => onNavigate('network')}
            />
          </div>
          <div className="abw-panel-body">
            <div style={{ width: '100%', height: 215 }}>
              <ResponsiveContainer>
                <BarChart data={portChartData} layout="vertical" margin={{ left: 22 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" />
                  <XAxis type="number" tick={{ fontSize: 10.5, fill: '#8b98a8' }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={92}
                    tick={{ fontSize: 10.5, fill: '#cbd5e1' }}
                  />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Bar dataKey="records" name="Attack Records" fill="#38bdf8" radius={[0, 0, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">Most Targeted Vendors & Ecosystems (7d)</span>
            <Button
              label="Explore All CVEs"
              size="sm"
              variant="ghost"
              onClick={() => onNavigate('vulnerabilities')}
            />
          </div>
          <div className="abw-panel-body">
            <div style={{ width: '100%', height: 215 }}>
              <ResponsiveContainer>
                <BarChart data={vendorChartData} layout="vertical" margin={{ left: 24 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" />
                  <XAxis type="number" tick={{ fontSize: 10.5, fill: '#8b98a8' }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={110}
                    tick={{ fontSize: 10.5, fill: '#cbd5e1' }}
                  />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Bar dataKey="count" name="Tracked Advisories" fill="#f97316" radius={[0, 0, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>
      </div>

      {/* Split Live Intelligence Feeds */}
      <div className="abw-grid-2">
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">Top AI-Prioritized Vulnerabilities</span>
            <Button
              label="View All"
              size="sm"
              variant="ghost"
              onClick={() => onNavigate('vulnerabilities')}
            />
          </div>
          <div className="abw-scroll-list">
            {top_vulnerabilities.slice(0, 14).map((v) => (
              <div key={v.id} className="abw-list-row clickable" onClick={() => onSelectVuln(v)}>
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
                    <span className={scoreClass(v.ai_risk_score)}>{v.ai_risk_score}</span>
                    <strong className="abw-mono" style={{ fontSize: 12.5 }}>
                      {v.id}
                    </strong>
                    <Badge variant={severityBadgeVariant(v.severity)} label={v.severity} />
                    {v.is_kev && <Badge variant="error" label="KEV" />}
                    {v.ransomware_use && <Badge variant="purple" label="Ransomware" />}
                    {v.is_ai_related && <Badge variant="cyan" label="AI/ML" />}
                  </div>
                  <Text type="supporting" size="xsm" hasTabularNumbers>
                    {v.cvss_score != null ? `CVSS ${v.cvss_score.toFixed(1)}` : ''}
                    {v.epss_score != null ? ` · EPSS ${(v.epss_score * 100).toFixed(1)}%` : ''}
                  </Text>
                </div>
                <Text size="sm" maxLines={2}>
                  {v.title}
                </Text>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  <Text type="supporting" size="xsm">
                    {v.vendor ?? v.ecosystem ?? 'Multi-vendor'} {v.product ? `· ${v.product}` : ''}
                  </Text>
                  <Text type="supporting" size="xsm">
                    <Timestamp value={v.published_at} format="relative_short" />
                  </Text>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">Breaking Cyber & Vulnerability Wire</span>
            <Button
              label="Full Wire"
              size="sm"
              variant="ghost"
              onClick={() => onNavigate('news')}
            />
          </div>
          <div className="abw-scroll-list">
            {recent_news.slice(0, 14).map((n) => {
              const safeNewsUrl = safeExternalUrl(n.url);
              return (
                <div key={n.id} className="abw-list-row">
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
                      <Badge variant="info" label={n.source} />
                      <Badge variant={severityBadgeVariant(n.severity)} label={n.severity} />
                      {n.tags.slice(0, 2).map((t) => (
                        <Badge key={t} variant={t === 'AI/LLM' ? 'cyan' : 'neutral'} label={t} />
                      ))}
                    </div>
                    <Text type="supporting" size="xsm">
                      <Timestamp value={n.published_at} format="relative_short" />
                    </Text>
                  </div>
                  {safeNewsUrl ? (
                    <a
                      href={safeNewsUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        color: 'var(--soc-text)',
                        textDecoration: 'none',
                        fontWeight: 600,
                        fontSize: 13,
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 5,
                      }}
                    >
                      <span>{n.title}</span>
                      <ExternalLink size={12} style={{ flexShrink: 0, opacity: 0.7 }} />
                    </a>
                  ) : (
                    <span
                      style={{
                        color: 'var(--soc-text)',
                        fontWeight: 600,
                        fontSize: 13,
                      }}
                    >
                      {n.title}
                    </span>
                  )}
                  {n.extracted_cves.length > 0 && (
                    <div className="abw-flex-wrap">
                      {n.extracted_cves.slice(0, 5).map((cve) => (
                        <button
                          key={cve}
                          type="button"
                          className="abw-cve-chip"
                          onClick={() => onSelectVulnId(cve)}
                        >
                          {cve}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
}
