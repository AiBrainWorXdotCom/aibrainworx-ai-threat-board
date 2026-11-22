import { useEffect, useState } from 'react';
import { useToast } from '@astryxdesign/core';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Drawer, DrawerHeader } from '@astryxdesign/core/Drawer';
import { Heading } from '@astryxdesign/core/Heading';
import { Layout, LayoutContent } from '@astryxdesign/core/Layout';
import { Markdown } from '@astryxdesign/core/Markdown';
import { ProgressBar } from '@astryxdesign/core/ProgressBar';
import { Spinner } from '@astryxdesign/core/Spinner';
import { Text } from '@astryxdesign/core/Text';
import { Timestamp } from '@astryxdesign/core/Timestamp';
import { Download, ExternalLink, FileText, LayoutGrid, Save, ShieldAlert, Sparkles } from 'lucide-react';
import { api, safeExternalUrl, severityBadgeVariant } from '../api';
import type { AiQueryResponse, NavTab, ThreatNewsItem, TriageStatus, Vulnerability } from '../types';
import { sanitizeMarkdownClient } from '../utils/opsec';
import { A2uiRenderer } from './A2uiRenderer';

interface InvestigationDrawerProps {
  vulnId: string | null;
  initialVuln?: Vulnerability | null;
  opsecMode?: boolean;
  readOnly?: boolean;
  onClose: () => void;
  onSelectVulnId: (id: string) => void;
  onNavigate?: (tab: NavTab) => void;
  onTriageUpdated?: () => void;
}

export function InvestigationDrawer({
  vulnId,
  initialVuln,
  opsecMode = false,
  readOnly = false,
  onClose,
  onSelectVulnId,
  onNavigate,
  onTriageUpdated,
}: InvestigationDrawerProps) {
  const toast = useToast();
  const [vuln, setVuln] = useState<Vulnerability | null>(initialVuln ?? null);
  const [relatedNews, setRelatedNews] = useState<ThreatNewsItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deepTriage, setDeepTriage] = useState<AiQueryResponse | null>(null);
  const [triageViewMode, setTriageViewMode] = useState<'a2ui' | 'markdown'>('a2ui');
  const [triageLoading, setTriageLoading] = useState(false);

  const [triageStatus, setTriageStatus] = useState<TriageStatus>('new');
  const [triageNotes, setTriageNotes] = useState('');
  const [triageSaving, setTriageSaving] = useState(false);
  const [triageSavedMsg, setTriageSavedMsg] = useState<string | null>(null);

  useEffect(() => {
    setDeepTriage(null);
    setTriageSavedMsg(null);
    if (!vulnId) {
      setVuln(null);
      setRelatedNews([]);
      setError(null);
      return;
    }
    if (initialVuln && initialVuln.id === vulnId) {
      setVuln(initialVuln);
      setTriageStatus(initialVuln.triage_status ?? 'new');
      setTriageNotes(initialVuln.triage_notes ?? '');
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .getVulnerabilityDetail(vulnId)
      .then((res) => {
        if (!cancelled) {
          setVuln(res.vulnerability);
          setRelatedNews(res.related_news);
          setTriageStatus(res.vulnerability.triage_status ?? 'new');
          setTriageNotes(res.vulnerability.triage_notes ?? '');
        }
      })
      .catch((err) => {
        if (!cancelled && !initialVuln) {
          setError(err instanceof Error ? err.message : String(err));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [vulnId, initialVuln]);

  const handleOpenChange = (isOpen: boolean) => {
    if (!isOpen) onClose();
  };

  const runDeepTriage = async () => {
    if (!vuln || triageLoading || readOnly) return;
    setTriageLoading(true);
    try {
      const resp = await api.triageVulnerability(vuln.id);
      setDeepTriage(resp);
    } finally {
      setTriageLoading(false);
    }
  };

  const saveAnalystTriage = async () => {
    if (!vuln || triageSaving || readOnly) return;
    setTriageSaving(true);
    setTriageSavedMsg(null);
    try {
      const updated = await api.updateVulnTriage(vuln.id, triageStatus, triageNotes);
      setVuln({ ...vuln, triage_status: updated.status, triage_notes: updated.notes });
      setTriageSavedMsg('Saved');
      onTriageUpdated?.();
    } finally {
      setTriageSaving(false);
    }
  };

  return (
    <Drawer
      isOpen={vulnId != null}
      onOpenChange={handleOpenChange}
      side="end"
      width={620}
      label={vulnId ? `Threat Investigation: ${vulnId}` : 'Threat Investigation'}
    >
      <Layout
        height="fill"
        header={
          <DrawerHeader
            title={vuln?.id ?? vulnId ?? 'Vulnerability Investigation'}
            subtitle={
              vuln
                ? `${vuln.vendor ?? vuln.ecosystem ?? 'Advisory'} ${vuln.product ?? ''}`.trim()
                : 'Loading live intelligence'
            }
            onOpenChange={handleOpenChange}
            endContent={
              vuln ? (
                <Badge variant={severityBadgeVariant(vuln.severity)} label={vuln.severity} />
              ) : undefined
            }
          />
        }
        content={
          <LayoutContent>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, paddingBottom: 24 }}>
              {loading && !vuln && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 24 }}>
                  <Spinner />
                  <Text>Loading vulnerability dossier...</Text>
                </div>
              )}

              {error && !vuln && (
                <div className="abw-alert-bar" role="alert">
                  <div>
                    <Text display="block">{error}</Text>
                    <div style={{ marginTop: 8 }}>
                      <Button
                        label="Search on NVD"
                        href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vulnId ?? '')}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        size="sm"
                        icon={<ExternalLink size={14} />}
                      />
                    </div>
                  </div>
                </div>
              )}

              {vuln && (
                <>
                  <div className="abw-flex-wrap">
                    <Badge
                      variant={
                        vuln.ai_risk_score >= 85
                          ? 'error'
                          : vuln.ai_risk_score >= 65
                            ? 'orange'
                            : 'info'
                      }
                      label={`AI RISK SCORE ${vuln.ai_risk_score}/100`}
                    />
                    {vuln.matched_stack && vuln.matched_stack.length > 0 && (
                      <Badge
                        variant="warning"
                        label={`MY STACK: ${vuln.matched_stack.join(', ')}`}
                      />
                    )}
                    {vuln.is_kev && <Badge variant="error" label="CISA KEV ACTIVE EXPLOIT" />}
                    {vuln.kev_days_remaining != null && (
                      <Badge
                        variant={
                          vuln.kev_days_remaining < 0
                            ? 'error'
                            : vuln.kev_days_remaining <= 7
                              ? 'warning'
                              : 'info'
                        }
                        label={
                          vuln.kev_days_remaining < 0
                            ? `KEV OVERDUE ${Math.abs(vuln.kev_days_remaining)}d`
                            : `KEV DUE IN ${vuln.kev_days_remaining}d`
                        }
                      />
                    )}
                    {vuln.epss_spike && (
                      <Badge
                        variant="orange"
                        label={`EPSS SURGE +${((vuln.epss_delta_24h ?? 0) * 100).toFixed(1)}%`}
                      />
                    )}
                    {vuln.ransomware_use && <Badge variant="purple" label="RANSOMWARE LINKED" />}
                    {vuln.has_public_exploit && <Badge variant="orange" label="PUBLIC EXPLOIT / POC" />}
                    {vuln.is_ai_related && <Badge variant="cyan" label="AI / ML INFRASTRUCTURE" />}
                    {vuln.sources.map((s) => (
                      <Badge key={s} variant="neutral" label={s} />
                    ))}
                  </div>

                  <div className="abw-flex-wrap" style={{ gap: 6 }}>
                    <Button
                      label="Export MD"
                      size="sm"
                      variant="secondary"
                      icon={<Download size={12} />}
                      onClick={() => void api.exportSingleVuln(vuln.id, 'markdown')}
                    />
                    <Button
                      label="Export JSON"
                      size="sm"
                      variant="secondary"
                      icon={<Download size={12} />}
                      onClick={() => void api.exportSingleVuln(vuln.id, 'json')}
                    />
                    <Button
                      label="Export STIX 2.1"
                      size="sm"
                      variant="secondary"
                      icon={<Download size={12} />}
                      onClick={() => void api.exportSingleVuln(vuln.id, 'stix')}
                    />
                  </div>

                  <div>
                    <Heading level={4} style={{ marginBottom: 6 }}>
                      {vuln.title}
                    </Heading>
                    <Text type="supporting" size="sm">
                      Published <Timestamp value={vuln.published_at} format="date_time" /> · Updated{' '}
                      <Timestamp value={vuln.updated_at} format="relative" />
                    </Text>
                  </div>

                  <section className="abw-panel">
                    <div className="abw-panel-head">
                      <span className="abw-panel-title">SOC Analyst Triage Workflow</span>
                      {triageSavedMsg && <Badge variant="success" label={triageSavedMsg} />}
                    </div>
                    <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <div className="abw-flex-wrap" style={{ alignItems: 'center', justifyContent: 'space-between' }}>
                        <select
                          className="abw-select"
                          aria-label="Triage Status"
                          disabled={readOnly}
                          value={triageStatus}
                          onChange={(e) => setTriageStatus(e.target.value as TriageStatus)}
                        >
                          <option value="new">Status: New / Untriaged</option>
                          <option value="investigating">Status: Investigating</option>
                          <option value="mitigated">Status: Mitigated / Patched</option>
                          <option value="false_positive">Status: False Positive</option>
                          <option value="accepted">Status: Risk Accepted</option>
                        </select>
                        <Button
                          label={triageSaving ? 'Saving...' : 'Save Triage'}
                          size="sm"
                          variant="primary"
                          icon={<Save size={12} />}
                          isLoading={triageSaving}
                          isDisabled={readOnly}
                          onClick={() => void saveAnalystTriage()}
                        />
                      </div>
                      <textarea
                        rows={2}
                        disabled={readOnly}
                        value={triageNotes}
                        onChange={(e) => setTriageNotes(e.target.value)}
                        placeholder="Record owner, compensating WAF rules, ticket ID, or verification notes..."
                        style={{
                          width: '100%',
                          background: 'var(--soc-surface)',
                          border: '1px solid var(--soc-border)',
                          color: 'var(--soc-text)',
                          padding: '6px 8px',
                          fontSize: 12,
                        }}
                      />
                    </div>
                  </section>

                  <section className="abw-panel">
                    <div className="abw-panel-head">
                      <span className="abw-panel-title">
                        <Sparkles size={13} color="#66efab" />
                        AiBrainWorX AI Triage Assessment
                      </span>
                      <Button
                        label={triageLoading ? 'Analyzing...' : 'Run Deep AI Triage'}
                        size="sm"
                        variant="secondary"
                        isLoading={triageLoading}
                        isDisabled={readOnly}
                        onClick={() => void runDeepTriage()}
                      />
                    </div>
                    <div className="abw-panel-body">
                      <Text display="block" size="sm">
                        {vuln.ai_summary}
                      </Text>
                      {deepTriage && (
                        <div style={{ borderTop: '1px solid var(--soc-border)', paddingTop: 10 }}>
                          <div
                            className="abw-flex-wrap"
                            style={{ justifyContent: 'space-between', marginBottom: 8 }}
                          >
                            <div className="abw-flex-wrap">
                              <Badge
                                variant="info"
                                label={`${deepTriage.provider_used} · ${deepTriage.model_used}`}
                              />
                              <Badge variant="neutral" label={`${deepTriage.latency_ms} ms`} />
                            </div>
                            {deepTriage.a2ui && (
                              <div className="abw-a2ui-mode-tabs">
                                <button
                                  type="button"
                                  className="abw-a2ui-mode-tab"
                                  data-active={triageViewMode === 'a2ui'}
                                  onClick={() => setTriageViewMode('a2ui')}
                                >
                                  <LayoutGrid size={11} /> A2UI
                                </button>
                                <button
                                  type="button"
                                  className="abw-a2ui-mode-tab"
                                  data-active={triageViewMode === 'markdown'}
                                  onClick={() => setTriageViewMode('markdown')}
                                >
                                  <FileText size={11} /> MD
                                </button>
                              </div>
                            )}
                          </div>
                          {deepTriage.fallback_reason && (
                            <Text type="supporting" size="xsm" display="block" style={{ marginBottom: 6 }}>
                              Fallback reason: {deepTriage.fallback_reason}
                            </Text>
                          )}
                          {deepTriage.a2ui && triageViewMode === 'a2ui' ? (
                            <A2uiRenderer
                              surface={deepTriage.a2ui}
                              opsecMode={opsecMode}
                              readOnly={readOnly}
                              compact
                              onOpenCve={onSelectVulnId}
                              onNavigate={(tab) => {
                                onClose();
                                onNavigate?.(tab);
                              }}
                              onTriageUpdated={() => {
                                onTriageUpdated?.();
                                if (vuln) {
                                  void api.getVulnerabilityDetail(vuln.id).then((res) => {
                                    setVuln(res.vulnerability);
                                    setTriageStatus(res.vulnerability.triage_status ?? 'new');
                                    setTriageNotes(res.vulnerability.triage_notes ?? '');
                                  });
                                }
                              }}
                              onNotify={(msg, tone) =>
                                toast({
                                  type: tone === 'error' ? 'error' : 'info',
                                  body: msg,
                                })
                              }
                            />
                          ) : (
                            <Markdown density="compact">
                              {sanitizeMarkdownClient(deepTriage.answer_markdown)}
                            </Markdown>
                          )}
                        </div>
                      )}
                    </div>
                  </section>

                  <div className="abw-grid-3">
                    <div className="abw-grid-3-cell">
                      <Text type="supporting" size="xsm" display="block">
                        CVSS BASE
                      </Text>
                      <div className="abw-kpi-value" style={{ fontSize: 21, marginTop: 4 }}>
                        {vuln.cvss_score != null ? vuln.cvss_score.toFixed(1) : 'N/A'}
                      </div>
                    </div>
                    <div className="abw-grid-3-cell">
                      <Text type="supporting" size="xsm" display="block">
                        FIRST EPSS (30d)
                      </Text>
                      <div className="abw-kpi-value" style={{ fontSize: 21, marginTop: 4 }}>
                        {vuln.epss_score != null ? `${(vuln.epss_score * 100).toFixed(1)}%` : 'N/A'}
                      </div>
                    </div>
                    <div className="abw-grid-3-cell">
                      <Text type="supporting" size="xsm" display="block">
                        EPSS PERCENTILE
                      </Text>
                      <div className="abw-kpi-value" style={{ fontSize: 21, marginTop: 4 }}>
                        {vuln.epss_percentile != null
                          ? `${(vuln.epss_percentile * 100).toFixed(0)}th`
                          : 'N/A'}
                      </div>
                    </div>
                  </div>

                  <section className="abw-panel">
                    <div className="abw-panel-head">
                      <span className="abw-panel-title">
                        AI Risk Factor Breakdown ({vuln.ai_risk_score}/100)
                      </span>
                    </div>
                    <div className="abw-panel-body">
                      {vuln.ai_score_factors.map((f) => (
                        <ProgressBar
                          key={f.label}
                          label={`${f.label} (+${f.points} pts)`}
                          value={f.points}
                          max={38}
                          hasValueLabel
                          formatValueLabel={() => f.detail}
                          variant={
                            f.points >= 20 ? 'error' : f.points >= 10 ? 'warning' : 'accent'
                          }
                        />
                      ))}
                    </div>
                  </section>

                  {vuln.kev_required_action && (
                    <div className="abw-alert-bar">
                      <div>
                        <div className="abw-flex-wrap" style={{ marginBottom: 4 }}>
                          <ShieldAlert size={14} color="#ef4444" />
                          <Text weight="semibold" size="sm">
                            CISA Mandatory Remediation Action
                            {vuln.kev_due_date ? ` (Due ${vuln.kev_due_date})` : ''}
                          </Text>
                        </div>
                        <Text size="sm" display="block">
                          {vuln.kev_required_action}
                        </Text>
                      </div>
                    </div>
                  )}

                  <section className="abw-panel">
                    <div className="abw-panel-head">
                      <span className="abw-panel-title">Technical Description</span>
                    </div>
                    <div className="abw-panel-body">
                      <Text size="sm" display="block" style={{ lineHeight: 1.55 }}>
                        {vuln.description || 'No extended description provided by upstream source.'}
                      </Text>
                    </div>
                  </section>

                  {(vuln.cvss_vector || vuln.patched_version || vuln.cwes.length > 0) && (
                    <section className="abw-panel">
                      <div className="abw-panel-head">
                        <span className="abw-panel-title">Taxonomy & Patch Metadata</span>
                      </div>
                      <div className="abw-panel-body">
                        {vuln.cvss_vector && (
                          <div>
                            <Text type="supporting" size="xsm" display="block">
                              CVSS Vector
                            </Text>
                            <Text type="code" size="xsm">
                              {vuln.cvss_vector}
                            </Text>
                          </div>
                        )}
                        {vuln.patched_version && (
                          <div>
                            <Text type="supporting" size="xsm" display="block">
                              First Patched Version
                            </Text>
                            <Badge variant="success" label={vuln.patched_version} />
                          </div>
                        )}
                        {vuln.cwes.length > 0 && (
                          <div>
                            <Text type="supporting" size="xsm" display="block">
                              Weaknesses (CWE)
                            </Text>
                            <div className="abw-flex-wrap" style={{ marginTop: 4 }}>
                              {vuln.cwes.map((c) => (
                                <Badge key={c} variant="purple" label={c} />
                              ))}
                            </div>
                          </div>
                        )}
                        {vuln.mitre_tactics.length > 0 && (
                          <div>
                            <Text type="supporting" size="xsm" display="block">
                              Inferred MITRE ATT&CK Tactics & Vectors
                            </Text>
                            <div className="abw-flex-wrap" style={{ marginTop: 4 }}>
                              {vuln.mitre_tactics.map((t) => (
                                <Badge key={t} variant="blue" label={t} />
                              ))}
                              {vuln.attack_vectors.map((v) => (
                                <Badge key={v} variant="teal" label={v} />
                              ))}
                            </div>
                          </div>
                        )}
                        {vuln.aliases.length > 0 && (
                          <div>
                            <Text type="supporting" size="xsm" display="block">
                              Aliases
                            </Text>
                            <div className="abw-flex-wrap" style={{ marginTop: 4 }}>
                              {vuln.aliases.map((a) => (
                                <button
                                  key={a}
                                  type="button"
                                  className="abw-cve-chip"
                                  onClick={() => onSelectVulnId(a)}
                                >
                                  {a}
                                </button>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </section>
                  )}

                  {relatedNews.length > 0 && (
                    <section className="abw-panel">
                      <div className="abw-panel-head">
                        <span className="abw-panel-title">
                          Correlated Security News & Exploits ({relatedNews.length})
                        </span>
                      </div>
                      <div>
                        {relatedNews.map((n) => {
                          const safeNewsUrl = safeExternalUrl(n.url);
                          const inner = (
                            <>
                              <div className="abw-flex-wrap">
                                <Badge variant="info" label={n.source} />
                                <Badge variant={severityBadgeVariant(n.severity)} label={n.severity} />
                                <Text type="supporting" size="xsm">
                                  <Timestamp value={n.published_at} format="relative" />
                                </Text>
                              </div>
                              <Text weight="semibold" size="sm" display="block">
                                {n.title}
                              </Text>
                            </>
                          );
                          return safeNewsUrl ? (
                            <a
                              key={n.id}
                              href={safeNewsUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="abw-list-row clickable"
                              style={{ textDecoration: 'none', color: 'inherit' }}
                            >
                              {inner}
                            </a>
                          ) : (
                            <div key={n.id} className="abw-list-row">
                              {inner}
                            </div>
                          );
                        })}
                      </div>
                    </section>
                  )}

                  {vuln.references.map((r) => safeExternalUrl(r)).filter((u): u is string => Boolean(u)).length > 0 && (
                    <section className="abw-panel">
                      <div className="abw-panel-head">
                        <span className="abw-panel-title">Primary References</span>
                      </div>
                      <div className="abw-panel-body">
                        {vuln.references
                          .map((r) => safeExternalUrl(r))
                          .filter((u): u is string => Boolean(u))
                          .map((refUrl) => (
                            <a
                              key={refUrl}
                              href={refUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{
                                color: 'var(--soc-cyan)',
                                fontSize: 12,
                                wordBreak: 'break-all',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 5,
                              }}
                            >
                              <ExternalLink size={12} />
                              {refUrl}
                            </a>
                          ))}
                      </div>
                    </section>
                  )}
                </>
              )}
            </div>
          </LayoutContent>
        }
      />
    </Drawer>
  );
}
