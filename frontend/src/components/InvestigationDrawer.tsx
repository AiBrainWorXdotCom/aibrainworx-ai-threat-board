import { useEffect, useState } from 'react';
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
import { ExternalLink, ShieldAlert, Sparkles } from 'lucide-react';
import { api, safeExternalUrl, severityBadgeVariant } from '../api';
import type { AiQueryResponse, ThreatNewsItem, Vulnerability } from '../types';

interface InvestigationDrawerProps {
  vulnId: string | null;
  initialVuln?: Vulnerability | null;
  onClose: () => void;
  onSelectVulnId: (id: string) => void;
}

export function InvestigationDrawer({
  vulnId,
  initialVuln,
  onClose,
  onSelectVulnId,
}: InvestigationDrawerProps) {
  const [vuln, setVuln] = useState<Vulnerability | null>(initialVuln ?? null);
  const [relatedNews, setRelatedNews] = useState<ThreatNewsItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deepTriage, setDeepTriage] = useState<AiQueryResponse | null>(null);
  const [triageLoading, setTriageLoading] = useState(false);

  useEffect(() => {
    setDeepTriage(null);
    if (!vulnId) {
      setVuln(null);
      setRelatedNews([]);
      setError(null);
      return;
    }
    if (initialVuln && initialVuln.id === vulnId) {
      setVuln(initialVuln);
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
    if (!vuln || triageLoading) return;
    setTriageLoading(true);
    try {
      const resp = await api.triageVulnerability(vuln.id);
      setDeepTriage(resp);
    } finally {
      setTriageLoading(false);
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
                    {vuln.is_kev && <Badge variant="error" label="CISA KEV ACTIVE EXPLOIT" />}
                    {vuln.ransomware_use && <Badge variant="purple" label="RANSOMWARE LINKED" />}
                    {vuln.has_public_exploit && <Badge variant="orange" label="PUBLIC EXPLOIT / POC" />}
                    {vuln.is_ai_related && <Badge variant="cyan" label="AI / ML INFRASTRUCTURE" />}
                    {vuln.sources.map((s) => (
                      <Badge key={s} variant="neutral" label={s} />
                    ))}
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
                      <span className="abw-panel-title">
                        <Sparkles size={13} color="#66efab" />
                        AiBrainWorX AI Triage Assessment
                      </span>
                      <Button
                        label={triageLoading ? 'Analyzing...' : 'Run Deep AI Triage'}
                        size="sm"
                        variant="secondary"
                        isLoading={triageLoading}
                        onClick={() => void runDeepTriage()}
                      />
                    </div>
                    <div className="abw-panel-body">
                      <Text display="block" size="sm">
                        {vuln.ai_summary}
                      </Text>
                      {deepTriage && (
                        <div style={{ borderTop: '1px solid var(--soc-border)', paddingTop: 10 }}>
                          <div className="abw-flex-wrap" style={{ marginBottom: 8 }}>
                            <Badge
                              variant="info"
                              label={`${deepTriage.provider_used} · ${deepTriage.model_used}`}
                            />
                            <Badge variant="neutral" label={`${deepTriage.latency_ms} ms`} />
                          </div>
                          {deepTriage.fallback_reason && (
                            <Text type="supporting" size="xsm" display="block" style={{ marginBottom: 6 }}>
                              Fallback reason: {deepTriage.fallback_reason}
                            </Text>
                          )}
                          <Markdown density="compact">{deepTriage.answer_markdown}</Markdown>
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
