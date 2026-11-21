import { useEffect, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { EmptyState } from '@astryxdesign/core/EmptyState';
import { Spinner } from '@astryxdesign/core/Spinner';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import { Timestamp } from '@astryxdesign/core/Timestamp';
import { ExternalLink, Newspaper, Search } from 'lucide-react';
import { api, safeExternalUrl, severityBadgeVariant } from '../api';
import type { ThreatNewsItem } from '../types';

interface NewsIntelViewProps {
  onSelectVulnId: (id: string) => void;
}

export function NewsIntelView({ onSelectVulnId }: NewsIntelViewProps) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('ALL');
  const [source, setSource] = useState('ALL');
  const [vulnOnly, setVulnOnly] = useState(false);
  const [aiOnly, setAiOnly] = useState(false);
  const [items, setItems] = useState<ThreatNewsItem[]>([]);
  const [sources, setSources] = useState<string[]>([]);
  const [totalMatched, setTotalMatched] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLoading(true);
      api
        .getNews({
          q: query,
          category,
          source,
          vuln_only: vulnOnly,
          ai_only: aiOnly,
          limit: 150,
        })
        .then((res) => {
          setItems(res.items);
          setSources(res.sources);
          setTotalMatched(res.total_matched);
        })
        .finally(() => setLoading(false));
    }, 180);
    return () => window.clearTimeout(timer);
  }, [query, category, source, vulnOnly, aiOnly]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <Newspaper size={14} color="#38bdf8" />
            Cybersecurity News, Advisories & Exploit Wire ({totalMatched})
          </span>
        </div>
        <div className="abw-panel-body">
          <Text type="supporting" size="xsm">
            Real-time aggregation from CISA Advisories, BleepingComputer, The Hacker News, Exploit-DB, Microsoft MSRC, Google Project Zero, Krebs, SecurityWeek, Dark Reading, SANS ISC & Hacker News
          </Text>

          <div className="abw-flex-wrap" style={{ gap: 8 }}>
            <div style={{ flex: '1 1 260px' }}>
              <TextInput
                label="Search threat reports"
                isLabelHidden
                value={query}
                onChange={setQuery}
                placeholder="Search headlines, CVE IDs, ransomware, zero-day, vendor..."
                startIcon={<Search size={14} />}
                hasClear
                width="100%"
              />
            </div>

            <select
              className="abw-select"
              aria-label="Category"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
            >
              <option value="ALL">All Categories</option>
              <option value="Advisory">Advisories (CISA / ICS)</option>
              <option value="Breaking News">Breaking Security News</option>
              <option value="Exploit PoC">Exploit-DB PoCs</option>
              <option value="Research">Deep Research (GPZ / SANS)</option>
              <option value="Vendor Patch">Vendor Patch (MSRC)</option>
              <option value="Community">Community (HN)</option>
            </select>

            <select
              className="abw-select"
              aria-label="Source"
              value={source}
              onChange={(e) => setSource(e.target.value)}
            >
              <option value="ALL">All Sources</option>
              {sources.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>

            <Button
              label="Vulnerability News Only"
              size="sm"
              variant={vulnOnly ? 'primary' : 'secondary'}
              onClick={() => setVulnOnly((v) => !v)}
            />
            <Button
              label="AI / LLM Only"
              size="sm"
              variant={aiOnly ? 'primary' : 'secondary'}
              onClick={() => setAiOnly((v) => !v)}
            />
          </div>
        </div>
      </section>

      {loading ? (
        <section className="abw-panel">
          <div className="abw-panel-body" style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
            <Spinner />
            <Text>Loading intelligence wire...</Text>
          </div>
        </section>
      ) : items.length === 0 ? (
        <section className="abw-panel">
          <div className="abw-panel-body">
            <EmptyState
              title="No reports match filters"
              description="Try clearing the search query or toggling off filters."
              actions={
                <Button
                  label="Clear Filters"
                  variant="primary"
                  onClick={() => {
                    setQuery('');
                    setCategory('ALL');
                    setSource('ALL');
                    setVulnOnly(false);
                    setAiOnly(false);
                  }}
                />
              }
            />
          </div>
        </section>
      ) : (
        <div className="abw-news-grid">
          {items.map((n) => {
            const safeUrl = safeExternalUrl(n.url);
            return (
              <article key={n.id} className="abw-news-cell">
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
                    <Badge variant="neutral" label={n.category} />
                    <Badge variant={severityBadgeVariant(n.severity)} label={n.severity} />
                  </div>
                  <Text type="supporting" size="xsm">
                    <Timestamp value={n.published_at} format="date_time" />
                  </Text>
                </div>

                {safeUrl ? (
                  <a
                    href={safeUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      color: 'var(--soc-text)',
                      textDecoration: 'none',
                      fontWeight: 600,
                      fontSize: 14.5,
                      lineHeight: 1.35,
                      display: 'inline-flex',
                      alignItems: 'flex-start',
                      gap: 6,
                    }}
                  >
                    <span>{n.title}</span>
                    <ExternalLink size={13} style={{ marginTop: 3, flexShrink: 0, opacity: 0.7 }} />
                  </a>
                ) : (
                  <span
                    style={{
                      color: 'var(--soc-text)',
                      fontWeight: 600,
                      fontSize: 14.5,
                      lineHeight: 1.35,
                    }}
                  >
                    {n.title}
                  </span>
                )}

                <Text type="supporting" size="sm" maxLines={3}>
                  {n.summary}
                </Text>

                <div className="abw-flex-wrap">
                  {n.extracted_cves.map((cve) => (
                    <button
                      key={cve}
                      type="button"
                      className="abw-cve-chip"
                      onClick={() => onSelectVulnId(cve)}
                    >
                      {cve}
                    </button>
                  ))}
                  {n.tags.map((t) => (
                    <Badge key={t} variant={t === 'AI/LLM' ? 'cyan' : 'purple'} label={t} />
                  ))}
                </div>

                <div style={{ marginTop: 'auto', paddingTop: 4, borderTop: '1px solid var(--soc-border)' }}>
                  <Text type="code" size="xsm" color="secondary">
                    {n.ai_triage_note}
                  </Text>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
