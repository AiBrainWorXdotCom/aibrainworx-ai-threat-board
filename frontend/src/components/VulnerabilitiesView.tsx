import { useEffect, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { EmptyState } from '@astryxdesign/core/EmptyState';
import { SegmentedControl, SegmentedControlItem } from '@astryxdesign/core/SegmentedControl';
import { Spinner } from '@astryxdesign/core/Spinner';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import { Timestamp } from '@astryxdesign/core/Timestamp';
import { Search, ShieldAlert } from 'lucide-react';
import { api, severityBadgeVariant } from '../api';
import type { Vulnerability } from '../types';

interface VulnerabilitiesViewProps {
  onSelectVuln: (v: Vulnerability) => void;
}

export function VulnerabilitiesView({ onSelectVuln }: VulnerabilitiesViewProps) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [kevOnly, setKevOnly] = useState(false);
  const [aiOnly, setAiOnly] = useState(false);
  const [ransomwareOnly, setRansomwareOnly] = useState(false);
  const [exploitOnly, setExploitOnly] = useState(false);
  const [days, setDays] = useState('0');
  const [sort, setSort] = useState('ai_score');
  const [items, setItems] = useState<Vulnerability[]>([]);
  const [totalMatched, setTotalMatched] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLoading(true);
      api
        .getVulnerabilities({
          q: query,
          severity,
          kev_only: kevOnly,
          ai_only: aiOnly,
          ransomware_only: ransomwareOnly,
          exploit_only: exploitOnly,
          days: Number(days),
          sort,
          limit: 200,
        })
        .then((res) => {
          setItems(res.items);
          setTotalMatched(res.total_matched);
        })
        .finally(() => setLoading(false));
    }, 180);
    return () => window.clearTimeout(timer);
  }, [query, severity, kevOnly, aiOnly, ransomwareOnly, exploitOnly, days, sort]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <ShieldAlert size={14} color="#66efab" />
            Vulnerability Intelligence Explorer ({totalMatched} Matches)
          </span>
          <SegmentedControl value={days} onChange={setDays} label="Timeframe" size="sm">
            <SegmentedControlItem value="1" label="24h" />
            <SegmentedControlItem value="7" label="Past 7d" />
            <SegmentedControlItem value="30" label="30d" />
            <SegmentedControlItem value="0" label="All Tracked" />
          </SegmentedControl>
        </div>
        <div className="abw-panel-body">
          <Text type="supporting" size="xsm">
            Correlated across CISA KEV, NIST NVD, GitHub Advisories, CIRCL, OSV AI Watchlist & FIRST EPSS
          </Text>

          <div className="abw-flex-wrap" style={{ gap: 8 }}>
            <div style={{ flex: '1 1 260px' }}>
              <TextInput
                label="Search vulnerabilities"
                isLabelHidden
                value={query}
                onChange={setQuery}
                placeholder="Filter by CVE, vendor, product, PyTorch, LangChain, CWE..."
                startIcon={<Search size={14} />}
                hasClear
                width="100%"
              />
            </div>

            <select
              className="abw-select"
              aria-label="Filter by severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              className="abw-select"
              aria-label="Sort order"
              value={sort}
              onChange={(e) => setSort(e.target.value)}
            >
              <option value="ai_score">Sort: AI Risk Score</option>
              <option value="cvss">Sort: CVSS Base</option>
              <option value="epss">Sort: FIRST EPSS %</option>
              <option value="published">Sort: Newest Published</option>
            </select>

            <Button
              label="CISA KEV"
              size="sm"
              variant={kevOnly ? 'primary' : 'secondary'}
              onClick={() => setKevOnly((v) => !v)}
            />
            <Button
              label="AI / ML Stack"
              size="sm"
              variant={aiOnly ? 'primary' : 'secondary'}
              onClick={() => setAiOnly((v) => !v)}
            />
            <Button
              label="Ransomware"
              size="sm"
              variant={ransomwareOnly ? 'primary' : 'secondary'}
              onClick={() => setRansomwareOnly((v) => !v)}
            />
            <Button
              label="Exploit PoC"
              size="sm"
              variant={exploitOnly ? 'primary' : 'secondary'}
              onClick={() => setExploitOnly((v) => !v)}
            />
          </div>
        </div>
      </section>

      {loading ? (
        <section className="abw-panel">
          <div className="abw-panel-body" style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
            <Spinner />
            <Text>Querying vulnerability graph...</Text>
          </div>
        </section>
      ) : items.length === 0 ? (
        <section className="abw-panel">
          <div className="abw-panel-body">
            <EmptyState
              title="No vulnerabilities match active filters"
              description="Broaden your search query, severity filter, or timeframe."
              actions={
                <Button
                  label="Reset Filters"
                  variant="primary"
                  onClick={() => {
                    setQuery('');
                    setSeverity('ALL');
                    setKevOnly(false);
                    setAiOnly(false);
                    setRansomwareOnly(false);
                    setExploitOnly(false);
                    setDays('0');
                  }}
                />
              }
            />
          </div>
        </section>
      ) : (
        <div className="abw-table-wrap">
          <table className="abw-table">
            <thead>
              <tr>
                <th>AI Risk</th>
                <th>CVE / Advisory</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>Target / Vendor</th>
                <th>Intelligence Summary & Signals</th>
                <th>Published</th>
              </tr>
            </thead>
            <tbody>
              {items.map((v) => (
                <tr key={v.id} className="clickable" onClick={() => onSelectVuln(v)}>
                  <td>
                    <span
                      className={
                        v.ai_risk_score >= 85
                          ? 'abw-score-badge abw-score-crit'
                          : v.ai_risk_score >= 70
                            ? 'abw-score-badge abw-score-high'
                            : v.ai_risk_score >= 45
                              ? 'abw-score-badge abw-score-med'
                              : 'abw-score-badge abw-score-low'
                      }
                    >
                      {v.ai_risk_score}
                    </span>
                  </td>
                  <td className="abw-mono" style={{ fontWeight: 600, whiteSpace: 'nowrap' }}>
                    {v.id}
                  </td>
                  <td>
                    <Badge variant={severityBadgeVariant(v.severity)} label={v.severity} />
                  </td>
                  <td className="abw-mono">
                    {v.cvss_score != null ? v.cvss_score.toFixed(1) : '—'}
                  </td>
                  <td className="abw-mono">
                    {v.epss_score != null ? `${(v.epss_score * 100).toFixed(1)}%` : '—'}
                  </td>
                  <td>
                    <Text weight="medium" size="sm" display="block">
                      {v.vendor ?? v.ecosystem ?? 'Advisory'}
                    </Text>
                    {v.product && (
                      <Text type="supporting" size="xsm" display="block">
                        {v.product}
                      </Text>
                    )}
                  </td>
                  <td style={{ minWidth: 280 }}>
                    <Text size="sm" display="block" maxLines={2}>
                      {v.title}
                    </Text>
                    <div className="abw-flex-wrap" style={{ marginTop: 4 }}>
                      {v.is_kev && <Badge variant="error" label="CISA KEV" />}
                      {v.ransomware_use && <Badge variant="purple" label="Ransomware" />}
                      {v.has_public_exploit && <Badge variant="orange" label="Exploit PoC" />}
                      {v.is_ai_related && <Badge variant="cyan" label="AI/ML" />}
                      {v.sources.map((s) => (
                        <Badge key={s} variant="neutral" label={s} />
                      ))}
                    </div>
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <Text type="supporting" size="xsm">
                      <Timestamp value={v.published_at} format="relative_short" />
                    </Text>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
