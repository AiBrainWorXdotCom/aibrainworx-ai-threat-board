import { useMemo, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Markdown } from '@astryxdesign/core/Markdown';
import { ProgressBar } from '@astryxdesign/core/ProgressBar';
import { Text } from '@astryxdesign/core/Text';
import { Timestamp } from '@astryxdesign/core/Timestamp';
import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  CheckCircle2,
  Circle,
  Copy,
  Download,
  ExternalLink,
  Globe,
  Layers,
  Newspaper,
  Search,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api, safeExternalUrl, severityBadgeVariant } from '../api';
import type {
  A2uiComponentNode,
  A2uiSurfacePayload,
  NavTab,
  TriageStatus,
} from '../types';
import {
  defangIp,
  redactDisplayText,
  redactHostname,
  redactIp,
  sanitizeMarkdownClient,
} from '../utils/opsec';

export const EXPECTED_A2UI_VERSION = '1.0';
export const EXPECTED_A2UI_CATALOG_ID = 'aibrainworx.soc.v1';

const ALLOWED_TABS: ReadonlySet<string> = new Set([
  'overview',
  'mystack',
  'vulnerabilities',
  'news',
  'network',
  'analyst',
  'alerts',
  'models',
]);

const ALLOWED_TRIAGE: ReadonlySet<string> = new Set([
  'new',
  'investigating',
  'mitigated',
  'false_positive',
  'accepted',
]);

export interface A2uiAction {
  type: 'open_cve' | 'set_triage' | 'export_stix' | 'export_md' | 'navigate_tab' | 'copy_text';
  label?: string;
  cveId?: string;
  status?: TriageStatus;
  tab?: NavTab;
  text?: string;
}

interface A2uiRendererProps {
  surface: A2uiSurfacePayload;
  opsecMode?: boolean;
  readOnly?: boolean;
  compact?: boolean;
  onOpenCve: (cveId: string) => void;
  onNavigate?: (tab: NavTab) => void;
  onTriageUpdated?: () => void;
  onNotify?: (message: string, tone?: 'info' | 'success' | 'error') => void;
}

interface ParsedSurface {
  valid: boolean;
  rootId: string;
  title: string;
  subtitle: string;
  dataModel: unknown;
  components: Map<string, A2uiComponentNode>;
}

const BLOCKED_POINTER_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const ALLOWED_KPI_TONES = new Set([
  'neutral',
  'critical',
  'high',
  'medium',
  'low',
  'success',
  'info',
  'warning',
  'error',
]);

/** Resolve an RFC 6901 JSON Pointer (`/a/b/0`) against the surface's `dataModel`. */
function resolvePointer(root: unknown, pointer: string): unknown {
  if (!pointer || pointer === '/') return root;
  if (!pointer.startsWith('/')) return undefined;
  const parts = pointer
    .slice(1)
    .split('/')
    .map((seg) => seg.replace(/~1/g, '/').replace(/~0/g, '~'));
  let cur: unknown = root;
  for (const part of parts) {
    if (cur == null || BLOCKED_POINTER_KEYS.has(part)) return undefined;
    if (Array.isArray(cur)) {
      const idx = Number(part);
      if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return undefined;
      cur = cur[idx];
    } else if (typeof cur === 'object') {
      if (!Object.prototype.hasOwnProperty.call(cur, part)) return undefined;
      cur = (cur as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return cur;
}

/** Resolves an A2UI 1.0 `{ "@path": "/..." }` dynamic data binding or returns the literal value. */
function resolveBinding(value: unknown, dataModel: unknown): unknown {
  if (
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    '@path' in (value as Record<string, unknown>) &&
    typeof (value as Record<string, unknown>)['@path'] === 'string'
  ) {
    return resolvePointer(dataModel, (value as Record<string, string>)['@path']);
  }
  return value;
}

function parseA2uiAction(raw: unknown): A2uiAction | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const type = typeof obj.type === 'string' ? obj.type.trim() : '';
  const label = typeof obj.label === 'string' ? obj.label : undefined;

  if (type === 'open_cve' || type === 'export_stix' || type === 'export_md') {
    const cveId = typeof obj.cveId === 'string' ? obj.cveId.trim() : '';
    if (!cveId || !/^[A-Za-z0-9._-]{4,40}$/.test(cveId)) return null;
    return { type, label, cveId };
  }
  if (type === 'set_triage') {
    const cveId = typeof obj.cveId === 'string' ? obj.cveId.trim() : '';
    const status = typeof obj.status === 'string' ? obj.status.trim().toLowerCase() : '';
    if (!cveId || !/^[A-Za-z0-9._-]{4,40}$/.test(cveId) || !ALLOWED_TRIAGE.has(status)) return null;
    return { type, label, cveId, status: status as TriageStatus };
  }
  if (type === 'navigate_tab') {
    const tab = typeof obj.tab === 'string' ? obj.tab.trim().toLowerCase() : '';
    if (!ALLOWED_TABS.has(tab)) return null;
    return { type, label, tab: tab as NavTab };
  }
  if (type === 'copy_text') {
    const text = typeof obj.text === 'string' ? obj.text.trim() : '';
    if (!text) return null;
    return { type, label, text };
  }
  return null;
}

function parseSurface(surface: A2uiSurfacePayload): ParsedSurface {
  if (
    surface.version !== EXPECTED_A2UI_VERSION ||
    surface.catalog_id !== EXPECTED_A2UI_CATALOG_ID ||
    !Array.isArray(surface.messages)
  ) {
    return {
      valid: false,
      rootId: '',
      title: '',
      subtitle: '',
      dataModel: {},
      components: new Map(),
    };
  }

  let rootId = 'root';
  let title = '';
  let subtitle = '';
  let dataModel: unknown = {};
  const components = new Map<string, A2uiComponentNode>();

  for (const msg of surface.messages) {
    if (msg.type === 'createSurface') {
      if (msg.catalogId !== EXPECTED_A2UI_CATALOG_ID) {
        return { valid: false, rootId: '', title: '', subtitle: '', dataModel: {}, components: new Map() };
      }
      rootId = msg.rootComponentId || 'root';
      title = msg.title || '';
      subtitle = msg.subtitle || '';
    } else if (msg.type === 'updateDataModel') {
      if (!msg.path || msg.path === '/') {
        dataModel = msg.value ?? {};
      }
    } else if (msg.type === 'updateComponents') {
      for (const comp of msg.components ?? []) {
        if (comp && typeof comp.id === 'string' && typeof comp.component === 'string') {
          components.set(comp.id, comp);
        }
      }
    }
  }

  return {
    valid: components.has(rootId),
    rootId,
    title,
    subtitle,
    dataModel,
    components,
  };
}

function scoreClass(score: number): string {
  if (score >= 85) return 'abw-score-badge abw-score-crit';
  if (score >= 70) return 'abw-score-badge abw-score-high';
  if (score >= 45) return 'abw-score-badge abw-score-med';
  return 'abw-score-badge abw-score-low';
}

function accentHex(accent?: string): string {
  switch (accent) {
    case 'red':
      return '#ef4444';
    case 'orange':
      return '#f97316';
    case 'cyan':
      return '#38bdf8';
    default:
      return '#66efab';
  }
}

function triageBadgeVariant(status: string): 'neutral' | 'warning' | 'success' | 'info' {
  switch (status) {
    case 'investigating':
      return 'warning';
    case 'mitigated':
      return 'success';
    case 'accepted':
    case 'false_positive':
      return 'info';
    default:
      return 'neutral';
  }
}

const CHART_TOOLTIP_STYLE = {
  background: '#0b0e13',
  border: '1px solid #2b3545',
  borderRadius: 0,
  fontSize: 12,
  fontFamily: 'ui-monospace, monospace',
};

export function A2uiRenderer({
  surface,
  opsecMode = false,
  readOnly = false,
  compact = false,
  onOpenCve,
  onNavigate,
  onTriageUpdated,
  onNotify,
}: A2uiRendererProps) {
  const parsed = useMemo(() => parseSurface(surface), [surface]);

  // Interactive client-side state for checklist items, inline triage status, and copy feedback
  const [checkedSteps, setCheckedSteps] = useState<Record<string, boolean>>({});
  const [triageOverrides, setTriageOverrides] = useState<Record<string, TriageStatus>>({});
  const [busyTriageKey, setBusyTriageKey] = useState<string | null>(null);
  const [copiedHint, setCopiedHint] = useState<string | null>(null);

  const dispatchAction = async (action: A2uiAction) => {
    switch (action.type) {
      case 'open_cve':
        if (action.cveId) onOpenCve(action.cveId);
        return;
      case 'navigate_tab':
        if (action.tab && onNavigate) onNavigate(action.tab);
        return;
      case 'export_stix':
        if (action.cveId) {
          try {
            await api.exportSingleVuln(action.cveId, 'stix');
            onNotify?.(`Exported STIX 2.1 bundle for ${action.cveId}`, 'success');
          } catch (err) {
            onNotify?.(err instanceof Error ? err.message : String(err), 'error');
          }
        }
        return;
      case 'export_md':
        if (action.cveId) {
          try {
            await api.exportSingleVuln(action.cveId, 'markdown');
            onNotify?.(`Exported Markdown dossier for ${action.cveId}`, 'success');
          } catch (err) {
            onNotify?.(err instanceof Error ? err.message : String(err), 'error');
          }
        }
        return;
      case 'set_triage':
        if (readOnly || !action.cveId || !action.status) return;
        {
          const key = `${action.cveId}:${action.status}`;
          setBusyTriageKey(key);
          try {
            const updated = await api.updateVulnTriage(
              action.cveId,
              action.status,
              `Updated via A2UI 1.0 SOC Surface (${new Date().toISOString().slice(0, 10)})`
            );
            setTriageOverrides((prev) => ({ ...prev, [action.cveId!]: updated.status }));
            onTriageUpdated?.();
            onNotify?.(`${action.cveId} marked as ${updated.status.replace('_', ' ')}`, 'success');
          } catch (err) {
            onNotify?.(err instanceof Error ? err.message : String(err), 'error');
          } finally {
            setBusyTriageKey(null);
          }
        }
        return;
      case 'copy_text':
        if (action.text) {
          const safeCopy = opsecMode ? redactDisplayText(action.text, true) : action.text;
          try {
            await navigator.clipboard.writeText(safeCopy);
            setCopiedHint(safeCopy);
            onNotify?.('Copied to clipboard', 'info');
            setTimeout(() => setCopiedHint((prev) => (prev === safeCopy ? null : prev)), 1800);
          } catch {
            onNotify?.('Clipboard permission unavailable in this browser context', 'error');
          }
        }
        return;
    }
  };

  if (!parsed.valid) {
    return null;
  }

  const renderNode = (nodeId: string, visited: Set<string>, depth: number): React.ReactNode => {
    if (depth > 6 || visited.has(nodeId)) return null;
    const node = parsed.components.get(nodeId);
    if (!node) return null;

    const nextVisited = new Set(visited);
    nextVisited.add(nodeId);
    const props = node.props ?? {};

    switch (node.component) {
      case 'Column': {
        const kids = node.children ?? [];
        return (
          <div
            key={node.id}
            style={{ display: 'flex', flexDirection: 'column', gap: compact ? 10 : 12 }}
          >
            {kids.map((cid) => renderNode(cid, nextVisited, depth + 1))}
          </div>
        );
      }

      case 'SplitGrid': {
        const kids = node.children ?? [];
        return (
          <div
            key={node.id}
            className="abw-a2ui-split"
            style={compact ? { gridTemplateColumns: '1fr' } : undefined}
          >
            {kids.map((cid) => renderNode(cid, nextVisited, depth + 1))}
          </div>
        );
      }

      case 'KpiStrip': {
        const rawItems = resolveBinding(props.items, parsed.dataModel);
        if (!Array.isArray(rawItems) || rawItems.length === 0) return null;
        return (
          <div key={node.id} className="abw-a2ui-kpi-grid">
            {rawItems.slice(0, 6).map((item, idx) => {
              const obj = (item ?? {}) as Record<string, unknown>;
              const rawTone = typeof obj.tone === 'string' ? obj.tone.trim().toLowerCase() : 'neutral';
              const tone = ALLOWED_KPI_TONES.has(rawTone) ? rawTone : 'neutral';
              return (
                <div key={idx} className={`abw-a2ui-kpi abw-a2ui-kpi-${tone}`}>
                  <span className="abw-a2ui-kpi-label">
                    {redactDisplayText(String(obj.label ?? ''), opsecMode)}
                  </span>
                  <span className="abw-a2ui-kpi-value">{String(obj.value ?? '—')}</span>
                  <span className="abw-a2ui-kpi-detail">
                    {redactDisplayText(String(obj.detail ?? ''), opsecMode)}
                  </span>
                </div>
              );
            })}
          </div>
        );
      }

      case 'Banner': {
        const rawData = resolveBinding(props.data, parsed.dataModel);
        if (!rawData || typeof rawData !== 'object') return null;
        const b = rawData as Record<string, unknown>;
        const tone = typeof b.tone === 'string' ? b.tone : 'info';
        const act = parseA2uiAction(b.action);
        const borderColor =
          tone === 'error'
            ? '#ef4444'
            : tone === 'warning'
              ? '#f97316'
              : tone === 'success'
                ? '#66efab'
                : '#38bdf8';
        const bg =
          tone === 'error'
            ? 'rgba(239, 68, 68, 0.09)'
            : tone === 'warning'
              ? 'rgba(249, 115, 22, 0.09)'
              : tone === 'success'
                ? 'rgba(102, 239, 171, 0.09)'
                : 'rgba(56, 189, 248, 0.09)';
        return (
          <div
            key={node.id}
            className="abw-alert-bar"
            style={{ borderColor: `${borderColor}66`, borderLeftColor: borderColor, background: bg }}
          >
            <div className="abw-alert-bar-body">
              <AlertTriangle size={15} color={borderColor} style={{ marginTop: 2, flexShrink: 0 }} />
              <div style={{ minWidth: 0 }}>
                <div className="abw-flex-wrap" style={{ marginBottom: 3 }}>
                  {typeof b.badge === 'string' && b.badge && (
                    <Badge
                      variant={
                        tone === 'error'
                          ? 'error'
                          : tone === 'warning'
                            ? 'orange'
                            : tone === 'success'
                              ? 'success'
                              : 'cyan'
                      }
                      label={b.badge}
                    />
                  )}
                  <strong style={{ fontSize: 13 }}>
                    {redactDisplayText(String(b.title ?? ''), opsecMode)}
                  </strong>
                </div>
                {typeof b.body === 'string' && b.body && (
                  <Text type="supporting" size="xsm" display="block">
                    {redactDisplayText(b.body, opsecMode)}
                  </Text>
                )}
              </div>
            </div>
            {act && (
              <Button
                label={act.label ?? 'Open'}
                size="sm"
                variant="secondary"
                isDisabled={act.type === 'set_triage' && readOnly}
                onClick={() => void dispatchAction(act)}
              />
            )}
          </div>
        );
      }

      case 'ExecutiveBrief': {
        const md = resolveBinding(props.markdown, parsed.dataModel);
        if (typeof md !== 'string' || !md.trim()) return null;
        const title = typeof props.title === 'string' ? props.title : 'AI Model Executive Synthesis';
        return (
          <section key={node.id} className="abw-a2ui-card">
            <div className="abw-a2ui-card-head">
              <span className="abw-a2ui-card-title">{title}</span>
              <Badge variant="cyan" label="SYNTHESIS" />
            </div>
            <div className="abw-a2ui-card-body">
              <Markdown density={compact ? 'compact' : undefined}>
                {sanitizeMarkdownClient(redactDisplayText(md, opsecMode))}
              </Markdown>
            </div>
          </section>
        );
      }

      case 'BarChart': {
        const rawSeries = resolveBinding(props.data, parsed.dataModel);
        if (!Array.isArray(rawSeries) || rawSeries.length === 0) return null;
        const series = rawSeries.slice(0, 8).map((item) => {
          const obj = (item ?? {}) as Record<string, unknown>;
          return {
            name: redactDisplayText(String(obj.name ?? ''), opsecMode),
            value: Number(obj.value ?? 0),
            detail: redactDisplayText(typeof obj.detail === 'string' ? obj.detail : '', opsecMode),
          };
        });
        const title = redactDisplayText(
          typeof props.title === 'string' ? props.title : 'Risk & Telemetry Profile',
          opsecMode
        );
        const subtitle = redactDisplayText(
          typeof props.subtitle === 'string' ? props.subtitle : '',
          opsecMode
        );
        const unit = typeof props.unit === 'string' ? props.unit : '';
        const fill = accentHex(typeof props.accent === 'string' ? props.accent : undefined);

        return (
          <section key={node.id} className="abw-a2ui-card">
            <div className="abw-a2ui-card-head">
              <div>
                <span className="abw-a2ui-card-title">{title}</span>
                {subtitle && (
                  <Text type="supporting" size="xsm" display="block" style={{ marginTop: 2 }}>
                    {subtitle}
                  </Text>
                )}
              </div>
              <Badge variant="neutral" label={`${series.length} ITEMS`} />
            </div>
            <div className="abw-a2ui-card-body" style={{ height: compact ? 195 : 225 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={series}
                  layout="vertical"
                  margin={{ top: 4, right: 16, left: 4, bottom: 4 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.14)" horizontal={false} />
                  <XAxis
                    type="number"
                    tick={{ fill: '#94a3b8', fontSize: 11 }}
                    stroke="rgba(148,163,184,0.22)"
                  />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={118}
                    tick={{ fill: '#cbd5e1', fontSize: 11, fontFamily: 'ui-monospace, monospace' }}
                    stroke="rgba(148,163,184,0.22)"
                  />
                  <Tooltip
                    contentStyle={CHART_TOOLTIP_STYLE}
                    cursor={{ fill: 'rgba(102, 239, 171, 0.06)' }}
                    formatter={(val, _name, entry) => {
                      const num = typeof val === 'number' ? val.toLocaleString() : String(val ?? '');
                      const payload = (entry as { payload?: { detail?: string } } | undefined)?.payload;
                      return [
                        `${num}${unit ? ` ${unit}` : ''}${payload?.detail ? ` — ${payload.detail}` : ''}`,
                        'Metric',
                      ];
                    }}
                  />
                  <Bar dataKey="value" barSize={16}>
                    {series.map((entry, idx) => (
                      <Cell
                        key={entry.name}
                        fill={idx === 0 ? fill : `${fill}cc`}
                        fillOpacity={Math.max(0.48, 1 - idx * 0.08)}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </section>
        );
      }

      case 'VulnTable': {
        const rawRows = resolveBinding(props.rows, parsed.dataModel);
        if (!Array.isArray(rawRows) || rawRows.length === 0) return null;
        const title = typeof props.title === 'string' ? props.title : 'Priority Vulnerabilities';

        return (
          <section key={node.id} className="abw-a2ui-card">
            <div className="abw-a2ui-card-head">
              <span className="abw-a2ui-card-title">
                <ShieldAlert size={13} color="#ef4444" />
                {title}
              </span>
              <Badge variant="neutral" label={`${rawRows.length} INTERACTIVE ROWS`} />
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table className="abw-a2ui-table">
                <thead>
                  <tr>
                    <th>CVE / Asset</th>
                    <th>Risk</th>
                    <th>CVSS / EPSS</th>
                    <th>Signals & Triage</th>
                    <th style={{ textAlign: 'right' }}>SOC Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rawRows.slice(0, 10).map((row) => {
                    const r = (row ?? {}) as Record<string, unknown>;
                    const id = String(r.id ?? '');
                    const aiRisk = Number(r.aiRisk ?? 0);
                    const sev = String(r.severity ?? 'MEDIUM');
                    const cvss = typeof r.cvss === 'number' ? r.cvss.toFixed(1) : '—';
                    const epss = typeof r.epssPct === 'number' ? `${r.epssPct.toFixed(1)}%` : '—';
                    const isKev = Boolean(r.isKev);
                    const kevDays = typeof r.kevDaysRemaining === 'number' ? r.kevDaysRemaining : null;
                    const ransomware = Boolean(r.ransomware);
                    const isAi = Boolean(r.isAi);
                    const hasExploit = Boolean(r.hasExploit);
                    const matchedStack = Array.isArray(r.matchedStack)
                      ? (r.matchedStack as string[])
                      : [];
                    const currentTriage = triageOverrides[id] ?? (String(r.triageStatus ?? 'new') as TriageStatus);
                    const isInvBusy = busyTriageKey === `${id}:investigating`;
                    const isMitBusy = busyTriageKey === `${id}:mitigated`;

                    return (
                      <tr key={id}>
                        <td style={{ minWidth: 230 }}>
                          <div className="abw-flex-wrap" style={{ marginBottom: 3 }}>
                            <button
                              type="button"
                              className="abw-cve-chip"
                              onClick={() => onOpenCve(id)}
                            >
                              {id}
                            </button>
                            <Badge variant={severityBadgeVariant(sev)} label={sev} />
                          </div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--soc-text)' }}>
                            {String(r.target ?? '')}
                          </div>
                          <div
                            style={{
                              fontSize: 11.5,
                              color: 'var(--soc-text-muted)',
                              marginTop: 2,
                              lineHeight: 1.35,
                            }}
                          >
                            {redactDisplayText(String(r.title ?? ''), opsecMode)}
                          </div>
                        </td>
                        <td>
                          <span className={scoreClass(aiRisk)}>{aiRisk}</span>
                        </td>
                        <td className="abw-mono" style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
                          <div>CVSS {cvss}</div>
                          <div style={{ color: 'var(--soc-text-muted)' }}>EPSS {epss}</div>
                        </td>
                        <td style={{ minWidth: 160 }}>
                          <div className="abw-flex-wrap">
                            {isKev && <Badge variant="error" label="KEV" />}
                            {kevDays !== null && (
                              <Badge
                                variant={kevDays < 0 ? 'error' : kevDays <= 7 ? 'warning' : 'info'}
                                label={kevDays < 0 ? `OVERDUE ${Math.abs(kevDays)}d` : `DUE ${kevDays}d`}
                              />
                            )}
                            {ransomware && <Badge variant="purple" label="RANSOMWARE" />}
                            {isAi && <Badge variant="cyan" label="AI/ML" />}
                            {hasExploit && <Badge variant="orange" label="PoC" />}
                            {matchedStack.length > 0 && (
                              <Badge variant="warning" label={`STACK: ${matchedStack[0]}`} />
                            )}
                            <Badge
                              variant={triageBadgeVariant(currentTriage)}
                              label={currentTriage.replace('_', ' ').toUpperCase()}
                            />
                          </div>
                        </td>
                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <div className="abw-flex-wrap" style={{ justifyContent: 'flex-end' }}>
                            <Button
                              label="Inspect"
                              size="sm"
                              variant="secondary"
                              icon={<Search size={11} />}
                              onClick={() => onOpenCve(id)}
                            />
                            <Button
                              label={currentTriage === 'investigating' ? 'Investigating' : 'Investigate'}
                              size="sm"
                              variant={currentTriage === 'investigating' ? 'primary' : 'secondary'}
                              isLoading={isInvBusy}
                              isDisabled={readOnly}
                              onClick={() =>
                                void dispatchAction({
                                  type: 'set_triage',
                                  cveId: id,
                                  status: 'investigating',
                                })
                              }
                            />
                            <Button
                              label={currentTriage === 'mitigated' ? 'Mitigated' : 'Mitigate'}
                              size="sm"
                              variant="secondary"
                              icon={<ShieldCheck size={11} />}
                              isLoading={isMitBusy}
                              isDisabled={readOnly}
                              onClick={() =>
                                void dispatchAction({
                                  type: 'set_triage',
                                  cveId: id,
                                  status: 'mitigated',
                                })
                              }
                            />
                            <Button
                              label="STIX"
                              size="sm"
                              variant="secondary"
                              icon={<Download size={11} />}
                              onClick={() =>
                                void dispatchAction({ type: 'export_stix', cveId: id })
                              }
                            />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        );
      }

      case 'ActionChecklist': {
        const rawItems = resolveBinding(props.items, parsed.dataModel);
        if (!Array.isArray(rawItems) || rawItems.length === 0) return null;
        const title = typeof props.title === 'string' ? props.title : 'Containment Playbook';
        const items = rawItems.slice(0, 8) as Record<string, unknown>[];
        const doneCount = items.filter((it, idx) => {
          const stepId = String(it.id ?? `step-${idx}`);
          return Boolean(checkedSteps[stepId]);
        }).length;

        return (
          <section key={node.id} className="abw-a2ui-card">
            <div className="abw-a2ui-card-head">
              <span className="abw-a2ui-card-title">
                <CheckCircle2 size={13} color="#66efab" />
                {title}
              </span>
              <Badge
                variant={doneCount === items.length ? 'success' : 'cyan'}
                label={`${doneCount}/${items.length} DONE`}
              />
            </div>
            <div className="abw-a2ui-card-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <ProgressBar
                label="Playbook completion"
                value={doneCount}
                max={Math.max(1, items.length)}
                variant={doneCount === items.length ? 'success' : 'accent'}
              />
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {items.map((it, idx) => {
                  const stepId = String(it.id ?? `step-${idx}`);
                  const checked = Boolean(checkedSteps[stepId]);
                  const priority = String(it.priority ?? 'P1');
                  const act = parseA2uiAction(it.action);
                  return (
                    <div
                      key={stepId}
                      className="abw-a2ui-step"
                      data-checked={checked}
                    >
                      <button
                        type="button"
                        className="abw-a2ui-step-toggle"
                        aria-label={`Toggle step ${String(it.title ?? idx + 1)}`}
                        onClick={() =>
                          setCheckedSteps((prev) => ({ ...prev, [stepId]: !prev[stepId] }))
                        }
                      >
                        {checked ? (
                          <CheckCircle2 size={16} color="#66efab" />
                        ) : (
                          <Circle size={16} color="#64748b" />
                        )}
                      </button>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="abw-flex-wrap" style={{ marginBottom: 2 }}>
                          <Badge
                            variant={
                              priority === 'P0' ? 'error' : priority === 'P1' ? 'orange' : 'cyan'
                            }
                            label={priority}
                          />
                          <span
                            style={{
                              fontSize: 12.5,
                              fontWeight: 600,
                              textDecoration: checked ? 'line-through' : 'none',
                              color: checked ? 'var(--soc-text-muted)' : 'var(--soc-text)',
                            }}
                          >
                            {redactDisplayText(String(it.title ?? ''), opsecMode)}
                          </span>
                        </div>
                        {typeof it.detail === 'string' && it.detail && (
                          <Text type="supporting" size="xsm" display="block">
                            {redactDisplayText(it.detail, opsecMode)}
                          </Text>
                        )}
                      </div>
                      {act && (
                        <div style={{ flexShrink: 0 }}>
                          <Button
                            label={act.label ?? 'Run'}
                            size="sm"
                            variant="secondary"
                            isDisabled={act.type === 'set_triage' && readOnly}
                            onClick={() => void dispatchAction(act)}
                          />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </section>
        );
      }

      case 'NewsFeed': {
        const rawItems = resolveBinding(props.items, parsed.dataModel);
        if (!Array.isArray(rawItems) || rawItems.length === 0) return null;
        const title = typeof props.title === 'string' ? props.title : 'Correlated Advisories';

        return (
          <section key={node.id} className="abw-a2ui-card">
            <div className="abw-a2ui-card-head">
              <span className="abw-a2ui-card-title">
                <Newspaper size={13} color="#38bdf8" />
                {title}
              </span>
              <Badge variant="neutral" label={`${rawItems.length} REPORTS`} />
            </div>
            <div className="abw-a2ui-news-grid">
              {rawItems.slice(0, 6).map((item, idx) => {
                const n = (item ?? {}) as Record<string, unknown>;
                const safeHref = safeExternalUrl(typeof n.url === 'string' ? n.url : undefined);
                const cves = Array.isArray(n.cves) ? (n.cves as string[]) : [];
                return (
                  <article key={String(n.id ?? idx)} className="abw-a2ui-news-item">
                    <div className="abw-flex-wrap" style={{ justifyContent: 'space-between', marginBottom: 4 }}>
                      <div className="abw-flex-wrap">
                        <Badge variant="cyan" label={String(n.source ?? 'Intel')} />
                        <Badge
                          variant={severityBadgeVariant(String(n.severity ?? 'INFO'))}
                          label={String(n.category ?? 'Advisory')}
                        />
                      </div>
                      {typeof n.publishedAt === 'string' && (
                        <Text type="supporting" size="xsm">
                          <Timestamp value={n.publishedAt} format="relative" />
                        </Text>
                      )}
                    </div>
                    <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 4, lineHeight: 1.35 }}>
                      {redactDisplayText(String(n.title ?? ''), opsecMode)}
                    </div>
                    {typeof n.summary === 'string' && n.summary && (
                      <Text type="supporting" size="xsm" display="block" style={{ marginBottom: 6 }}>
                        {redactDisplayText(n.summary, opsecMode)}
                      </Text>
                    )}
                    <div className="abw-flex-wrap" style={{ justifyContent: 'space-between', marginTop: 'auto' }}>
                      <div className="abw-flex-wrap">
                        {cves.slice(0, 3).map((cve) => (
                          <button
                            key={cve}
                            type="button"
                            className="abw-cve-chip"
                            onClick={() => onOpenCve(cve)}
                          >
                            {cve}
                          </button>
                        ))}
                      </div>
                      {safeHref && (
                        <a
                          href={safeHref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="abw-a2ui-ext-link"
                        >
                          Source <ExternalLink size={11} />
                        </a>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          </section>
        );
      }

      case 'IocPanel': {
        const rawNet = resolveBinding(props.data, parsed.dataModel);
        if (!rawNet || typeof rawNet !== 'object') return null;
        const net = rawNet as Record<string, unknown>;
        const c2s = Array.isArray(net.c2s) ? (net.c2s as Record<string, unknown>[]) : [];
        const ports = Array.isArray(net.ports) ? (net.ports as Record<string, unknown>[]) : [];
        const title = typeof props.title === 'string' ? props.title : 'Live Network & C2 Telemetry';

        return (
          <section key={node.id} className="abw-a2ui-card">
            <div className="abw-a2ui-card-head">
              <span className="abw-a2ui-card-title">
                <Globe size={13} color="#f97316" />
                {title}
              </span>
              <div className="abw-flex-wrap">
                {opsecMode && <Badge variant="warning" label="OPSEC REDACTED" />}
                <Badge variant="neutral" label={`INFOCON ${String(net.infocon ?? 'GREEN')}`} />
              </div>
            </div>
            <div className="abw-a2ui-card-body">
              {c2s.length > 0 ? (
                <div style={{ overflowX: 'auto' }}>
                  <table className="abw-a2ui-table">
                    <thead>
                      <tr>
                        <th>Botnet C2 IP</th>
                        <th>Port</th>
                        <th>Malware Family</th>
                        <th>Country / Status</th>
                        <th style={{ textAlign: 'right' }}>Safe Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {c2s.slice(0, 6).map((c, idx) => {
                        const rawIp = String(c.ip ?? '');
                        const shownIp = opsecMode ? redactIp(rawIp) : defangIp(rawIp);
                        const host =
                          typeof c.hostname === 'string' && c.hostname
                            ? opsecMode
                              ? redactHostname(c.hostname)
                              : c.hostname
                            : null;
                        const defanged = defangIp(rawIp);
                        const isCopied = copiedHint === (opsecMode ? redactIp(rawIp) : defanged);
                        return (
                          <tr key={`${rawIp}-${idx}`}>
                            <td className="abw-mono" style={{ fontSize: 12 }}>
                              <div>{shownIp}</div>
                              {host && (
                                <div style={{ fontSize: 10.5, color: 'var(--soc-text-muted)' }}>
                                  {host}
                                </div>
                              )}
                            </td>
                            <td className="abw-mono" style={{ fontSize: 12 }}>
                              {String(c.port ?? '')}
                            </td>
                            <td>
                              <Badge variant="error" label={String(c.malware ?? 'C2')} />
                            </td>
                            <td style={{ fontSize: 12 }}>
                              {String(c.country ?? '--')} · {String(c.status ?? 'online')}
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <Button
                                label={isCopied ? 'Copied' : 'Copy Defanged'}
                                size="sm"
                                variant="secondary"
                                icon={isCopied ? <Check size={11} /> : <Copy size={11} />}
                                onClick={() =>
                                  void dispatchAction({
                                    type: 'copy_text',
                                    text: defanged,
                                  })
                                }
                              />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : ports.length > 0 ? (
                <div className="abw-flex-wrap">
                  {ports.map((p, idx) => (
                    <Badge
                      key={idx}
                      variant="orange"
                      label={`${String(p.port ?? '')}/${String(p.service ?? '')} · ${Number(p.records ?? 0).toLocaleString()} hits`}
                    />
                  ))}
                </div>
              ) : (
                <Text type="supporting" size="sm">
                  No active botnet C2 telemetry rows in current store.
                </Text>
              )}
            </div>
          </section>
        );
      }

      case 'ActionBar': {
        const rawActions = Array.isArray(props.actions) ? props.actions : [];
        const actions = rawActions
          .map(parseA2uiAction)
          .filter((a): a is A2uiAction => a !== null);
        if (actions.length === 0) return null;
        return (
          <div key={node.id} className="abw-a2ui-actionbar">
            <span className="abw-a2ui-actionbar-label">
              <Layers size={12} /> ALLOWLISTED SOC ACTIONS
            </span>
            <div className="abw-flex-wrap">
              {actions.map((act, idx) => (
                <Button
                  key={`${act.type}-${idx}`}
                  label={act.label ?? act.type}
                  size="sm"
                  variant={idx === 0 && act.type !== 'navigate_tab' ? 'primary' : 'secondary'}
                  icon={
                    act.type === 'navigate_tab' ? (
                      <ArrowUpRight size={12} />
                    ) : act.type === 'export_stix' || act.type === 'export_md' ? (
                      <Download size={12} />
                    ) : undefined
                  }
                  isDisabled={act.type === 'set_triage' && readOnly}
                  onClick={() => void dispatchAction(act)}
                />
              ))}
            </div>
          </div>
        );
      }

      default:
        // Unknown or unapproved component types are dropped silently (A2UI security boundary)
        return null;
    }
  };

  return (
    <div className="abw-a2ui-surface" data-surface-id={surface.surface_id}>
      {parsed.title && (
        <div className="abw-a2ui-surface-header">
          <div>
            <div className="abw-a2ui-surface-title">{parsed.title}</div>
            {parsed.subtitle && (
              <Text type="supporting" size="xsm" display="block" style={{ marginTop: 2 }}>
                {redactDisplayText(parsed.subtitle, opsecMode)}
              </Text>
            )}
          </div>
          <div className="abw-flex-wrap">
            <Badge variant="success" label={`A2UI v${surface.version}`} />
            <Badge variant="neutral" label={surface.catalog_id} />
          </div>
        </div>
      )}
      {renderNode(parsed.rootId, new Set(), 0)}
    </div>
  );
}
