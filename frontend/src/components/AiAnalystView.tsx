import { useState } from 'react';
import { useToast } from '@astryxdesign/core';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Markdown } from '@astryxdesign/core/Markdown';
import { Spinner } from '@astryxdesign/core/Spinner';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import { Code2, Copy, Cpu, FileText, LayoutGrid, Send, Sparkles } from 'lucide-react';
import { api } from '../api';
import type { AiQueryResponse, NavTab } from '../types';
import { redactDisplayText, sanitizeMarkdownClient } from '../utils/opsec';
import { A2uiRenderer } from './A2uiRenderer';

interface AiAnalystViewProps {
  activeProvider: string;
  activeModel: string;
  opsecMode?: boolean;
  readOnly?: boolean;
  onSelectVulnId: (id: string) => void;
  onNavigate?: (tab: NavTab) => void;
  onTriageUpdated?: () => void;
  onOpenAiModels: () => void;
}

type TurnViewMode = 'a2ui' | 'markdown' | 'json';

interface ChatTurn {
  id: string;
  query: string;
  response: AiQueryResponse;
  viewMode: TurnViewMode;
}

const PRESET_PROMPTS = [
  'Summarize all critical vulnerabilities and zero-days from this past week',
  'What AI, LLM, PyTorch, LangChain, or MCP supply-chain vulnerabilities are active?',
  'Which CISA KEV vulnerabilities have known ransomware campaign linkage?',
  'What breaking exploit PoCs and advisories were published in the last 48 hours?',
  'Summarize top attacked network ports, botnet C2s, and phishing threats right now',
  'Check my stack exposure and top priority fixes right now',
];

export function AiAnalystView({
  activeProvider,
  activeModel,
  opsecMode = false,
  readOnly = false,
  onSelectVulnId,
  onNavigate,
  onTriageUpdated,
  onOpenAiModels,
}: AiAnalystViewProps) {
  const toast = useToast();
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [error, setError] = useState<string | null>(null);

  const submitQuery = async (promptText?: string) => {
    const q = (promptText ?? query).trim();
    if (!q || loading || readOnly) return;
    setLoading(true);
    setError(null);
    if (!promptText) setQuery('');
    try {
      const resp = await api.analyzeQuery(q);
      setTurns((prev) => [
        {
          id: String(Date.now()),
          query: q,
          response: resp,
          viewMode: resp.a2ui ? 'a2ui' : 'markdown',
        },
        ...prev,
      ]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const setTurnViewMode = (turnId: string, mode: TurnViewMode) => {
    setTurns((prev) => prev.map((t) => (t.id === turnId ? { ...t, viewMode: mode } : t)));
  };

  const handleNotify = (message: string, tone: 'info' | 'success' | 'error' = 'info') => {
    toast({
      type: tone === 'error' ? 'error' : 'info',
      body: message,
    });
  };

  const handleCopyJson = async (turn: ChatTurn) => {
    if (!turn.response.a2ui) return;
    const raw = JSON.stringify(turn.response.a2ui, null, 2);
    const safe = opsecMode ? redactDisplayText(raw, true) : raw;
    try {
      await navigator.clipboard.writeText(safe);
      handleNotify('Copied A2UI 1.0 envelope JSON to clipboard', 'info');
    } catch {
      handleNotify('Clipboard unavailable in this browser context', 'error');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <Sparkles size={14} color="#66efab" />
            AiBrainWorX AI Threat Intelligence Analyst
          </span>
          <div className="abw-flex-wrap">
            <Badge variant="success" label="A2UI 1.0 INTERACTIVE SURFACES" />
            <Badge variant="cyan" label={`${activeProvider} · ${activeModel}`} />
            <Button
              label="Configure Provider / Local Models"
              size="sm"
              variant="secondary"
              icon={<Cpu size={12} />}
              onClick={onOpenAiModels}
            />
          </div>
        </div>
        <div className="abw-panel-body">
          <Text type="supporting" size="sm">
            Ask natural-language threat questions across all ingested CVEs, CISA KEVs, FIRST EPSS probabilities, AI/ML advisories, Exploit-DB PoCs, and breaking security news. Responses render as declarative, zero-HTML{' '}
            <strong>A2UI 1.0 Interactive SOC Surfaces</strong> (strictly allowlisted Meta Astryx widgets, Recharts profiles, live triage actions &amp; containment checklists) with one-click Markdown and raw A2UI JSON inspection.
          </Text>

          <div className="abw-flex-wrap" style={{ gap: 8 }}>
            <div style={{ flex: '1 1 420px' }}>
              <TextInput
                label="Threat analyst question"
                isLabelHidden
                value={query}
                onChange={setQuery}
                onEnter={() => void submitQuery()}
                placeholder="Ask e.g. 'What Synology, Cisco, or AI/LLM vulnerabilities hit CISA KEV this week?'"
                hasClear
                width="100%"
              />
            </div>
            <Button
              label="Analyze"
              variant="primary"
              icon={<Send size={13} />}
              isLoading={loading}
              isDisabled={readOnly}
              onClick={() => void submitQuery()}
            />
          </div>

          <div className="abw-flex-wrap">
            {PRESET_PROMPTS.map((p) => (
              <Button
                key={p}
                label={p}
                size="sm"
                variant="secondary"
                isDisabled={loading || readOnly}
                onClick={() => void submitQuery(p)}
              />
            ))}
          </div>
        </div>
      </section>

      {loading && (
        <section className="abw-panel">
          <div className="abw-panel-body" style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
            <Spinner />
            <Text>
              Correlating threat graph, validating A2UI 1.0 surface catalog, and querying {activeProvider} ({activeModel})...
            </Text>
          </div>
        </section>
      )}

      {error && (
        <div className="abw-alert-bar" role="alert">
          <Text>{error}</Text>
        </div>
      )}

      {turns.map((t) => {
        const hasA2ui = Boolean(t.response.a2ui);
        return (
          <section key={t.id} className="abw-panel">
            <div className="abw-panel-head">
              <div className="abw-flex-wrap">
                <Badge variant="info" label={`${t.response.provider_used} · ${t.response.model_used}`} />
                <Badge variant="neutral" label={`${t.response.latency_ms} ms`} />
                <Text type="supporting" size="xsm">
                  Matched {t.response.matched_vuln_count} CVEs · {t.response.matched_news_count} news
                </Text>
              </div>
              <div className="abw-flex-wrap">
                {hasA2ui && (
                  <div className="abw-a2ui-mode-tabs" role="tablist" aria-label="Response render mode">
                    <button
                      type="button"
                      role="tab"
                      aria-selected={t.viewMode === 'a2ui'}
                      className="abw-a2ui-mode-tab"
                      data-active={t.viewMode === 'a2ui'}
                      onClick={() => setTurnViewMode(t.id, 'a2ui')}
                    >
                      <LayoutGrid size={12} />
                      Interactive A2UI
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={t.viewMode === 'markdown'}
                      className="abw-a2ui-mode-tab"
                      data-active={t.viewMode === 'markdown'}
                      onClick={() => setTurnViewMode(t.id, 'markdown')}
                    >
                      <FileText size={12} />
                      Markdown
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={t.viewMode === 'json'}
                      className="abw-a2ui-mode-tab"
                      data-active={t.viewMode === 'json'}
                      onClick={() => setTurnViewMode(t.id, 'json')}
                    >
                      <Code2 size={12} />
                      A2UI JSON
                    </button>
                  </div>
                )}
              </div>
            </div>
            <div className="abw-panel-body">
              {t.response.fallback_reason && (
                <div
                  className="abw-alert-bar"
                  style={{
                    borderColor: 'rgba(245, 158, 11, 0.5)',
                    borderLeftColor: '#f59e0b',
                    background: 'rgba(245, 158, 11, 0.08)',
                  }}
                >
                  <Text size="xsm">
                    External/local model fallback to Built-in Rust Engine: {t.response.fallback_reason}
                  </Text>
                </div>
              )}

              {t.response.a2ui && (
                <div style={{ display: t.viewMode === 'a2ui' ? 'block' : 'none' }}>
                  <A2uiRenderer
                    surface={t.response.a2ui}
                    opsecMode={opsecMode}
                    readOnly={readOnly}
                    onOpenCve={onSelectVulnId}
                    onNavigate={onNavigate}
                    onTriageUpdated={onTriageUpdated}
                    onNotify={handleNotify}
                  />
                </div>
              )}

              {t.viewMode === 'json' && t.response.a2ui && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div className="abw-flex-wrap" style={{ justifyContent: 'space-between' }}>
                    <Text type="supporting" size="xsm">
                      Declarative A2UI 1.0 <code>agent_to_renderer</code> wire envelope (catalog{' '}
                      <code>{t.response.a2ui.catalog_id}</code> · zero HTML/JS · <code>@path</code> data bindings)
                    </Text>
                    <Button
                      label="Copy Envelope JSON"
                      size="sm"
                      variant="secondary"
                      icon={<Copy size={12} />}
                      onClick={() => void handleCopyJson(t)}
                    />
                  </div>
                  <pre className="abw-a2ui-json-pre">
                    {redactDisplayText(JSON.stringify(t.response.a2ui, null, 2), opsecMode)}
                  </pre>
                </div>
              )}

              {(!t.response.a2ui || t.viewMode === 'markdown') && (
                <Markdown>{sanitizeMarkdownClient(redactDisplayText(t.response.answer_markdown, opsecMode))}</Markdown>
              )}

              {t.response.cited_cves.length > 0 && t.viewMode !== 'a2ui' && (
                <div style={{ borderTop: '1px solid var(--soc-border)', paddingTop: 10 }}>
                  <Text type="supporting" size="xsm" display="block" style={{ marginBottom: 6 }}>
                    INSPECT CITED VULNERABILITIES
                  </Text>
                  <div className="abw-flex-wrap">
                    {t.response.cited_cves.map((cve) => (
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
              )}
            </div>
          </section>
        );
      })}
    </div>
  );
}
