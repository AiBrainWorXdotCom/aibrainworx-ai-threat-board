import { useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Markdown } from '@astryxdesign/core/Markdown';
import { Spinner } from '@astryxdesign/core/Spinner';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import { Cpu, Send, Sparkles } from 'lucide-react';
import { api } from '../api';
import type { AiQueryResponse } from '../types';

interface AiAnalystViewProps {
  activeProvider: string;
  activeModel: string;
  onSelectVulnId: (id: string) => void;
  onOpenAiModels: () => void;
}

interface ChatTurn {
  id: string;
  query: string;
  response: AiQueryResponse;
}

const PRESET_PROMPTS = [
  'Summarize all critical vulnerabilities and zero-days from this past week',
  'What AI, LLM, PyTorch, LangChain, or MCP supply-chain vulnerabilities are active?',
  'Which CISA KEV vulnerabilities have known ransomware campaign linkage?',
  'What breaking exploit PoCs and advisories were published in the last 48 hours?',
  'Summarize top attacked network ports, botnet C2s, and phishing threats right now',
];

export function AiAnalystView({
  activeProvider,
  activeModel,
  onSelectVulnId,
  onOpenAiModels,
}: AiAnalystViewProps) {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [error, setError] = useState<string | null>(null);

  const submitQuery = async (promptText?: string) => {
    const q = (promptText ?? query).trim();
    if (!q || loading) return;
    setLoading(true);
    setError(null);
    if (!promptText) setQuery('');
    try {
      const resp = await api.analyzeQuery(q);
      setTurns((prev) => [{ id: String(Date.now()), query: q, response: resp }, ...prev]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
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
            Ask natural-language threat questions across all ingested CVEs, CISA KEVs, FIRST EPSS probabilities, AI/ML advisories, Exploit-DB PoCs, and breaking security news. Uses your configured local model (Ollama, LM Studio, llama.cpp) or cloud AI provider, with automatic fallback to the local Rust Threat Graph.
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
                isDisabled={loading}
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
              Correlating threat graph and querying {activeProvider} ({activeModel})...
            </Text>
          </div>
        </section>
      )}

      {error && (
        <div className="abw-alert-bar" role="alert">
          <Text>{error}</Text>
        </div>
      )}

      {turns.map((t) => (
        <section key={t.id} className="abw-panel">
          <div className="abw-panel-head">
            <div className="abw-flex-wrap">
              <Badge variant="info" label={`${t.response.provider_used} · ${t.response.model_used}`} />
              <Badge variant="neutral" label={`${t.response.latency_ms} ms`} />
            </div>
            <Text type="supporting" size="xsm">
              Matched {t.response.matched_vuln_count} CVEs · {t.response.matched_news_count} news reports
            </Text>
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

            <Markdown>{t.response.answer_markdown}</Markdown>

            {t.response.cited_cves.length > 0 && (
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
      ))}
    </div>
  );
}
