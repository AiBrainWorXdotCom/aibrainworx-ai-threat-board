import { useEffect, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Spinner } from '@astryxdesign/core/Spinner';
import { StatusDot } from '@astryxdesign/core/StatusDot';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import { Check, Cpu, RefreshCw, Save, Trash2, Zap } from 'lucide-react';
import { api } from '../api';
import type {
  AiConfigPublic,
  AiModelsResponse,
  AiProviderKind,
  AiProviderPreset,
  AiTestResponse,
} from '../types';

interface AiModelsViewProps {
  readOnly?: boolean;
  opsecMode?: boolean;
  onConfigSaved: () => void;
}

function extractApiError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  const idx = msg.indexOf('{');
  if (idx !== -1) {
    try {
      const parsed = JSON.parse(msg.slice(idx)) as { error?: string };
      if (parsed.error) return parsed.error;
    } catch {
      // fall back to raw message
    }
  }
  return msg;
}

export function AiModelsView({
  readOnly = false,
  opsecMode = false,
  onConfigSaved,
}: AiModelsViewProps) {
  const [config, setConfig] = useState<AiConfigPublic | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<AiProviderKind>('builtin');
  const [baseUrl, setBaseUrl] = useState('');
  const [model, setModel] = useState('');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [allowLan, setAllowLan] = useState(false);
  const [saveKeychain, setSaveKeychain] = useState(false);
  const [temperature, setTemperature] = useState('0.2');
  const [maxTokens, setMaxTokens] = useState('1600');
  const [timeoutSecs, setTimeoutSecs] = useState('60');
  const [systemPrompt, setSystemPrompt] = useState('');

  const [modelsResp, setModelsResp] = useState<AiModelsResponse | null>(null);
  const [fetchingModels, setFetchingModels] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<AiTestResponse | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedFlag, setSavedFlag] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    api.getAiConfig().then((cfg) => {
      setConfig(cfg);
      setSelectedProvider(cfg.provider);
      setBaseUrl(cfg.base_url);
      setModel(cfg.model);
      setAllowLan(cfg.allow_lan_endpoints);
      setSaveKeychain(cfg.save_key_to_keychain);
      setTemperature(String(cfg.temperature));
      setMaxTokens(String(cfg.max_tokens));
      setTimeoutSecs(String(cfg.timeout_secs));
      setSystemPrompt(cfg.system_prompt);
    });
  }, []);

  const currentPreset: AiProviderPreset | undefined = config?.presets.find(
    (p) => p.id === selectedProvider
  );

  const handleSelectProvider = (preset: AiProviderPreset) => {
    setSelectedProvider(preset.id);
    setModelsResp(null);
    setTestResult(null);
    setSavedFlag(false);
    setSaveError(null);
    setApiKeyInput('');

    if (config && preset.id === config.provider) {
      setBaseUrl(config.base_url);
      setModel(config.model);
    } else {
      setBaseUrl(preset.default_base_url);
      setModel(preset.default_model);
    }
  };

  const handleFetchModels = async () => {
    setFetchingModels(true);
    setModelsResp(null);
    try {
      const res = await api.listAiModels({
        provider: selectedProvider,
        base_url: baseUrl.trim() || undefined,
        api_key: apiKeyInput.trim() || undefined,
      });
      setModelsResp(res);
    } catch (err) {
      setModelsResp({
        ok: false,
        models: [],
        source: baseUrl.trim() || selectedProvider,
        error: extractApiError(err),
      });
    } finally {
      setFetchingModels(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await api.testAiConnection({
        provider: selectedProvider,
        base_url: baseUrl.trim() || undefined,
        model: model.trim() || undefined,
        api_key: apiKeyInput.trim() || undefined,
        timeout_secs: Number(timeoutSecs) || 60,
      });
      setTestResult(res);
    } catch (err) {
      setTestResult({
        ok: false,
        latency_ms: 0,
        provider_label: currentPreset?.name ?? selectedProvider,
        model: model.trim() || currentPreset?.default_model || '',
        reply: null,
        error: extractApiError(err),
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (readOnly) return;
    setSaving(true);
    setSavedFlag(false);
    setSaveError(null);
    try {
      const updated = await api.updateAiConfig({
        provider: selectedProvider,
        base_url: baseUrl.trim(),
        model: model.trim(),
        api_key: apiKeyInput.trim() || undefined,
        temperature: Number(temperature) || 0.2,
        max_tokens: Number(maxTokens) || 1600,
        timeout_secs: Number(timeoutSecs) || 60,
        system_prompt: systemPrompt.trim() || undefined,
        allow_lan_endpoints: allowLan,
        save_key_to_keychain: saveKeychain,
      });
      setConfig(updated);
      setBaseUrl(updated.base_url);
      setModel(updated.model);
      setAllowLan(updated.allow_lan_endpoints);
      setSaveKeychain(updated.save_key_to_keychain);
      setApiKeyInput('');
      setSavedFlag(true);
      onConfigSaved();
    } catch (err) {
      setSaveError(extractApiError(err));
    } finally {
      setSaving(false);
    }
  };

  const handleClearKey = async () => {
    if (readOnly) return;
    setSaving(true);
    setSaveError(null);
    try {
      const updated = await api.updateAiConfig({
        provider: selectedProvider,
        clear_api_key: true,
      });
      setConfig(updated);
      setSaveKeychain(updated.save_key_to_keychain);
      setApiKeyInput('');
      onConfigSaved();
    } catch (err) {
      setSaveError(extractApiError(err));
    } finally {
      setSaving(false);
    }
  };

  if (!config) {
    return (
      <section className="abw-panel">
        <div className="abw-panel-body" style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
          <Spinner />
          <Text>Loading AI provider & local model registry...</Text>
        </div>
      </section>
    );
  }

  const localPresets = config.presets.filter((p) => p.group === 'local');
  const cloudPresets = config.presets.filter((p) => p.group === 'cloud');
  const isEditingSavedProvider = config.provider === selectedProvider;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <Cpu size={14} color="#66efab" />
            AI Provider & Local Model Hub
          </span>
          <div className="abw-flex-wrap">
            <StatusDot variant="success" label="Active AI" isPulsing />
            <Badge variant="cyan" label={`ACTIVE: ${config.active_label}`} />
          </div>
        </div>
        <div className="abw-panel-body">
          <Text type="supporting" size="sm">
            Connect any local LLM server (Ollama, LM Studio, llama.cpp, vLLM, SGLang, LocalAI) or any cloud API (OpenAI, Anthropic Claude, Google Gemini, OpenRouter, Groq, DeepSeek, Mistral, xAI Grok, or any Custom OpenAI-compatible endpoint). If a remote/local endpoint is offline, queries automatically fall back to the built-in Rust Threat Graph.
          </Text>
        </div>
      </section>

      <div className="abw-grid-asymmetric" style={{ gridTemplateColumns: 'minmax(260px, 0.9fr) minmax(0, 1.55fr)' }}>
        {/* Left: Provider Directory */}
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">Select Provider ({config.presets.length})</span>
          </div>

          <div className="abw-rail-section">LOCAL MODELS (ZERO CLOUD)</div>
          <div>
            {localPresets.map((p) => {
              const isSelected = selectedProvider === p.id;
              const isActive = config.provider === p.id;
              return (
                <button
                  key={p.id}
                  type="button"
                  className="abw-nav-btn"
                  data-active={isSelected}
                  onClick={() => handleSelectProvider(p)}
                >
                  <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <span style={{ fontWeight: 600 }}>{p.name}</span>
                    <span className="abw-mono" style={{ fontSize: 10.5, color: 'var(--soc-text-muted)' }}>
                      {p.default_base_url || 'Built-in deterministic engine'}
                    </span>
                  </span>
                  {isActive && <Badge variant="success" label="ACTIVE" />}
                </button>
              );
            })}
          </div>

          <div className="abw-rail-section" style={{ borderTop: '1px solid var(--soc-border)', marginTop: 4 }}>
            CLOUD & CUSTOM APIS
          </div>
          <div>
            {cloudPresets.map((p) => {
              const isSelected = selectedProvider === p.id;
              const isActive = config.provider === p.id;
              return (
                <button
                  key={p.id}
                  type="button"
                  className="abw-nav-btn"
                  data-active={isSelected}
                  onClick={() => handleSelectProvider(p)}
                >
                  <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <span style={{ fontWeight: 600 }}>{p.name}</span>
                    <span className="abw-mono" style={{ fontSize: 10.5, color: 'var(--soc-text-muted)' }}>
                      {p.default_model}
                    </span>
                  </span>
                  <div className="abw-flex-wrap">
                    {p.env_key_present && <Badge variant="info" label="ENV" />}
                    {isActive && <Badge variant="success" label="ACTIVE" />}
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        {/* Right: Configuration Panel */}
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              Configure // {currentPreset?.name ?? selectedProvider}
            </span>
            {isEditingSavedProvider ? (
              <Badge variant="success" label="CURRENTLY ACTIVE" />
            ) : (
              <Badge variant="warning" label="UNSAVED SELECTION" />
            )}
          </div>

          <div className="abw-panel-body">
            {currentPreset && (
              <Text type="supporting" size="sm">
                {currentPreset.description}
              </Text>
            )}

            {selectedProvider !== 'builtin' && (
              <>
                <div>
                  <Text weight="semibold" size="xsm" display="block" style={{ marginBottom: 6 }}>
                    ENDPOINT BASE URL
                  </Text>
                  <TextInput
                    label="Base URL"
                    isLabelHidden
                    type={opsecMode ? 'password' : 'text'}
                    value={baseUrl}
                    onChange={setBaseUrl}
                    placeholder={currentPreset?.default_base_url || 'http://127.0.0.1:11434'}
                    width="100%"
                  />
                </div>

                <div>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: 6,
                      gap: 8,
                      flexWrap: 'wrap',
                    }}
                  >
                    <Text weight="semibold" size="xsm">
                      MODEL IDENTIFIER
                    </Text>
                    <Button
                      label={fetchingModels ? 'Discovering...' : 'Fetch Installed / Available Models'}
                      size="sm"
                      variant="secondary"
                      icon={<RefreshCw size={12} />}
                      isLoading={fetchingModels}
                      onClick={() => void handleFetchModels()}
                    />
                  </div>
                  <TextInput
                    label="Model name"
                    isLabelHidden
                    value={model}
                    onChange={setModel}
                    placeholder={currentPreset?.default_model || 'qwen2.5:14b'}
                    width="100%"
                  />

                  {currentPreset && currentPreset.suggested_models.length > 0 && (
                    <div className="abw-flex-wrap" style={{ marginTop: 8 }}>
                      <Text type="supporting" size="xsm">
                        Quick presets:
                      </Text>
                      {currentPreset.suggested_models.map((m) => (
                        <button
                          key={m}
                          type="button"
                          className="abw-cve-chip"
                          onClick={() => setModel(m)}
                        >
                          {m}
                        </button>
                      ))}
                    </div>
                  )}

                  {modelsResp && (
                    <div
                      style={{
                        marginTop: 10,
                        border: '1px solid var(--soc-border-strong)',
                        background: 'var(--soc-surface)',
                        padding: 10,
                      }}
                    >
                      {modelsResp.ok ? (
                        <>
                          <Text type="supporting" size="xsm" display="block" style={{ marginBottom: 6 }}>
                            Discovered {modelsResp.models.length} model(s) from {modelsResp.source} (click to select):
                          </Text>
                          {modelsResp.models.length === 0 ? (
                            <Text size="xsm">Endpoint responded OK but returned 0 loaded models.</Text>
                          ) : (
                            <div className="abw-flex-wrap" style={{ maxHeight: 140, overflowY: 'auto' }}>
                              {modelsResp.models.map((m) => (
                                <button
                                  key={m}
                                  type="button"
                                  className="abw-cve-chip"
                                  style={
                                    model === m
                                      ? {
                                          borderColor: 'var(--soc-mint)',
                                          background: 'var(--soc-mint-soft)',
                                        }
                                      : undefined
                                  }
                                  onClick={() => setModel(m)}
                                >
                                  {m}
                                </button>
                              ))}
                            </div>
                          )}
                        </>
                      ) : (
                        <Text size="xsm" color="secondary">
                          Discovery failed: {modelsResp.error}
                        </Text>
                      )}
                    </div>
                  )}
                </div>

                <div>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: 6,
                      gap: 8,
                      flexWrap: 'wrap',
                    }}
                  >
                    <Text weight="semibold" size="xsm">
                      API KEY {currentPreset?.requires_api_key ? '(REQUIRED)' : '(OPTIONAL FOR LOCAL)'}
                    </Text>
                    <div className="abw-flex-wrap">
                      {!currentPreset?.requires_api_key && (
                        <Badge variant="neutral" label="NO KEY NEEDED FOR LOCAL" />
                      )}
                      {currentPreset?.env_key_present && (
                        <Badge variant="info" label={`ENV ${currentPreset.env_var_name} SET`} />
                      )}
                      {isEditingSavedProvider && config.has_api_key && (
                        <>
                          <Badge variant="success" label={`SESSION KEY: ${config.api_key_masked}`} />
                          <Button
                            label="Clear Key"
                            size="sm"
                            variant="ghost"
                            icon={<Trash2 size={12} />}
                            onClick={() => void handleClearKey()}
                          />
                        </>
                      )}
                    </div>
                  </div>
                  <TextInput
                    label="API key"
                    isLabelHidden
                    type="password"
                    value={apiKeyInput}
                    onChange={setApiKeyInput}
                    placeholder={
                      isEditingSavedProvider && config.has_api_key
                        ? 'Leave blank to keep session key, or enter new key to replace'
                        : currentPreset?.requires_api_key
                          ? `Enter API key (or set ${currentPreset.env_var_name ?? 'env var'})`
                          : 'Optional bearer token for secured local proxies (or CUSTOM_AI_API_KEY)'
                    }
                    width="100%"
                  />
                  <Text type="supporting" size="xsm" display="block" style={{ marginTop: 6 }}>
                    Session-only by default: UI-entered keys stay in server RAM only and are never written to SQLite/disk. Opt in to OS Keychain below to securely persist credentials across restarts.
                  </Text>

                  <div
                    style={{
                      marginTop: 10,
                      padding: 10,
                      border: '1px solid var(--soc-border)',
                      background: 'var(--soc-surface)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 8,
                    }}
                  >
                    <label
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 8,
                        fontSize: 12.5,
                        cursor: readOnly || !config.keychain_available ? 'not-allowed' : 'pointer',
                      }}
                    >
                      <span>
                        <input
                          type="checkbox"
                          checked={saveKeychain}
                          disabled={readOnly || !config.keychain_available}
                          onChange={(e) => setSaveKeychain(e.target.checked)}
                          style={{ marginRight: 8 }}
                        />
                        Save API Key to OS Keychain (Credential Manager / macOS Keychain / Secret Service)
                      </span>
                      <Badge
                        variant={
                          !config.keychain_available
                            ? 'warning'
                            : config.keychain_has_key
                              ? 'success'
                              : 'info'
                        }
                        label={
                          !config.keychain_available
                            ? 'KEYCHAIN UNAVAILABLE'
                            : config.keychain_has_key
                              ? 'STORED IN KEYCHAIN'
                              : 'KEYCHAIN READY'
                        }
                      />
                    </label>

                    <label
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 8,
                        fontSize: 12.5,
                        cursor: readOnly ? 'not-allowed' : 'pointer',
                      }}
                    >
                      <span>
                        <input
                          type="checkbox"
                          checked={allowLan}
                          disabled={readOnly}
                          onChange={(e) => setAllowLan(e.target.checked)}
                          style={{ marginRight: 8 }}
                        />
                        Allow Private LAN AI Endpoints (e.g. 192.168.x.x / 10.x Ollama or LM Studio)
                      </span>
                      <Badge
                        variant={allowLan ? 'warning' : 'success'}
                        label={allowLan ? 'LAN OPT-IN ON' : 'LOOPBACK + HTTPS ONLY'}
                      />
                    </label>
                  </div>
                </div>
              </>
            )}

            <div className="abw-grid-3">
              <div className="abw-grid-3-cell">
                <Text type="supporting" size="xsm" display="block" style={{ marginBottom: 4 }}>
                  TEMPERATURE
                </Text>
                <TextInput
                  label="Temperature"
                  isLabelHidden
                  value={temperature}
                  onChange={setTemperature}
                  width="100%"
                />
              </div>
              <div className="abw-grid-3-cell">
                <Text type="supporting" size="xsm" display="block" style={{ marginBottom: 4 }}>
                  MAX TOKENS
                </Text>
                <TextInput
                  label="Max tokens"
                  isLabelHidden
                  value={maxTokens}
                  onChange={setMaxTokens}
                  width="100%"
                />
              </div>
              <div className="abw-grid-3-cell">
                <Text type="supporting" size="xsm" display="block" style={{ marginBottom: 4 }}>
                  TIMEOUT (SECONDS)
                </Text>
                <TextInput
                  label="Timeout seconds"
                  isLabelHidden
                  value={timeoutSecs}
                  onChange={setTimeoutSecs}
                  width="100%"
                />
              </div>
            </div>

            <div>
              <Text weight="semibold" size="xsm" display="block" style={{ marginBottom: 6 }}>
                SOC ANALYST SYSTEM PROMPT
              </Text>
              <textarea
                aria-label="SOC Analyst System Prompt"
                disabled={readOnly}
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
                rows={3}
                style={{
                  width: '100%',
                  padding: '8px 10px',
                  border: '1px solid var(--soc-border-strong)',
                  background: 'var(--soc-surface)',
                  color: 'var(--soc-text)',
                  fontFamily: 'var(--font-family-code, ui-monospace, monospace)',
                  fontSize: 12,
                  resize: 'vertical',
                }}
              />
            </div>

            <div className="abw-flex-wrap" style={{ gap: 10 }}>
              <Button
                label={testing ? 'Testing...' : 'Test Connection'}
                variant="secondary"
                icon={<Zap size={13} />}
                isLoading={testing}
                isDisabled={readOnly}
                onClick={() => void handleTest()}
              />
              <Button
                label="Save & Activate Provider"
                variant="primary"
                icon={<Save size={13} />}
                isLoading={saving}
                isDisabled={readOnly}
                onClick={() => void handleSave()}
              />
              {savedFlag && (
                <span className="abw-flex-wrap" style={{ color: 'var(--soc-mint)', fontSize: 12 }}>
                  <Check size={14} /> Provider saved & active
                </span>
              )}
            </div>

            {saveError && (
              <div
                className="abw-alert-bar"
                role="alert"
                style={{
                  borderColor: 'rgba(239, 68, 68, 0.5)',
                  borderLeftColor: '#ef4444',
                  background: 'var(--soc-red-bg)',
                }}
              >
                <div>
                  <div className="abw-mono" style={{ fontWeight: 700, fontSize: 12, marginBottom: 4 }}>
                    CONFIGURATION REJECTED
                  </div>
                  <Text size="xsm" display="block">
                    {saveError}
                  </Text>
                </div>
              </div>
            )}

            {testResult && (
              <div
                className="abw-alert-bar"
                style={{
                  borderColor: testResult.ok
                    ? 'rgba(102, 239, 171, 0.5)'
                    : 'rgba(239, 68, 68, 0.5)',
                  borderLeftColor: testResult.ok ? '#66efab' : '#ef4444',
                  background: testResult.ok ? 'var(--soc-mint-soft)' : 'var(--soc-red-bg)',
                }}
              >
                <div>
                  <div className="abw-mono" style={{ fontWeight: 700, fontSize: 12, marginBottom: 4 }}>
                    {testResult.ok
                      ? `CONNECTED · ${testResult.provider_label} (${testResult.model}) · ${testResult.latency_ms} ms`
                      : `CONNECTION FAILED · ${testResult.provider_label} (${testResult.model})`}
                  </div>
                  <Text size="xsm" display="block">
                    {testResult.ok ? testResult.reply : testResult.error}
                  </Text>
                </div>
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
