import { useEffect, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { EmptyState } from '@astryxdesign/core/EmptyState';
import { Spinner } from '@astryxdesign/core/Spinner';
import { Text } from '@astryxdesign/core/Text';
import { TextInput } from '@astryxdesign/core/TextInput';
import { Layers, PackageCheck, Search, ShieldAlert, Trash2, Upload } from 'lucide-react';
import { api, severityBadgeVariant } from '../api';
import type { MyStackPayload, Vulnerability } from '../types';

interface MyStackViewProps {
  readOnly: boolean;
  onSelectVuln: (v: Vulnerability) => void;
  onStackUpdated?: () => void;
}

export function MyStackView({ readOnly, onSelectVuln, onStackUpdated }: MyStackViewProps) {
  const [payload, setPayload] = useState<MyStackPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [importing, setImporting] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const [vendorsText, setVendorsText] = useState('');
  const [productsText, setProductsText] = useState('');
  const [keywordsText, setKeywordsText] = useState('');

  const [manifestName, setManifestName] = useState('package-lock.json');
  const [manifestText, setManifestText] = useState('');
  const [replaceExisting, setReplaceExisting] = useState(true);
  const [compFilter, setCompFilter] = useState('');

  const syncFromPayload = (res: MyStackPayload) => {
    setPayload(res);
    setVendorsText(res.config.vendors.join(', '));
    setProductsText(res.config.products.join(', '));
    setKeywordsText(res.config.keywords.join(', '));
  };

  useEffect(() => {
    setLoading(true);
    api
      .getStack()
      .then(syncFromPayload)
      .catch((e) => setErrMsg(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const parseCsvTerms = (raw: string) =>
    raw
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length >= 2);

  const handleSaveWatchlist = async () => {
    setSaving(true);
    setErrMsg(null);
    setStatusMsg(null);
    try {
      const updated = await api.updateStack({
        vendors: parseCsvTerms(vendorsText),
        products: parseCsvTerms(productsText),
        keywords: parseCsvTerms(keywordsText),
      });
      syncFromPayload(updated);
      setStatusMsg(
        `Watchlist saved & correlated: ${updated.summary.matched_vuln_count} exposed CVEs found.`
      );
      onStackUpdated?.();
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const handleImportText = async () => {
    if (!manifestText.trim()) {
      setErrMsg('Paste a lockfile/SBOM manifest or choose a local file first.');
      return;
    }
    setImporting(true);
    setErrMsg(null);
    setStatusMsg(null);
    try {
      const res = await api.importStack(manifestName || 'manifest.json', manifestText, replaceExisting);
      const refreshed = await api.getStack();
      syncFromPayload(refreshed);
      setStatusMsg(
        `Parsed ${res.format_detected}: ${res.imported_components} packages (${res.total_components} total) -> ${res.matched_vulnerabilities} matched CVEs.`
      );
      onStackUpdated?.();
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setImporting(false);
    }
  };

  const handleFileUpload = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      setErrMsg('Selected manifest exceeds the 2 MB local import limit.');
      return;
    }
    const content = await file.text();
    setManifestName(file.name);
    setManifestText(content);
    setImporting(true);
    setErrMsg(null);
    setStatusMsg(null);
    try {
      const res = await api.importStack(file.name, content, replaceExisting);
      const refreshed = await api.getStack();
      syncFromPayload(refreshed);
      setStatusMsg(
        `Imported ${file.name} (${res.format_detected}): ${res.imported_components} packages -> ${res.matched_vulnerabilities} matched CVEs.`
      );
      onStackUpdated?.();
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setImporting(false);
    }
  };

  const handleClear = async () => {
    setSaving(true);
    setErrMsg(null);
    setStatusMsg(null);
    try {
      const cleared = await api.clearStack();
      syncFromPayload(cleared);
      setManifestText('');
      setStatusMsg('Cleared My Stack inventory and watchlist.');
      onStackUpdated?.();
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="abw-panel" style={{ padding: 40, display: 'flex', justifyContent: 'center' }}>
        <Spinner size="md" />
      </div>
    );
  }

  const summary = payload?.summary;
  const matchedVulns = payload?.matched_vulnerabilities ?? [];
  const components = payload?.config.components ?? [];
  const filteredComps = components
    .filter((c) =>
      !compFilter.trim()
        ? true
        : `${c.name} ${c.ecosystem} ${c.version}`.toLowerCase().includes(compFilter.toLowerCase())
    )
    .slice(0, 120);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <Layers size={14} color="#66efab" />
            My Stack — 100% Local SBOM & Watchlist Correlation
          </span>
          <div className="abw-flex-wrap">
            <Badge
              variant={summary && summary.matched_vuln_count > 0 ? 'error' : 'success'}
              label={`${summary?.matched_vuln_count ?? 0} Exposed CVEs`}
            />
            <Badge
              variant={summary && summary.matched_kev_count > 0 ? 'warning' : 'neutral'}
              label={`${summary?.matched_kev_count ?? 0} Active KEVs`}
            />
            <Badge variant="info" label={`${summary?.component_count ?? 0} Packages`} />
          </div>
        </div>
        <div className="abw-panel-body">
          <Text type="supporting" size="xsm">
            Zero telemetry leaves your machine: dependencies, SBOMs, and lockfiles are parsed locally inside Rust and correlated strictly in-memory/SQLite against live CVE feeds.
          </Text>
          {statusMsg && (
            <div style={{ border: '1px solid #166534', background: 'rgba(22,101,52,0.16)', padding: '8px 10px', fontSize: 12, color: '#86efac' }}>
              {statusMsg}
            </div>
          )}
          {errMsg && (
            <div style={{ border: '1px solid #991b1b', background: 'rgba(153,27,27,0.18)', padding: '8px 10px', fontSize: 12, color: '#fca5a5' }}>
              {errMsg}
            </div>
          )}
        </div>
      </section>

      <div className="abw-grid-2">
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              <Upload size={14} color="#38bdf8" />
              Import SBOM or Lockfile (Max 2 MB)
            </span>
          </div>
          <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <Text type="supporting" size="xsm">
              Auto-detects CycloneDX JSON, SPDX JSON, package-lock.json, package.json, Cargo.lock, Cargo.toml, requirements.txt, pyproject.toml, go.mod, and pom.xml.
            </Text>

            <div className="abw-flex-wrap" style={{ alignItems: 'center', justifyContent: 'space-between' }}>
              <label
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '6px 10px',
                  border: '1px solid var(--soc-border)',
                  background: 'var(--soc-surface-elevated)',
                  cursor: readOnly ? 'not-allowed' : 'pointer',
                  fontSize: 12,
                }}
              >
                <Upload size={13} />
                Choose Local File
                <input
                  type="file"
                  disabled={readOnly || importing}
                  style={{ display: 'none' }}
                  onChange={(e) => handleFileUpload(e.target.files?.[0])}
                />
              </label>

              <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={replaceExisting}
                  disabled={readOnly}
                  onChange={(e) => setReplaceExisting(e.target.checked)}
                />
                Replace existing package list
              </label>
            </div>

            <TextInput
              label="Manifest filename hint"
              value={manifestName}
              onChange={setManifestName}
              placeholder="package-lock.json / bom.json / Cargo.lock / requirements.txt"
              width="100%"
            />

            <textarea
              className="abw-textarea"
              rows={6}
              disabled={readOnly}
              value={manifestText}
              onChange={(e) => setManifestText(e.target.value)}
              placeholder='Paste CycloneDX SBOM, package-lock.json, Cargo.lock, requirements.txt, go.mod, or pom.xml...'
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

            <div className="abw-flex-wrap">
              <Button
                label={importing ? 'Parsing...' : 'Parse & Correlate'}
                variant="primary"
                size="sm"
                icon={<PackageCheck size={13} />}
                isLoading={importing}
                isDisabled={readOnly}
                onClick={handleImportText}
              />
              <Button
                label="Clear Stack"
                variant="destructive"
                size="sm"
                icon={<Trash2 size={13} />}
                isDisabled={readOnly || saving}
                onClick={handleClear}
              />
            </div>
          </div>
        </section>

        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              <ShieldAlert size={14} color="#f97316" />
              Infrastructure & Vendor Watchlist
            </span>
          </div>
          <div className="abw-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <Text type="supporting" size="xsm">
              Track proprietary appliances, OS platforms, AI runtimes, or SaaS vendors that do not appear in language lockfiles.
            </Text>

            <TextInput
              label="Watched Vendors (comma-separated)"
              value={vendorsText}
              onChange={setVendorsText}
              placeholder="e.g. Microsoft, Fortinet, Palo Alto, OpenSSL, Cisco"
              width="100%"
            />

            <TextInput
              label="Watched Products (comma-separated)"
              value={productsText}
              onChange={setProductsText}
              placeholder="e.g. pan-os, nginx, exchange, confluence, torch, vllm"
              width="100%"
            />

            <TextInput
              label="Extra Stack Keywords (comma-separated)"
              value={keywordsText}
              onChange={setKeywordsText}
              placeholder="e.g. mcp, kubernetes, postgres, langchain"
              width="100%"
            />

            <div style={{ marginTop: 4 }}>
              <Button
                label={saving ? 'Correlating...' : 'Save Watchlist & Re-Correlate'}
                variant="primary"
                size="sm"
                isLoading={saving}
                isDisabled={readOnly}
                onClick={handleSaveWatchlist}
              />
            </div>
          </div>
        </section>
      </div>

      <section className="abw-panel">
        <div className="abw-panel-head">
          <span className="abw-panel-title">
            <ShieldAlert size={14} color="#ef4444" />
            Exposed Vulnerabilities in Your Stack ({matchedVulns.length})
          </span>
        </div>
        <div className="abw-table-wrap">
          {matchedVulns.length === 0 ? (
            <EmptyState
              title="No matching stack vulnerabilities"
              description="Upload an SBOM/lockfile or add vendor/product watch terms above to highlight direct exposure across your stack."
            />
          ) : (
            <table className="abw-table">
              <thead>
                <tr>
                  <th>AI Risk</th>
                  <th>CVE</th>
                  <th>Severity</th>
                  <th>Matched Stack</th>
                  <th>CVSS / EPSS</th>
                  <th>Triage</th>
                  <th>Summary</th>
                </tr>
              </thead>
              <tbody>
                {matchedVulns.map((v) => (
                  <tr key={v.id} onClick={() => onSelectVuln(v)} style={{ cursor: 'pointer' }}>
                    <td>
                      <strong>{v.ai_risk_score}</strong>
                    </td>
                    <td>
                      <div className="abw-flex-wrap" style={{ gap: 4 }}>
                        <code className="abw-mono" style={{ color: '#66efab', fontWeight: 600 }}>
                          {v.id}
                        </code>
                        {v.is_kev && <Badge variant="error" label="KEV" />}
                      </div>
                    </td>
                    <td>
                      <Badge variant={severityBadgeVariant(v.severity)} label={v.severity} />
                    </td>
                    <td>
                      <div className="abw-flex-wrap" style={{ gap: 4 }}>
                        {(v.matched_stack ?? []).map((tag) => (
                          <Badge key={tag} variant="warning" label={tag} />
                        ))}
                      </div>
                    </td>
                    <td className="abw-mono" style={{ fontSize: 12 }}>
                      {v.cvss_score != null ? v.cvss_score.toFixed(1) : '--'} /{' '}
                      {v.epss_score != null ? `${(v.epss_score * 100).toFixed(1)}%` : '--'}
                    </td>
                    <td>
                      <Badge variant="neutral" label={(v.triage_status || 'new').toUpperCase()} />
                    </td>
                    <td>{v.title}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {components.length > 0 && (
        <section className="abw-panel">
          <div className="abw-panel-head">
            <span className="abw-panel-title">
              <PackageCheck size={14} color="#66efab" />
              Parsed Local Package Inventory ({components.length})
            </span>
            <div style={{ width: 240 }}>
              <TextInput
                label="Filter packages"
                isLabelHidden
                value={compFilter}
                onChange={setCompFilter}
                placeholder="Filter packages..."
                startIcon={<Search size={13} />}
                hasClear
                width="100%"
              />
            </div>
          </div>
          <div className="abw-table-wrap" style={{ maxHeight: 320, overflowY: 'auto' }}>
            <table className="abw-table">
              <thead>
                <tr>
                  <th>Package / Component</th>
                  <th>Version</th>
                  <th>Ecosystem</th>
                  <th>Source Manifest</th>
                </tr>
              </thead>
              <tbody>
                {filteredComps.map((c, idx) => (
                  <tr key={`${c.ecosystem}-${c.name}-${c.version}-${idx}`}>
                    <td className="abw-mono" style={{ fontWeight: 600 }}>
                      {c.name}
                    </td>
                    <td className="abw-mono">{c.version || '--'}</td>
                    <td>
                      <Badge variant="neutral" label={c.ecosystem.toUpperCase()} />
                    </td>
                    <td style={{ fontSize: 12 }}>{c.source_file}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
