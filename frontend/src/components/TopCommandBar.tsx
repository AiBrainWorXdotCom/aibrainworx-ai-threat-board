import { useEffect, useState } from 'react';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { StatusDot } from '@astryxdesign/core/StatusDot';
import {
  Bell,
  BellRing,
  Moon,
  RefreshCw,
  Sun,
  Volume2,
  VolumeX,
} from 'lucide-react';

interface TopCommandBarProps {
  infoconStatus: string;
  threatIndex: number;
  threatLabel: string;
  nextSweepAt: string | null;
  lastSweepAt: string | null;
  sweepInProgress: boolean;
  sseConnected: boolean;
  unacknowledgedAlerts: number;
  activeAiProvider: string;
  activeAiModel: string;
  soundEnabled: boolean;
  darkMode: boolean;
  onToggleSound: () => void;
  onToggleDarkMode: () => void;
  onEnableDesktopAlerts: () => void;
  onRefreshNow: () => void;
  onOpenAlerts: () => void;
  onOpenAiModels: () => void;
}

function formatCountdown(targetIso: string | null, nowMs: number): string {
  if (!targetIso) return '60:00';
  const diffSec = Math.max(0, Math.floor((new Date(targetIso).getTime() - nowMs) / 1000));
  const mins = Math.floor(diffSec / 60);
  const secs = diffSec % 60;
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

export function TopCommandBar({
  infoconStatus,
  threatIndex,
  threatLabel,
  nextSweepAt,
  lastSweepAt,
  sweepInProgress,
  sseConnected,
  unacknowledgedAlerts,
  activeAiProvider,
  activeAiModel,
  soundEnabled,
  darkMode,
  onToggleSound,
  onToggleDarkMode,
  onEnableDesktopAlerts,
  onRefreshNow,
  onOpenAlerts,
  onOpenAiModels,
}: TopCommandBarProps) {
  const [nowMs, setNowMs] = useState(() => Date.now());

  useEffect(() => {
    const id = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const infoconLower = infoconStatus.toLowerCase();
  const infoconVariant =
    infoconLower === 'red'
      ? 'error'
      : infoconLower === 'orange'
        ? 'orange'
        : infoconLower === 'yellow'
          ? 'warning'
          : 'success';

  const indexDotVariant =
    threatIndex >= 80
      ? 'error'
      : threatIndex >= 62
        ? 'warning'
        : threatIndex >= 40
          ? 'accent'
          : 'success';

  return (
    <header className="abw-topbar">
      <div className="abw-brand">
        <img
          src="/aibrainworx-logo.png"
          alt="AiBrainWorX"
          className="abw-wordmark"
        />
        <span className="abw-brand-divider" aria-hidden="true" />
        <span className="abw-brand-ops">THREAT OPS // AI CYBER ANALYSIS</span>
      </div>

      <div className="abw-topbar-right">
        <div className="abw-instrument-strip">
          <div className="abw-inst-cell" title="Real-time Server-Sent Events stream status">
            <StatusDot
              variant={sseConnected ? 'success' : 'warning'}
              label={sseConnected ? 'SSE Live' : 'Reconnecting'}
              isPulsing={sseConnected}
            />
            <span className="abw-inst-label">SSE</span>
            <strong>{sseConnected ? 'LIVE' : 'SYNC'}</strong>
          </div>

          <div className="abw-inst-cell" title="SANS Internet Storm Center INFOCON Threat Level">
            <span className="abw-inst-label">INFOCON</span>
            <Badge variant={infoconVariant} label={infoconStatus.toUpperCase()} />
          </div>

          <div className="abw-inst-cell" title="AiBrainWorX AI Composite Global Threat Posture Index">
            <StatusDot variant={indexDotVariant} label={threatLabel} isPulsing={threatIndex >= 70} />
            <span className="abw-inst-label">INDEX</span>
            <strong>{threatIndex}/100</strong>
            <Badge
              variant={
                threatIndex >= 80
                  ? 'error'
                  : threatIndex >= 62
                    ? 'orange'
                    : threatIndex >= 40
                      ? 'warning'
                      : 'success'
              }
              label={threatLabel}
            />
          </div>

          <div
            className="abw-inst-cell"
            title={
              lastSweepAt
                ? `Last synced: ${new Date(lastSweepAt).toLocaleString()}`
                : 'Initial sweep running'
            }
          >
            <span className="abw-inst-label">NEXT SYNC</span>
            <strong>{sweepInProgress ? 'SCANNING' : formatCountdown(nextSweepAt, nowMs)}</strong>
          </div>

          <button
            type="button"
            className="abw-inst-cell"
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--soc-text)',
              cursor: 'pointer',
            }}
            title="Configure AI provider or local models (Ollama, LM Studio, OpenAI, Claude, Gemini, Custom)"
            onClick={onOpenAiModels}
          >
            <span className="abw-inst-label">AI</span>
            <strong style={{ color: 'var(--soc-mint)' }}>
              {activeAiProvider === 'Built-in Rust Engine'
                ? 'RUST ENGINE'
                : `${activeAiProvider} · ${activeAiModel}`}
            </strong>
          </button>
        </div>

        <Button
          label={sweepInProgress ? 'Scanning' : 'Scan Now'}
          variant="primary"
          size="sm"
          icon={<RefreshCw size={13} />}
          isLoading={sweepInProgress}
          onClick={onRefreshNow}
        />

        <Button
          label="Alerts"
          variant={unacknowledgedAlerts > 0 ? 'destructive' : 'secondary'}
          size="sm"
          icon={unacknowledgedAlerts > 0 ? <BellRing size={13} /> : <Bell size={13} />}
          endContent={
            <Badge
              variant={unacknowledgedAlerts > 0 ? 'error' : 'neutral'}
              label={unacknowledgedAlerts}
            />
          }
          onClick={onOpenAlerts}
        />

        <Button
          label={soundEnabled ? 'Mute alert chime' : 'Enable alert chime'}
          variant="secondary"
          size="sm"
          isIconOnly
          tooltip={soundEnabled ? 'Alert Chime On' : 'Alert Chime Muted'}
          icon={soundEnabled ? <Volume2 size={14} /> : <VolumeX size={14} />}
          onClick={onToggleSound}
        />

        <Button
          label="Desktop Notifications"
          variant="secondary"
          size="sm"
          isIconOnly
          tooltip="Enable Browser Desktop Alert Notifications"
          icon={<Bell size={14} />}
          onClick={onEnableDesktopAlerts}
        />

        <Button
          label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          variant="secondary"
          size="sm"
          isIconOnly
          tooltip={darkMode ? 'Light Theme' : 'Dark Theme'}
          icon={darkMode ? <Sun size={14} /> : <Moon size={14} />}
          onClick={onToggleDarkMode}
        />
      </div>
    </header>
  );
}
