import { useCallback, useEffect, useRef, useState } from 'react';
import { Theme, LayerProvider, useToast } from '@astryxdesign/core';
import { Badge } from '@astryxdesign/core/Badge';
import { Button } from '@astryxdesign/core/Button';
import { Spinner } from '@astryxdesign/core/Spinner';
import { Text } from '@astryxdesign/core/Text';
import { neutralTheme } from '@astryxdesign/theme-neutral/built';
import {
  Activity,
  BellRing,
  Bot,
  Cpu,
  Globe,
  Newspaper,
  ShieldAlert,
} from 'lucide-react';
import { api, playAlertChime } from './api';
import { AiAnalystView } from './components/AiAnalystView';
import { AiModelsView } from './components/AiModelsView';
import { FeedsAndAlertsView } from './components/FeedsAndAlertsView';
import { InvestigationDrawer } from './components/InvestigationDrawer';
import { NetworkIocView } from './components/NetworkIocView';
import { NewsIntelView } from './components/NewsIntelView';
import { OverviewView } from './components/OverviewView';
import { TopCommandBar } from './components/TopCommandBar';
import { VulnerabilitiesView } from './components/VulnerabilitiesView';
import type { DashboardPayload, NavTab, SseEvent, Vulnerability } from './types';

function DashboardWorkspace({
  darkMode,
  onToggleDarkMode,
}: {
  darkMode: boolean;
  onToggleDarkMode: () => void;
}) {
  const toast = useToast();
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [dashboard, setDashboard] = useState<DashboardPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [sseConnected, setSseConnected] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [drawerVulnId, setDrawerVulnId] = useState<string | null>(null);
  const [drawerInitialVuln, setDrawerInitialVuln] = useState<Vulnerability | null>(null);

  const soundRef = useRef(soundEnabled);
  soundRef.current = soundEnabled;

  const loadDashboard = useCallback(async () => {
    try {
      const payload = await api.getDashboard();
      setDashboard(payload);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
    const bootPoll = window.setInterval(() => {
      void api.getDashboard().then((p) => {
        setDashboard(p);
      });
    }, 30000);
    return () => window.clearInterval(bootPoll);
  }, [loadDashboard]);

  // Real-time SSE listener for new vulnerability alerts & hourly sweep events
  useEffect(() => {
    const es = new EventSource('/api/events');
    es.onopen = () => setSseConnected(true);
    es.onerror = () => setSseConnected(false);

    es.onmessage = (ev) => {
      try {
        const parsed = JSON.parse(ev.data) as SseEvent;
        if (parsed.type === 'NewAlert') {
          const alert = parsed.payload;
          setDashboard((prev) =>
            prev
              ? {
                  ...prev,
                  alerts: [alert, ...prev.alerts.filter((a) => a.id !== alert.id)].slice(0, 60),
                  kpis: {
                    ...prev.kpis,
                    unacknowledged_alerts: prev.kpis.unacknowledged_alerts + 1,
                  },
                }
              : prev
          );

          if (soundRef.current) {
            playAlertChime();
          }

          if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
            new Notification(`AiBrainWorX ${alert.severity} Alert`, {
              body: alert.title,
            });
          }

          toast({
            type: alert.severity === 'CRITICAL' ? 'error' : 'info',
            body: `[${alert.severity}] ${alert.title}`,
            autoHideDuration: 8000,
            endContent: alert.cve_ids[0] ? (
              <Button
                label="Inspect"
                size="sm"
                variant="secondary"
                onClick={() => {
                  setDrawerInitialVuln(null);
                  setDrawerVulnId(alert.cve_ids[0]);
                }}
              />
            ) : undefined,
          });
        } else if (parsed.type === 'SweepStarted') {
          setDashboard((prev) => (prev ? { ...prev, sweep_in_progress: true } : prev));
        } else if (parsed.type === 'SweepCompleted') {
          void loadDashboard();
          toast({
            type: 'info',
            body: `Hourly sweep complete: ${parsed.payload.total_vulns} CVEs, ${parsed.payload.total_news} reports (${parsed.payload.new_alerts} new alerts).`,
            autoHideDuration: 4500,
          });
        }
      } catch {
        // ignore keepalive / non-JSON chunks
      }
    };

    return () => {
      es.close();
    };
  }, [loadDashboard, toast]);

  const handleSelectVuln = (v: Vulnerability) => {
    setDrawerInitialVuln(v);
    setDrawerVulnId(v.id);
  };

  const handleSelectVulnId = (id: string) => {
    setDrawerInitialVuln(null);
    setDrawerVulnId(id);
  };

  const handleRefreshNow = async () => {
    setDashboard((prev) => (prev ? { ...prev, sweep_in_progress: true } : prev));
    await api.triggerRefresh();
    window.setTimeout(() => {
      void loadDashboard();
    }, 3500);
  };

  const handleAckAlert = async (id: string) => {
    await api.ackAlert(id);
    setDashboard((prev) =>
      prev
        ? {
            ...prev,
            alerts: prev.alerts.map((a) => (a.id === id ? { ...a, acknowledged: true } : a)),
            kpis: {
              ...prev.kpis,
              unacknowledged_alerts: Math.max(0, prev.kpis.unacknowledged_alerts - 1),
            },
          }
        : prev
    );
  };

  const handleAckAll = async () => {
    await api.ackAllAlerts();
    setDashboard((prev) =>
      prev
        ? {
            ...prev,
            alerts: prev.alerts.map((a) => ({ ...a, acknowledged: true })),
            kpis: { ...prev.kpis, unacknowledged_alerts: 0 },
          }
        : prev
    );
  };

  const handleTriggerTestAlert = async () => {
    await api.triggerTestAlert();
  };

  const handleEnableDesktopAlerts = async () => {
    if (typeof Notification === 'undefined') {
      toast({ type: 'info', body: 'Browser notifications are not available in this context.' });
      return;
    }
    const perm = await Notification.requestPermission();
    toast({
      type: 'info',
      body:
        perm === 'granted'
          ? 'Desktop browser vulnerability notifications enabled.'
          : `Desktop notification permission: ${perm}`,
    });
  };

  const navSections: {
    heading: string;
    items: {
      id: NavTab;
      label: string;
      icon: React.ReactNode;
      badge?: number | string;
      badgeVariant?: 'error' | 'cyan' | 'neutral';
    }[];
  }[] = [
    {
      heading: 'Operations',
      items: [
        { id: 'overview', label: 'War Room', icon: <Activity size={15} /> },
        {
          id: 'vulnerabilities',
          label: 'Vulnerabilities',
          icon: <ShieldAlert size={15} />,
          badge: dashboard?.kpis.total_vulnerabilities,
          badgeVariant: 'neutral',
        },
      ],
    },
    {
      heading: 'Intelligence',
      items: [
        {
          id: 'news',
          label: 'News & Advisories',
          icon: <Newspaper size={15} />,
          badge: dashboard?.kpis.news_count_24h,
          badgeVariant: 'cyan',
        },
        { id: 'network', label: 'Network IOCs', icon: <Globe size={15} /> },
        { id: 'analyst', label: 'AI Threat Analyst', icon: <Bot size={15} /> },
      ],
    },
    {
      heading: 'System',
      items: [
        {
          id: 'models',
          label: 'AI Models',
          icon: <Cpu size={15} />,
          badge:
            dashboard?.active_ai_provider &&
            dashboard.active_ai_provider !== 'Built-in Rust Engine'
              ? 'EXT'
              : 'LOCAL',
          badgeVariant: 'cyan',
        },
        {
          id: 'alerts',
          label: 'Feeds & Alerts',
          icon: <BellRing size={15} />,
          badge: dashboard?.kpis.unacknowledged_alerts,
          badgeVariant: (dashboard?.kpis.unacknowledged_alerts ?? 0) > 0 ? 'error' : 'neutral',
        },
      ],
    },
  ];

  return (
    <div className="abw-shell">
      <TopCommandBar
        infoconStatus={dashboard?.telemetry.infocon_status ?? 'green'}
        threatIndex={dashboard?.ai_brief.global_threat_index ?? 0}
        threatLabel={dashboard?.ai_brief.threat_level_label ?? 'INIT'}
        nextSweepAt={dashboard?.next_sweep_at ?? null}
        lastSweepAt={dashboard?.last_sweep_at ?? null}
        sweepInProgress={dashboard?.sweep_in_progress ?? loading}
        sseConnected={sseConnected}
        unacknowledgedAlerts={dashboard?.kpis.unacknowledged_alerts ?? 0}
        activeAiProvider={dashboard?.active_ai_provider ?? 'Built-in Rust Engine'}
        activeAiModel={dashboard?.active_ai_model ?? 'local-threat-graph-v1'}
        soundEnabled={soundEnabled}
        darkMode={darkMode}
        onToggleSound={() => setSoundEnabled((s) => !s)}
        onToggleDarkMode={onToggleDarkMode}
        onEnableDesktopAlerts={() => void handleEnableDesktopAlerts()}
        onRefreshNow={() => void handleRefreshNow()}
        onOpenAlerts={() => setActiveTab('alerts')}
        onOpenAiModels={() => setActiveTab('models')}
      />

      <div className="abw-workspace">
        <aside className="abw-rail" aria-label="Dashboard Navigation">
          {navSections.map((sec) => (
            <div key={sec.heading}>
              <div className="abw-rail-section">{sec.heading}</div>
              {sec.items.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className="abw-nav-btn"
                  data-active={activeTab === item.id}
                  onClick={() => setActiveTab(item.id)}
                >
                  <span className="abw-nav-btn-left">
                    {item.icon}
                    <span>{item.label}</span>
                  </span>
                  {item.badge != null && (
                    <Badge variant={item.badgeVariant ?? 'neutral'} label={item.badge} />
                  )}
                </button>
              ))}
            </div>
          ))}

          <div className="abw-rail-footer">
            <div>RUST ENGINE // AXUM 0.8</div>
            <div>
              {dashboard?.kpis.feeds_ok ?? 0}/{dashboard?.kpis.feeds_total ?? 25} FEEDS ·{' '}
              {dashboard?.total_sweeps ?? 0} SWEEPS
            </div>
            <div>META ASTRYX UI v0.7.16</div>
          </div>
        </aside>

        <main className="abw-main">
          {!dashboard ? (
            <div className="abw-panel">
              <div className="abw-panel-body" style={{ flexDirection: 'row', alignItems: 'center', gap: 12 }}>
                <Spinner />
                <div>
                  <Text weight="semibold" display="block">
                    Connecting to AiBrainWorX Rust Threat Intelligence Engine...
                  </Text>
                  <Text type="supporting" size="sm" display="block">
                    Running concurrent collection across CISA KEV, NVD, GitHub Advisories, CIRCL, OSV, FIRST EPSS, SANS ISC, Feodo, OpenPhish & 11 security news/exploit wires.
                  </Text>
                </div>
              </div>
            </div>
          ) : (
            <>
              {activeTab === 'overview' && (
                <OverviewView
                  data={dashboard}
                  onSelectVuln={handleSelectVuln}
                  onSelectVulnId={handleSelectVulnId}
                  onAckAlert={(id) => void handleAckAlert(id)}
                  onNavigate={setActiveTab}
                />
              )}
              {activeTab === 'vulnerabilities' && (
                <VulnerabilitiesView onSelectVuln={handleSelectVuln} />
              )}
              {activeTab === 'news' && <NewsIntelView onSelectVulnId={handleSelectVulnId} />}
              {activeTab === 'network' && (
                <NetworkIocView
                  telemetry={dashboard.telemetry}
                  onSelectVulnId={handleSelectVulnId}
                />
              )}
              {activeTab === 'analyst' && (
                <AiAnalystView
                  activeProvider={dashboard.active_ai_provider}
                  activeModel={dashboard.active_ai_model}
                  onSelectVulnId={handleSelectVulnId}
                  onOpenAiModels={() => setActiveTab('models')}
                />
              )}
              {activeTab === 'models' && (
                <AiModelsView onConfigSaved={() => void loadDashboard()} />
              )}
              {activeTab === 'alerts' && (
                <FeedsAndAlertsView
                  alerts={dashboard.alerts}
                  feeds={dashboard.feed_health}
                  onAckAlert={(id) => void handleAckAlert(id)}
                  onAckAll={() => void handleAckAll()}
                  onTriggerTestAlert={() => void handleTriggerTestAlert()}
                  onSelectVulnId={handleSelectVulnId}
                  onRulesUpdated={() => void loadDashboard()}
                />
              )}
            </>
          )}
        </main>
      </div>

      <InvestigationDrawer
        vulnId={drawerVulnId}
        initialVuln={drawerInitialVuln}
        onClose={() => {
          setDrawerVulnId(null);
          setDrawerInitialVuln(null);
        }}
        onSelectVulnId={handleSelectVulnId}
      />
    </div>
  );
}

export default function App() {
  const [darkMode, setDarkMode] = useState(true);

  return (
    <Theme theme={neutralTheme} mode={darkMode ? 'dark' : 'light'}>
      <LayerProvider toast={{ position: 'topEnd', maxVisible: 4 }}>
        <DashboardWorkspace
          darkMode={darkMode}
          onToggleDarkMode={() => setDarkMode((d) => !d)}
        />
      </LayerProvider>
    </Theme>
  );
}
