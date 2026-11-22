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
  Layers,
  LogOut,
  Newspaper,
  ShieldAlert,
} from 'lucide-react';
import { ApiError, IS_DEMO_MODE, api, playAlertChime } from './api';
import { AccountSecurityModal } from './components/AccountSecurityModal';
import { AiAnalystView } from './components/AiAnalystView';
import { AiModelsView } from './components/AiModelsView';
import { AuthScreen } from './components/AuthScreen';
import { FeedsAndAlertsView } from './components/FeedsAndAlertsView';
import { InvestigationDrawer } from './components/InvestigationDrawer';
import { MyStackView } from './components/MyStackView';
import { NetworkIocView } from './components/NetworkIocView';
import { NewsIntelView } from './components/NewsIntelView';
import { OverviewView } from './components/OverviewView';
import { TopCommandBar } from './components/TopCommandBar';
import { VulnerabilitiesView } from './components/VulnerabilitiesView';
import type {
  AuthStatusResponse,
  DashboardPayload,
  NavTab,
  SseEvent,
  Vulnerability,
} from './types';

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
  const [opsecMode, setOpsecMode] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem('abw_opsec_mode') === '1';
    } catch {
      return false;
    }
  });
  const [authStatus, setAuthStatus] = useState<AuthStatusResponse | null>(null);
  const [securityModalOpen, setSecurityModalOpen] = useState(false);

  const [drawerVulnId, setDrawerVulnId] = useState<string | null>(null);
  const [drawerInitialVuln, setDrawerInitialVuln] = useState<Vulnerability | null>(null);

  const soundRef = useRef(soundEnabled);
  soundRef.current = soundEnabled;

  const toggleOpsecMode = () => {
    setOpsecMode((prev) => {
      const next = !prev;
      try {
        window.localStorage.setItem('abw_opsec_mode', next ? '1' : '0');
      } catch {
        // ignore storage errors
      }
      return next;
    });
  };

  const refreshAuthStatus = useCallback(async () => {
    const status = await api.getAuthStatus();
    setAuthStatus(status);
    return status;
  }, []);

  const loadDashboard = useCallback(async () => {
    try {
      const payload = await api.getDashboard();
      setDashboard(payload);
    } catch (err) {
      const is401 =
        (err instanceof ApiError && err.status === 401) ||
        (err instanceof Error && err.message.includes('401'));
      if (is401) {
        void refreshAuthStatus().catch(() => {
          setAuthStatus((prev) =>
            prev
              ? { ...prev, authenticated: false }
              : {
                  auth_required: true,
                  setup_required: false,
                  authenticated: false,
                  username: null,
                  display_name: null,
                  totp_enabled: false,
                  recovery_codes_remaining: 0,
                  token_auth_enabled: false,
                  wallboard_mode: false,
                  offline_mode: false,
                  no_auth_mode: false,
                }
          );
        });
      }
    } finally {
      setLoading(false);
    }
  }, [refreshAuthStatus]);

  useEffect(() => {
    let active = true;
    api
      .getAuthStatus()
      .then((status) => {
        if (!active) return;
        setAuthStatus(status);
        if (!status.auth_required || status.authenticated) {
          void loadDashboard();
        } else {
          setLoading(false);
        }
      })
      .catch(() => {
        if (active) void loadDashboard();
      });
    return () => {
      active = false;
    };
  }, [loadDashboard]);

  const canQueryApi =
    authStatus === null ? false : !authStatus.auth_required || authStatus.authenticated;

  useEffect(() => {
    if (!canQueryApi) return;
    const bootPoll = window.setInterval(() => {
      void loadDashboard();
    }, 30000);
    return () => window.clearInterval(bootPoll);
  }, [canQueryApi, loadDashboard]);

  // Real-time SSE listener for new vulnerability alerts & hourly sweep events
  useEffect(() => {
    if (IS_DEMO_MODE || !canQueryApi) {
      setSseConnected(false);
      return;
    }
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
    await loadDashboard();
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

  const serverWallboard = dashboard?.server_mode.wallboard_mode || authStatus?.wallboard_mode || false;
  const serverOffline = dashboard?.server_mode.offline_mode || authStatus?.offline_mode || false;
  const authRequired = authStatus?.auth_required || dashboard?.server_mode.auth_required || false;
  const authenticated = authStatus?.authenticated ?? false;

  const handleAuthenticated = async () => {
    setLoading(true);
    await refreshAuthStatus();
    await loadDashboard();
  };

  const handleLogout = async () => {
    setSecurityModalOpen(false);
    await api.logout();
    setDashboard(null);
    await refreshAuthStatus().catch(() => {
      setAuthStatus((prev) => (prev ? { ...prev, authenticated: false } : prev));
    });
  };

  const navSections: {
    heading: string;
    items: {
      id: NavTab;
      label: string;
      icon: React.ReactNode;
      badge?: number | string;
      badgeVariant?: 'error' | 'cyan' | 'neutral' | 'warning';
    }[];
  }[] = [
    {
      heading: 'Operations',
      items: [
        { id: 'overview', label: 'War Room', icon: <Activity size={15} /> },
        {
          id: 'mystack',
          label: 'My Stack',
          icon: <Layers size={15} />,
          badge: dashboard?.kpis.stack_exposed_count,
          badgeVariant: (dashboard?.kpis.stack_exposed_count ?? 0) > 0 ? 'warning' : 'neutral',
        },
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

  if (authStatus === null) {
    return (
      <div className="abw-auth-backdrop">
        <div className="abw-auth-grid" aria-hidden="true" />
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, zIndex: 2 }}>
          <Spinner />
          <Text weight="semibold">Verifying local session...</Text>
        </div>
      </div>
    );
  }

  if (authRequired && !authenticated) {
    return <AuthScreen authStatus={authStatus} onAuthenticated={handleAuthenticated} />;
  }

  return (
    <div className="abw-shell">
      <TopCommandBar
        infoconStatus={dashboard?.telemetry.infocon_status ?? 'green'}
        threatIndex={dashboard?.ai_brief.global_threat_index ?? 0}
        threatLabel={dashboard?.ai_brief.threat_level_label ?? 'INIT'}
        nextSweepAt={dashboard?.next_sweep_at ?? null}
        lastSweepAt={dashboard?.last_sweep_at ?? null}
        sweepInProgress={dashboard?.sweep_in_progress ?? loading}
        sseConnected={IS_DEMO_MODE ? true : sseConnected}
        unacknowledgedAlerts={dashboard?.kpis.unacknowledged_alerts ?? 0}
        activeAiProvider={dashboard?.active_ai_provider ?? 'Built-in Rust Engine'}
        activeAiModel={dashboard?.active_ai_model ?? 'local-threat-graph-v1'}
        soundEnabled={soundEnabled}
        darkMode={darkMode}
        opsecMode={opsecMode}
        wallboardMode={serverWallboard}
        offlineMode={serverOffline}
        authRequired={authRequired}
        username={authStatus.username}
        totpEnabled={authStatus.totp_enabled}
        onToggleSound={() => setSoundEnabled((s) => !s)}
        onToggleDarkMode={onToggleDarkMode}
        onToggleOpsecMode={toggleOpsecMode}
        onEnableDesktopAlerts={() => void handleEnableDesktopAlerts()}
        onRefreshNow={() => void handleRefreshNow()}
        onOpenAlerts={() => setActiveTab('alerts')}
        onOpenAiModels={() => setActiveTab('models')}
        onOpenSecurity={() => setSecurityModalOpen(true)}
        onLogout={() => void handleLogout()}
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
            <div>RUST ENGINE // AXUM 0.8 + SQLITE</div>
            <div>
              {dashboard?.kpis.feeds_ok ?? 0}/{dashboard?.kpis.feeds_total ?? 25} FEEDS ·{' '}
              {dashboard?.total_sweeps ?? 0} SWEEPS
            </div>
            <div>META ASTRYX UI v0.7.16</div>
            {authRequired && authenticated && (
              <div style={{ marginTop: 6 }}>
                <Button
                  label="Lock Session"
                  size="sm"
                  variant="secondary"
                  icon={<LogOut size={12} />}
                  onClick={() => void handleLogout()}
                />
              </div>
            )}
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
                  opsecMode={opsecMode}
                  readOnly={serverWallboard}
                  onSelectVuln={handleSelectVuln}
                  onSelectVulnId={handleSelectVulnId}
                  onAckAlert={(id) => void handleAckAlert(id)}
                  onDeltaReviewed={() => void loadDashboard()}
                  onNavigate={setActiveTab}
                />
              )}
              {activeTab === 'mystack' && (
                <MyStackView
                  readOnly={serverWallboard}
                  onSelectVuln={handleSelectVuln}
                  onStackUpdated={() => void loadDashboard()}
                />
              )}
              {activeTab === 'vulnerabilities' && (
                <VulnerabilitiesView onSelectVuln={handleSelectVuln} />
              )}
              {activeTab === 'news' && <NewsIntelView onSelectVulnId={handleSelectVulnId} />}
              {activeTab === 'network' && (
                <NetworkIocView
                  telemetry={dashboard.telemetry}
                  opsecMode={opsecMode}
                  onSelectVulnId={handleSelectVulnId}
                />
              )}
              {activeTab === 'analyst' && (
                <AiAnalystView
                  activeProvider={dashboard.active_ai_provider}
                  activeModel={dashboard.active_ai_model}
                  opsecMode={opsecMode}
                  readOnly={serverWallboard}
                  onSelectVulnId={handleSelectVulnId}
                  onNavigate={setActiveTab}
                  onTriageUpdated={() => void loadDashboard()}
                  onOpenAiModels={() => setActiveTab('models')}
                />
              )}
              {activeTab === 'models' && (
                <AiModelsView
                  readOnly={serverWallboard}
                  opsecMode={opsecMode}
                  onConfigSaved={() => void loadDashboard()}
                />
              )}
              {activeTab === 'alerts' && (
                <FeedsAndAlertsView
                  alerts={dashboard.alerts}
                  feeds={dashboard.feed_health}
                  readOnly={serverWallboard}
                  opsecMode={opsecMode}
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
        opsecMode={opsecMode}
        readOnly={serverWallboard}
        onClose={() => {
          setDrawerVulnId(null);
          setDrawerInitialVuln(null);
        }}
        onSelectVulnId={handleSelectVulnId}
        onNavigate={setActiveTab}
        onTriageUpdated={() => void loadDashboard()}
      />

      <AccountSecurityModal
        open={securityModalOpen}
        authStatus={authStatus}
        onClose={() => setSecurityModalOpen(false)}
        onRefreshAuth={async () => {
          await refreshAuthStatus();
        }}
        onLogout={handleLogout}
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
