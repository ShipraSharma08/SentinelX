import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  authApi,
  dashboardApi,
  alertsApi,
  assetsApi,
  incidentsApi,
  clearSession,
  getStoredSession,
  storeSession,
  ApiError,
  type AuthSession,
  type DashboardOverview,
  type RecentAlert,
  type AlertItem,
  type AssetItem,
  type IncidentItem,
  type RecentPrediction,
  type RecentNetworkFlow,
} from './lib/api'
import MLPredictionUpload from './components/MLPredictionUpload'
import './App.css'
import './Dashboard.css'

type Tab = 'overview' | 'alerts' | 'assets' | 'incidents' | 'predictions' | 'flows'

type DashboardData = {
  overview: DashboardOverview
  alerts: RecentAlert[]
  predictions: RecentPrediction[]
  flows: RecentNetworkFlow[]
}

const emptyData: DashboardData = {
  overview: {
    totalAssets: 0,
    totalNetworkFlows: 0,
    totalPredictions: 0,
    totalAlerts: 0,
    openAlerts: 0,
    criticalAlerts: 0,
    totalIncidents: 0,
    activeIncidents: 0,
    maliciousPredictions: 0,
  },
  alerts: [],
  predictions: [],
  flows: [],
}

const dateTime = (value?: string | null) => {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

const number = (value: number | null | undefined) =>
  value == null ? '—' : value.toLocaleString()

const percent = (value: number | null) =>
  value == null ? '—' : `${(value * 100).toFixed(1)}%`

function App() {
  const [session, setSession] = useState<AuthSession | null>(() => getStoredSession())
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [usernameOrEmail, setUsernameOrEmail] = useState('')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [authError, setAuthError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const [tab, setTab] = useState<Tab>('overview')
  const [data, setData] = useState<DashboardData>(emptyData)
  const [loading, setLoading] = useState(false)
  const [dashboardError, setDashboardError] = useState('')
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  // Alerts View state
  const [alertList, setAlertList] = useState<AlertItem[]>([])
  const [alertTotal, setAlertTotal] = useState(0)
  const [alertPage, setAlertPage] = useState(0)
  const [alertPages, setAlertPages] = useState(1)
  const [alertStatusFilter, setAlertStatusFilter] = useState('ALL')
  const [alertSeverityFilter, setAlertSeverityFilter] = useState('ALL')
  const [alertSearchTerm, setAlertSearchTerm] = useState('')
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null)
  const [alertsLoading, setAlertsLoading] = useState(false)
  const [alertActionLoading, setAlertActionLoading] = useState(false)
  const [alertActionMessage, setAlertActionMessage] = useState('')

  // Assets View state
  const [assetList, setAssetList] = useState<AssetItem[]>([])
  const [assetSearchTerm, setAssetSearchTerm] = useState('')
  const [assetTypeFilter, setAssetTypeFilter] = useState('ALL')
  const [selectedAsset, setSelectedAsset] = useState<AssetItem | null>(null)
  const [assetsLoading, setAssetsLoading] = useState(false)

  // Incidents View state
  const [incidentList, setIncidentList] = useState<IncidentItem[]>([])
  const [incidentsLoading, setIncidentsLoading] = useState(false)

  const handleAuthExpiry = useCallback(() => {
    clearSession()
    setSession(null)
    setAuthError('Your session expired. Please sign in again.')
  }, [])

  const loadDashboard = useCallback(async (activeSession: AuthSession) => {
    setLoading(true)
    setDashboardError('')

    try {
      const [overview, alerts, predictions, flows] = await Promise.all([
        dashboardApi.getOverview(activeSession),
        dashboardApi.getRecentAlerts(activeSession),
        dashboardApi.getRecentPredictions(activeSession),
        dashboardApi.getRecentFlows(activeSession),
      ])

      setData({ overview, alerts, predictions, flows })
      setLastUpdated(new Date())
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        handleAuthExpiry()
      } else {
        setDashboardError(
          error instanceof Error
            ? error.message
            : 'Unable to load dashboard data.',
        )
      }
    } finally {
      setLoading(false)
    }
  }, [handleAuthExpiry])

  const loadAlerts = useCallback(async (activeSession: AuthSession, page = 0, status = alertStatusFilter, severity = alertSeverityFilter) => {
    setAlertsLoading(true)
    try {
      const result = await alertsApi.search(activeSession, {
        page,
        size: 15,
        status: status === 'ALL' ? undefined : status,
        severity: severity === 'ALL' ? undefined : severity,
      })
      setAlertList(result.content)
      setAlertTotal(result.totalElements)
      setAlertPages(result.totalPages || 1)
      setAlertPage(result.number)
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        handleAuthExpiry()
      } else {
        setDashboardError(
          error instanceof Error ? error.message : 'Unable to load security alerts.',
        )
      }
    } finally {
      setAlertsLoading(false)
    }
  }, [alertStatusFilter, alertSeverityFilter, handleAuthExpiry])

  const loadAssets = useCallback(async (activeSession: AuthSession) => {
    setAssetsLoading(true)
    try {
      const list = await assetsApi.getAll(activeSession)
      setAssetList(list)
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        handleAuthExpiry()
      } else {
        setDashboardError(
          error instanceof Error ? error.message : 'Unable to load monitored assets.',
        )
      }
    } finally {
      setAssetsLoading(false)
    }
  }, [handleAuthExpiry])

  const loadIncidents = useCallback(async (activeSession: AuthSession) => {
    setIncidentsLoading(true)
    try {
      const list = await incidentsApi.getAll(activeSession)
      setIncidentList(list)
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        handleAuthExpiry()
      } else {
        setDashboardError(
          error instanceof Error ? error.message : 'Unable to load incidents.',
        )
      }
    } finally {
      setIncidentsLoading(false)
    }
  }, [handleAuthExpiry])

  useEffect(() => {
    if (!session) return
    void loadDashboard(session)
  }, [session, loadDashboard])

  useEffect(() => {
    if (!session) return
    if (tab === 'alerts') {
      void loadAlerts(session, alertPage, alertStatusFilter, alertSeverityFilter)
    } else if (tab === 'assets') {
      void loadAssets(session)
    } else if (tab === 'incidents') {
      void loadIncidents(session)
    }
  }, [session, tab, alertPage, alertStatusFilter, alertSeverityFilter, loadAlerts, loadAssets, loadIncidents])

  async function handleAcknowledgeAlert(alertId: number) {
    if (!session) return
    setAlertActionLoading(true)
    setAlertActionMessage('')
    try {
      const updated = await alertsApi.acknowledge(session, alertId)
      setSelectedAlert(updated)
      setAlertActionMessage(`Alert #${alertId} acknowledged successfully.`)
      void loadAlerts(session, alertPage, alertStatusFilter, alertSeverityFilter)
      void loadDashboard(session)
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        handleAuthExpiry()
      } else {
        setAlertActionMessage(
          error instanceof Error ? error.message : 'Failed to acknowledge alert.',
        )
      }
    } finally {
      setAlertActionLoading(false)
    }
  }

  async function handleResolveAlert(alertId: number) {
    if (!session) return
    setAlertActionLoading(true)
    setAlertActionMessage('')
    try {
      const updated = await alertsApi.resolve(session, alertId)
      setSelectedAlert(updated)
      setAlertActionMessage(`Alert #${alertId} resolved successfully.`)
      void loadAlerts(session, alertPage, alertStatusFilter, alertSeverityFilter)
      void loadDashboard(session)
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        handleAuthExpiry()
      } else {
        setAlertActionMessage(
          error instanceof Error ? error.message : 'Failed to resolve alert.',
        )
      }
    } finally {
      setAlertActionLoading(false)
    }
  }

  async function handleAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setAuthError('')
    setSubmitting(true)

    try {
      const result =
        mode === 'login'
          ? await authApi.login({ usernameOrEmail, password })
          : await authApi.register({ username, email, password })

      storeSession(result)
      setSession(result)
      setPassword('')
    } catch (error) {
      setAuthError(
        error instanceof Error ? error.message : 'Authentication failed.',
      )
    } finally {
      setSubmitting(false)
    }
  }

  function logout() {
    clearSession()
    setSession(null)
    setData(emptyData)
    setTab('overview')
    setUsernameOrEmail('')
    setPassword('')
    setAuthError('')
    setSelectedAlert(null)
    setSelectedAsset(null)
  }

  if (!session) {
    return (
      <main className="auth-screen">
        <section className="auth-visual">
          <div className="dash-brand">
            <span className="brand-mark">
              S<span>X</span>
            </span>{' '}
            Sentinel<span>X</span>
          </div>

          <div className="auth-hero">
            <div className="live-label">
              <i /> SECURITY OPERATIONS PLATFORM
            </div>

            <h1>
              Anticipate
              <br />
              <span>threats.</span>
              <br />
              Investigate with clarity.
            </h1>

            <p>Turn network activity into actionable security insights.</p>

            <div className="auth-benefits">
              <div>
                <b>01</b>
                <span>
                  <strong>Network intelligence</strong>
                  <small>Visibility across monitored assets</small>
                </span>
              </div>

              <div>
                <b>02</b>
                <span>
                  <strong>Threat investigation</strong>
                  <small>Security events and suspicious behaviour</small>
                </span>
              </div>

              <div>
                <b>03</b>
                <span>
                  <strong>ML-assisted insights</strong>
                  <small>Model predictions for security analysis</small>
                </span>
              </div>
            </div>
          </div>

          <small className="auth-foot">
            BUILT FOR SECURITY OPERATIONS
          </small>
        </section>

        <section className="auth-form-side">
          <form className="auth-box" onSubmit={handleAuth}>
            <div className="auth-emblem">⌑</div>
            <div className="dash-kicker">SECURE ACCESS</div>

            <h2>
              {mode === 'login' ? 'Welcome back' : 'Create your account'}
            </h2>

            <p>
              {mode === 'login'
                ? 'Sign in to access your security workspace.'
                : 'Register for access to SentinelX.'}
            </p>

            <div className="auth-switch">
              <button
                type="button"
                className={mode === 'login' ? 'selected' : ''}
                onClick={() => {
                  setMode('login')
                  setAuthError('')
                }}
              >
                Sign in
              </button>

              <button
                type="button"
                className={mode === 'register' ? 'selected' : ''}
                onClick={() => {
                  setMode('register')
                  setAuthError('')
                }}
              >
                Register
              </button>
            </div>

            {mode === 'register' && (
              <>
                <label>Username</label>
                <input
                  required
                  minLength={3}
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="Choose a username"
                />

                <label>Email</label>
                <input
                  required
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@example.com"
                />
              </>
            )}

            {mode === 'login' && (
              <>
                <label>Username or email</label>
                <input
                  required
                  autoComplete="username"
                  value={usernameOrEmail}
                  onChange={(event) => setUsernameOrEmail(event.target.value)}
                  placeholder="Enter username or email"
                />
              </>
            )}
            <label>Password</label>
<div style={{ position: 'relative' }}>
  <input
    required
    minLength={mode === 'register' ? 8 : undefined}
    type={showPassword ? 'text' : 'password'}
    autoComplete={
      mode === 'login' ? 'current-password' : 'new-password'
    }
    value={password}
    onChange={(event) => setPassword(event.target.value)}
    placeholder="Enter password"
    style={{ paddingRight: 46 }}
  />

  <button
    type="button"
    onClick={() => setShowPassword((visible) => !visible)}
    aria-label={showPassword ? 'Hide password' : 'Show password'}
    title={showPassword ? 'Hide password' : 'Show password'}
    style={{
      position: 'absolute',
      right: 12,
      top: '50%',
      transform: 'translateY(-50%)',
      background: 'transparent',
      border: 'none',
      color: '#8fa2b9',
      cursor: 'pointer',
      padding: 4,
      fontSize: 16,
      lineHeight: 1,
    }}
  >
    {showPassword ? '🙈' : '👁'}
  </button>
</div>

           

            {authError && <div className="auth-error">{authError}</div>}

            <button
              className="auth-submit"
              type="submit"
              disabled={submitting}
            >
              {submitting
                ? 'Please wait…'
                : mode === 'login'
                  ? 'Sign into SentinelX →'
                  : 'Create account →'}
            </button>

            <small className="auth-secure">
              Protected access · SentinelX Security Platform
            </small>
          </form>
        </section>
      </main>
    )
  }

  const o = data.overview

  const nav: { id: Tab; label: string; icon: string; count?: number }[] = [
    { id: 'overview', label: 'Overview', icon: '▦' },
    { id: 'alerts', label: 'Security alerts', icon: '◈', count: o.openAlerts },
    { id: 'assets', label: 'Monitored assets', icon: '▣', count: o.totalAssets },
    { id: 'incidents', label: 'Incidents', icon: '◎', count: o.activeIncidents },
    { id: 'predictions', label: 'ML predictions', icon: '⌁', count: o.totalPredictions },
    { id: 'flows', label: 'Network activity', icon: '⇄', count: o.totalNetworkFlows },
  ]

  const canManageAlerts = [
    'ADMIN',
    'SOC_ANALYST',
    'SECURITY_ENGINEER',
  ].includes(session.user.role)

  const canGeneratePredictions = [
    'ADMIN',
    'SOC_ANALYST',
    'SECURITY_ENGINEER',
  ].includes(session.user.role)

  // Filtered lists for client-side text queries
  const filteredAlerts = alertList.filter((a) => {
    if (!alertSearchTerm.trim()) return true
    const term = alertSearchTerm.toLowerCase()
    return (
      a.title.toLowerCase().includes(term) ||
      (a.description && a.description.toLowerCase().includes(term)) ||
      String(a.id).includes(term)
    )
  })

  const filteredAssets = assetList.filter((asset) => {
    const matchesType =
      assetTypeFilter === 'ALL' ||
      asset.assetType.toUpperCase() === assetTypeFilter.toUpperCase()
    if (!matchesType) return false

    if (!assetSearchTerm.trim()) return true
    const term = assetSearchTerm.toLowerCase()
    return (
      asset.ipAddress.toLowerCase().includes(term) ||
      (asset.hostname && asset.hostname.toLowerCase().includes(term)) ||
      (asset.operatingSystem && asset.operatingSystem.toLowerCase().includes(term))
    )
  })

  return (
    <div className="dashboard-shell">
      <aside className="sidebar">
        <div className="side-brand">
          <span className="brand-mark">
            S<span>X</span>
          </span>
          <span>
            Sentinel<span>X</span>
          </span>
        </div>

        <div className="side-caption">WORKSPACE</div>

        <nav>
          {nav.map((item) => (
            <button
              key={item.id}
              className={tab === item.id ? 'nav-item active' : 'nav-item'}
              onClick={() => {
                setTab(item.id)
                setSelectedAlert(null)
                setSelectedAsset(null)
              }}
            >
              <span>{item.icon}</span>
              <span style={{ flex: 1 }}>{item.label}</span>
              {item.count != null && item.count > 0 && (
                <small style={{
                  font: '10px "DM Mono", monospace',
                  padding: '2px 6px',
                  borderRadius: 4,
                  background: item.id === 'alerts' && o.criticalAlerts > 0 ? '#43242c' : '#142a40',
                  color: item.id === 'alerts' && o.criticalAlerts > 0 ? '#ff9da5' : '#8fa2b9',
                }}>
                  {item.count}
                </small>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-state">
            <i /> API SESSION ACTIVE
          </div>

          <div className="user-mini">
            <div className="avatar">
              {session.user.username.slice(0, 1).toUpperCase()}
            </div>
            <span>
              <strong>{session.user.username}</strong>
              <small>{session.user.role}</small>
            </span>
          </div>

          <button className="logout-button" onClick={logout}>
            ↪ Sign out
          </button>
        </div>
      </aside>

      <main className="dashboard-main">
        <header className="dashboard-topbar">
          <div className="mobile-brand">
            Sentinel<span>X</span>
          </div>

          <div className="breadcrumb">
            Security operations <span>/</span>{' '}
            {nav.find((item) => item.id === tab)?.label}
          </div>

          <div className="top-actions">
            <span className="top-live">
              <i /> CONNECTED
            </span>

            <button
              className="refresh-button"
              onClick={() => {
                if (tab === 'overview') void loadDashboard(session)
                else if (tab === 'alerts') void loadAlerts(session, alertPage, alertStatusFilter, alertSeverityFilter)
                else if (tab === 'assets') void loadAssets(session)
                else if (tab === 'incidents') void loadIncidents(session)
                else void loadDashboard(session)
              }}
              disabled={loading || alertsLoading || assetsLoading || incidentsLoading}
            >
              {loading || alertsLoading || assetsLoading || incidentsLoading ? '↻ Loading' : '↻ Refresh'}
            </button>

            <button className="top-avatar" title={session.user.username}>
              {session.user.username.slice(0, 1).toUpperCase()}
            </button>
          </div>
        </header>

        <div className="dashboard-content">
          <div className="page-heading">
            <div>
              <div className="dash-kicker">SECURITY PLATFORM</div>
              <h1>
                {tab === 'overview'
                  ? 'Command centre'
                  : nav.find((item) => item.id === tab)?.label}
              </h1>
              <p>
                {tab === 'overview' && 'Continuous network intelligence, ML-based detection, and active threat posture.'}
                {tab === 'alerts' && 'Inspect, filter, acknowledge, and resolve detected security alerts.'}
                {tab === 'assets' && 'Monitored network endpoints, hostnames, and asset criticality.'}
                {tab === 'incidents' && 'Track active investigations and resolution status.'}
                {tab === 'predictions' && 'Evaluate traffic flows against trained ML threat detection models.'}
                {tab === 'flows' && 'Raw bidirectional network telemetry and traffic metrics.'}
              </p>
            </div>

            <div className="updated-label">
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString()}`
                : 'Awaiting data'}
            </div>
          </div>

          {dashboardError && (
            <div className="dashboard-error">
              <strong>Data unavailable</strong>
              <span>{dashboardError}</span>
              <button onClick={() => void loadDashboard(session)}>
                Retry
              </button>
            </div>
          )}

          {/* OVERVIEW TAB */}
          {tab === 'overview' && (
            <>
              <div className="section-heading">
                <h2>Security posture</h2>
                <span>LIVE TELEMETRY</span>
              </div>

              <div className="metric-grid">
                <Metric
                  label="Total assets"
                  value={o.totalAssets}
                  icon="▣"
                  tone="blue"
                  detail="Monitored endpoints"
                  onClick={() => setTab('assets')}
                />

                <Metric
                  label="Network flows"
                  value={o.totalNetworkFlows}
                  icon="⇄"
                  tone="cyan"
                  detail="Recorded flows"
                  onClick={() => setTab('flows')}
                />

                <Metric
                  label="ML predictions"
                  value={o.totalPredictions}
                  icon="⌁"
                  tone="purple"
                  detail={`${o.maliciousPredictions} flagged as attack`}
                  onClick={() => setTab('predictions')}
                />

                <Metric
                  label="Total alerts"
                  value={o.totalAlerts}
                  icon="◈"
                  tone="orange"
                  detail={`${o.openAlerts} currently open`}
                  onClick={() => setTab('alerts')}
                />

                <Metric
                  label="Critical alerts"
                  value={o.criticalAlerts}
                  icon="⚠"
                  tone="red"
                  detail="High priority investigations"
                  onClick={() => {
                    setAlertSeverityFilter('CRITICAL')
                    setTab('alerts')
                  }}
                />

                <Metric
                  label="Active incidents"
                  value={o.activeIncidents}
                  icon="◎"
                  tone="green"
                  detail={`${o.totalIncidents} total recorded`}
                  onClick={() => setTab('incidents')}
                />
              </div>

              <div className="two-column">
                <section className="panel">
                  <PanelTitle
                    title="Recent security alerts"
                    action="View all alerts"
                    onAction={() => setTab('alerts')}
                  />
                  <AlertList
                    alerts={data.alerts.slice(0, 5)}
                    onSelectAlert={(a) => setSelectedAlert(a)}
                  />
                </section>

                <section className="panel">
                  <PanelTitle
                    title="ML intelligence"
                    action="Run ML inference"
                    onAction={() => setTab('predictions')}
                  />
                  <PredictionList predictions={data.predictions.slice(0, 5)} />
                </section>
              </div>

              <section className="panel flow-preview">
                <PanelTitle
                  title="Recent network activity"
                  action="View all flows"
                  onAction={() => setTab('flows')}
                />
                <FlowTable flows={data.flows.slice(0, 5)} />
              </section>
            </>
          )}

          {/* ALERTS TAB */}
          {tab === 'alerts' && (
            <section className="panel full-panel">
              <PanelTitle
                title="Security Alert Register"
                action="Refresh"
                onAction={() => void loadAlerts(session, alertPage, alertStatusFilter, alertSeverityFilter)}
              />

              <div className="filter-toolbar">
                <input
                  type="text"
                  className="filter-input"
                  placeholder="Search alerts by title, description, or ID…"
                  value={alertSearchTerm}
                  onChange={(e) => setAlertSearchTerm(e.target.value)}
                />

                <select
                  className="filter-select"
                  value={alertSeverityFilter}
                  onChange={(e) => {
                    setAlertSeverityFilter(e.target.value)
                    setAlertPage(0)
                  }}
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>

                <select
                  className="filter-select"
                  value={alertStatusFilter}
                  onChange={(e) => {
                    setAlertStatusFilter(e.target.value)
                    setAlertPage(0)
                  }}
                >
                  <option value="ALL">All Statuses</option>
                  <option value="OPEN">Open</option>
                  <option value="ACKNOWLEDGED">Acknowledged</option>
                  <option value="RESOLVED">Resolved</option>
                </select>
              </div>

              {alertsLoading ? (
                <div className="empty-state">
                  <span>↻</span>
                  <p>Loading security alerts from backend…</p>
                </div>
              ) : filteredAlerts.length === 0 ? (
                <EmptyState text="No security alerts match the selected criteria." />
              ) : (
                <div className="table-wrap">
                  <table className="table-interactive">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Alert title</th>
                        <th>Severity</th>
                        <th>Risk score</th>
                        <th>Status</th>
                        <th>Created at</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAlerts.map((alert) => (
                        <tr key={alert.id} onClick={() => setSelectedAlert(alert)}>
                          <td>
                            <span style={{ font: '10px "DM Mono", monospace', color: '#68829f' }}>
                              #{alert.id}
                            </span>
                          </td>
                          <td>
                            <strong style={{ color: '#edf5ff', display: 'block', fontSize: 11 }}>
                              {alert.title}
                            </strong>
                            <small style={{ color: '#73879f', fontSize: 9 }}>
                              {alert.description ? alert.description.slice(0, 75) + '…' : 'No description'}
                            </small>
                          </td>
                          <td>
                            <span className={`severity ${alert.severity.toLowerCase()}`}>
                              {alert.severity}
                            </span>
                          </td>
                          <td>
                            <div className="risk-meter" style={{ minWidth: 90 }}>
                              <span style={{ font: '10px "DM Mono", monospace', color: '#c4d3e5' }}>
                                {alert.riskScore != null ? alert.riskScore.toFixed(1) : '—'}
                              </span>
                              <div className="risk-meter-bar">
                                <div
                                  className="risk-meter-fill"
                                  style={{
                                    width: `${Math.min(100, alert.riskScore || 0)}%`,
                                    background:
                                      (alert.riskScore || 0) >= 90
                                        ? '#ff8b94'
                                        : (alert.riskScore || 0) >= 70
                                          ? '#f5a97f'
                                          : (alert.riskScore || 0) >= 40
                                            ? '#eed485'
                                            : '#8ee2b8',
                                  }}
                                />
                              </div>
                            </div>
                          </td>
                          <td>
                            <span className={`badge-status ${(alert.status || 'open').toLowerCase()}`}>
                              {alert.status}
                            </span>
                          </td>
                          <td>
                            <span style={{ font: '9px "DM Mono", monospace', color: '#889cb2' }}>
                              {dateTime(alert.createdAt)}
                            </span>
                          </td>
                          <td onClick={(e) => e.stopPropagation()}>
                            <div style={{ display: 'flex', gap: 6 }}>
                              {alert.status === 'OPEN' && canManageAlerts && (
                                <button
                                  className="btn-action-ack"
                                  style={{ padding: '4px 8px', fontSize: 10 }}
                                  onClick={() => void handleAcknowledgeAlert(alert.id)}
                                >
                                  Ack
                                </button>
                              )}
                              {alert.status !== 'RESOLVED' && canManageAlerts && (
                                <button
                                  className="btn-action-resolve"
                                  style={{ padding: '4px 8px', fontSize: 10 }}
                                  onClick={() => void handleResolveAlert(alert.id)}
                                >
                                  Resolve
                                </button>
                              )}
                              {!canManageAlerts && (
                                <small style={{ color: '#5b6e82', fontSize: 9, fontStyle: 'italic' }}>
                                  View only
                                </small>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="pagination-controls">
                <span>
                  Showing {filteredAlerts.length} of {alertTotal} alerts (Page {alertPage + 1} of {alertPages})
                </span>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    className="pagination-btn"
                    disabled={alertPage <= 0 || alertsLoading}
                    onClick={() => setAlertPage((p) => Math.max(0, p - 1))}
                  >
                    ← Previous
                  </button>
                  <button
                    className="pagination-btn"
                    disabled={alertPage >= alertPages - 1 || alertsLoading}
                    onClick={() => setAlertPage((p) => p + 1)}
                  >
                    Next →
                  </button>
                </div>
              </div>
            </section>
          )}

          {/* ASSETS TAB */}
          {tab === 'assets' && (
            <section className="panel full-panel">
              <PanelTitle
                title="Monitored Assets & Network Endpoints"
                action="Refresh"
                onAction={() => void loadAssets(session)}
              />

              <div className="filter-toolbar">
                <input
                  type="text"
                  className="filter-input"
                  placeholder="Lookup by IP address, hostname, or OS…"
                  value={assetSearchTerm}
                  onChange={(e) => setAssetSearchTerm(e.target.value)}
                />

                <select
                  className="filter-select"
                  value={assetTypeFilter}
                  onChange={(e) => setAssetTypeFilter(e.target.value)}
                >
                  <option value="ALL">All Asset Types</option>
                  <option value="SERVER">Server</option>
                  <option value="WORKSTATION">Workstation</option>
                  <option value="NETWORK_ENDPOINT">Network Endpoint</option>
                </select>
              </div>

              {assetsLoading ? (
                <div className="empty-state">
                  <span>↻</span>
                  <p>Loading asset inventory from database…</p>
                </div>
              ) : filteredAssets.length === 0 ? (
                <EmptyState text="No monitored assets recorded yet." />
              ) : (
                <div className="table-wrap">
                  <table className="table-interactive">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>IP address</th>
                        <th>Hostname</th>
                        <th>Type</th>
                        <th>Criticality</th>
                        <th>MAC address</th>
                        <th>Operating system</th>
                        <th>Discovered / Updated</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAssets.map((asset) => (
                        <tr key={asset.id} onClick={() => setSelectedAsset(asset)}>
                          <td>
                            <span style={{ font: '10px "DM Mono", monospace', color: '#68829f' }}>
                              #{asset.id}
                            </span>
                          </td>
                          <td>
                            <strong style={{ font: '11px "DM Mono", monospace', color: '#58d3e2' }}>
                              {asset.ipAddress}
                            </strong>
                          </td>
                          <td>{asset.hostname || '—'}</td>
                          <td>
                            <span style={{ font: '10px "DM Mono", monospace', color: '#9bb1c8' }}>
                              {asset.assetType}
                            </span>
                          </td>
                          <td>
                            <span className={`criticality ${(asset.criticality || 'medium').toLowerCase()}`}>
                              {asset.criticality}
                            </span>
                          </td>
                          <td>
                            <span style={{ font: '10px "DM Mono", monospace', color: '#73879f' }}>
                              {asset.macAddress || '—'}
                            </span>
                          </td>
                          <td>{asset.operatingSystem || '—'}</td>
                          <td>
                            <span style={{ font: '9px "DM Mono", monospace', color: '#73879f' }}>
                              {dateTime(asset.updatedAt || asset.createdAt)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {/* INCIDENTS TAB */}
          {tab === 'incidents' && (
            <section className="panel full-panel">
              <PanelTitle
                title="Security Incidents"
                action="Refresh"
                onAction={() => void loadIncidents(session)}
              />

              {incidentsLoading ? (
                <div className="empty-state">
                  <span>↻</span>
                  <p>Loading security incidents…</p>
                </div>
              ) : incidentList.length === 0 ? (
                <div className="empty-state">
                  <span>◎</span>
                  <strong>No Active Incidents</strong>
                  <p>There are currently no open security incidents reported in the system.</p>
                  <small style={{ color: '#5b6e82' }}>
                    When high-priority security events are escalated, they will appear here with assigned SOC analyst workflows.
                  </small>
                </div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Incident title</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Assigned to</th>
                        <th>Detected at</th>
                        <th>Resolved at</th>
                        <th>Resolution notes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {incidentList.map((inc) => (
                        <tr key={inc.id}>
                          <td>#{inc.id}</td>
                          <td>
                            <strong>{inc.title}</strong>
                            {inc.description && <small style={{ display: 'block', color: '#73879f' }}>{inc.description}</small>}
                          </td>
                          <td>
                            <span className={`severity ${inc.severity.toLowerCase()}`}>
                              {inc.severity}
                            </span>
                          </td>
                          <td>
                            <span className={`badge-status ${inc.status.toLowerCase()}`}>
                              {inc.status}
                            </span>
                          </td>
                          <td>{inc.assignedTo ? inc.assignedTo.username : 'Unassigned'}</td>
                          <td>{dateTime(inc.detectedAt)}</td>
                          <td>{dateTime(inc.resolvedAt)}</td>
                          <td>{inc.resolutionNotes || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {/* PREDICTIONS TAB */}
          {tab === 'predictions' && (
            <>
              {canGeneratePredictions ? (
                <MLPredictionUpload
                  session={session}
                  onSaved={() => {
                    void loadDashboard(session)
                  }}
                  onUnauthorized={handleAuthExpiry}
                />
              ) : (
                <section className="panel full-panel">
                  <div className="panel-title">
                    <h2>ML prediction access</h2>
                    <span>READ ONLY</span>
                  </div>
                  <p style={{ color: '#8fa2b9', fontSize: 12 }}>
                    Your VIEWER role permits inspection of existing ML predictions. Generating new predictions
                    via on-demand CSV inference requires an authorized role (SOC_ANALYST, SECURITY_ENGINEER, or ADMIN).
                  </p>
                </section>
              )}

              <section className="panel full-panel" style={{ marginTop: 17 }}>
                <PanelTitle title="Recent ML predictions register" />
                <PredictionList predictions={data.predictions} />
              </section>
            </>
          )}

          {/* FLOWS TAB */}
          {tab === 'flows' && (
            <section className="panel full-panel">
              <PanelTitle title="Network Activity Telemetry" />
              <FlowTable flows={data.flows} />
            </section>
          )}

          <footer className="dashboard-footer">
            <span>SentinelX · Security Operations Platform · Core API Connected</span>
            <span>Logged in as <b>{session.user.username}</b> ({session.user.role})</span>
          </footer>
        </div>
      </main>

      {/* ALERT DETAILS MODAL */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-container" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <span className="dash-kicker">ALERT INVESTIGATION</span>
                <h3>{selectedAlert.title}</h3>
              </div>
              <button className="modal-close" onClick={() => setSelectedAlert(null)}>
                ×
              </button>
            </div>

            <div className="modal-body">
              {alertActionMessage && (
                <div style={{
                  padding: '10px 14px',
                  borderRadius: 6,
                  background: '#123425',
                  border: '1px solid #1f6443',
                  color: '#8cebc0',
                  fontSize: 11,
                }}>
                  {alertActionMessage}
                </div>
              )}

              <div className="detail-grid">
                <div className="detail-item">
                  <label>ALERT ID</label>
                  <span style={{ font: '11px "DM Mono", monospace' }}>#{selectedAlert.id}</span>
                </div>

                <div className="detail-item">
                  <label>SEVERITY</label>
                  <span className={`severity ${selectedAlert.severity.toLowerCase()}`}>
                    {selectedAlert.severity}
                  </span>
                </div>

                <div className="detail-item">
                  <label>CURRENT STATUS</label>
                  <span className={`badge-status ${(selectedAlert.status || 'open').toLowerCase()}`}>
                    {selectedAlert.status}
                  </span>
                </div>

                <div className="detail-item">
                  <label>RISK SCORE</label>
                  <span style={{ font: '11px "DM Mono", monospace', color: '#52d3dc' }}>
                    {selectedAlert.riskScore != null ? `${selectedAlert.riskScore.toFixed(2)} / 100` : '—'}
                  </span>
                </div>

                <div className="detail-item">
                  <label>ML PREDICTION ID</label>
                  <span style={{ font: '11px "DM Mono", monospace' }}>
                    {selectedAlert.mlPredictionId ? `#${selectedAlert.mlPredictionId}` : 'None'}
                  </span>
                </div>

                <div className="detail-item">
                  <label>DETECTED AT</label>
                  <span>{dateTime(selectedAlert.createdAt)}</span>
                </div>

                <div className="detail-item">
                  <label>ACKNOWLEDGED AT</label>
                  <span>{dateTime(selectedAlert.acknowledgedAt)}</span>
                </div>

                <div className="detail-item">
                  <label>RESOLVED AT</label>
                  <span>{dateTime(selectedAlert.resolvedAt)}</span>
                </div>
              </div>

              <div className="detail-item">
                <label>INCIDENT / ALERT DESCRIPTION</label>
                <p style={{ margin: '6px 0 0', color: '#c5d5e5', fontSize: 12, lineHeight: 1.6 }}>
                  {selectedAlert.description || 'No detailed security description available.'}
                </p>
              </div>

              {!canManageAlerts && (
                <div className="rbac-hint">
                  <span>ℹ</span> Read-only mode: Acknowledging or resolving alerts requires SOC Analyst or Security Engineer permissions.
                </div>
              )}
            </div>

            <div className="modal-foot">
              <button
                className="refresh-button"
                onClick={() => setSelectedAlert(null)}
              >
                Close
              </button>

              {canManageAlerts && selectedAlert.status === 'OPEN' && (
                <button
                  className="btn-action-ack"
                  disabled={alertActionLoading}
                  onClick={() => void handleAcknowledgeAlert(selectedAlert.id)}
                >
                  {alertActionLoading ? 'Updating…' : 'Acknowledge Alert'}
                </button>
              )}

              {canManageAlerts && selectedAlert.status !== 'RESOLVED' && (
                <button
                  className="btn-action-resolve"
                  disabled={alertActionLoading}
                  onClick={() => void handleResolveAlert(selectedAlert.id)}
                >
                  {alertActionLoading ? 'Updating…' : 'Resolve Alert'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ASSET DETAILS MODAL */}
      {selectedAsset && (
        <div className="modal-overlay" onClick={() => setSelectedAsset(null)}>
          <div className="modal-container" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div>
                <span className="dash-kicker">ASSET TELEMETRY</span>
                <h3>{selectedAsset.ipAddress}</h3>
              </div>
              <button className="modal-close" onClick={() => setSelectedAsset(null)}>
                ×
              </button>
            </div>

            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>ASSET ID</label>
                  <span style={{ font: '11px "DM Mono", monospace' }}>#{selectedAsset.id}</span>
                </div>

                <div className="detail-item">
                  <label>IP ADDRESS</label>
                  <strong style={{ font: '11px "DM Mono", monospace', color: '#58d3e2' }}>
                    {selectedAsset.ipAddress}
                  </strong>
                </div>

                <div className="detail-item">
                  <label>CRITICALITY</label>
                  <span className={`criticality ${(selectedAsset.criticality || 'medium').toLowerCase()}`}>
                    {selectedAsset.criticality}
                  </span>
                </div>

                <div className="detail-item">
                  <label>ASSET TYPE</label>
                  <span>{selectedAsset.assetType}</span>
                </div>

                <div className="detail-item">
                  <label>HOSTNAME</label>
                  <span>{selectedAsset.hostname || '—'}</span>
                </div>

                <div className="detail-item">
                  <label>MAC ADDRESS</label>
                  <span style={{ font: '11px "DM Mono", monospace' }}>{selectedAsset.macAddress || '—'}</span>
                </div>

                <div className="detail-item">
                  <label>OPERATING SYSTEM</label>
                  <span>{selectedAsset.operatingSystem || '—'}</span>
                </div>

                <div className="detail-item">
                  <label>FIRST SEEN</label>
                  <span>{dateTime(selectedAsset.createdAt)}</span>
                </div>
              </div>
            </div>

            <div className="modal-foot">
              <button
                className="btn-action-ack"
                onClick={() => {
                  setAlertSearchTerm(selectedAsset.ipAddress)
                  setSelectedAsset(null)
                  setTab('alerts')
                }}
              >
                Search alerts for this IP →
              </button>
              <button className="refresh-button" onClick={() => setSelectedAsset(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Metric({
  label,
  value,
  icon,
  tone,
  detail,
  onClick,
}: {
  label: string
  value: number
  icon: string
  tone: string
  detail: string
  onClick?: () => void
}) {
  return (
    <article
      className="metric-card"
      onClick={onClick}
      style={{ cursor: onClick ? 'pointer' : 'default' }}
      title={onClick ? `Navigate to ${label}` : undefined}
    >
      <div className="metric-top">
        <span>{label}</span>
        <span className={`metric-icon ${tone}`}>{icon}</span>
      </div>
      <strong>{number(value)}</strong>
      <small>{detail}</small>
    </article>
  )
}

function PanelTitle({
  title,
  action,
  onAction,
}: {
  title: string
  action?: string
  onAction?: () => void
}) {
  return (
    <div className="panel-title">
      <h2>{title}</h2>
      {action && <button onClick={onAction}>{action} →</button>}
    </div>
  )
}

function AlertList({
  alerts,
  onSelectAlert,
}: {
  alerts: RecentAlert[]
  onSelectAlert?: (alert: RecentAlert) => void
}) {
  if (!alerts.length) {
    return <EmptyState text="No security alerts have been recorded." />
  }

  return (
    <div className="record-list">
      {alerts.map((alert) => (
        <div
          className="record-row"
          key={alert.id}
          style={{ cursor: onSelectAlert ? 'pointer' : 'default' }}
          onClick={() => onSelectAlert && onSelectAlert(alert)}
        >
          <div className="record-symbol alert-symbol">!</div>

          <div className="record-main">
            <strong>{alert.title}</strong>
            <small>
              {alert.description || `Alert #${alert.id}`} ·{' '}
              {dateTime(alert.createdAt)}
            </small>
          </div>

          <div className="record-meta">
            <span className={`severity ${alert.severity.toLowerCase()}`}>
              {alert.severity}
            </span>
            <small className="status-text">{alert.status}</small>
          </div>
        </div>
      ))}
    </div>
  )
}

function PredictionList({
  predictions,
}: {
  predictions: RecentPrediction[]
}) {
  if (!predictions.length) {
    return <EmptyState text="No ML predictions have been recorded." />
  }

  return (
    <div className="record-list">
      {predictions.map((item) => (
        <div className="record-row" key={item.id}>
          <div className="record-symbol prediction-symbol">⌁</div>

          <div className="record-main">
            <strong>{item.prediction}</strong>
            <small>
              {item.modelName} · v{item.modelVersion} ·{' '}
              {dateTime(item.predictedAt)}
            </small>
          </div>

          <div className="record-meta">
            <strong className="confidence">{percent(item.confidence)}</strong>
            <small className="status-text">Confidence</small>
          </div>
        </div>
      ))}
    </div>
  )
}

function FlowTable({ flows }: { flows: RecentNetworkFlow[] }) {
  if (!flows.length) {
    return (
      <EmptyState text="No network flows recorded yet. Telemetry will stream in from the collector." />
    )
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Packets</th>
            <th>Bytes sent</th>
            <th>Bytes recvd</th>
            <th>Duration</th>
            <th>Timestamp</th>
          </tr>
        </thead>

        <tbody>
          {flows.map((flow) => (
            <tr key={flow.id}>
              <td>
                <span style={{ font: '10px "DM Mono", monospace', color: '#58d3e2' }}>
                  {flow.sourceIp || '—'}
                </span>
                {flow.sourcePort != null ? `:${flow.sourcePort}` : ''}
              </td>
              <td>
                <span style={{ font: '10px "DM Mono", monospace', color: '#cbd7e7' }}>
                  {flow.destinationIp || '—'}
                </span>
                {flow.destinationPort != null
                  ? `:${flow.destinationPort}`
                  : ''}
              </td>
              <td>
                <span className="severity" style={{ background: '#1c2838', color: '#9bb1c8' }}>
                  {flow.protocol || '—'}
                </span>
              </td>
              <td>{number(flow.packets)}</td>
              <td>{number(flow.bytesSent)}</td>
              <td>{number(flow.bytesReceived)}</td>
              <td>{flow.duration != null ? `${flow.duration.toFixed(3)}s` : '—'}</td>
              <td>{dateTime(flow.timestamp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="empty-state">
      <span>◇</span>
      <p>{text}</p>
    </div>
  )
}

export default App
