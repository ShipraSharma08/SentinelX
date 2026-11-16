import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  authApi,
  dashboardApi,
  clearSession,
  getStoredSession,
  storeSession,
  ApiError,
  type AuthSession,
  type DashboardOverview,
  type RecentAlert,
  type RecentPrediction,
  type RecentNetworkFlow,
} from './lib/api'
import MLPredictionUpload from './components/MLPredictionUpload'
import './App.css'
import './Dashboard.css'

type Tab = 'overview' | 'alerts' | 'predictions' | 'flows'

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

const dateTime = (value: string) => {
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
  const [authError, setAuthError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const [tab, setTab] = useState<Tab>('overview')
  const [data, setData] = useState<DashboardData>(emptyData)
  const [loading, setLoading] = useState(false)
  const [dashboardError, setDashboardError] = useState('')
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

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
        clearSession()
        setSession(null)
        setAuthError('Your session expired. Please sign in again.')
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
  }, [])

  useEffect(() => {
    if (session) void loadDashboard(session)
  }, [session, loadDashboard])

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
            <input
              required
              minLength={mode === 'register' ? 8 : undefined}
              type="password"
              autoComplete={
                mode === 'login' ? 'current-password' : 'new-password'
              }
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter password"
            />

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

  const nav: { id: Tab; label: string; icon: string }[] = [
    { id: 'overview', label: 'Overview', icon: '▦' },
    { id: 'alerts', label: 'Security alerts', icon: '◈' },
    { id: 'predictions', label: 'ML predictions', icon: '⌁' },
    { id: 'flows', label: 'Network activity', icon: '⇄' },
  ]

  const canGeneratePredictions = [
    'ADMIN',
    'SOC_ANALYST',
    'SECURITY_ENGINEER',
  ].includes(session.user.role)

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
              onClick={() => setTab(item.id)}
            >
              <span>{item.icon}</span>
              {item.label}
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
              onClick={() => void loadDashboard(session)}
              disabled={loading}
            >
              {loading ? '↻ Loading' : '↻ Refresh'}
            </button>

            <button className="top-avatar" title={session.user.username}>
              {session.user.username.slice(0, 1).toUpperCase()}
            </button>
          </div>
        </header>

        <div className="dashboard-content">
          <div className="page-heading">
            <div>
              <div className="dash-kicker">SECURITY OVERVIEW</div>
              <h1>
                {tab === 'overview'
                  ? 'Command centre'
                  : nav.find((item) => item.id === tab)?.label}
              </h1>
              <p>
                Monitor your environment and review security intelligence.
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

          {(tab === 'overview' || tab === 'alerts') && (
            <>
              <div className="section-heading">
                <h2>Security posture</h2>
                <span>LIVE BACKEND DATA</span>
              </div>

              <div className="metric-grid">
                <Metric
                  label="Total assets"
                  value={o.totalAssets}
                  icon="▣"
                  tone="blue"
                  detail="Monitored assets"
                />

                <Metric
                  label="Network flows"
                  value={o.totalNetworkFlows}
                  icon="⇄"
                  tone="cyan"
                  detail="Recorded flows"
                />

                <Metric
                  label="ML predictions"
                  value={o.totalPredictions}
                  icon="⌁"
                  tone="purple"
                  detail={`${o.maliciousPredictions} malicious`}
                />

                <Metric
                  label="Total alerts"
                  value={o.totalAlerts}
                  icon="◈"
                  tone="orange"
                  detail={`${o.openAlerts} currently open`}
                />

                <Metric
                  label="Critical alerts"
                  value={o.criticalAlerts}
                  icon="⚠"
                  tone="red"
                  detail="Critical severity"
                />

                <Metric
                  label="Active incidents"
                  value={o.activeIncidents}
                  icon="◎"
                  tone="green"
                  detail={`${o.totalIncidents} total incidents`}
                />
              </div>

              <div className="two-column">
                <section className="panel">
                  <PanelTitle
                    title="Recent security alerts"
                    action="View all"
                    onAction={() => setTab('alerts')}
                  />
                  <AlertList alerts={data.alerts.slice(0, 5)} />
                </section>

                <section className="panel">
                  <PanelTitle
                    title="ML intelligence"
                    action="View all"
                    onAction={() => setTab('predictions')}
                  />
                  <PredictionList predictions={data.predictions.slice(0, 5)} />
                </section>
              </div>
            </>
          )}

          {tab === 'predictions' && (
            <>
              {canGeneratePredictions ? (
                <MLPredictionUpload
                  session={session}
                  onSaved={() => void loadDashboard(session)}
                  onUnauthorized={() => {
                    clearSession()
                    setSession(null)
                    setAuthError(
                      'Your session expired. Please sign in again.',
                    )
                  }}
                />
              ) : (
                <section className="panel full-panel">
                  <div className="panel-title">
                    <h2>ML prediction access</h2>
                    <span>READ ONLY</span>
                  </div>
                  <p>
                    Your VIEWER role allows you to review existing ML
                    predictions. Generating new predictions requires an
                    authorized role.
                  </p>
                </section>
              )}

              <section className="panel full-panel">
                <PanelTitle title="Recent ML predictions" />
                <PredictionList predictions={data.predictions} />
              </section>
            </>
          )}

          {tab === 'alerts' && (
            <section className="panel full-panel">
              <PanelTitle title="Security alert register" />
              <AlertList alerts={data.alerts} />
            </section>
          )}

          {tab === 'flows' && (
            <section className="panel full-panel">
              <PanelTitle title="Recent network flows" />
              <FlowTable flows={data.flows} />
            </section>
          )}

          {tab === 'overview' && (
            <section className="panel flow-preview">
              <PanelTitle
                title="Recent network activity"
                action="View all"
                onAction={() => setTab('flows')}
              />
              <FlowTable flows={data.flows.slice(0, 5)} />
            </section>
          )}

          <footer className="dashboard-footer">
            <span>SentinelX · Security Operations Platform</span>
            <span>Authenticated as {session.user.username}</span>
          </footer>
        </div>
      </main>
    </div>
  )
}

function Metric({
  label,
  value,
  icon,
  tone,
  detail,
}: {
  label: string
  value: number
  icon: string
  tone: string
  detail: string
}) {
  return (
    <article className="metric-card">
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

function AlertList({ alerts }: { alerts: RecentAlert[] }) {
  if (!alerts.length) {
    return <EmptyState text="No security alerts have been recorded." />
  }

  return (
    <div className="record-list">
      {alerts.map((alert) => (
        <div className="record-row" key={alert.id}>
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
      <EmptyState text="No network flows recorded yet. Data will appear here when available." />
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
            <th>Timestamp</th>
          </tr>
        </thead>

        <tbody>
          {flows.map((flow) => (
            <tr key={flow.id}>
              <td>
                {flow.sourceIp || '—'}
                {flow.sourcePort != null ? `:${flow.sourcePort}` : ''}
              </td>
              <td>
                {flow.destinationIp || '—'}
                {flow.destinationPort != null
                  ? `:${flow.destinationPort}`
                  : ''}
              </td>
              <td>{flow.protocol || '—'}</td>
              <td>{number(flow.packets)}</td>
              <td>{number(flow.bytesSent)}</td>
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
