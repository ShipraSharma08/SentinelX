export interface AuthUser {
  id: number
  username: string
  email: string
  role: string
}

export interface AuthResponse {
  accessToken: string
  tokenType: string
  expiresIn: number
  user: AuthUser
}

export type AuthSession = AuthResponse

export interface LoginRequest {
  usernameOrEmail: string
  password: string
}

export interface RegisterRequest {
  username: string
  email: string
  password: string
}

export interface DashboardOverview {
  totalAssets: number
  totalNetworkFlows: number
  totalPredictions: number
  totalAlerts: number
  openAlerts: number
  criticalAlerts: number
  totalIncidents: number
  activeIncidents: number
  maliciousPredictions: number
}

export interface RecentAlert {
  id: number
  title: string
  description: string | null
  severity: string
  riskScore: number | null
  status: string
  mlPredictionId: number | null
  createdAt: string
  acknowledgedAt?: string | null
  resolvedAt?: string | null
}

export type AlertItem = RecentAlert

export interface PageResponse<T> {
  content: T[]
  totalElements: number
  totalPages: number
  size: number
  number: number
}

export interface RecentPrediction {
  id: number
  prediction: string
  modelName: string
  modelVersion: string
  confidence: number | null
  riskScore: number | null
  predictedAt: string
}

export interface RecentNetworkFlow {
  id: number
  sourceIp: string | null
  destinationIp: string | null
  sourcePort: number | null
  destinationPort: number | null
  protocol: string | null
  bytesSent: number | null
  bytesReceived: number | null
  packets: number | null
  duration: number | null
  timestamp: string
}

export interface AssetItem {
  id: number
  ipAddress: string
  hostname: string | null
  macAddress: string | null
  assetType: string
  operatingSystem: string | null
  criticality: string
  createdAt: string
  updatedAt: string
}

export interface IncidentItem {
  id: number
  title: string
  description: string | null
  severity: string
  status: string
  assignedTo: {
    id: number
    username: string
    email: string
  } | null
  detectedAt: string
  acknowledgedAt: string | null
  resolvedAt: string | null
  resolutionNotes: string | null
}

export interface PredictionResult {
  id: number
  prediction: string
  model: string
  modelVersion: string
  confidence: number
  riskScore: number
  predictedAt: string
}

const API_BASE = '/api'

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  let response: Response

  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        Accept: 'application/json',
        ...options.headers,
      },
    })
  } catch {
    throw new ApiError(
      'Cannot reach SentinelX API. Check that the backend is running.',
      0,
    )
  }

  const responseText = await response.text()
  let data: unknown

  try {
    data = responseText ? JSON.parse(responseText) : null
  } catch {
    data = null
  }

  if (!response.ok) {
    const payload =
      data && typeof data === 'object'
        ? (data as Record<string, unknown>)
        : {}

    const message =
      payload.detail ??
      payload.message ??
      payload.title ??
      payload.error

    throw new ApiError(
      typeof message === 'string'
        ? message
        : `Request failed with status ${response.status}.`,
      response.status,
    )
  }

  return data as T
}

async function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })
}

function getAuthenticated<T>(
  path: string,
  session: AuthSession,
): Promise<T> {
  return request<T>(path, {
    method: 'GET',
    headers: {
      Authorization: `${session.tokenType} ${session.accessToken}`,
    },
  })
}

function patchAuthenticated<T>(
  path: string,
  session: AuthSession,
  body?: unknown,
): Promise<T> {
  return request<T>(path, {
    method: 'PATCH',
    headers: {
      Authorization: `${session.tokenType} ${session.accessToken}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  })
}

function postAuthenticated<T>(
  path: string,
  session: AuthSession,
  body: unknown,
): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: {
      Authorization: `${session.tokenType} ${session.accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })
}

export const authApi = {
  login(request: LoginRequest): Promise<AuthResponse> {
    return post<AuthResponse>('/auth/login', request)
  },

  register(request: RegisterRequest): Promise<AuthResponse> {
    return post<AuthResponse>('/auth/register', request)
  },
}

export const dashboardApi = {
  getOverview(session: AuthSession): Promise<DashboardOverview> {
    return getAuthenticated<DashboardOverview>(
      '/dashboard/overview',
      session,
    )
  },

  getRecentAlerts(session: AuthSession): Promise<RecentAlert[]> {
    return getAuthenticated<RecentAlert[]>(
      '/dashboard/recent-alerts',
      session,
    )
  },

  getRecentPredictions(session: AuthSession): Promise<RecentPrediction[]> {
    return getAuthenticated<RecentPrediction[]>(
      '/dashboard/recent-predictions',
      session,
    )
  },

  getRecentFlows(session: AuthSession): Promise<RecentNetworkFlow[]> {
    return getAuthenticated<RecentNetworkFlow[]>(
      '/dashboard/recent-flows',
      session,
    )
  },
}

export const alertsApi = {
  getAll(session: AuthSession): Promise<AlertItem[]> {
    return getAuthenticated<AlertItem[]>('/alerts', session)
  },

  search(
    session: AuthSession,
    params: {
      status?: string
      severity?: string
      page?: number
      size?: number
    } = {},
  ): Promise<PageResponse<AlertItem>> {
    const query = new URLSearchParams()
    if (params.status && params.status !== 'ALL') query.set('status', params.status)
    if (params.severity && params.severity !== 'ALL') query.set('severity', params.severity)
    if (params.page != null) query.set('page', String(params.page))
    if (params.size != null) query.set('size', String(params.size))

    const qs = query.toString()
    return getAuthenticated<PageResponse<AlertItem>>(
      `/alerts/search${qs ? `?${qs}` : ''}`,
      session,
    )
  },

  getById(session: AuthSession, id: number): Promise<AlertItem> {
    return getAuthenticated<AlertItem>(`/alerts/${id}`, session)
  },

  acknowledge(session: AuthSession, id: number): Promise<AlertItem> {
    return patchAuthenticated<AlertItem>(`/alerts/${id}/acknowledge`, session)
  },

  resolve(session: AuthSession, id: number): Promise<AlertItem> {
    return patchAuthenticated<AlertItem>(`/alerts/${id}/resolve`, session)
  },
}

export const assetsApi = {
  getAll(session: AuthSession): Promise<AssetItem[]> {
    return getAuthenticated<AssetItem[]>('/assets', session)
  },

  getById(session: AuthSession, id: number): Promise<AssetItem> {
    return getAuthenticated<AssetItem>(`/assets/${id}`, session)
  },

  getByIp(session: AuthSession, ipAddress: string): Promise<AssetItem> {
    return getAuthenticated<AssetItem>(`/assets/ip/${encodeURIComponent(ipAddress)}`, session)
  },
}

export const incidentsApi = {
  getAll(session: AuthSession): Promise<IncidentItem[]> {
    return getAuthenticated<IncidentItem[]>('/incidents', session)
  },
}

export const mlApi = {
  predict(
    session: AuthSession,
    features: Record<string, number>,
  ): Promise<PredictionResult> {
    return postAuthenticated<PredictionResult>('/ml/predict', session, { features })
  },
}

const SESSION_KEY = 'sentinelx.session'

export function getStoredSession(): AuthSession | null {
  try {
    const stored = sessionStorage.getItem(SESSION_KEY)

    if (!stored) return null

    const session: AuthSession = JSON.parse(stored)

    if (
      typeof session.accessToken !== 'string' ||
      !session.accessToken ||
      typeof session.tokenType !== 'string' ||
      !session.user ||
      typeof session.user.username !== 'string'
    ) {
      sessionStorage.removeItem(SESSION_KEY)
      return null
    }

    return session
  } catch {
    return null
  }
}

export function storeSession(session: AuthSession): void {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session))
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_KEY)
}
