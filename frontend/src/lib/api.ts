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

interface LoginRequest {
  usernameOrEmail: string
  password: string
}

interface RegisterRequest {
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
