/**
 * Minimal HTTP client for the Olympus API.
 *
 * Wraps ``fetch`` with JSON defaults and bearer-token auth so that
 * feature components can call ``api.get('/path')`` without boilerplate.
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';

interface ApiResponse<T> {
  data: T;
  status: number;
}

async function request<T>(method: string, path: string): Promise<ApiResponse<T>> {
  const token = localStorage.getItem('olympus_token') ?? '';
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'X-API-Key': token } : {}),
    },
  });

  if (!res.ok) {
    throw new Error(`API ${method} ${path} failed: ${res.status}`);
  }

  const data: T = await res.json();
  return { data, status: res.status };
}

const api = {
  get: <T>(path: string) => request<T>('GET', path),
};

export default api;
