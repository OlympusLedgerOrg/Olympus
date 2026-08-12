// SPDX-License-Identifier: Apache-2.0

/** User registration + key reissue. */

import { apiFetch } from "./core";

// ─── User registration ────────────────────────────────────────────────────────

export type RegisterRequest = {
  email: string;
  password: string;
  name?: string;
  scopes?: string[];
};

export type RegisterResponse = {
  user_id: string;
  email?: string;
  api_key: string;
  key_id?: string;
  scopes?: string[];
  role?: string;
};

export function registerPublicUser(body: RegisterRequest): Promise<RegisterResponse> {
  return apiFetch<RegisterResponse>("/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ─── Key reissue (recovery path — no existing key required) ──────────────────

export type ReissueKeyResponse = {
  api_key: string;
  key_id: string;
  scopes: string[];
  expires_at: string;
};

export function reissueKey(email: string, password: string): Promise<ReissueKeyResponse> {
  return apiFetch<ReissueKeyResponse>("/auth/reissue-key", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      password,
      scopes: ["read", "verify", "ingest", "commit", "write"],
    }),
  });
}
