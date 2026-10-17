// Minimal Vercel function req/res shapes — structural only, no @vercel/node dep
// (same pattern as the movie and admin repos).
export interface ApiRequest {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, string | string[] | undefined>;
  body?: unknown;
}

export interface ApiResponse {
  status(code: number): ApiResponse;
  setHeader(name: string, value: string | string[]): ApiResponse;
  send(body: unknown): void;
}

export type Handler = (req: ApiRequest, res: ApiResponse) => void | Promise<void>;

export function header(
  headers: ApiRequest['headers'],
  name: string
): string | undefined {
  const v = headers[name.toLowerCase()] ?? headers[name];
  return Array.isArray(v) ? v[0] : v;
}

/** Best-effort client IP (Vercel puts it in x-forwarded-for). */
export function clientIp(req: ApiRequest): string {
  const fwd = header(req.headers, 'x-forwarded-for');
  if (fwd) return fwd.split(',')[0].trim().slice(0, 64);
  return 'unknown';
}

/** Public user shape — never includes password hashes or tokens. */
export interface PublicUser {
  id: string;
  email: string;
  displayName: string;
  emailVerified: boolean;
  role: 'user' | 'admin';
  createdAt: string;
}
