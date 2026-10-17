// Input validation. All user input is validated server-side; client-side
// validation mirrors these rules but is never trusted.
export class ValidationError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'ValidationError';
    this.code = code;
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

/** Normalize for uniqueness: trim + lowercase. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function assertEmail(email: unknown): string {
  if (typeof email !== 'string') throw new ValidationError('invalid_email', 'Email is required.');
  const v = email.trim();
  if (v.length === 0 || v.length > 254 || !EMAIL_RE.test(v)) {
    throw new ValidationError('invalid_email', 'Enter a valid email address.');
  }
  return v;
}

export function assertDisplayName(name: unknown): string {
  if (typeof name !== 'string') throw new ValidationError('invalid_name', 'Name is required.');
  const v = name.trim().replace(/\s+/g, ' ');
  if (v.length < 1 || v.length > 60) {
    throw new ValidationError('invalid_name', 'Name must be 1–60 characters.');
  }
  return v;
}

// Small blocklist of the most abused passwords. The length floor does the
// heavy lifting; this catches "password1234" style entries.
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password12', 'password123', 'password1234',
  '1234567890', '12345678901', 'qwerty12345', 'letmein1234', 'welcome123',
  'admin12345', 'iloveyou12', 'monkey1234', 'dragon1234', 'football12',
]);

export function assertPassword(password: unknown): string {
  if (typeof password !== 'string') throw new ValidationError('invalid_password', 'Password is required.');
  if (password.length < 10 || password.length > 128) {
    throw new ValidationError('weak_password', 'Password must be at least 10 characters.');
  }
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    throw new ValidationError('weak_password', 'That password is too common. Choose a stronger one.');
  }
  return password;
}

export function assertTerms(accepted: unknown): void {
  if (accepted !== true) {
    throw new ValidationError('terms_required', 'You must accept the terms and privacy policy.');
  }
}

export function bodyObject(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ValidationError('invalid_body', 'Request body must be a JSON object.');
  }
  return body as Record<string, unknown>;
}
