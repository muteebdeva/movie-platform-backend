// Typed auth errors (4xx with stable codes for the frontend).
export class AuthError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
  }
}

export const invalidCredentials = () =>
  new AuthError(401, 'invalid_credentials', 'Incorrect email or password.');

export const emailNotVerified = () =>
  new AuthError(403, 'email_not_verified', 'Please verify your email address first.');

export const accountSuspended = () =>
  new AuthError(403, 'account_suspended', 'This account has been suspended.');

export const unauthorized = () =>
  new AuthError(401, 'unauthorized', 'Not signed in.');

export const forbidden = () =>
  new AuthError(403, 'forbidden', 'You do not have permission to do that.');

export const invalidToken = (what = 'token') =>
  new AuthError(400, 'invalid_token', `This ${what} is invalid or has expired.`);

export const emailInUse = () =>
  new AuthError(409, 'email_in_use', 'An account with this email already exists.');
