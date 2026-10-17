// Outgoing email via Resend (HTTPS API, no SDK). Entirely optional: when
// RESEND_API_KEY / EMAIL_FROM are not configured, sendEmail reports
// { sent: false } and callers must NOT claim an email was delivered.
export interface EmailResult {
  sent: boolean;
  id?: string;
}

export function emailConfigured(): boolean {
  return Boolean(process.env.RESEND_API_KEY && process.env.EMAIL_FROM);
}

export async function sendEmail(opts: { to: string; subject: string; html: string }): Promise<EmailResult> {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM;
  if (!apiKey || !from) return { sent: false };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      signal: controller.signal,
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: opts.to, subject: opts.subject, html: opts.html }),
    });
    if (!res.ok) {
      console.error('[email] resend failed:', res.status);
      return { sent: false };
    }
    const data = (await res.json().catch(() => ({}))) as { id?: string };
    return { sent: true, id: data.id };
  } catch (e) {
    console.error('[email] send error:', e);
    return { sent: false };
  } finally {
    clearTimeout(timer);
  }
}

export function verificationEmail(to: string, name: string, link: string): { subject: string; html: string } {
  return {
    subject: 'Verify your email',
    html: `<p>Hi ${escapeHtml(name)},</p><p>Click the link below to verify your email address:</p><p><a href="${link}">${link}</a></p><p>This link expires in 24 hours.</p>`,
  };
}

export function resetEmail(to: string, name: string, link: string): { subject: string; html: string } {
  return {
    subject: 'Reset your password',
    html: `<p>Hi ${escapeHtml(name)},</p><p>Click the link below to reset your password:</p><p><a href="${link}">${link}</a></p><p>This link expires in 1 hour. If you didn't request this, you can ignore it.</p>`,
  };
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
