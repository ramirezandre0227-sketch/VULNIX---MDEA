// Cliente de la API /api/v1. Sesión del mismo origen + token CSRF (Sanctum), sin tokens en localStorage.

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status; this.code = code; this.details = details;
  }
}

function xsrf() {
  const m = document.cookie.split('; ').find((c) => c.startsWith('XSRF-TOKEN='));
  return m ? decodeURIComponent(m.split('=')[1]) : '';
}

let onUnauthenticated = () => {};
export const setUnauthenticatedHandler = (fn) => { onUnauthenticated = fn; };

export async function ensureCsrf() {
  await fetch('/sanctum/csrf-cookie', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
}

export async function request(method, path, { body, form, blob } = {}) {
  const headers = { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
  if (method !== 'GET') {
    if (!xsrf()) await ensureCsrf();
    headers['X-XSRF-TOKEN'] = xsrf();
  }
  let payload;
  if (form) payload = form;
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const res = await fetch(`/api/v1${path}`, { method, headers, body: payload, credentials: 'same-origin' });
  if (res.status === 401 && path !== '/auth/login') onUnauthenticated();
  if (res.status === 419) await ensureCsrf();
  if (!res.ok) {
    let err = {};
    try { err = (await res.json()).error ?? {}; } catch { /* respuesta no JSON */ }
    throw new ApiError(res.status, err.code ?? `HTTP_${res.status}`, err.message ?? 'Error de comunicación con la API.', err.details);
  }
  if (blob) return { blob: await res.blob(), headers: res.headers };
  return res.status === 204 ? null : res.json();
}

export const api = {
  get: (p) => request('GET', p),
  post: (p, body) => request('POST', p, { body }),
  patch: (p, body) => request('PATCH', p, { body }),
  upload: (p, formData) => request('POST', p, { form: formData }),
  download: async (p, filename) => {
    const { blob, headers } = await request('GET', p, { blob: true });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    return headers.get('X-Vulnix-SHA256');
  },
};

export function qs(params) {
  const s = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== '' && v != null)).toString();
  return s ? `?${s}` : '';
}
