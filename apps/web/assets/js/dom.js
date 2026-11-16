// Construcción de DOM segura: TODO dato externo se inserta como texto (nunca innerHTML).
// Los hallazgos contienen fragmentos de código hostil: esta regla es crítica.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'href') el.setAttribute('href', safeHref(value));
    else if (key === 'value') el.value = value;
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function safeHref(url) {
  const s = String(url);
  if (s.startsWith('#') || s.startsWith('/')) return s;
  try {
    const u = new URL(s);
    return ['http:', 'https:'].includes(u.protocol) ? u.href : '#';
  } catch { return '#'; }
}

export function externalLink(url, text) {
  return h('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, text ?? url);
}

export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

export const fmtDate = (iso) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString('es-ES', { dateStyle: 'medium', timeStyle: 'short' });
};

export const fmtBytes = (n) => {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0; let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
};

export const short = (hash, n = 12) => (hash ? `${String(hash).slice(0, n)}…` : '—');

const LABELS = {
  APPROVED: 'Aprobado', REJECTED: 'Rechazado', REVIEW_REQUIRED: 'Revisión requerida', INCONCLUSIVE: 'Inconcluso',
  CREATED: 'Creado', VALIDATING: 'Validando', QUEUED: 'En cola', RUNNING: 'Ejecutando', NORMALIZING: 'Normalizando',
  EVALUATING: 'Evaluando', COMPLETED: 'Completado', FAILED: 'Fallido', CANCELLED: 'Cancelado', TIMED_OUT: 'Tiempo agotado',
  SUCCEEDED: 'Correcto', SKIPPED: 'Omitido', PENDING: 'Pendiente', REVOKED: 'Revocada', ACTIVE: 'Activa', DRAFT: 'Borrador',
  RETIRED: 'Retirada', PASS: 'Cumple', FAIL: 'No cumple', MISSING: 'No planificado', NOT_VERIFIED: 'Sin verificar',
  NOT_EXECUTED: 'No ejecutado', EVIDENCE_INVALID: 'Evidencia inválida',
  CRITICAL: 'Crítico', HIGH: 'Alto', MEDIUM: 'Medio', LOW: 'Bajo', INFO: 'Info',
};
export const label = (v) => LABELS[v] ?? v ?? '—';

const RUNNING = new Set(['CREATED', 'VALIDATING', 'QUEUED', 'RUNNING', 'NORMALIZING', 'EVALUATING']);
export function badge(value, extraClass = '') {
  if (!value) return h('span', { class: 'badge outline' }, '—');
  return h('span', { class: `badge ${value} ${extraClass}`.trim() },
    RUNNING.has(value) ? h('span', { class: 'dot pulse' }) : null, label(value));
}
export const sevBadge = (s) => h('span', { class: `badge sev-${s}` }, label(s));

export function table(columns, rows, { onRow, empty = 'Sin datos.' } = {}) {
  if (!rows.length) return h('div', { class: 'empty' }, empty);
  return h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, columns.map((c) => h('th', { class: c.class }, c.title)))),
    h('tbody', {}, rows.map((r) => h('tr', { class: onRow ? 'clickable' : null, onClick: onRow ? () => onRow(r) : null },
      columns.map((c) => h('td', { class: c.class }, c.render ? c.render(r) : (r[c.key] ?? '—'))))))));
}

export function alertBox(kind, ...content) { return h('div', { class: `alert ${kind}`, role: kind === 'error' ? 'alert' : 'status' }, ...content); }

export function toast(message, kind = 'success') {
  const el = h('div', { class: `toast alert ${kind}`, role: 'status' }, message);
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

export function field(labelText, input, hint) {
  return h('div', { class: 'field' }, h('label', {}, labelText), input, hint ? h('div', { class: 'hint' }, hint) : null);
}

export function select(name, options, value) {
  return h('select', { name }, options.map(([v, text]) => h('option', { value: v, selected: v === value ? true : null }, text)));
}
