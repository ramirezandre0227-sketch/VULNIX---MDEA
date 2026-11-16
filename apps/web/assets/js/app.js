import { api, ApiError, ensureCsrf, setUnauthenticatedHandler } from './api.js';
import { alertBox, clear, h } from './dom.js';
import { renderDashboard, renderSystem } from './views/dashboard.js';
import { renderProjects, renderProject } from './views/projects.js';
import { renderAnalysis, renderAnalyses } from './views/analysis.js';
import { renderFinding } from './views/finding.js';
import { renderExceptions, renderPolicies, renderPolicy } from './views/governance.js';
import { renderAudit, renderUsers } from './views/admin.js';

export const state = { user: null, timers: new Set() };
export const can = (ability) => Boolean(state.user?.abilities?.includes(ability));

const ROUTES = [
  [/^#\/?$/, renderDashboard, 'dashboard'],
  [/^#\/projects$/, renderProjects, 'projects'],
  [/^#\/projects\/([0-9a-f-]{36})$/, renderProject, 'projects'],
  [/^#\/analyses$/, renderAnalyses, 'analyses'],
  [/^#\/analyses\/([0-9a-f-]{36})$/, renderAnalysis, 'analyses'],
  [/^#\/findings\/([0-9a-f-]{36})$/, renderFinding, 'analyses'],
  [/^#\/exceptions$/, renderExceptions, 'exceptions'],
  [/^#\/policies$/, renderPolicies, 'policies'],
  [/^#\/policies\/([0-9a-f-]{36})$/, renderPolicy, 'policies'],
  [/^#\/audit$/, renderAudit, 'audit'],
  [/^#\/users$/, renderUsers, 'users'],
  [/^#\/system$/, renderSystem, 'system'],
];

const root = document.getElementById('app');

// ------------------------------------------------------------------ tema (Liquid Glass claro por defecto)
const THEME_KEY = 'vulnix.theme';
const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');
function themePref() {
  try { return localStorage.getItem(THEME_KEY) || 'light'; } catch { return 'light'; }
}
function applyTheme(pref = themePref()) {
  const dark = pref === 'dark' || (pref === 'system' && darkQuery.matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
}
applyTheme();
darkQuery.addEventListener('change', () => applyTheme());

// Botón flotante único (fijo en pantalla, fuera de #app para sobrevivir a cada render):
// cada clic rota Claro → Oscuro → Sistema.
const THEMES = {
  light: { label: 'Claro', next: 'dark', icon: [['circle', { cx: 12, cy: 12, r: 4 }], ['path', { d: 'M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4' }]] },
  dark: { label: 'Oscuro', next: 'system', icon: [['path', { d: 'M20.5 14.2A8.5 8.5 0 0 1 9.8 3.5a8.5 8.5 0 1 0 10.7 10.7z' }]] },
  system: { label: 'Sistema', next: 'light', icon: [['rect', { x: 3, y: 4, width: 18, height: 12, rx: 2 }], ['path', { d: 'M8 20h8M12 16v4' }]] },
};
function svgIcon(shapes) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  for (const [k, v] of Object.entries({ viewBox: '0 0 24 24', width: 22, height: 22, fill: 'none', stroke: 'currentColor',
    'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false' })) svg.setAttribute(k, String(v));
  for (const [tag, attrs] of shapes) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
    svg.appendChild(el);
  }
  return svg;
}
function mountThemeFab() {
  const btn = h('button', { type: 'button', class: 'theme-fab', onClick: () => {
    const value = (THEMES[themePref()] ?? THEMES.light).next;
    try { localStorage.setItem(THEME_KEY, value); } catch { /* almacenamiento bloqueado: solo esta sesión */ }
    applyTheme(value);
    render();
  } });
  const render = () => {
    const pref = THEMES[themePref()] ? themePref() : 'light';
    const t = THEMES[pref];
    const text = `Tema: ${t.label}. Cambiar a ${THEMES[t.next].label}`;
    btn.dataset.mode = pref;
    btn.dataset.label = t.label;
    btn.setAttribute('aria-label', text);
    btn.title = text;
    clear(btn).appendChild(svgIcon(t.icon));
  };
  render();
  document.body.appendChild(btn);
}
mountThemeFab();

export function every(ms, fn) {
  const id = setInterval(fn, ms);
  state.timers.add(id);
  return id;
}

function stopTimers() { state.timers.forEach(clearInterval); state.timers.clear(); }

function layout(active, content) {
  const link = (href, key, text) => h('a', { href, class: active === key ? 'active' : null }, text);
  const u = state.user;
  return h('div', { class: 'shell' },
    h('aside', { class: 'sidebar' },
      h('div', { class: 'brand' }, h('img', { src: '/assets/favicon.svg', alt: '' }), h('div', {}, 'VULNIX', h('small', {}, 'Gate DevSecOps local'))),
      h('div', { class: 'me' }, h('strong', {}, u.display_name), h('span', {}, `${u.username} · ${u.role_label}`),
        h('button', { class: 'btn small', onClick: logout }, 'Cerrar sesión')),
      h('nav', { class: 'nav', 'aria-label': 'Principal' },
        link('#/', 'dashboard', 'Panel'),
        link('#/projects', 'projects', 'Proyectos'),
        link('#/analyses', 'analyses', 'Análisis'),
        h('div', { class: 'sep' }, 'Gobierno'),
        link('#/exceptions', 'exceptions', 'Excepciones'),
        link('#/policies', 'policies', 'Políticas'),
        can('audit.view') ? link('#/audit', 'audit', 'Auditoría') : null,
        can('users.manage') ? link('#/users', 'users', 'Usuarios') : null,
        (can('system.view') || can('projects.view_all')) ? link('#/system', 'system', 'Sistema') : null)),
    h('main', { class: 'main', id: 'main' }, content));
}

export async function route() {
  stopTimers();
  if (!state.user) return renderLogin();
  const hash = (location.hash || '#/').split('?')[0];
  const match = ROUTES.map(([re, fn, key]) => [hash.match(re), fn, key]).find(([m]) => m);
  if (!match) { location.hash = '#/'; return; }
  const [m, fn, key] = match;
  const container = h('div', {}, h('div', { class: 'boot' }, 'Cargando…'));
  clear(root).appendChild(layout(key, container));
  try {
    const view = await fn(...m.slice(1));
    clear(container).appendChild(view);
  } catch (e) {
    clear(container).appendChild(errorView(e));
  }
  document.getElementById('main')?.focus?.();
}

export function errorView(e) {
  if (e instanceof ApiError) {
    return alertBox('error', h('strong', {}, `${e.code}: `), e.message,
      e.details ? h('pre', { class: 'snippet small' }, JSON.stringify(e.details, null, 2)) : null);
  }
  console.error(e);
  return alertBox('error', 'Error inesperado en la interfaz.');
}

function renderLogin(message) {
  const error = h('div');
  const user = h('input', { name: 'username', autocomplete: 'username', required: true, autofocus: true });
  const pass = h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true });
  const submit = h('button', { class: 'btn primary', type: 'submit' }, 'Entrar');
  const form = h('form', { class: 'stack', onSubmit: async (ev) => {
    ev.preventDefault();
    submit.disabled = true; clear(error);
    try {
      await ensureCsrf();
      const res = await api.post('/auth/login', { username: user.value, password: pass.value });
      state.user = res.user;
      route();
    } catch (e) {
      error.appendChild(errorView(e));
      submit.disabled = false;
    }
  } },
  h('div', { class: 'field' }, h('label', {}, 'Usuario'), user),
  h('div', { class: 'field' }, h('label', {}, 'Contraseña'), pass),
  submit);
  clear(root).appendChild(h('div', { class: 'login-wrap' }, h('div', { class: 'login' },
    h('div', { class: 'brand' }, h('img', { src: '/assets/favicon.svg', alt: '', width: 34, height: 34 }),
      h('div', {}, 'VULNIX', h('small', {}, 'Evaluación de proyectos web · red interna'))),
    message ? alertBox('info', message) : null, error, form,
    h('p', { class: 'legal' }, 'Acceso restringido y auditado. VULNIX es un evaluador técnico: no certifica la ausencia total de vulnerabilidades.'))));
}

async function logout() {
  try { await api.post('/auth/logout'); } catch { /* sesión ya cerrada */ }
  state.user = null;
  renderLogin('Sesión cerrada.');
}

setUnauthenticatedHandler(() => {
  if (state.user) { state.user = null; stopTimers(); renderLogin('La sesión expiró. Inicie sesión de nuevo.'); }
});

async function boot() {
  try {
    const res = await api.get('/auth/me');
    state.user = res.user;
  } catch { state.user = null; }
  window.addEventListener('hashchange', route);
  route();
}

boot();
