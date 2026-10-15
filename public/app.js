/* Northstar Workspace — intentionally fictional workspace data; real authentication. */
'use strict';

const app = document.getElementById('app');
const state = { user: null, csrfToken: '', googleEnabled: false, authMode: 'login', page: 'overview', dashboard: null, renderId: 0 };
let toastTimer;
const icons = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>',
  people: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/><circle cx="9" cy="7" r="4"/>',
  shield: '<path d="m12 3 8 3v6c0 4-4 7.5-8 9-4-1.5-8-5-8-9V6Z"/><path d="m9 12 2 2 4-4"/>',
  settings: '<path d="m9 3-.6 2.2-2 .9L4.3 5.5 2 9.5 3.6 11v2L2 14.5l2.3 4 2.1-.6 2 .9L9 21h6l.6-2.2 2-.9 2.1.6 2.3-4-1.6-1.5v-2L22 9.5l-2.3-4-2.1.6-2-.9L15 3Z"/><circle cx="12" cy="12" r="3"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
  down: '<path d="m8 10 4 4 4-4"/>',
  external: '<path d="M15 3h6v6m0-6-9 9"/><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4m7 14 5-5-5-5m5 5H9"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="m3 3 18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.5 5.3A11 11 0 0 1 12 5c6.5 0 10 7 10 7a18 18 0 0 1-3.4 4.2M6.6 6.6A20 20 0 0 0 2 12s3.5 7 10 7c1.8 0 3.3-.5 4.6-1.2"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 11h18"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  activity: '<path d="M2 12h5l3-8 4 16 3-8h5"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  key: '<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-3-3 3-3m-6 0 3-3"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.01"/>',
  github: '<path d="M9 19c-4.3 1.3-4.3-2.2-6-2.7M15 22v-3.9c0-1.1-.4-1.7-.9-2.2 3-.3 6.2-1.5 6.2-6.9a5.3 5.3 0 0 0-1.4-3.7A5 5 0 0 0 18.8 2s-1.2-.4-3.8 1.4a13 13 0 0 0-7 0C5.4 1.6 4.2 2 4.2 2a5 5 0 0 0-.1 3.3A5.3 5.3 0 0 0 2.7 9c0 5.4 3.2 6.6 6.2 6.9-.5.5-.9 1.2-.9 2.2V22"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 6a7.5 7.5 0 0 1 12.4 1L20 12M4 12l1.5 5A7.5 7.5 0 0 0 18 18"/>',
  laptop: '<rect x="4" y="3" width="16" height="13" rx="2"/><path d="M2 20h20l-2-4H4Z"/>',
  sparkle: '<path d="m12 3 2.3 6.7L21 12l-6.7 2.3L12 21l-2.3-6.7L3 12l6.7-2.3Z"/>',
  flag: '<path d="M4 22V3m0 1c4-4 8 4 16 0v11c-8 4-12-4-16 0"/>',
  chart: '<path d="M4 20h16M7 16v-5m5 5V4m5 12V8"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 6 9 7 9-7"/>',
};
const icon = (name, size = 18) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name] || icons.grid}</svg>`;
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const initials = (name) => String(name || 'You').trim().split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase();
const nameOf = (user) => user?.name || user?.displayName || 'Workspace member';
const firstName = () => nameOf(state.user).trim().split(/\s+/)[0];
const isAnalyst = () => ['analyst', 'admin'].includes(state.user?.role);
const isAdmin = () => state.user?.role === 'admin';
const badge = (text, style = '', dot = false) => `<span class="badge ${style ? `badge-${style}` : ''}">${dot ? '<span class="dot"></span>' : ''}${escape(text)}</span>`;
const loading = () => '<div class="loading-state" role="status"><span class="spinner" aria-hidden="true"></span>Loading workspace…</div>';
const dateLabel = (value, options = {}) => { const date = new Date(value); return Number.isNaN(date.getTime()) ? '—' : date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', ...options }); };
const dateTime = (value) => { const date = new Date(value); return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); };
function relativeTime(value) {
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return '';
  const minutes = Math.max(0, Math.floor((Date.now() - time) / 60000));
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
  return dateLabel(value);
}

function toast(message, error = false) {
  clearTimeout(toastTimer);
  const target = document.getElementById('toast');
  target.textContent = message;
  target.className = `toast visible${error ? ' error' : ''}`;
  toastTimer = setTimeout(() => { target.className = 'toast'; }, 5000);
}

async function api(path, options = {}) {
  const headers = { Accept: 'application/json', ...options.headers };
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['X-CSRF-Token'] = state.csrfToken;
  }
  let response;
  try { response = await fetch(path, { credentials: 'same-origin', ...options, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) }); }
  catch { throw Object.assign(new Error('We couldn’t connect. Check your connection and try again.'), { code: 'NETWORK_ERROR' }); }
  const data = await response.json().catch(() => ({}));
  if (data.csrfToken) state.csrfToken = data.csrfToken;
  if (!response.ok) {
    if (response.status === 401 && state.user && data.error?.code === 'AUTH_REQUIRED') {
      state.user = null;
      state.dashboard = null;
      const session = await fetch('/api/me', { credentials: 'same-origin' }).then(r => r.json()).catch(() => null);
      if (session?.csrfToken) state.csrfToken = session.csrfToken;
      renderAuth('login', 'Your session has ended. Sign in to continue.');
    }
    throw Object.assign(new Error(data.error?.message || 'Something went wrong. Please try again.'), { status: response.status, code: data.error?.code });
  }
  return data;
}

function passwordField(id, label, autocomplete, hint = '', required = true) {
  return `<div class="field"><label for="${id}">${label}</label><div class="password-wrap"><input id="${id}" name="${id}" type="password" autocomplete="${autocomplete}" ${required ? 'required' : ''} ${autocomplete === 'new-password' ? 'minlength="12" maxlength="128"' : 'maxlength="128"'} placeholder="${autocomplete === 'current-password' ? 'Enter your password' : 'Choose a strong password'}"/><button class="icon-button password-toggle" type="button" data-action="toggle-password" data-target="${id}" aria-label="Show ${label.toLowerCase()}" aria-pressed="false">${icon('eye', 17)}</button></div>${hint ? `<small>${hint}</small>` : ''}</div>`;
}

const googleIcon = '<svg width="17" height="17" viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M21.6 12.23c0-.71-.06-1.4-.18-2.05H12v3.88h5.38a4.6 4.6 0 0 1-2 3.02v2.52h3.25c1.9-1.75 2.97-4.33 2.97-7.37Z"/><path fill="#34A853" d="M12 22c2.7 0 4.96-.9 6.62-2.4l-3.25-2.52c-.9.6-2.05.97-3.37.97-2.6 0-4.8-1.76-5.6-4.12H3.05v2.6A10 10 0 0 0 12 22Z"/><path fill="#FBBC05" d="M6.4 13.93a6 6 0 0 1 0-3.86V7.48H3.05a10 10 0 0 0 0 9.04l3.35-2.59Z"/><path fill="#EA4335" d="M12 5.95c1.47 0 2.78.51 3.82 1.52l2.86-2.86A9.6 9.6 0 0 0 12 2a10 10 0 0 0-8.95 5.48l3.35 2.6A5.99 5.99 0 0 1 12 5.94Z"/></svg>';

function renderAuth(mode = 'login', message = '', email = '') {
  state.authMode = mode;
  const register = mode === 'register';
  app.innerHTML = `<div class="auth-page"><section class="auth-left"><a href="/" class="brand" aria-label="Northstar home"><span class="brand-mark" aria-hidden="true">✳</span><span class="brand-word">northstar<span>®</span></span></a><main id="main-content" class="auth-form-wrap"><div class="auth-kicker"><span class="dot"></span>Your next great work starts here</div><h1>${register ? 'Make room for great work.' : 'A little focus.<br>A lot of possibility.'}</h1><p class="auth-subtitle">${register ? 'Create your Northstar account and find your team’s next direction.' : 'Welcome back. Sign in to your team’s workspace.'}</p><div class="auth-tabs" role="tablist" aria-label="Account access"><button type="button" role="tab" aria-selected="${!register}" class="auth-tab ${!register ? 'active' : ''}" data-action="auth-tab" data-mode="login">Sign in</button><button type="button" role="tab" aria-selected="${register}" class="auth-tab ${register ? 'active' : ''}" data-action="auth-tab" data-mode="register">Create an account</button></div><div id="auth-feedback" role="status" aria-live="polite">${message ? `<div class="success-message">${escape(message)}</div>` : ''}</div><form id="auth-form" data-mode="${mode}">${register ? '<div class="field"><label for="name">Full name</label><input id="name" name="name" autocomplete="name" required maxlength="80" placeholder="Alex Morgan"/></div>' : ''}<div class="field"><label for="email">Email address</label><input type="email" id="email" name="email" autocomplete="email" required maxlength="254" placeholder="you@example.com" value="${escape(email)}"/></div>${passwordField('password', 'Password', register ? 'new-password' : 'current-password', register ? 'Use 12–128 characters. A unique passphrase works well.' : '')}<button class="button button-primary button-full auth-submit" type="submit">${register ? 'Create account' : 'Sign in to your workspace'}${icon('arrow', 16)}</button></form><div class="divider">or continue with</div>${state.googleEnabled ? `<a class="button google-button" href="/api/auth/google">${googleIcon}Google</a>` : `<button class="button google-button" type="button" disabled>${googleIcon}Google</button><p class="google-note">Google sign-in is being set up for this workspace.</p>`}<p class="auth-terms">This is a public learning lab with fictional workspace data.<br>Use a test email and a password you don’t use elsewhere.</p></main><footer class="auth-footer"><span class="footer-links"><span>A SecureNow learning lab</span><a href="/privacy.html">Privacy</a><a href="/terms.html">Terms</a></span><a href="https://github.com/securenow-ai/lab-auth" target="_blank" rel="noopener noreferrer">Explore the open-source lab ${icon('external', 11)}</a></footer></section><aside class="auth-visual" aria-label="About Northstar Workspace"><div class="eyebrow">A calmer way to work</div><h2>Good work starts<br>with a <span>clear direction.</span></h2><p>A little space for your projects, your people, and the ideas that move you forward.</p><div class="preview-window" aria-hidden="true"><div class="preview-top"><span></span><span></span><span></span><small>YOUR WORKSPACE, AT A GLANCE</small></div><div class="preview-content"><div class="preview-label">Monday, made manageable</div><h3>Let’s make room for progress.</h3><div class="preview-stats"><div class="preview-stat"><span>ACTIVE PROJECTS</span><strong>03</strong></div><div class="preview-stat"><span>TEAM MEMBERS</span><strong>08</strong></div><div class="preview-stat"><span>GOOD IDEAS</span><strong>∞</strong></div></div><div class="preview-row"><span class="mini-icon">${icon('folder', 13)}</span><div><p>Website refresh</p><small>A fresh perspective, coming soon.</small></div>${badge('In progress')}</div></div></div><div class="visual-bottom">${icon('shield', 17)}Fictional company. Real authentication. A place to learn.</div></aside></div>`;
  document.title = `${register ? 'Create account' : 'Sign in'} · Northstar Workspace`;
}

const navItems = [
  ['overview', 'grid', 'Overview'], ['projects', 'folder', 'Projects'], ['team', 'people', 'Team'], ['security', 'shield', 'Security activity'], ['settings', 'settings', 'Account settings'], ['admin', 'key', 'Administration'],
];
function availableNav() { return navItems.filter(([id]) => id !== 'admin' || isAdmin()).filter(([id]) => id !== 'security' || isAnalyst()); }
function pageTitle() { return navItems.find(([id]) => id === state.page)?.[2] || 'About this lab'; }

function renderShell() {
  app.innerHTML = `<div class="workspace"><div class="mobile-backdrop" id="mobile-backdrop" hidden data-action="close-menu"></div><aside class="sidebar" id="sidebar" aria-label="Workspace navigation"><a class="brand" href="#overview"><span class="brand-mark" aria-hidden="true">✳</span><span class="brand-word">northstar<span>®</span></span></a><div class="workspace-select"><span class="workspace-symbol">N</span><span>Northstar Workspace</span><span class="chevron">${icon('down', 14)}</span></div><p class="nav-label">Workspace</p><nav class="nav">${availableNav().map(([id, symbol, label]) => `<a class="nav-item ${state.page === id ? 'active' : ''}" href="#${id}" ${state.page === id ? 'aria-current="page"' : ''}>${icon(symbol, 17)}<span>${label}</span>${id === 'projects' ? '<span class="nav-count">3</span>' : ''}</a>`).join('')}</nav><div class="nav-divider"></div><a class="nav-item ${state.page === 'about' ? 'active' : ''}" href="#about" ${state.page === 'about' ? 'aria-current="page"' : ''}>${icon('info', 17)}About this lab</a><div class="sidebar-bottom"><div class="lab-card"><div class="lab-heading">${icon('shield', 14)}Built for learning</div><p>A real authentication app in a fictional workspace.</p><a href="https://github.com/securenow-ai/lab-auth" target="_blank" rel="noopener noreferrer">View the open-source lab ${icon('external', 11)}</a></div><div class="sidebar-profile"><span class="avatar">${escape(initials(nameOf(state.user)))}</span><div class="profile-text"><strong>${escape(nameOf(state.user))}</strong><small>${escape(state.user.role)}</small></div><button class="icon-button" type="button" data-action="logout" aria-label="Sign out">${icon('logout', 16)}</button></div></div></aside><div class="workspace-main"><header class="topbar"><div class="breadcrumbs"><button class="icon-button mobile-menu" type="button" data-action="open-menu" aria-label="Open navigation" aria-expanded="false" aria-controls="sidebar">${icon('menu', 19)}</button><span>Workspace</span>${icon('chevron', 10)}<span id="breadcrumb-current">${pageTitle()}</span></div><div class="topbar-actions"><span class="lab-pill"><span class="dot"></span><span class="pill-word">SECURENOW </span>AUTH LAB</span><a href="#settings" class="avatar topbar-avatar" aria-label="Account settings">${escape(initials(nameOf(state.user)))}</a></div></header><main id="main-content" class="content" tabindex="-1">${loading()}</main></div></div>`;
}

function footer() { return `<footer class="workspace-footer"><span>© ${new Date().getFullYear()} Northstar Workspace. A fictional company for real learning.</span><span class="footer-links"><a href="/privacy.html">Privacy</a><a href="/terms.html">Terms</a><a href="https://github.com/securenow-ai/lab-auth" target="_blank" rel="noopener noreferrer">SecureNow Auth Lab ${icon('external', 10)}</a></span></footer>`; }
function heading(title, subtitle, actions = '') { return `<div class="page-heading"><div><h1>${escape(title)}</h1><p>${escape(subtitle)}</p></div>${actions}</div>`; }
function refreshButton() { return `<div class="heading-actions"><button class="button button-secondary" data-action="refresh" type="button">${icon('refresh', 14)}<span>Refresh</span></button></div>`; }
function renderError(message) { return `<div class="panel"><div class="empty-state">${icon('info', 28)}<h3>We couldn’t load this page.</h3><p>${escape(message)}</p><button class="button button-secondary" type="button" data-action="refresh">${icon('refresh', 14)}Try again</button></div></div>`; }

async function navigate(page, focus = false) {
  if (!state.user) return;
  const allowed = [...availableNav().map(([id]) => id), 'about'];
  state.page = allowed.includes(page) ? page : 'overview';
  const renderId = ++state.renderId;
  if (!document.getElementById('main-content')?.classList.contains('content')) renderShell();
  document.querySelectorAll('.nav-item').forEach(el => { const active = el.getAttribute('href') === `#${state.page}`; el.classList.toggle('active', active); if (active) el.setAttribute('aria-current', 'page'); else el.removeAttribute('aria-current'); });
  document.getElementById('breadcrumb-current').textContent = pageTitle();
  document.title = `${pageTitle()} · Northstar Workspace`;
  closeMenu();
  const content = document.getElementById('main-content');
  content.innerHTML = loading();
  try {
    let markup;
    if (['overview', 'projects', 'team'].includes(state.page)) {
      if (!state.dashboard) state.dashboard = await api('/api/dashboard');
      markup = state.page === 'overview' ? renderOverview(state.dashboard) : state.page === 'projects' ? renderProjects(state.dashboard) : renderTeam(state.dashboard);
    } else if (state.page === 'security') markup = renderSecurity(await api('/api/security'));
    else if (state.page === 'admin') markup = renderAdmin(await api('/api/admin/users'));
    else if (state.page === 'settings') markup = renderSettings();
    else markup = renderAbout();
    if (renderId !== state.renderId || !state.user) return;
    content.innerHTML = markup + footer();
    if (focus) content.focus({ preventScroll: true });
  } catch (error) { if (renderId === state.renderId && state.user) content.innerHTML = renderError(error.message) + footer(); }
}

function projectTable(projects) {
  const colors = ['', 'purple', 'orange', 'blue'];
  return `<div class="table-scroll"><table><thead><tr><th scope="col">Project name</th><th scope="col">Status</th><th scope="col">Progress</th><th scope="col">Team</th></tr></thead><tbody>${projects.map((project, index) => { const progress = Math.max(0, Math.min(100, Number(project.progress) || 0)); return `<tr><td><div class="project-name"><span class="project-symbol ${colors[index % 4]}">${icon('folder', 14)}</span>${escape(project.name)}</div></td><td>${badge(project.status || 'Active', index === 1 ? 'purple' : '', true)}</td><td><div class="progress-cell"><progress class="progress-track" max="100" value="${progress}" aria-label="Project progress">${progress}%</progress>${progress}%</div></td><td>${escape(project.members || 0)} people</td></tr>`; }).join('')}</tbody></table></div>`;
}

function renderOverview(data) {
  const stats = data.stats || {};
  const projects = data.projects || [];
  const activity = data.activity || [];
  const date = new Date().toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' });
  const cards = [
    ['Active projects', stats.projects ?? projects.length, 'folder', 'Moving good ideas forward'],
    ['Team members', stats.activeMembers ?? 8, 'people', 'A little better, together'],
    ['Open tasks', stats.openTasks ?? 12, 'check', 'One step at a time'],
    ['Demo uptime', stats.uptime ?? '99.9%', 'activity', 'Illustrative workspace metric'],
  ];
  return heading(`Good to see you, ${firstName()}.`, 'Here’s a little perspective on your workspace today.', `<span class="date-label">${icon('calendar', 14)}${escape(date)}</span>`) + `<section class="welcome-card" aria-labelledby="welcome-title"><div><p class="eyebrow">Your space to move forward</p><h2 id="welcome-title">A clear view. A fresh start.</h2><p>Keep your projects in sight and your team in sync.<br>Great things happen one small step at a time.</p><a class="button button-primary" href="#projects">Explore your projects ${icon('arrow', 13)}</a></div><div class="welcome-art" aria-hidden="true"><div class="orbit"></div><div class="art-card art-one">${icon('folder', 18)}<div><small>YOUR NEXT CHAPTER</small><strong>Good ideas, in motion.</strong></div></div><div class="art-card art-two">${icon('check', 18)}<div><small>ONE STEP CLOSER</small><strong>Make a little progress.</strong></div></div><span class="art-star">✳</span></div></section><section class="stat-grid" aria-label="Fictional workspace metrics">${cards.map(([label, value, symbol, note]) => `<article class="stat-card"><div class="stat-header"><span>${escape(label)}</span><span class="stat-icon">${icon(symbol, 13)}</span></div><div class="stat-value">${escape(value)}</div><p class="stat-footer">${label === 'Demo uptime' ? '' : '<span>↗</span>'}${escape(note)}</p></article>`).join('')}</section><div class="section-grid"><section class="panel"><div class="panel-heading"><h2>Your projects <span class="section-count">${projects.length}</span></h2><a class="button button-subtle" href="#projects">View all ${icon('arrow', 12)}</a></div>${projectTable(projects)}</section><section class="panel"><div class="panel-heading"><h2>Workspace activity</h2>${badge('Demo data', 'gray')}</div><div class="activity-list">${activity.map((item, index) => `<div class="activity-row"><span class="activity-icon ${['', 'purple', 'orange', 'blue'][index % 4]}">${icon(['check', 'folder', 'people', 'flag'][index % 4], 13)}</span><div class="activity-copy"><p>${escape(item.title)}</p><small>${escape(item.description)}</small></div><span class="activity-time">${escape(relativeTime(item.createdAt))}</span></div>`).join('') || '<div class="empty-state"><p>No workspace updates yet.</p></div>'}</div></section></div>`;
}

function renderProjects(data) {
  const projects = data.projects || [];
  return heading('Good ideas, in motion.', 'A little overview of what your fictional team is working on.') + `<div class="info-banner">${icon('info', 18)}<div><strong>A workspace for exploring</strong>These projects are sample content. Account and sign-in activity are real.</div></div><section class="project-grid" aria-label="Sample projects">${projects.map((project, index) => { const progress = Math.max(0, Math.min(100, Number(project.progress) || 0)); return `<article class="project-card"><div class="project-card-top"><span class="project-symbol ${['', 'purple', 'orange', 'blue'][index % 4]}">${icon('folder', 18)}</span>${badge(project.status || 'Active', index === 1 ? 'purple' : '', true)}</div><h2>${escape(project.name)}</h2><p>${escape(project.description || 'Making a little room for the next good idea.')}</p><div class="project-card-meta"><span>Progress</span><span>${progress}%</span></div><progress class="progress-track" max="100" value="${progress}" aria-label="Project progress">${progress}%</progress><div class="project-card-meta"><span>${icon('people', 12)} ${escape(project.members || 0)} collaborators</span><span>Demo project</span></div></article>`; }).join('')}</section>`;
}

function renderTeam(data) {
  return heading('Better, together.', 'Meet the fictional people behind your Northstar projects.') + `<div class="info-banner">${icon('people', 18)}<div><strong>Your sample team</strong>These profiles are fictional. ${isAdmin() ? 'Manage real account permissions in Administration.' : 'Your workspace role is managed by an administrator.'}</div></div><section class="team-grid" aria-label="Fictional team members">${(data.team || []).map((member, index) => `<article class="team-card"><span class="avatar ${['', 'avatar-purple', 'avatar-orange', 'avatar-blue'][index % 4]}">${escape(member.avatar || initials(member.name))}</span><h2>${escape(member.name)}</h2><p>Northstar Workspace</p>${badge(member.role || 'Member', index === 1 ? 'purple' : 'gray')}</article>`).join('')}</section>`;
}

function humanEvent(type) {
  const names = { 'auth.login_succeeded': 'Signed in successfully', 'auth.login_failed': 'Sign-in attempt failed', 'auth.registration_requested': 'Registration requested', 'auth.logout': 'Signed out', 'auth.password_changed': 'Password changed', 'auth.google_failed': 'Google sign-in failed', 'auth.rate_limited': 'Sign-in rate limit reached', 'csrf.rejected': 'Request verification failed', 'authorization.denied': 'Access denied', 'admin.role_changed': 'Workspace role changed' };
  return names[type] || String(type || 'Account activity').replace(/[._-]/g, ' ').replace(/^./, char => char.toUpperCase());
}
function eventOutcome(outcome) { return /fail|denied|blocked|error/i.test(outcome) ? 'red' : /success|allow/i.test(outcome) ? '' : 'gray'; }
function renderSecurity(data) {
  const sessions = data.sessions || [];
  const events = data.events || [];
  return heading('A little peace of mind.', 'Review real authentication events and your active sessions.', refreshButton()) + `<div class="info-banner security-notice">${icon('shield', 18)}<div><strong>Authentication activity, in one place</strong>This page shows the application’s audit trail. Detection alerts and response policies are managed separately in SecureNow.</div></div><section class="security-grid" aria-label="Account security overview"><article class="security-card"><span class="security-icon">${icon('lock', 19)}</span><h2>Your account role</h2><p>Server-enforced workspace permissions</p>${badge(state.user.role, isAdmin() ? 'purple' : '')}</article><article class="security-card"><span class="security-icon">${icon('laptop', 19)}</span><h2>Active sessions</h2><p>Your current sign-ins across devices</p>${badge(`${sessions.length} active`, 'gray')}</article><article class="security-card"><span class="security-icon">${icon('activity', 19)}</span><h2>Recent audit events</h2><p>Authentication and account changes</p>${badge(`${events.length} recorded`, 'gray')}</article></section><div class="security-panels"><section class="panel"><div class="panel-heading"><h2>Your active sessions</h2>${badge('Real activity', 'gray')}</div>${sessions.length ? `<div class="table-scroll"><table><thead><tr><th scope="col">Session</th><th scope="col">Started</th><th scope="col">Last seen</th><th scope="col">Expires</th></tr></thead><tbody>${sessions.map(session => `<tr><td><span class="session-label">${icon('laptop', 15)}${session.current ? 'This browser' : 'Another session'}${session.current ? badge('Current') : ''}</span></td><td>${escape(dateTime(session.createdAt))}</td><td>${escape(dateTime(session.lastSeenAt))}</td><td>${escape(dateTime(session.expiresAt))}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty-state"><p>No active sessions to display.</p></div>'}</section><section class="panel"><div class="panel-heading"><h2>Authentication audit trail</h2><span class="muted text-small">Most recent first</span></div>${events.length ? `<div class="table-scroll"><table><thead><tr><th scope="col">Event</th><th scope="col">Result</th><th scope="col">Time</th><th scope="col">Reference</th></tr></thead><tbody>${events.map(event => `<tr><td class="stacked"><span class="event-name">${escape(humanEvent(event.type))}</span><span class="mono muted">${escape(event.type)}</span></td><td>${badge(event.outcome || 'Recorded', eventOutcome(event.outcome || ''))}</td><td>${escape(dateTime(event.createdAt))}</td><td class="mono">${escape((event.requestId || event.id || '').slice(0, 12))}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty-state"><p>No authentication events have been recorded yet.</p></div>'}</section></div>`;
}

function renderSettings() {
  const user = state.user;
  const methods = user.authMethods || [];
  const hasPassword = methods.includes('password');
  return heading('Make yourself at home.', 'Your account details and a few ways to keep them safe.') + `<div class="settings-grid"><section class="panel profile-card" aria-labelledby="profile-title"><div class="profile-card-top"><span class="avatar">${escape(initials(nameOf(user)))}</span><div><h2 id="profile-title">${escape(nameOf(user))}</h2>${badge(user.role, isAdmin() ? 'purple' : 'gray')}</div></div><dl class="details-list"><div class="details-row"><dt>Email address</dt><dd>${escape(user.email)}</dd></div><div class="details-row"><dt>Sign-in methods</dt><dd>${methods.map(method => method === 'google' ? 'Google' : method === 'password' ? 'Email and password' : escape(method)).join(' · ') || 'Email and password'}</dd></div><div class="details-row"><dt>Joined Northstar</dt><dd>${escape(dateLabel(user.createdAt, { year: 'numeric' }))}</dd></div></dl></section><section class="panel"><div class="panel-heading"><h2>Change your password</h2>${icon('key', 17)}</div>${hasPassword ? `<form id="password-form" class="settings-form"><p>A unique passphrase keeps this account separate from the rest.</p><div id="password-feedback" role="status" aria-live="polite"></div>${passwordField('current-password', 'Current password', 'current-password')}${passwordField('new-password', 'New password', 'new-password', 'Use 12–128 characters. Avoid reusing a password from another account.')}${passwordField('confirm-password', 'Confirm new password', 'new-password')}<button class="button button-primary" type="submit">Update password ${icon('arrow', 14)}</button></form>` : `<div class="panel-body"><div class="info-banner info-banner-last">${icon('info', 18)}<div><strong>You sign in with Google</strong>Your password is managed in your Google account. This workspace doesn’t have a separate password for you.</div></div></div>`}</section></div>`;
}

function renderAdmin(data) {
  return heading('The right access, for everyone.', 'Manage permissions for real accounts in this learning lab.', refreshButton()) + `<div class="info-banner">${icon('key', 18)}<div><strong>Roles shape what people can see</strong>Members explore the workspace. Analysts also view security activity. Administrators can manage account roles. Changes take effect on the server.</div></div><section class="panel"><div class="panel-heading"><h2>Workspace accounts <span class="section-count">${(data.users || []).length}</span></h2>${badge('Administrator access', 'purple')}</div><div class="table-scroll"><table><thead><tr><th scope="col">Account</th><th scope="col">Created</th><th scope="col">Sign-in methods</th><th scope="col">Workspace role</th></tr></thead><tbody>${(data.users || []).map(user => `<tr><td><div class="admin-name"><span class="avatar">${escape(initials(nameOf(user)))}</span><div><strong>${escape(nameOf(user))}${user.id === state.user.id ? ' (you)' : ''}</strong><small>${escape(user.email)}</small></div></div></td><td>${escape(dateLabel(user.createdAt, { year: 'numeric' }))}</td><td>${(user.authMethods || []).map(method => method === 'google' ? 'Google' : 'Password').map(escape).join(', ') || '—'}</td><td><form class="admin-actions" data-user-id="${escape(user.id)}"><label class="sr-only" for="role-${escape(user.id)}">Role for ${escape(nameOf(user))}</label><select id="role-${escape(user.id)}" name="role" class="role-select" aria-label="Role for ${escape(nameOf(user))}">${['member', 'analyst', 'admin'].map(role => `<option value="${role}" ${user.role === role ? 'selected' : ''}>${role[0].toUpperCase() + role.slice(1)}</option>`).join('')}</select><button class="button button-secondary" type="submit">Save</button></form></td></tr>`).join('')}</tbody></table></div></section>`;
}

function renderAbout() {
  return heading('A place to learn, by doing.', 'Meet the SecureNow authentication lab.') + `<article class="panel about-card"><h2>Fictional workspace. Real authentication.</h2><p>Northstar is a made-up company with sample projects and teammates. Registration, email and password sign-in, Google sign-in, sessions, and role-based permissions work with real accounts.</p><h2>Built for an authentication learning series</h2><p>This public lab accompanies a practical walkthrough of threat modeling, finding authentication risks, connecting SecureNow, and validating detections and response policies. The repository documents setup, deployment, and the security controls in this app.</p><h2>Make a test account</h2><p>Use a test email address and a unique password. Keep personal or confidential information out of your profile. Workspace members can explore the sample dashboard; analysts and administrators have additional access.</p><a class="button button-primary" href="https://github.com/securenow-ai/lab-auth" target="_blank" rel="noopener noreferrer">Explore the repository ${icon('external', 14)}</a></article>`;
}

function closeMenu() {
  document.getElementById('sidebar')?.classList.remove('open');
  const backdrop = document.getElementById('mobile-backdrop');
  if (backdrop) backdrop.hidden = true;
  document.querySelector('[data-action="open-menu"]')?.setAttribute('aria-expanded', 'false');
}

document.addEventListener('click', async event => {
  if (event.target.closest('.skip-link')) {
    event.preventDefault();
    const main = document.getElementById('main-content');
    main.setAttribute('tabindex', '-1');
    main.focus();
    return;
  }
  const target = event.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;
  if (action === 'auth-tab') {
    const email = document.getElementById('email')?.value || '';
    renderAuth(target.dataset.mode, '', email);
  } else if (action === 'toggle-password') {
    const input = document.getElementById(target.dataset.target);
    const visible = input.type === 'password';
    input.type = visible ? 'text' : 'password';
    target.setAttribute('aria-pressed', String(visible));
    target.setAttribute('aria-label', `${visible ? 'Hide' : 'Show'} password`);
    target.innerHTML = icon(visible ? 'eyeOff' : 'eye', 17);
  } else if (action === 'logout') {
    target.disabled = true;
    try {
      await api('/api/auth/logout', { method: 'POST', body: {} });
      state.user = null;
      state.dashboard = null;
      state.renderId++;
      history.replaceState(null, '', '/');
      const session = await api('/api/me');
      state.csrfToken = session.csrfToken;
      renderAuth('login', 'You’re signed out. See you next time.');
    } catch (error) { target.disabled = false; toast(error.message, true); }
  } else if (action === 'refresh') {
    state.dashboard = null;
    navigate(state.page);
  } else if (action === 'open-menu') {
    document.getElementById('sidebar')?.classList.add('open');
    document.getElementById('mobile-backdrop').hidden = false;
    target.setAttribute('aria-expanded', 'true');
    document.querySelector('.sidebar .nav-item')?.focus();
  } else if (action === 'close-menu') closeMenu();
});

document.addEventListener('submit', async event => {
  const form = event.target;
  if (form.id === 'auth-form') {
    event.preventDefault();
    const button = form.querySelector('[type="submit"]');
    const feedback = document.getElementById('auth-feedback');
    const values = new FormData(form);
    const email = String(values.get('email')).trim();
    const register = form.dataset.mode === 'register';
    button.disabled = true;
    button.innerHTML = `<span class="spinner" aria-hidden="true"></span>${register ? 'Creating your account…' : 'Signing you in…'}`;
    feedback.innerHTML = '';
    try {
      const body = { email, password: String(values.get('password')) };
      if (register) body.name = String(values.get('name')).trim();
      const data = await api(register ? '/api/auth/register' : '/api/auth/login', { method: 'POST', body });
      if (register && !data.user) {
        renderAuth('login', data.message || 'If this address can be registered, your account is ready. Sign in to continue.', email);
        document.getElementById('password')?.focus();
      } else {
        state.user = data.user;
        state.dashboard = null;
        history.replaceState(null, '', '/#overview');
        renderShell();
        navigate('overview', true);
      }
    } catch (error) {
      if (error.code?.includes('CSRF')) {
        const session = await api('/api/me').catch(() => null);
        if (session) state.csrfToken = session.csrfToken;
      }
      feedback.innerHTML = `<div class="error-message" role="alert">${escape(error.message)}</div>`;
      button.disabled = false;
      button.innerHTML = `${register ? 'Create account' : 'Sign in to your workspace'}${icon('arrow', 16)}`;
    }
  } else if (form.id === 'password-form') {
    event.preventDefault();
    const feedback = document.getElementById('password-feedback');
    const values = new FormData(form);
    feedback.innerHTML = '';
    if (values.get('new-password') !== values.get('confirm-password')) {
      feedback.innerHTML = '<div class="error-message" role="alert">Your new passwords don’t match. Check both fields and try again.</div>';
      document.getElementById('confirm-password').focus();
      return;
    }
    const button = form.querySelector('[type="submit"]');
    button.disabled = true;
    try {
      const data = await api('/api/auth/password', { method: 'POST', body: { currentPassword: String(values.get('current-password')), newPassword: String(values.get('new-password')) } });
      if (data.user) state.user = data.user;
      form.reset();
      feedback.innerHTML = '<div class="success-message">Your password has been updated.</div>';
    } catch (error) { feedback.innerHTML = `<div class="error-message" role="alert">${escape(error.message)}</div>`; }
    finally { button.disabled = false; }
  } else if (form.classList.contains('admin-actions')) {
    event.preventDefault();
    const button = form.querySelector('button');
    const role = new FormData(form).get('role');
    button.disabled = true;
    try {
      await api(`/api/admin/users/${encodeURIComponent(form.dataset.userId)}`, { method: 'PATCH', body: { role } });
      const session = await api('/api/me');
      state.user = session.user;
      state.dashboard = null;
      if (!state.user) {
        state.renderId++;
        history.replaceState(null, '', '/');
        renderAuth('login', 'Your permissions have changed. Sign in again to continue.');
        return;
      }
      const page = isAdmin() ? 'admin' : 'overview';
      history.replaceState(null, '', `/#${page}`);
      state.page = page;
      renderShell();
      await navigate(page);
      toast('Workspace role updated.');
    } catch (error) { button.disabled = false; toast(error.message, true); }
  }
});

window.addEventListener('hashchange', () => { if (state.user) navigate(location.hash.slice(1) || 'overview', true); });
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') closeMenu();
  if (event.target.matches('.auth-tab') && ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
    event.preventDefault();
    const mode = event.key === 'Home' ? 'login' : event.key === 'End' ? 'register' : state.authMode === 'login' ? 'register' : 'login';
    const email = document.getElementById('email')?.value || '';
    renderAuth(mode, '', email);
    document.querySelector(`.auth-tab[data-mode="${mode}"]`)?.focus();
  }
});

async function start() {
  try {
    const session = await api('/api/me');
    state.user = session.user;
    state.csrfToken = session.csrfToken;
    state.googleEnabled = Boolean(session.googleEnabled);
    const params = new URLSearchParams(location.search);
    const oauthError = params.get('auth_error');
    if (params.has('auth') || oauthError) history.replaceState(null, '', location.pathname + location.hash);
    if (state.user) {
      state.page = location.hash.slice(1) || 'overview';
      renderShell();
      await navigate(state.page);
    } else {
      renderAuth();
      if (oauthError) document.getElementById('auth-feedback').innerHTML = `<div class="error-message" role="alert">${oauthError === 'account_exists' ? 'There’s already an account with this email. Sign in with your email and password.' : 'Google sign-in couldn’t be completed. Please try again.'}</div>`;
    }
  } catch (error) {
    app.innerHTML = `<main id="main-content" class="boot-screen"><span class="brand-mark" aria-hidden="true">✳</span><h2>We’re having trouble connecting.</h2><p>${escape(error.message)}</p><button class="button button-primary" type="button" id="retry-connection">Try again</button></main>`;
    document.getElementById('retry-connection').addEventListener('click', start);
  }
}

start();
