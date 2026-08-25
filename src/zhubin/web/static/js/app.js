// Zhubin Web UI — vanilla JS SPA
'use strict';

const API = '/api';
let currentView = 'unlock';

// ─── Helpers ───────────────────────────────────────────────────────────────

function getCsrfToken() {
  const parts = document.cookie.split(';');
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.startsWith('zhubin_csrf=')) {
      return decodeURIComponent(trimmed.slice('zhubin_csrf='.length));
    }
  }
  return '';
}

function secretUrl(group, name) {
  return `/groups/${encodeURIComponent(group)}/secrets/${encodeURIComponent(name)}`;
}

async function apiFetch(path, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (method !== 'GET' && method !== 'HEAD') {
    headers['X-CSRF-Token'] = getCsrfToken();
  }
  const res = await fetch(API + path, {
    headers,
    credentials: 'same-origin',
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

function showToast(msg, type = 'info') {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(`view-${name}`)?.classList.add('active');
  currentView = name;
  if (name === 'dashboard') loadDashboard();
  if (name === 'secrets')   loadSecrets();
  if (name === 'groups')    loadGroups();
  if (name === 'devices')   loadDevices();
  if (name === 'git')       loadGit();
}

function openModal(title, bodyHtml) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = bodyHtml;
  document.getElementById('modal-overlay').style.display = 'flex';
}

function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
}

// ─── Auth ───────────────────────────────────────────────────────────────────

async function doUnlock(e) {
  e.preventDefault();
  const btn = document.getElementById('unlock-btn');
  const statusEl = document.getElementById('unlock-status');
  btn.disabled = true;
  btn.textContent = 'Unlocking…';
  statusEl.style.display = 'none';
  const passphrase = document.getElementById('passphrase').value;
  try {
    await apiFetch('/unlock', {
      method: 'POST',
      body: JSON.stringify({ passphrase }),
    });
    statusEl.className = 'status-badge status-success';
    statusEl.textContent = '✓ Vault unlocked';
    statusEl.style.display = 'block';
    document.getElementById('main-nav').style.display = 'flex';
    showView('dashboard');
  } catch (err) {
    statusEl.className = 'status-badge status-error';
    statusEl.textContent = '✗ ' + err.message;
    statusEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Unlock Vault';
  }
}

async function lockVault() {
  try {
    await apiFetch('/lock', { method: 'POST' });
  } catch (_) {}
  document.getElementById('main-nav').style.display = 'none';
  document.getElementById('passphrase').value = '';
  showView('unlock');
  showToast('Vault locked', 'info');
}

// ─── Dashboard ──────────────────────────────────────────────────────────────

async function loadDashboard() {
  try {
    const st = await apiFetch('/status');
    document.getElementById('stat-groups').querySelector('.stat-value').textContent = st.groups;
    document.getElementById('stat-secrets').querySelector('.stat-value').textContent = st.total_secrets;
    document.getElementById('stat-devices').querySelector('.stat-value').textContent = st.devices;
    document.getElementById('stat-git').querySelector('.stat-value').textContent = st.git.branch;

    const git = st.git;
    const gitEl = document.getElementById('git-status-content');
    gitEl.innerHTML = `
      <div class="git-row"><span class="git-label">Branch</span><span>${git.branch}</span></div>
      <div class="git-row"><span class="git-label">Remote</span><span>${git.remote || '—'}</span></div>
      <div class="git-row"><span class="git-label">Ahead</span><span>${git.ahead}</span></div>
      <div class="git-row"><span class="git-label">Behind</span><span>${git.behind}</span></div>
      <div class="git-row"><span class="git-label">Uncommitted</span><span>${git.uncommitted}</span></div>
      ${git.has_conflicts ? '<div class="git-row" style="color:var(--danger)">⚠ Merge conflicts detected</div>' : ''}
    `;
  } catch (err) {
    showToast('Failed to load dashboard: ' + err.message, 'error');
  }
}

// ─── Secrets ────────────────────────────────────────────────────────────────

let allSecrets = [];

async function loadSecrets() {
  const el = document.getElementById('secrets-list');
  try {
    const groups = await apiFetch('/groups');
    allSecrets = [];
    for (const g of groups) {
      const secrets = await apiFetch(`/groups/${g.name}/secrets`);
      allSecrets.push(...secrets);
    }
    renderSecrets(allSecrets);
  } catch (err) {
    el.textContent = 'Error: ' + err.message;
  }
}

function renderSecrets(secrets) {
  const el = document.getElementById('secrets-list');
  if (!secrets.length) { el.innerHTML = '<p style="color:var(--text2)">No secrets yet.</p>'; return; }
  el.innerHTML = secrets.map(s => `
    <div class="secret-item">
      <div class="secret-info">
        <span class="secret-path">${s.group}/${s.name}</span>
      </div>
      <div class="secret-actions">
        <button class="btn btn-secondary" onclick="viewSecret('${s.group}','${s.name}')">View</button>
        <button class="btn btn-secondary" onclick="copySecret('${s.group}','${s.name}','password')">Copy PW</button>
        <button class="btn btn-secondary" onclick="editSecretModal('${s.group}','${s.name}')">Edit</button>
        <button class="btn btn-danger" onclick="deleteSecret('${s.group}','${s.name}')">Delete</button>
      </div>
    </div>
  `).join('');
}

function searchSecrets(q) {
  if (!q) { renderSecrets(allSecrets); return; }
  const filtered = allSecrets.filter(s =>
    (s.group + '/' + s.name).toLowerCase().includes(q.toLowerCase())
  );
  renderSecrets(filtered);
}

async function viewSecret(group, name) {
  try {
    const s = await apiFetch(secretUrl(group, name));
    openModal(`${group}/${name}`, `
      <div class="form-group"><label>Username</label><input readonly value="${s.username || ''}"/></div>
      <div class="form-group"><label>Password</label>
        <div style="display:flex;gap:.5rem">
          <input type="password" id="pw-field" readonly value="••••••••"/>
          <button class="btn btn-secondary" onclick="togglePw()">Show</button>
          <button class="btn btn-primary" onclick="copySecret('${group}','${name}','password');closeModal()">Copy</button>
        </div>
      </div>
      <div class="form-group"><label>URL</label><input readonly value="${s.url || ''}"/></div>
      <div class="form-group"><label>Notes</label><textarea readonly rows="3">${s.notes || ''}</textarea></div>
    `);
  } catch (err) { showToast(err.message, 'error'); }
}

function togglePw() {
  const f = document.getElementById('pw-field');
  f.type = f.type === 'password' ? 'text' : 'password';
}

async function copySecret(group, name, field) {
  try {
    await apiFetch(`${secretUrl(group, name)}/copy?field=${encodeURIComponent(field)}&timeout=30`, { method: 'POST' });
    showToast(`${field} copied — clears in 30s`, 'success');
  } catch (err) { showToast(err.message, 'error'); }
}

function showAddSecret() {
  openModal('Add Secret', `
    <form id="add-secret-form" onsubmit="submitAddSecret(event)">
      <div class="form-group"><label>Group</label>
        <input id="ns-group" placeholder="e.g. personal" required/>
      </div>
      <div class="form-group"><label>Name</label>
        <input id="ns-name" placeholder="e.g. github or ilo/bank/s" required/>
      </div>
      <div class="form-group"><label>Username</label><input id="ns-user"/></div>
      <div class="form-group"><label>Password</label><input type="password" id="ns-pw"/></div>
      <div class="form-group"><label>URL</label><input id="ns-url" type="url"/></div>
      <div class="form-group"><label>Notes</label><textarea id="ns-notes" rows="3"></textarea></div>
      <button type="submit" class="btn btn-primary btn-full">Save Secret</button>
    </form>
  `);
}

async function submitAddSecret(e) {
  e.preventDefault();
  const group = document.getElementById('ns-group').value;
  const name  = document.getElementById('ns-name').value;
  const body = {
    username: document.getElementById('ns-user').value,
    password: document.getElementById('ns-pw').value,
    url: document.getElementById('ns-url').value,
    notes: document.getElementById('ns-notes').value,
  };
  try {
    await apiFetch(`/groups/${encodeURIComponent(group)}/secrets?name=${encodeURIComponent(name)}`, {
      method: 'POST', body: JSON.stringify(body),
    });
    closeModal();
    showToast('Secret added', 'success');
    loadSecrets();
  } catch (err) { showToast(err.message, 'error'); }
}

async function editSecretModal(group, name) {
  try {
    const s = await apiFetch(secretUrl(group, name));
    openModal(`Edit ${group}/${name}`, `
      <form id="edit-secret-form" onsubmit="submitEditSecret(event,'${group}','${name}')">
        <div class="form-group"><label>Username</label><input id="es-user" value="${s.username || ''}"/></div>
        <div class="form-group"><label>Password</label><input type="password" id="es-pw" placeholder="(unchanged — enter new value)"/></div>
        <div class="form-group"><label>URL</label><input id="es-url" type="url" value="${s.url || ''}"/></div>
        <div class="form-group"><label>Notes</label><textarea id="es-notes" rows="3">${s.notes || ''}</textarea></div>
        <button type="submit" class="btn btn-primary btn-full">Save Changes</button>
      </form>
    `);
  } catch (err) { showToast(err.message, 'error'); }
}

async function submitEditSecret(e, group, name) {
  e.preventDefault();
  const pw = document.getElementById('es-pw').value;
  const body = {
    username: document.getElementById('es-user').value,
    url: document.getElementById('es-url').value,
    notes: document.getElementById('es-notes').value,
  };
  // Omit password when unchanged so the server keeps the existing value.
  // The GET secret endpoint never returns the password.
  if (pw) body.password = pw;
  try {
    await apiFetch(secretUrl(group, name), { method: 'PUT', body: JSON.stringify(body) });
    closeModal();
    showToast('Secret updated', 'success');
    loadSecrets();
  } catch (err) { showToast(err.message, 'error'); }
}

async function deleteSecret(group, name) {
  if (!confirm(`Delete ${group}/${name}?`)) return;
  try {
    await apiFetch(secretUrl(group, name), { method: 'DELETE' });
    showToast('Secret deleted', 'success');
    loadSecrets();
  } catch (err) { showToast(err.message, 'error'); }
}

// ─── Groups ─────────────────────────────────────────────────────────────────

async function loadGroups() {
  const el = document.getElementById('groups-list');
  try {
    const groups = await apiFetch('/groups');
    if (!groups.length) { el.innerHTML = '<p style="color:var(--text2)">No groups yet.</p>'; return; }
    el.innerHTML = groups.map(g => `
      <div class="group-card">
        <div class="group-name">${g.name}</div>
        <div class="group-meta">${g.secret_count} secrets · ${g.device_count} device(s)</div>
        <div class="group-meta">${new Date(g.created_at).toLocaleDateString()}</div>
        <div class="group-actions">
          <button class="btn btn-secondary" onclick="rotateGroup('${g.name}')">Rotate Key</button>
        </div>
      </div>
    `).join('');
  } catch (err) { el.textContent = 'Error: ' + err.message; }
}

function showCreateGroup() {
  openModal('Create Group', `
    <form onsubmit="submitCreateGroup(event)">
      <div class="form-group"><label>Group Name</label>
        <input id="cg-name" placeholder="e.g. personal" required pattern="[a-zA-Z0-9_\\-\\.]+"/>
      </div>
      <button type="submit" class="btn btn-primary btn-full">Create</button>
    </form>
  `);
}

async function submitCreateGroup(e) {
  e.preventDefault();
  const name = document.getElementById('cg-name').value;
  try {
    await apiFetch('/groups', { method: 'POST', body: JSON.stringify({ name }) });
    closeModal(); showToast('Group created', 'success'); loadGroups();
  } catch (err) { showToast(err.message, 'error'); }
}

async function rotateGroup(name) {
  if (!confirm(`Rotate encryption key for group '${name}'? All secrets will be re-encrypted.`)) return;
  try {
    await apiFetch(`/groups/${name}/rotate`, { method: 'POST' });
    showToast(`Group '${name}' key rotated`, 'success');
  } catch (err) { showToast(err.message, 'error'); }
}

// ─── Devices ─────────────────────────────────────────────────────────────────

async function loadDevices() {
  const el = document.getElementById('devices-list');
  try {
    const devices = await apiFetch('/devices');
    if (!devices.length) { el.innerHTML = '<p>No devices.</p>'; return; }
    el.innerHTML = devices.map(d => `
      <div class="device-item">
        <div class="device-info">
          <span class="device-name">${d.name}
            <span class="badge ${d.revoked ? 'badge-revoked' : 'badge-active'}">${d.revoked ? 'revoked' : 'active'}</span>
          </span>
          <span class="device-meta">${d.platform} · ${d.hostname} · ${d.id.slice(0,8)}…</span>
          <span class="key-display" style="margin-top:.4rem">${d.fingerprint || d.public_key}</span>
        </div>
        <div style="display:flex;flex-direction:column;gap:.4rem">
          ${!d.revoked ? `<button class="btn btn-secondary" onclick="authorizeDevice('${d.name}')">Authorize</button>
          <button class="btn btn-danger" onclick="revokeDevice('${d.name}')">Revoke</button>` : ''}
        </div>
      </div>
    `).join('');
  } catch (err) { el.textContent = 'Error: ' + err.message; }
}

async function authorizeDevice(name) {
  try {
    const d = await apiFetch(`/devices/${name}`);
    const groups = (d.groups && d.groups.length) ? d.groups.join(', ') : '(none)';
    const ok = confirm(
      `You are about to authorize:\n\n` +
      `Device: ${d.name}\n` +
      `Fingerprint:\n${d.fingerprint}\n\n` +
      `This device will receive access to:\n${groups}\n\n` +
      `Compare this fingerprint with the value shown on the target device before continuing.`
    );
    if (!ok) return;
    await apiFetch(`/devices/${name}/authorize`, { method: 'POST' });
    showToast(`Device '${name}' authorized`, 'success'); loadDevices();
  } catch (err) { showToast(err.message, 'error'); }
}

async function revokeDevice(name) {
  if (!confirm(
    `Revoke device '${name}'?\n\n` +
    `Revocation prevents future group keys from being issued to this device, ` +
    `but Git history may still contain keys wrapped for it.\n\n` +
    `Affected groups will be rotated (recommended if the device may be compromised).`
  )) return;
  try {
    await apiFetch(`/devices/${name}/revoke?rotate=true`, { method: 'POST' });
    showToast(`Device '${name}' revoked`, 'success'); loadDevices();
  } catch (err) { showToast(err.message, 'error'); }
}

// ─── Git ─────────────────────────────────────────────────────────────────────

async function loadGit() {
  const el = document.getElementById('git-detail');
  try {
    const st = await apiFetch('/git/status');
    el.innerHTML = `
      <div class="git-row"><span class="git-label">Branch</span><span>${st.branch}</span></div>
      <div class="git-row"><span class="git-label">Remote</span><span>${st.remote || '—'}</span></div>
      <div class="git-row"><span class="git-label">Ahead</span><span>${st.ahead}</span></div>
      <div class="git-row"><span class="git-label">Behind</span><span>${st.behind}</span></div>
      <div class="git-row"><span class="git-label">Uncommitted</span><span>${st.uncommitted.length > 0 ? st.uncommitted.join(', ') : 'clean'}</span></div>
      ${st.has_conflicts ? '<p style="color:var(--danger);margin-top:.5rem">⚠ Merge conflicts — resolve manually</p>' : ''}
    `;
  } catch (err) { el.textContent = 'Error: ' + err.message; }
}

async function doSync() {
  try {
    const r = await apiFetch('/git/sync', { method: 'POST' });
    showToast('Sync complete', 'success');
    loadGit();
  } catch (err) { showToast('Sync error: ' + err.message, 'error'); }
}

// ─── Init ─────────────────────────────────────────────────────────────────────

(async function init() {
  try {
    await apiFetch('/csrf');
    const st = await apiFetch('/status');
    if (!st.locked) {
      document.getElementById('main-nav').style.display = 'flex';
      showView('dashboard');
    } else {
      showView('unlock');
    }
  } catch (_) {
    showView('unlock');
  }
})();
