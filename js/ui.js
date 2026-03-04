import { formatSize, formatDate, escapeHtml } from './utils.js';
import { renderPreview } from './preview.js';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

export function showScreen(name) {
  for (const el of $$('.screen')) {
    el.classList.toggle('active', el.id === `screen-${name}`);
  }
  for (const el of $$('.nav-item')) {
    el.classList.toggle('active', el.dataset.screen === name);
  }
}

// Setup screen
export function renderSetup(clientId, onSave) {
  const input = $('#client-id-input');
  if (clientId) input.value = clientId;

  $('#setup-form').onsubmit = (e) => {
    e.preventDefault();
    const val = input.value.trim();
    if (val) onSave(val);
  };
}

// Login screen
export function renderLogin(user) {
  const container = $('#user-info');
  if (user) {
    container.innerHTML = `
      <div class="user-card">
        ${user.photoLink ? `<img src="${user.photoLink}" class="user-avatar" alt="" />` : ''}
        <div>
          <div class="user-name">${escapeHtml(user.displayName)}</div>
          <div class="user-email">${escapeHtml(user.emailAddress)}</div>
        </div>
      </div>`;
    $('#sign-in-btn').style.display = 'none';
    $('#sign-out-btn').style.display = '';
    $('#start-scan-btn').style.display = '';
  } else {
    container.innerHTML = '';
    $('#sign-in-btn').style.display = '';
    $('#sign-out-btn').style.display = 'none';
    $('#start-scan-btn').style.display = 'none';
  }
}

// Scan screen
export function renderScanProgress(page, fileCount) {
  const bar = $('#scan-progress-bar');
  const label = $('#scan-progress-label');
  bar.style.width = '100%';
  bar.classList.add('indeterminate');
  label.textContent = `Scanning... Page ${page} \u2022 ${fileCount.toLocaleString()} files`;
}

export function renderScanResults(stats) {
  $('#scan-progress-bar').classList.remove('indeterminate');
  $('#scan-progress-bar').style.width = '100%';
  $('#scan-progress-label').textContent = 'Scan complete';

  const container = $('#scan-results');
  container.innerHTML = `
    <div class="stats-grid">
      <div class="stat">
        <div class="stat-value">${stats.totalGroups.toLocaleString()}</div>
        <div class="stat-label">Duplicate groups</div>
      </div>
      <div class="stat">
        <div class="stat-value">${stats.totalFiles.toLocaleString()}</div>
        <div class="stat-label">Duplicate files</div>
      </div>
      <div class="stat">
        <div class="stat-value">${formatSize(stats.totalWasted)}</div>
        <div class="stat-label">Potential savings</div>
      </div>
      ${stats.uncertainCount > 0 ? `
      <div class="stat stat-warning">
        <div class="stat-value">${stats.uncertainCount}</div>
        <div class="stat-label">Uncertain (size mismatch)</div>
      </div>` : ''}
    </div>`;
  container.style.display = '';
  $('#review-btn').style.display = '';
}

// Review screen
let currentGroupIndex = 0;
let groups = [];
let decisions = {};
let onDecision = null;
let currentFilter = 'pending';

export function initReview(dupGroups, existingDecisions, decisionCallback) {
  groups = dupGroups;
  decisions = existingDecisions;
  onDecision = decisionCallback;
  currentGroupIndex = 0;
  currentFilter = 'pending';
  updateFilterCounts();
  renderCurrentGroup();
}

function getFilteredGroups() {
  if (currentFilter === 'all') return groups;
  return groups.filter((g) => {
    const d = decisions[g.md5];
    if (currentFilter === 'pending') return !d;
    if (currentFilter === 'decided') return d && d.action === 'keep';
    if (currentFilter === 'skipped') return d && d.action === 'skip';
    return true;
  });
}

function updateFilterCounts() {
  let pending = 0, decided = 0, skipped = 0;
  for (const g of groups) {
    const d = decisions[g.md5];
    if (!d) pending++;
    else if (d.action === 'keep') decided++;
    else if (d.action === 'skip') skipped++;
  }
  const setCount = (id, count) => {
    const el = document.getElementById(id);
    if (el) el.textContent = count;
  };
  setCount('count-pending', pending);
  setCount('count-decided', decided);
  setCount('count-skipped', skipped);
  setCount('count-all', groups.length);
}

export function renderCurrentGroup() {
  const filtered = getFilteredGroups();
  const container = $('#review-content');

  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-state">No groups in this filter</div>`;
    $('#review-nav-label').textContent = '0 / 0';
    return;
  }

  if (currentGroupIndex >= filtered.length) currentGroupIndex = filtered.length - 1;
  if (currentGroupIndex < 0) currentGroupIndex = 0;

  const group = filtered[currentGroupIndex];
  const decision = decisions[group.md5];

  $('#review-nav-label').textContent = `${currentGroupIndex + 1} / ${filtered.length}`;

  const filesHtml = group.files.map((f, i) => `
    <div class="file-card ${decision?.keep === f.id ? 'file-keep' : ''}" data-file-id="${f.id}" data-index="${i}">
      <div class="file-preview" id="preview-${f.id}"></div>
      <div class="file-meta">
        <div class="file-name" title="${escapeHtml(f.path || f.name)}">${escapeHtml(f.name)}</div>
        <div class="file-path">${escapeHtml(f.path || '/')}</div>
        <div class="file-details">
          <span>${formatSize(parseInt(f.size) || 0)}</span>
          <span>${formatDate(f.modifiedTime)}</span>
        </div>
      </div>
      <div class="file-actions">
        <button class="btn btn-keep ${decision?.keep === f.id ? 'active' : ''}" data-action="keep" data-file-id="${f.id}" data-md5="${group.md5}">
          Keep
        </button>
      </div>
    </div>
  `).join('');

  container.innerHTML = `
    <div class="group-header">
      <div class="group-md5">MD5: ${group.md5.slice(0, 12)}...</div>
      <div class="group-info">${group.files.length} files \u2022 ${formatSize(group.wastedSize)} wasted</div>
      ${group.uncertain ? '<div class="group-warning">Size mismatch - review carefully</div>' : ''}
    </div>
    <div class="files-grid">${filesHtml}</div>
    <div class="group-actions">
      <button class="btn btn-skip ${decision?.action === 'skip' ? 'active' : ''}" id="skip-group">Skip</button>
    </div>
  `;

  // Load previews async
  for (const f of group.files) {
    const el = document.getElementById(`preview-${f.id}`);
    if (el) renderPreview(el, f);
  }

  // Wire up keep buttons
  for (const btn of container.querySelectorAll('[data-action="keep"]')) {
    btn.onclick = () => {
      const md5 = btn.dataset.md5;
      const fileId = btn.dataset.fileId;
      decisions[md5] = { keep: fileId, action: 'keep' };
      onDecision?.(md5, decisions[md5]);
      updateFilterCounts();
      renderCurrentGroup();
    };
  }

  // Wire up skip
  const skipBtn = document.getElementById('skip-group');
  if (skipBtn) {
    skipBtn.onclick = () => {
      decisions[group.md5] = { action: 'skip' };
      onDecision?.(group.md5, decisions[group.md5]);
      updateFilterCounts();
      renderCurrentGroup();
    };
  }
}

export function setupReviewNav() {
  $('#prev-group')?.addEventListener('click', () => {
    currentGroupIndex--;
    renderCurrentGroup();
  });
  $('#next-group')?.addEventListener('click', () => {
    currentGroupIndex++;
    renderCurrentGroup();
  });

  for (const btn of $$('.filter-btn')) {
    btn.addEventListener('click', () => {
      currentFilter = btn.dataset.filter;
      for (const b of $$('.filter-btn')) b.classList.toggle('active', b === btn);
      currentGroupIndex = 0;
      renderCurrentGroup();
    });
  }
}

// Execute screen
export function renderDryRun(groups, decisions) {
  const moves = [];
  for (const g of groups) {
    const d = decisions[g.md5];
    if (!d || d.action !== 'keep') continue;
    for (const f of g.files) {
      if (f.id !== d.keep) {
        moves.push({ file: f, group: g });
      }
    }
  }

  const container = $('#execute-dry-run');
  if (moves.length === 0) {
    container.innerHTML = '<div class="empty-state">No files to move. Review duplicates first.</div>';
    $('#execute-confirm-section').style.display = 'none';
    return moves;
  }

  container.innerHTML = `
    <div class="dry-run-header">${moves.length} files will be moved to <code>_dupes/</code></div>
    <table class="dry-run-table">
      <thead><tr><th>File</th><th>Size</th><th>Current Path</th></tr></thead>
      <tbody>
        ${moves.map((m) => `
          <tr>
            <td>${escapeHtml(m.file.name)}</td>
            <td>${formatSize(parseInt(m.file.size) || 0)}</td>
            <td class="path-cell">${escapeHtml(m.file.path || '/')}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    <div class="dry-run-total">Total: ${formatSize(moves.reduce((s, m) => s + (parseInt(m.file.size) || 0), 0))}</div>
  `;
  $('#execute-confirm-section').style.display = '';
  return moves;
}

export function renderExecuteProgress(current, total) {
  const bar = $('#execute-progress-bar');
  const label = $('#execute-progress-label');
  const pct = Math.round((current / total) * 100);
  bar.style.width = `${pct}%`;
  bar.classList.remove('indeterminate');
  label.textContent = `Moving files... ${current}/${total}`;
}

export function renderExecuteResults(results) {
  const container = $('#execute-results');
  const succeeded = results.filter((r) => r.ok).length;
  const failed = results.filter((r) => !r.ok);

  let html = `<div class="execute-summary">Moved ${succeeded} of ${results.length} files</div>`;

  if (failed.length > 0) {
    html += `<div class="execute-errors">
      <div class="error-header">${failed.length} failed:</div>
      ${failed.map((f) => `<div class="error-item">${escapeHtml(f.name)}: ${escapeHtml(f.error)}</div>`).join('')}
    </div>`;
  }

  container.innerHTML = html;
  container.style.display = '';
}
