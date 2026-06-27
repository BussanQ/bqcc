'use strict';

/* ---------- helpers ---------- */

function svgIcon(name) {
  return '<svg class="icon"><use href="#i-' + name + '"></use></svg>';
}

function collectPayload(form) {
  const payload = {};
  for (const element of form.elements) {
    if (!element.name) continue;
    if (element.type === 'checkbox') {
      payload[element.name] = element.checked;
    } else {
      payload[element.name] = element.value;
    }
  }
  return payload;
}

function getByPath(obj, path) {
  if (!obj) return undefined;
  return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

/* ---------- toast ---------- */

function toast(message, kind) {
  const stack = document.querySelector('#toast-stack');
  if (!stack) return;
  const el = document.createElement('div');
  el.className = 'toast ' + (kind || 'info');
  const icon = kind === 'err' ? 'alert' : kind === 'ok' ? 'check' : 'arrow';
  el.innerHTML = svgIcon(icon) + '<span></span>';
  el.querySelector('span').textContent = message;
  stack.appendChild(el);
  setTimeout(() => {
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 240);
  }, 2600);
}

/* ---------- structured result ---------- */

const HIGHLIGHT_LABELS = {
  did: 'DID',
  identityId: '身份',
  objectCid: '对象 CID',
  manifestCid: '清单 CID',
  cid: 'CID',
  objectFile: '对象文件',
  manifestFile: '清单文件',
  memoryFile: '记忆文件',
  outFile: '输出文件',
  file: '文件',
  signerKeyId: '签名 key',
  nonce: 'Nonce',
  expiresAt: '过期时间',
  plaintext: '明文',
  message: '说明',
};

function collectHighlights(data, out, depth) {
  if (!data || typeof data !== 'object' || depth > 3) return;
  for (const [key, value] of Object.entries(data)) {
    if (value == null) continue;
    if (HIGHLIGHT_LABELS[key] && out[key] === undefined) {
      if (typeof value === 'string' || typeof value === 'number') {
        out[key] = String(value);
      } else if (Array.isArray(value) && value.every((v) => typeof v === 'string')) {
        out[key] = value.join('\n');
      }
    }
    if (typeof value === 'object') collectHighlights(value, out, depth + 1);
  }
}

function renderResult(json) {
  const status = document.querySelector('#result-status');
  const highlights = document.querySelector('#result-highlights');
  const raw = document.querySelector('#global-result');
  if (raw) raw.textContent = typeof json === 'string' ? json : JSON.stringify(json, null, 2);
  if (!status || !highlights) return;

  highlights.innerHTML = '';
  const ok = json && json.ok === true;
  const data = json && json.data;

  // verification verdict
  let verdict = null;
  if (data && typeof data.valid === 'boolean') {
    verdict = data.valid;
  }

  status.className = 'result-status show ' + (ok ? (verdict === false ? 'err' : 'ok') : 'err');
  let label;
  if (!ok) {
    label = (json && json.error && json.error.message) || '操作失败';
    status.innerHTML = svgIcon('alert') + '<span></span>';
  } else if (verdict === true) {
    label = (data && data.message) || '验证通过';
    status.innerHTML = svgIcon('check') + '<span></span>';
  } else if (verdict === false) {
    label = (data && data.message) || '验证未通过';
    status.innerHTML = svgIcon('x') + '<span></span>';
  } else {
    label = '操作成功';
    status.innerHTML = svgIcon('check') + '<span></span>';
  }
  status.querySelector('span').textContent = label;

  if (ok && data && typeof data === 'object') {
    const found = {};
    collectHighlights(data, found, 0);
    for (const [key, value] of Object.entries(found)) {
      if (key === 'message' && verdict !== null) continue;
      const row = document.createElement('div');
      row.className = 'highlight';
      const k = document.createElement('span');
      k.className = 'h-key';
      k.textContent = HIGHLIGHT_LABELS[key] || key;
      const v = document.createElement('span');
      v.className = 'h-val';
      v.textContent = value;
      v.title = value;
      const copy = document.createElement('button');
      copy.className = 'copy-btn';
      copy.type = 'button';
      copy.innerHTML = svgIcon('copy');
      copy.addEventListener('click', () => copyText(value, copy));
      row.append(k, v, copy);
      highlights.appendChild(row);
    }
  }
}

/* ---------- clipboard ---------- */

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text || '');
    toast('已复制到剪贴板', 'ok');
    if (button) {
      const original = button.innerHTML;
      button.innerHTML = svgIcon('check');
      setTimeout(() => (button.innerHTML = original), 1200);
    }
  } catch (error) {
    toast('复制失败：' + error.message, 'err');
  }
}

/* ---------- chaining ---------- */

function applyFill(form, json) {
  const spec = form.dataset.fill;
  if (!spec || !json || !json.ok) return;
  let rules;
  try {
    rules = JSON.parse(spec);
  } catch (_) {
    return;
  }
  for (const rule of rules) {
    const value = getByPath(json.data, rule.path);
    const target = document.querySelector(rule.target);
    if (value === undefined || !target) continue;
    target.value = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    target.classList.add('just-filled');
    setTimeout(() => target.classList.remove('just-filled'), 900);
  }
}

/* ---------- form submit ---------- */

async function submitAction(form) {
  const endpoint = form.dataset.endpoint;
  if (!endpoint) return;
  const confirmText = form.dataset.confirm;
  if (confirmText && !window.confirm(confirmText)) return;
  const button = form.querySelector('button[type="submit"]');
  const original = button ? button.innerHTML : '';
  if (button) {
    button.disabled = true;
    button.textContent = '处理中…';
  }
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(collectPayload(form)),
    });
    const json = await res.json();
    renderResult(json);
    if (json.ok) {
      const okToast = form.dataset.toast || '操作成功';
      const verdict = json.data && typeof json.data.valid === 'boolean' ? json.data.valid : null;
      if (verdict === false) {
        toast((json.data && json.data.message) || '验证未通过', 'err');
      } else {
        toast(okToast, 'ok');
      }
      applyFill(form, json);
      refreshSummary();
    } else {
      toast((json.error && json.error.message) || '操作失败', 'err');
    }
  } catch (error) {
    renderResult({ ok: false, error: { code: 'network_error', message: error.message } });
    toast('网络错误：' + error.message, 'err');
  } finally {
    if (button) {
      button.disabled = false;
      button.innerHTML = original;
    }
  }
}

/* ---------- live summary refresh ---------- */

async function refreshSummary() {
  try {
    const res = await fetch('/api/summary');
    const json = await res.json();
    if (!json.ok || !json.data) return;
    const s = json.data;
    const metrics = document.querySelectorAll('.identity-strip .mini-metrics b');
    if (metrics.length === 3) {
      metrics[0].textContent = s.eventCount ?? 0;
      metrics[1].textContent = (s.keyCounts && s.keyCounts.device) ?? 0;
      metrics[2].textContent = s.attestationCount ?? 0;
    }
  } catch (_) {
    /* non-fatal */
  }
}

/* ---------- events ---------- */

document.addEventListener('submit', (event) => {
  const form = event.target.closest('.action-form');
  if (!form) return;
  event.preventDefault();
  submitAction(form);
});

document.addEventListener('click', async (event) => {
  const copyValue = event.target.closest('[data-copy-value]');
  if (copyValue) {
    copyText(copyValue.dataset.copyValue, copyValue);
    return;
  }

  const copyButton = event.target.closest('[data-copy-target]');
  if (copyButton) {
    const target = document.querySelector(copyButton.dataset.copyTarget);
    if (target) copyText(target.textContent || '', copyButton);
    return;
  }

  const rawToggle = event.target.closest('#raw-toggle');
  if (rawToggle) {
    const raw = document.querySelector('#global-result');
    if (raw) {
      raw.classList.toggle('collapsed');
      rawToggle.classList.toggle('open', !raw.classList.contains('collapsed'));
    }
    return;
  }

  const fetchButton = event.target.closest('[data-fetch-json]');
  if (fetchButton) {
    const endpoint = fetchButton.dataset.fetchJson;
    const original = fetchButton.innerHTML;
    fetchButton.disabled = true;
    fetchButton.textContent = '加载中…';
    try {
      const res = await fetch(endpoint);
      const json = await res.json();
      renderResult(json);
      if (json.ok) {
        toast('已加载', 'ok');
        const target = fetchButton.dataset.fillTarget;
        const path = fetchButton.dataset.fillPath;
        if (target && path) {
          const value = getByPath(json.data, path);
          const el = document.querySelector(target);
          if (el && value !== undefined) {
            el.value = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
          }
        }
      } else {
        toast((json.error && json.error.message) || '加载失败', 'err');
      }
    } catch (error) {
      renderResult({ ok: false, error: { code: 'network_error', message: error.message } });
      toast('网络错误：' + error.message, 'err');
    } finally {
      fetchButton.disabled = false;
      fetchButton.innerHTML = original;
    }
  }
});
