const resultPanel = () => document.querySelector('#global-result');

function formValue(form, name) {
  const el = form.elements[name];
  if (!el) return undefined;
  if (el.type === 'checkbox') return el.checked;
  return el.value;
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

function showResult(value) {
  const panel = resultPanel();
  if (!panel) return;
  panel.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  panel.closest('.result-panel')?.classList.add('has-result');
}

async function submitAction(form) {
  const endpoint = form.dataset.endpoint;
  if (!endpoint) return;
  const confirmText = form.dataset.confirm;
  if (confirmText && !window.confirm(confirmText)) return;
  const button = form.querySelector('button[type="submit"]');
  const original = button?.textContent;
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
    showResult(json);
    if (json.ok) {
      document.body.classList.add('pulse-success');
      setTimeout(() => document.body.classList.remove('pulse-success'), 700);
    }
  } catch (error) {
    showResult({ ok: false, error: { code: 'network_error', message: error.message } });
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = original;
    }
  }
}

document.addEventListener('submit', (event) => {
  const form = event.target.closest('.action-form');
  if (!form) return;
  event.preventDefault();
  submitAction(form);
});

document.addEventListener('click', async (event) => {
  const copyButton = event.target.closest('[data-copy-target]');
  if (copyButton) {
    const target = document.querySelector(copyButton.dataset.copyTarget);
    if (!target) return;
    await navigator.clipboard.writeText(target.textContent || '');
    const original = copyButton.textContent;
    copyButton.textContent = '已复制';
    setTimeout(() => (copyButton.textContent = original), 1200);
    return;
  }

  const fetchButton = event.target.closest('[data-fetch-json]');
  if (fetchButton) {
    const endpoint = fetchButton.dataset.fetchJson;
    const original = fetchButton.textContent;
    fetchButton.disabled = true;
    fetchButton.textContent = '加载中…';
    try {
      const res = await fetch(endpoint);
      showResult(await res.json());
    } catch (error) {
      showResult({ ok: false, error: { code: 'network_error', message: error.message } });
    } finally {
      fetchButton.disabled = false;
      fetchButton.textContent = original;
    }
  }
});
