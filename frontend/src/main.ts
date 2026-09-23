import './style.css';

const API_URL = '/api';  // через прокси Vite
const SYSTEM_ID = 'support-demo';
const API_KEY = 'demo-key-12345678901234567890123456789012';

const messagesEl = document.getElementById('messages')!;
const inputEl = document.getElementById('input') as HTMLInputElement;
const sendBtn = document.getElementById('sendBtn')!;
const maskedEl = document.getElementById('maskedContent')!;
const statusEl = document.getElementById('status')!;
const statusText = document.getElementById('statusText')!;

async function checkHealth() {
  try {
    const r = await fetch(`${API_URL}/health/live`);
    if (!r.ok) throw new Error();
    const data = await r.json();
    statusEl.classList.add('ok');
    statusEl.classList.remove('error');
    statusText.textContent = data.mode === 'local-echo'
      ? 'Локальный режим'
      : 'LLM подключена';
  } catch {
    statusEl.classList.add('error');
    statusEl.classList.remove('ok');
    statusText.textContent = 'Сервис недоступен';
  }
}

function addMessage(text: string, role: 'user' | 'ai') {
  const div = document.createElement('div');
  div.className = `message message-${role}`;
  div.textContent = text;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function setMasked(text: string) {
  maskedEl.innerHTML = '';
  const pre = document.createElement('pre');
  pre.className = 'masked-text';
  pre.textContent = text;
  maskedEl.appendChild(pre);
}

function setMaskedError(text: string) {
  maskedEl.innerHTML = '';
  const div = document.createElement('div');
  div.className = 'error-text';
  div.textContent = text;
  maskedEl.appendChild(div);
}

async function send() {
  const text = inputEl.value.trim();
  if (!text) return;

  addMessage(text, 'user');
  inputEl.value = '';
  sendBtn.setAttribute('disabled', 'true');

  try {
    const r = await fetch(`${API_URL}/v1/proxy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-system-id': SYSTEM_ID,
        'x-api-key': API_KEY,
      },
      body: JSON.stringify({ text }),
    });

    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error((err as any).detail || `HTTP ${r.status}`);
    }

    const data = await r.json();

    if (data.masked && data.masked.text) {
      setMasked(data.masked.text);
    }

    addMessage(data.answer || '(пустой ответ)', 'ai');
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Неизвестная ошибка';
    addMessage(`Ошибка соединения: ${msg}`, 'ai');
    setMaskedError(`Ошибка соединения: ${msg}`);
  } finally {
    sendBtn.removeAttribute('disabled');
    inputEl.focus();
  }
}

sendBtn.addEventListener('click', send);
inputEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') send();
});

checkHealth();
setInterval(checkHealth, 30000);