/* ─── State ────────────────────────────────────────────── */
const state = {
  file: null,
  shareCode: null,
  shareKey: null,       // base64-encoded key (passwordless mode)
  currentTab: 'send',
};

/* ─── DOM refs ─────────────────────────────────────────── */
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dom = {
  tabSend:    $('#tabSend'),
  tabReceive: $('#tabReceive'),
  panelSend:  $('#panelSend'),
  panelReceive: $('#panelReceive'),

  dropZone:    $('#dropZone'),
  dropContent: $('#dropZoneContent'),
  fileInfo:    $('#fileInfo'),
  fileName:    $('#fileName'),
  fileSize:    $('#fileSize'),
  fileInput:   $('#fileInput'),
  removeFile:  $('#removeFile'),

  password:   $('#password'),
  togglePw:   $('#togglePw'),
  expiry:     $('#expiry'),

  uploadBtn:     $('#uploadBtn'),
  uploadBtnText: $('#uploadBtnText'),

  progressWrap:  $('#progressWrap'),
  progressFill:  $('#progressFill'),
  progressText:  $('#progressText'),

  result:       $('#result'),
  shareLink:    $('#shareLink'),
  copyLink:     $('#copyLink'),
  resultHint:   $('#resultHint'),
  showQr:       $('#showQr'),
  newTransfer:  $('#newTransfer'),

  receiveCode:  $('#receiveCode'),
  receivePw:    $('#receivePw'),
  pwRow:        $('#pwRow'),
  receiveBtn:   $('#receiveBtn'),
  receiveBtnText: $('#receiveBtnText'),

  receiveProgress:      $('#receiveProgress'),
  receiveProgressFill:  $('#receiveProgressFill'),
  receiveProgressText:  $('#receiveProgressText'),

  receiveInfo:   $('#receiveInfo'),
  receiveFileName: $('#receiveFileName'),
  receiveFileSize: $('#receiveFileSize'),
  downloadBtn:   $('#downloadBtn'),

  qrModal:  $('#qrModal'),
  qrOverlay: $('#qrOverlay'),
  qrBody:   $('#qrBody'),
  closeQr:  $('#closeQr'),

  toast: $('#toast'),
};

/* ─── Utilities ─────────────────────────────────────────── */
function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

function showToast(msg, type) {
  dom.toast.textContent = msg;
  dom.toast.className = 'toast' + (type ? ' ' + type : '');
  dom.toast.classList.remove('hidden');
  clearTimeout(dom.toast._timer);
  dom.toast._timer = setTimeout(() => dom.toast.classList.add('hidden'), 3000);
}

function setProgress(el, fillEl, textEl, pct, text) {
  el.classList.remove('hidden');
  fillEl.style.width = pct + '%';
  textEl.textContent = text + (pct === 100 ? '' : ` (${Math.round(pct)}%)`);
}

function hideProgress(el, fillEl) {
  el.classList.add('hidden');
  fillEl.style.width = '0%';
}

/* ─── Crypto (AES-GCM + PBKDF2) ─────────────────────────── */

async function generateKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function exportKey(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

function importKey(base64) {
  const raw = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptFile(file, password) {
  const data = await file.arrayBuffer();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  let key, salt = null, keyB64 = null;

  if (password) {
    salt = crypto.getRandomValues(new Uint8Array(16));
    key = await deriveKey(password, salt);
  } else {
    key = await generateKey();
    keyB64 = await exportKey(key);
  }

  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);

  return {
    encrypted,
    iv,
    salt,
    keyB64,
  };
}

async function decryptFile(encryptedData, iv, salt, password, keyB64) {
  let key;
  if (keyB64) {
    key = await importKey(keyB64);
  } else {
    key = await deriveKey(password, salt);
  }
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedData);
}

/* ─── Tab Switching ────────────────────────────────────── */
function switchTab(tab) {
  state.currentTab = tab;
  dom.tabSend.classList.toggle('active', tab === 'send');
  dom.tabReceive.classList.toggle('active', tab === 'receive');
  dom.panelSend.classList.toggle('active', tab === 'send');
  dom.panelReceive.classList.toggle('active', tab === 'receive');
}

dom.tabSend.addEventListener('click', () => switchTab('send'));
dom.tabReceive.addEventListener('click', () => switchTab('receive'));

/* ─── Password toggle ─────────────────────────────────── */
dom.togglePw.addEventListener('click', () => {
  const input = dom.password;
  if (input.type === 'password') {
    input.type = 'text';
    dom.togglePw.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
  } else {
    input.type = 'password';
    dom.togglePw.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
  }
});

/* ─── File Selection ──────────────────────────────────── */
dom.dropZone.addEventListener('click', () => dom.fileInput.click());

dom.dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dom.dropZone.classList.add('dragover');
});
dom.dropZone.addEventListener('dragleave', () => {
  dom.dropZone.classList.remove('dragover');
});
dom.dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dom.dropZone.classList.remove('dragover');
  const files = e.dataTransfer.files;
  if (files.length) selectFile(files[0]);
});

dom.fileInput.addEventListener('change', () => {
  if (dom.fileInput.files.length) selectFile(dom.fileInput.files[0]);
});

dom.removeFile.addEventListener('click', (e) => {
  e.stopPropagation();
  clearFile();
});

function selectFile(file) {
  state.file = file;
  dom.fileName.textContent = file.name;
  dom.fileSize.textContent = formatSize(file.size);
  dom.dropContent.classList.add('hidden');
  dom.fileInfo.classList.remove('hidden');
  dom.uploadBtn.disabled = false;
  resetUploadResult();
}

function clearFile() {
  state.file = null;
  dom.fileInput.value = '';
  dom.dropContent.classList.remove('hidden');
  dom.fileInfo.classList.add('hidden');
  dom.uploadBtn.disabled = true;
  resetUploadResult();
}

function resetUploadResult() {
  dom.result.classList.add('hidden');
  hideProgress(dom.progressWrap, dom.progressFill);
}

/* ─── Upload ───────────────────────────────────────────── */
dom.uploadBtn.addEventListener('click', uploadFile);

async function uploadFile() {
  if (!state.file) return;

  dom.uploadBtn.disabled = true;
  dom.uploadBtnText.textContent = '准备中...';
  resetUploadResult();

  try {
    // 1) Encrypt in browser
    setProgress(dom.progressWrap, dom.progressFill, dom.progressText, 0, '加密中');
    const password = dom.password.value.trim();

    // Yield to let UI update
    await new Promise(r => setTimeout(r, 50));

    const { encrypted, iv, salt, keyB64 } = await encryptFile(state.file, password);

    setProgress(dom.progressWrap, dom.progressFill, dom.progressText, 50, '加密完成，上传中');

    // 2) Upload encrypted blob
    const blob = new Blob([encrypted]);
    const formData = new FormData();
    formData.append('file', blob, 'data.enc');
    formData.append('filename', state.file.name);
    formData.append('iv', btoa(String.fromCharCode(...iv)));
    formData.append('salt', salt ? btoa(String.fromCharCode(...salt)) : '');
    formData.append('hasPassword', password ? 'true' : 'false');
    formData.append('expiresIn', dom.expiry.value);

    const resp = await fetch('/api/upload', { method: 'POST', body: formData });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || '上传失败');
    }

    const data = await resp.json();
    state.shareCode = data.code;
    state.shareKey = keyB64;

    setProgress(dom.progressWrap, dom.progressFill, dom.progressText, 100, '上传完成');

    // 3) Build share link
    let link;
    if (data.fullUrl) {
      link = keyB64 ? data.fullUrl + '#' + keyB64 : data.fullUrl;
    } else if (keyB64) {
      link = window.location.origin + '/dl/' + data.code + '#' + keyB64;
    } else {
      link = window.location.origin + '/dl/' + data.code;
    }

    dom.shareLink.value = link;
    dom.resultHint.textContent = password
      ? '接收方需要输入密码才能解密文件'
      : '此链接包含解密密钥，请安全分享';
    dom.result.classList.remove('hidden');

    dom.uploadBtnText.textContent = '上传并生成分享链接';
    dom.uploadBtn.disabled = false;

  } catch (err) {
    console.error(err);
    showToast(err.message || '上传失败，请重试', 'error');
    dom.uploadBtnText.textContent = '上传并生成分享链接';
    dom.uploadBtn.disabled = false;
    hideProgress(dom.progressWrap, dom.progressFill);
  }
}

/* ─── Result: Copy Link ────────────────────────────────── */
dom.copyLink.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(dom.shareLink.value);
    dom.copyLink.textContent = '已复制';
    dom.copyLink.classList.add('copied');
    setTimeout(() => {
      dom.copyLink.textContent = '复制';
      dom.copyLink.classList.remove('copied');
    }, 2000);
  } catch {
    dom.shareLink.select();
    document.execCommand('copy');
    showToast('已复制到剪贴板', 'success');
  }
});

/* ─── Result: QR Code ──────────────────────────────────── */
dom.showQr.addEventListener('click', async () => {
  dom.qrBody.innerHTML = '<div class="qr-loading">生成中...</div>';
  dom.qrModal.classList.remove('hidden');
  try {
    const resp = await fetch('/api/qr/' + state.shareCode);
    if (!resp.ok) throw new Error();
    const svg = await resp.text();
    dom.qrBody.innerHTML = svg;
  } catch {
    dom.qrBody.innerHTML = '<div class="qr-loading" style="color:var(--danger)">二维码生成失败</div>';
  }
});

dom.closeQr.addEventListener('click', () => dom.qrModal.classList.add('hidden'));
dom.qrOverlay.addEventListener('click', () => dom.qrModal.classList.add('hidden'));

/* ─── Result: New Transfer ────────────────────────────── */
dom.newTransfer.addEventListener('click', () => {
  clearFile();
  dom.result.classList.add('hidden');
  dom.uploadBtn.disabled = true;
});

/* ─── Receive: Code Input ──────────────────────────────── */
dom.receiveCode.addEventListener('input', checkReceiveCode);
dom.receivePw.addEventListener('input', checkReceiveCode);

function checkReceiveCode() {
  const code = extractCode(dom.receiveCode.value.trim());
  dom.receiveBtn.disabled = !code;
}

function extractCode(input) {
  // Support full URL: https://host/dl/abc123
  const m = input.match(/\/dl\/([a-zA-Z0-9]+)/);
  return m ? m[1] : input;
}

/* ─── Receive: Fetch Info ──────────────────────────────── */
dom.receiveBtn.addEventListener('click', fetchFileInfo);

async function fetchFileInfo() {
  const code = extractCode(dom.receiveCode.value.trim());
  if (!code) return;

  dom.receiveBtn.disabled = true;
  dom.receiveBtnText.textContent = '获取中...';
  dom.receiveInfo.classList.add('hidden');

  try {
    const resp = await fetch('/api/info/' + encodeURIComponent(code));
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || '文件不存在');
    }

    const meta = await resp.json();
    state.shareCode = code;

    dom.receiveFileName.textContent = meta.filename;
    dom.receiveFileSize.textContent = formatSize(meta.size);
    dom.receiveInfo.classList.remove('hidden');

    // Show/hide password field
    if (meta.hasPassword) {
      dom.pwRow.classList.remove('hidden');
    } else {
      dom.pwRow.classList.add('hidden');
      dom.receivePw.value = '';
    }

    // Store crypto params on the download button
    dom.downloadBtn.dataset.iv = meta.iv;
    dom.downloadBtn.dataset.salt = meta.salt || '';
    dom.downloadBtn.dataset.hasPassword = meta.hasPassword;
    dom.downloadBtn.dataset.filename = meta.filename;

    dom.receiveBtnText.textContent = '获取文件';
    dom.receiveBtn.disabled = false;

  } catch (err) {
    showToast(err.message, 'error');
    dom.receiveBtnText.textContent = '获取文件';
    dom.receiveBtn.disabled = false;
  }
}

/* ─── Receive: Download & Decrypt ──────────────────────── */
dom.downloadBtn.addEventListener('click', downloadAndDecrypt);

async function downloadAndDecrypt() {
  const code = state.shareCode;
  if (!code) return;

  dom.downloadBtn.disabled = true;
  dom.downloadBtn.textContent = '下载中...';

  try {
    // 1) Download encrypted data
    setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 0, '下载中');
    const resp = await fetch('/api/data/' + encodeURIComponent(code));
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || '下载失败');
    }

    const encrypted = await resp.arrayBuffer();
    setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 50, '解密中');

    await new Promise(r => setTimeout(r, 30));

    // 2) Get IV
    const ivB64 = dom.downloadBtn.dataset.iv;
    const saltB64 = dom.downloadBtn.dataset.salt;
    const hasPassword = dom.downloadBtn.dataset.hasPassword === 'true';
    const filename = dom.downloadBtn.dataset.filename;

    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));

    // 3) Get key (from URL hash or password)
    let keyB64 = null;
    let password = null;

    if (!hasPassword) {
      keyB64 = extractKeyFromHash();
    } else {
      password = dom.receivePw.value.trim();
      if (!password) {
        throw new Error('请输入解密密码');
      }
    }

    let salt = null;
    if (saltB64) {
      salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    }

    // 4) Decrypt
    const decrypted = await decryptFile(encrypted, iv, salt, password, keyB64);

    setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 85, '解密完成');

    // 5) Trigger download
    const blob = new Blob([decrypted]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 100, '下载完成');
    showToast('文件解密并下载成功', 'success');

    setTimeout(() => {
      hideProgress(dom.receiveProgress, dom.receiveProgressFill);
    }, 2000);

    dom.downloadBtn.textContent = '解密并下载';
    dom.downloadBtn.disabled = false;

  } catch (err) {
    console.error(err);
    showToast(err.message || '下载失败', 'error');
    dom.downloadBtn.textContent = '解密并下载';
    dom.downloadBtn.disabled = false;
    hideProgress(dom.receiveProgress, dom.receiveProgressFill);
  }
}

/* ─── URL Hash Key Extraction ─────────────────────────── */
function extractKeyFromHash() {
  const hash = window.location.hash.replace(/^#/, '');
  return hash || null;
}

/* ─── Auto-detect code from URL ────────────────────────── */
function autoDetectFromURL() {
  const m = window.location.pathname.match(/\/dl\/([a-zA-Z0-9]+)/);
  if (m) {
    const code = m[1];
    dom.receiveCode.value = window.location.origin + '/dl/' + code;
    dom.receiveBtn.disabled = false;
    switchTab('receive');
    // Auto-fetch after short delay
    setTimeout(fetchFileInfo, 400);
  }
}

/* ─── Init ─────────────────────────────────────────────── */
autoDetectFromURL();
