/* ─── State ────────────────────────────────────────────── */
const state = {
  file: null,
  shareCode: null,
  shareKey: null,
  currentTab: 'send',
};

/* ─── Constants ────────────────────────────────────────── */
const CHUNK_SIZE = 32 * 1024 * 1024; // 32MB — fewer chunks = less overhead
const UPLOAD_POOL = 3;               // concurrent upload connections

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
  receiveKey:   $('#receiveKey'),
  keyRow:       $('#keyRow'),
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
  textEl.textContent = text + (pct < 100 ? ` (${Math.round(pct)}%)` : '');
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

// Derive per-chunk IV from master IV and chunk index
// AES-GCM requires a unique 12-byte IV per encryption with the same key.
// Scheme: XOR the last 4 bytes of masterIV with the chunk index (big-endian).
function deriveChunkIV(masterIV, chunkIndex) {
  const iv = new Uint8Array(12);
  iv.set(masterIV);
  iv[11] ^= (chunkIndex & 0xFF);
  iv[10] ^= ((chunkIndex >> 8) & 0xFF);
  iv[9] ^= ((chunkIndex >> 16) & 0xFF);
  iv[8] ^= ((chunkIndex >> 24) & 0xFF);
  return iv;
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

/* ─── Upload (Parallel Chunks) ──────────────────────────── */
dom.uploadBtn.addEventListener('click', uploadFile);

async function uploadFile() {
  if (!state.file) return;

  const file = state.file;
  const fileSize = file.size;
  const numChunks = Math.ceil(fileSize / CHUNK_SIZE);
  const password = dom.password.value.trim();

  dom.uploadBtn.disabled = true;
  dom.uploadBtnText.textContent = '准备中...';
  resetUploadResult();

  const startTime = Date.now();

  try {
    // 1) Create upload session (validates file size upfront)
    const initResp = await fetch('/api/upload/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ size: fileSize }),
    });
    if (!initResp.ok) {
      const err = await initResp.json();
      throw new Error(err.error || '初始化上传失败');
    }
    const { code } = await initResp.json();
    state.shareCode = code;

    // 2) Generate master key & IV
    let masterKey, salt = null, keyB64 = null;
    const masterIV = crypto.getRandomValues(new Uint8Array(12));

    if (password) {
      salt = crypto.getRandomValues(new Uint8Array(16));
      masterKey = await deriveKey(password, salt);
    } else {
      masterKey = await generateKey();
      keyB64 = await exportKey(masterKey);
    }

    // 3) Parallel upload pool — 3 concurrent connections maximize
    //    throughput on bandwidth-limited servers.
    let nextIndex = 0;
    let completed = 0;
    let failed = false;

    async function worker() {
      while (nextIndex < numChunks && !failed) {
        const i = nextIndex++;

        // Read & encrypt one chunk (32MB at a time — low memory overhead)
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, fileSize);
        const chunkData = await file.slice(start, end).arrayBuffer();

        const chunkIV = deriveChunkIV(masterIV, i);
        const encrypted = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: chunkIV }, masterKey, chunkData
        );

        // Upload to its own part file (no collision — each chunk -> data.enc.<i>)
        const resp = await fetch(`/api/upload/${code}/chunk/${i}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/octet-stream' },
          body: encrypted,
        });
        if (!resp.ok) {
          failed = true;
          throw new Error(`分片 ${i + 1}/${numChunks} 上传失败`);
        }

        completed++;
        const pct = Math.round((completed / numChunks) * 90);
        setProgress(dom.progressWrap, dom.progressFill, dom.progressText,
          pct, `上传中 (${completed}/${numChunks})`);
      }
    }

    const workers = Array.from({ length: UPLOAD_POOL }, () => worker());
    await Promise.all(workers);

    // 4) Complete — server concatenates part files into data.enc
    setProgress(dom.progressWrap, dom.progressFill, dom.progressText, 95, '完成上传');
    const completeResp = await fetch(`/api/upload/${code}/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        filename: file.name,
        size: fileSize,
        iv: btoa(String.fromCharCode(...masterIV)),
        salt: salt ? btoa(String.fromCharCode(...salt)) : '',
        hasPassword: password ? 'true' : 'false',
        expiresIn: dom.expiry.value,
        chunkSize: CHUNK_SIZE,
        numChunks,
      }),
    });
    if (!completeResp.ok) throw new Error('上传确认失败');

    const data = await completeResp.json();
    state.shareKey = keyB64;

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
    setProgress(dom.progressWrap, dom.progressFill, dom.progressText, 100,
      `上传完成 (${formatSize(fileSize)}, ${elapsed}s)`);

    // 5) Build share link
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

    if (meta.hasPassword) {
      dom.pwRow.classList.remove('hidden');
      dom.keyRow.classList.add('hidden');
    } else {
      dom.pwRow.classList.add('hidden');
      dom.receivePw.value = '';
      dom.keyRow.classList.remove('hidden');
      // Auto-fill key from URL hash (passwordless mode)
      const hashKey = extractKeyFromHash();
      dom.receiveKey.value = hashKey || '';
    }

    // Store full metadata on download button for later use
    dom.downloadBtn.dataset.iv = meta.iv;
    dom.downloadBtn.dataset.salt = meta.salt || '';
    dom.downloadBtn.dataset.hasPassword = meta.hasPassword;
    dom.downloadBtn.dataset.filename = meta.filename;
    dom.downloadBtn.dataset.chunkSize = meta.chunkSize || '0';
    dom.downloadBtn.dataset.numChunks = meta.numChunks || '1';
    dom.downloadBtn.dataset.fileSize = meta.size;

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

  // Show progress immediately — PBKDF2 (600k iterations) blocks 1-2s
  setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 0, '连接中...');

  dom.downloadBtn.disabled = true;
  dom.downloadBtn.textContent = '下载中...';

  try {
    const ivB64 = dom.downloadBtn.dataset.iv;
    const saltB64 = dom.downloadBtn.dataset.salt;
    const hasPassword = dom.downloadBtn.dataset.hasPassword === 'true';
    const filename = dom.downloadBtn.dataset.filename;
    const chunkSize = parseInt(dom.downloadBtn.dataset.chunkSize);
    const numChunks = parseInt(dom.downloadBtn.dataset.numChunks);
    const fileSize = parseInt(dom.downloadBtn.dataset.fileSize);

    const masterIV = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));

    // 1) Resolve decryption key
    let masterKey;
    if (!hasPassword) {
      const keyB64 = dom.receiveKey.value.trim();
      if (!keyB64) throw new Error('解密密钥不存在，请检查分享链接是否包含 #密钥');
      masterKey = await importKey(keyB64);
    } else {
      const password = dom.receivePw.value.trim();
      if (!password) throw new Error('请输入解密密码');
      let salt = null;
      if (saltB64) salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
      masterKey = await deriveKey(password, salt);
    }

    // ChunkSize === 0 → old-format single-chunk file (backward compat)
    if (chunkSize === 0) {
      await legacyDownload(code, masterKey, masterIV, filename);
    } else {
      await streamDownload(code, masterKey, masterIV, chunkSize, numChunks, fileSize, filename);
    }

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

/* ─── Legacy single-chunk download (backward compat) ─── */
async function legacyDownload(code, key, iv, filename) {
  setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 0, '下载中');

  const resp = await fetch('/api/data/' + encodeURIComponent(code));
  if (!resp.ok) {
    const err = await resp.json();
    throw new Error(err.error || '下载失败');
  }

  const encrypted = await resp.arrayBuffer();
  setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 50, '解密中');
  await new Promise(r => setTimeout(r, 30));

  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);

  triggerDownload(decrypted, filename);
  setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 100, '下载完成');
  showToast('文件解密并下载成功', 'success');
}

/* ─── Streaming chunked download ─────────────────────────── */
async function streamDownload(code, masterKey, masterIV, chunkSize, numChunks, fileSize, filename) {
  const encChunkSize = chunkSize + 16; // each encrypted chunk = plaintext + GCM tag
  const lastChunkPlainSize = fileSize - (numChunks - 1) * chunkSize;
  const lastEncChunkSize = lastChunkPlainSize + 16;
  const totalEncrypted = (numChunks - 1) * encChunkSize + lastEncChunkSize;

  setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 0, '下载中');

  const resp = await fetch('/api/data/' + encodeURIComponent(code));
  if (!resp.ok) {
    const err = await resp.json();
    throw new Error(err.error || '下载失败');
  }

  const reader = resp.body.getReader();
  let buffer = new Uint8Array(0);
  let chunkIndex = 0;
  const decryptedParts = [];
  let downloadedBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    downloadedBytes += value.length;

    // Append new data to rolling buffer
    const newBuf = new Uint8Array(buffer.length + value.length);
    newBuf.set(buffer);
    newBuf.set(value, buffer.length);
    buffer = newBuf;

    // Extract and decrypt complete chunks from buffer
    while (true) {
      const isLast = chunkIndex === numChunks - 1;
      const expectedSize = isLast ? lastEncChunkSize : encChunkSize;

      if (buffer.length < expectedSize) break;

      const encChunk = buffer.slice(0, expectedSize);
      buffer = buffer.slice(expectedSize);

      const chunkIV = deriveChunkIV(masterIV, chunkIndex);
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: chunkIV }, masterKey, encChunk
      );

      decryptedParts.push(decrypted);
      chunkIndex++;

      const pct = Math.round((downloadedBytes / totalEncrypted) * 80);
      setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText,
        pct, `下载解密中 (${Math.min(chunkIndex, numChunks)}/${numChunks})`);
    }
  }

  // Safety check
  if (chunkIndex !== numChunks) {
    throw new Error(`下载不完整 (收到 ${chunkIndex}/${numChunks} 个分片)`);
  }

  setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 90, '生成文件');
  await new Promise(r => setTimeout(r, 20));

  triggerDownloadFromParts(decryptedParts, filename);
  setProgress(dom.receiveProgress, dom.receiveProgressFill, dom.receiveProgressText, 100, '下载完成');
  showToast('文件解密并下载成功', 'success');

  setTimeout(() => {
    hideProgress(dom.receiveProgress, dom.receiveProgressFill);
  }, 2000);
}

/* ─── Trigger browser download ─────────────────────────── */
function triggerDownload(data, filename) {
  const blob = new Blob([data]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function triggerDownloadFromParts(parts, filename) {
  const blob = new Blob(parts);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
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
    setTimeout(fetchFileInfo, 400);
  }
}

/* ─── Init ─────────────────────────────────────────────── */
autoDetectFromURL();
