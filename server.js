require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const https = require('https');
const { execSync } = require('child_process');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT) || 3443;
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './uploads');
const PUBLIC_URL = process.env.PUBLIC_URL || '';

// Trust proxy (Nginx/Caddy reverse proxy)
if (process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', 1);
}

// Get local network IP
function getLocalIP() {
  const nets = require('os').networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return '127.0.0.1';
}

// ─── Self-Signed Certificate ──────────────────────────────
const CERT_DIR = path.join(__dirname, 'certs');
const KEY_PATH = path.join(CERT_DIR, 'key.pem');
const CERT_PATH = path.join(CERT_DIR, 'cert.pem');

function ensureCert() {
  if (!fs.existsSync(CERT_DIR)) {
    fs.mkdirSync(CERT_DIR, { recursive: true });
  }
  if (!fs.existsSync(KEY_PATH) || !fs.existsSync(CERT_PATH)) {
    console.log('  → 正在生成自签名证书（首次运行）...');
    try {
      execSync(
        `openssl req -x509 -newkey rsa:2048 -keyout "${KEY_PATH}" -out "${CERT_PATH}" -days 3650 -nodes -subj "/CN=DropShare"`,
        { stdio: 'pipe', timeout: 15000 }
      );
      console.log('  ✓ 证书已生成');
    } catch (err) {
      console.error('  ✗ 证书生成失败（需要安装 openssl）:', err.message);
      console.log('  → 将仅启动 HTTP 服务');
      return false;
    }
  }
  return true;
}

const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 1073741824; // 1GB
const UPLOAD_MAX = parseInt(process.env.UPLOAD_MAX) || 50;
const DOWNLOAD_MAX = parseInt(process.env.DOWNLOAD_MAX) || 200;

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ─── Security Headers ───────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains'
  );
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self'"
  );
  next();
});

// ─── CORS ───────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.CORS_ORIGIN || '*', methods: ['GET', 'POST'] }));

// ─── Body Parser (JSON API only) ─────────────────────────────────────
app.use(express.json({ limit: '1mb' }));

// ─── Static Files ──────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate Limiters ─────────────────────────────────────────────────
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: UPLOAD_MAX,
  message: { error: '上传请求过于频繁，请稍后再试' },
});

const downloadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: DOWNLOAD_MAX,
  message: { error: '下载请求过于频繁，请稍后再试' },
});

// ─── Helpers ───────────────────────────────────────────────────────
function getFileDir(code) {
  return path.join(UPLOAD_DIR, code);
}

function getMetadataPath(code) {
  return path.join(getFileDir(code), 'metadata.json');
}

function getDataPath(code) {
  return path.join(getFileDir(code), 'data.enc');
}

function generateCode() {
  return uuidv4().replace(/-/g, '').substring(0, 12);
}

// ─── Upload: Init Session ──────────────────────────────────────────
app.post('/api/upload/init', uploadLimiter, (req, res) => {
  // Validate file size upfront (original plaintext size)
  const { size } = req.body;
  if (size && parseInt(size) > MAX_FILE_SIZE) {
    return res.status(413).json({
      error: `文件超过大小限制 ${(MAX_FILE_SIZE / 1024 / 1024).toFixed(0)}MB`,
    });
  }

  const code = generateCode();
  try {
    fs.mkdirSync(getFileDir(code), { recursive: true });
    res.json({ code });
  } catch (err) {
    console.error('Init error:', err);
    res.status(500).json({ error: '初始化上传失败' });
  }
});

// ─── Upload: Parallel chunk (each chunk → separate part file) ──────
// Client uploads 3 chunks at once via concurrent HTTP requests,
// maximizing throughput on bandwidth-limited connections.
// Server stores each chunk as data.enc.<N>; concatenated at /complete.
app.post('/api/upload/:code/chunk/:index', (req, res) => {
  const { code, index } = req.params;

  if (!/^[a-zA-Z0-9]+$/.test(code)) {
    return res.status(400).json({ error: '无效的分享码' });
  }

  const fileDir = getFileDir(code);
  if (!fs.existsSync(fileDir)) {
    return res.status(404).json({ error: '上传会话不存在' });
  }

  const partPath = getDataPath(code) + '.' + index;
  const writeStream = fs.createWriteStream(partPath);

  req.pipe(writeStream);

  writeStream.on('finish', () => {
    if (!res.headersSent) res.json({ success: true });
  });

  writeStream.on('error', (err) => {
    console.error('Chunk write error:', err);
    if (!res.headersSent) res.status(500).json({ error: '写入分片失败' });
  });

  req.on('error', (err) => {
    console.error('Chunk read error:', err);
    if (!res.headersSent) res.status(500).json({ error: '读取分片失败' });
  });
});

// ─── Upload: Complete (concatenate part files + write metadata) ────
app.post('/api/upload/:code/complete', uploadLimiter, (req, res) => {
  const { code } = req.params;

  if (!/^[a-zA-Z0-9]+$/.test(code)) {
    return res.status(400).json({ error: '无效的分享码' });
  }

  const fileDir = getFileDir(code);
  if (!fs.existsSync(fileDir)) {
    return res.status(404).json({ error: '上传会话不存在' });
  }

  const { filename, iv, salt, hasPassword, expiresIn, chunkSize, numChunks, size } = req.body;

  if (!filename || !iv) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  // Concatenate part files (data.enc.0, data.enc.1, ...) into data.enc
  const dataPath = getDataPath(code);
  const n = parseInt(numChunks) || 1;
  for (let i = 0; i < n; i++) {
    const partPath = dataPath + '.' + i;
    if (fs.existsSync(partPath)) {
      const part = fs.readFileSync(partPath);
      fs.appendFileSync(dataPath, part);
      fs.unlinkSync(partPath);
    }
  }

  const hours = parseInt(expiresIn) || 24;
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

  const metadata = {
    filename,
    size: parseInt(size),
    iv,
    salt: salt || null,
    hasPassword: hasPassword === 'true',
    expiresAt,
    maxDownloads: 0,
    downloadCount: 0,
    createdAt: new Date().toISOString(),
    chunkSize: parseInt(chunkSize) || 0,
    numChunks: n,
  };

  try {
    fs.writeFileSync(getMetadataPath(code), JSON.stringify(metadata, null, 2));
  } catch (err) {
    console.error('Metadata write error:', err);
    return res.status(500).json({ error: '写入元数据失败' });
  }

  const fullUrl = PUBLIC_URL ? `${PUBLIC_URL}/dl/${code}` : undefined;

  res.json({
    code,
    url: `/dl/${code}`,
    fullUrl,
    expiresAt,
  });
});

// ─── Get Metadata ──────────────────────────────────────────────────
app.get('/api/info/:code', downloadLimiter, (req, res) => {
  const { code } = req.params;

  if (!/^[a-zA-Z0-9]+$/.test(code)) {
    return res.status(400).json({ error: '无效的分享码' });
  }

  const metaPath = getMetadataPath(code);
  if (!fs.existsSync(metaPath)) {
    return res.status(404).json({ error: '文件不存在或已过期' });
  }

  const metadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));

  // Check expiry
  if (new Date(metadata.expiresAt) < new Date()) {
    fs.rmSync(getFileDir(code), { recursive: true, force: true });
    return res.status(410).json({ error: '文件已过期' });
  }

  // Check download limit
  if (metadata.maxDownloads > 0 && metadata.downloadCount >= metadata.maxDownloads) {
    fs.rmSync(getFileDir(code), { recursive: true, force: true });
    return res.status(410).json({ error: '文件下载次数已达上限' });
  }

  res.json({
    filename: metadata.filename,
    size: metadata.size,
    iv: metadata.iv,
    salt: metadata.salt,
    hasPassword: metadata.hasPassword,
    expiresAt: metadata.expiresAt,
    downloadCount: metadata.downloadCount,
    maxDownloads: metadata.maxDownloads,
    chunkSize: metadata.chunkSize || 0,
    numChunks: metadata.numChunks || 1,
  });
});

// ─── Download Encrypted Data (zero-copy via sendFile) ──────────────
app.get('/api/data/:code', downloadLimiter, (req, res) => {
  const { code } = req.params;

  if (!/^[a-zA-Z0-9]+$/.test(code)) {
    return res.status(400).json({ error: '无效的分享码' });
  }

  const dataPath = getDataPath(code);
  const metaPath = getMetadataPath(code);

  if (!fs.existsSync(dataPath) || !fs.existsSync(metaPath)) {
    return res.status(404).json({ error: '文件不存在或已过期' });
  }

  const metadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));

  // Check expiry
  if (new Date(metadata.expiresAt) < new Date()) {
    fs.rmSync(getFileDir(code), { recursive: true, force: true });
    return res.status(410).json({ error: '文件已过期' });
  }

  // Check download limit
  if (metadata.maxDownloads > 0 && metadata.downloadCount >= metadata.maxDownloads) {
    fs.rmSync(getFileDir(code), { recursive: true, force: true });
    return res.status(410).json({ error: '文件下载次数已达上限' });
  }

  // Increment download count
  metadata.downloadCount++;
  fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));

  // Custom headers for the client
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('X-Filename', encodeURIComponent(metadata.filename));
  res.setHeader('X-Has-Password', String(metadata.hasPassword));
  res.setHeader('X-IV', metadata.iv);
  res.setHeader('X-Salt', metadata.salt || '');
  res.setHeader('Access-Control-Expose-Headers', 'X-Filename, X-Has-Password, X-IV, X-Salt');

  // sendFile uses kernel sendfile syscall — zero-copy from disk to socket
  res.sendFile(dataPath, {
    acceptRanges: true,
    cacheControl: false,
  });
});

// ─── QR Code ──────────────────────────────────────────────────────
app.get('/api/qr/:code', async (req, res) => {
  const { code } = req.params;

  if (!/^[a-zA-Z0-9]+$/.test(code)) {
    return res.status(400).json({ error: '无效的分享码' });
  }

  const metaPath = getMetadataPath(code);
  if (!fs.existsSync(metaPath)) {
    return res.status(404).json({ error: '文件不存在' });
  }

  try {
    const url = PUBLIC_URL
      ? `${PUBLIC_URL}/dl/${code}`
      : `${req.protocol}://${req.get('host')}/dl/${code}`;
    const qrSvg = await QRCode.toString(url, {
      type: 'svg',
      margin: 1,
      width: 256,
      color: { dark: '#1e293b', light: '#ffffff' },
    });
    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(qrSvg);
  } catch (err) {
    res.status(500).json({ error: '生成二维码失败' });
  }
});

// ─── SPA Fallback ─────────────────────────────────────────────────
app.get('/dl*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Cleanup Cron (every 30 minutes) ──────────────────────────────
cron.schedule('*/30 * * * *', () => {
  const dirs = fs.readdirSync(UPLOAD_DIR).filter((d) => {
    const dirPath = path.join(UPLOAD_DIR, d);
    // Only process directories (skip stray files like Thumbs.db)
    try { if (!fs.statSync(dirPath).isDirectory()) return false; } catch { return false; }
    const metaPath = path.join(dirPath, 'metadata.json');

    // Incomplete upload (no metadata) — remove after 24 h
    if (!fs.existsSync(metaPath)) {
      try {
        const stat = fs.statSync(dirPath);
        return Date.now() - stat.mtimeMs > 24 * 60 * 60 * 1000;
      } catch {
        return false;
      }
    }

    try {
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
      return new Date(meta.expiresAt) < new Date();
    } catch {
      return true;
    }
  });

  for (const dir of dirs) {
    fs.rmSync(path.join(UPLOAD_DIR, dir), { recursive: true, force: true });
    console.log(`[Cleanup] Deleted expired file: ${dir}`);
  }
});

// ─── Start Server ────────────────────────────────────────────────
const localIP = getLocalIP();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✓ DropShare 已启动`);
  console.log(`  ────────────────────────────`);
  console.log(`  本机:   http://localhost:${PORT}`);
  if (PUBLIC_URL) {
    console.log(`  公网:   ${PUBLIC_URL}`);
  } else {
    console.log(`  手机:   http://${localIP}:${PORT}`);
  }
  console.log(`  ────────────────────────────`);
  console.log(`  上传目录: ${UPLOAD_DIR}`);
  console.log(`  最大文件: ${(MAX_FILE_SIZE / 1024 / 1024).toFixed(0)}MB`);
});

// HTTPS (for Web Crypto on mobile)
if (ensureCert()) {
  const httpsOptions = {
    key: fs.readFileSync(KEY_PATH),
    cert: fs.readFileSync(CERT_PATH),
  };
  https.createServer(httpsOptions, app).listen(HTTPS_PORT, '0.0.0.0', () => {
    if (PUBLIC_URL) {
      console.log(`  HTTPS:  ${PUBLIC_URL}`);
    } else {
      console.log(`  HTTPS:  https://${localIP}:${HTTPS_PORT}  ← 手机访问这个`);
    }
    console.log(`  ────────────────────────────\n`);
  });
} else {
  console.log(`\n`);
}
