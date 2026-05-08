require('dotenv').config();
const express = require('express');
const multer = require('multer');
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
const PUBLIC_URL = process.env.PUBLIC_URL || ''; // e.g. https://dropshare.example.com

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

// ─── Static Files ──────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Multer (file upload) ──────────────────────────────────────────
const upload = multer({
  dest: path.join(UPLOAD_DIR, 'temp'),
  limits: { fileSize: MAX_FILE_SIZE },
});

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

// ─── Upload ────────────────────────────────────────────────────────
app.post('/api/upload', uploadLimiter, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: '请选择要上传的文件' });
    }

    const { filename, iv, salt, hasPassword, expiresIn } = req.body;

    if (!filename || !iv) {
      // Cleanup temp file
      fs.unlink(req.file.path, () => {});
      return res.status(400).json({ error: '缺少必要参数' });
    }

    const code = generateCode();
    const fileDir = getFileDir(code);
    fs.mkdirSync(fileDir, { recursive: true });

    // Move temp file to final location
    const dataPath = getDataPath(code);
    fs.renameSync(req.file.path, dataPath);

    // Expiry time
    const hours = parseInt(expiresIn) || 24;
    const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

    // Metadata
    const metadata = {
      filename: filename,
      size: req.file.size,
      iv: iv,
      salt: salt || null,
      hasPassword: hasPassword === 'true',
      expiresAt: expiresAt,
      maxDownloads: 0, // 0 = unlimited
      downloadCount: 0,
      createdAt: new Date().toISOString(),
    };

    fs.writeFileSync(getMetadataPath(code), JSON.stringify(metadata, null, 2));

    res.json({
      code,
      url: `/dl/${code}`,
      fullUrl: PUBLIC_URL ? `${PUBLIC_URL}/dl/${code}` : undefined,
      expiresAt,
    });
  } catch (err) {
    console.error('Upload error:', err);
    // Cleanup temp file if it exists
    if (req.file && req.file.path) {
      fs.unlink(req.file.path, () => {});
    }
    res.status(500).json({ error: '上传失败，请重试' });
  }
});

// ─── Get Metadata ──────────────────────────────────────────────────
app.get('/api/info/:code', downloadLimiter, (req, res) => {
  const { code } = req.params;

  // Sanitize: only allow alphanumeric
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
    // Cleanup expired file
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
  });
});

// ─── Download Encrypted Data ──────────────────────────────────────
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

  // Send the encrypted file
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', fs.statSync(dataPath).size);
  res.setHeader('X-Filename', encodeURIComponent(metadata.filename));
  res.setHeader('X-Has-Password', metadata.hasPassword);
  res.setHeader('X-IV', metadata.iv);
  res.setHeader('X-Salt', metadata.salt || '');
  res.setHeader('Access-Control-Expose-Headers', 'X-Filename, X-Has-Password, X-IV, X-Salt');

  const stream = fs.createReadStream(dataPath);
  stream.pipe(res);

  stream.on('error', () => {
    res.status(500).json({ error: '下载失败' });
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
// /dl/:code and /dl both serve the main page; JS reads code from URL
app.get('/dl*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Cleanup Cron (every 30 minutes) ──────────────────────────────
cron.schedule('*/30 * * * *', () => {
  const dirs = fs.readdirSync(UPLOAD_DIR).filter((d) => {
    // Skip temp directory
    if (d === 'temp') return false;
    const metaPath = path.join(UPLOAD_DIR, d, 'metadata.json');
    if (!fs.existsSync(metaPath)) return false;
    try {
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
      return new Date(meta.expiresAt) < new Date();
    } catch {
      return true; // Corrupted = delete
    }
  });

  for (const dir of dirs) {
    fs.rmSync(path.join(UPLOAD_DIR, dir), { recursive: true, force: true });
    console.log(`[Cleanup] Deleted expired file: ${dir}`);
  }
});

// Ensure temp directory exists
const tempDir = path.join(UPLOAD_DIR, 'temp');
if (!fs.existsSync(tempDir)) {
  fs.mkdirSync(tempDir, { recursive: true });
}

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
