# DropShare — 文件快传

端到端加密（AES-256-GCM）、无需登录、即用即焚的文件互传工具。浏览器中加密后上传，服务器只存密文。

## 目录结构

```
dropshare/
├── server.js            # Express 服务端：上传/下载/二维码/定时清理
├── package.json         # 依赖：express, multer, cors, dotenv, qrcode, uuid, node-cron
├── ecosystem.config.js  # PM2 进程配置（单进程 fork 模式，1.5G 内存上限）
├── .env                 # 本地配置（已 gitignore）
├── .env.example         # 配置模板
├── .gitignore
├── CLAUDE.md
├── public/
│   ├── index.html       # SPA 入口（发送/接收两个面板）
│   ├── css/style.css    # 深色主题 UI
│   └── js/app.js        # 前端逻辑：Web Crypto 加密/解密、上传下载、二维码
├── uploads/             # 上传文件存储（gitignore）
│   └── temp/            # multer 临时目录
└── certs/               # 自签名证书（gitignore）
    ├── key.pem
    └── cert.pem
```

## 关键设计

- **加密**：浏览器端 AES-256-GCM 加密，密钥通过 URL hash 传递（不经过网络），或由接收方输入密码（PBKDF2 600000 次迭代）
- **存储**：每个分享码一个目录，内放 `data.enc`（密文）和 `metadata.json`（文件名/IV/salt/有效期）
- **清理**：`node-cron` 每 30 分钟扫描并删除过期文件
- **HTTPS**：首次运行自动用 openssl 生成自签名证书（手机端 Web Crypto 需要 HTTPS）
- **速率限制**：上传 30次/15分钟，下载 100次/15分钟

## 配置 (.env)

| 变量 | 默认值 | 说明 |
|------|--------|------|
| PORT | 8080 | HTTP 端口 |
| HTTPS_PORT | 3443 | HTTPS 端口 |
| UPLOAD_DIR | ./uploads | 存储目录 |
| MAX_FILE_SIZE | 5368709120 (5GB) | 单文件上限 |
| CORS_ORIGIN | * | CORS |
| PUBLIC_URL | 空 | 有域名/反代时设置，留空自动用服务器 IP |
| TRUST_PROXY | false | 反代后面时设为 true |
| UPLOAD_MAX | 30 | 上传频率限制 |
| DOWNLOAD_MAX | 100 | 下载频率限制 |

## 运行

```bash
npm install
npm start          # 开发/直接运行
pm2 start ecosystem.config.js   # 生产用 PM2
```

## 部署要点

- 需要 Node.js 18+ 和 openssl（生成自签名证书）
- 云服务器安全组放行 TCP 8080 和 3443
- 2核2G 优化：单进程 fork 模式、1.5G 内存自动重启
