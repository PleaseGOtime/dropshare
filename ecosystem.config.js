module.exports = {
  apps: [{
    name: 'dropshare',
    script: 'server.js',

    // 资源限制 — 2核2G 服务器优化
    max_memory_restart: '1500M',   // 内存超过 1.5G 自动重启
    instances: 1,                   // 单进程，省内存
    exec_mode: 'fork',              // fork 模式比 cluster 省内存

    // 日志关闭（减小开销）
    error_file: '/dev/null',
    out_file: '/dev/null',

    // 自动重启
    restart_delay: 5000,            // 崩溃后等待 5 秒重启
    max_restarts: 5,                // 1 分钟内最多重启 5 次，超出则停掉
    min_uptime: '30s',              // 运行超过 30 秒才算成功启动

    // 优雅重启
    kill_timeout: 10000,
    listen_timeout: 5000,
  }]
};
