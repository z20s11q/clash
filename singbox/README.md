# sing-box AnyTLS + Reality 一键部署

基于 sing-box **v1.13.x**，使用 AnyTLS 协议 + Reality TLS 伪装，一键部署代理服务端并自动生成客户端配置。

## 快速开始

在裸云服务器上（需 root 权限），执行以下命令即可完成全部部署：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/z20s11q/clash/main/singbox/install-singbox.sh) 用户名 密码
```

将 `用户名` 和 `密码` 替换为你自己想设的值，例如：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/z20s11q/clash/main/singbox/install-singbox.sh) myuser myP@ssw0rd
```

## 脚本做了什么

1. 安装依赖（curl、tar、jq、openssl）
2. 下载安装 sing-box **1.13.x** 最新稳定版
3. 验证 Reality 支持（检查 `with_utls` build tag）
4. 验证 handshake 目标站点连通性（不通则自动切换备选）
5. 自动生成 Reality 密钥对和 short_id
6. 写入服务端配置到 `/etc/sing-box/config.json`，并校验
7. 创建 systemd 服务并启动（开机自启）
8. 自动获取服务器公网 IP
9. 在**脚本执行目录**生成 `client-config.json`（已自动填好 IP、密码、公钥等）

## 部署完成后

### 服务端管理

```bash
systemctl status sing-box      # 查看状态
journalctl -u sing-box -n 50   # 查看日志
systemctl restart sing-box     # 重启
systemctl stop sing-box        # 停止
```

### 客户端使用

部署完成后，脚本会在当前目录生成 `client-config.json`，所有参数已自动填好。

将该文件复制到客户端机器上，安装 sing-box 后直接运行：

```bash
sing-box run -c client-config.json
```

> 客户端使用 sing-box 1.12.x 或 1.13.x 均可。

## 配置说明

### 服务端配置

- 协议：AnyTLS
- 端口：443
- TLS 伪装：Reality（handshake 到 www.bilibili.com，不通则自动切换备选）
- 配置路径：`/etc/sing-box/config.json`

### 客户端配置

- 入站：TUN 模式（全局代理）
- DNS：Google DoT (8.8.8.8) 走代理，阿里 (223.5.5.5) 直连
- 路由：私有 IP 直连，其余走代理
- TLS：uTLS Chrome 指纹 + Reality

## 常见问题

### "REALITY: processed invalid connection" 错误

该错误来自 `metacubex/utls` 库的 Reality 握手逻辑，常见原因：

1. **密钥不匹配** — 客户端的 `public_key` 和服务端的 `private_key` 不是同一对
2. **short_id 不匹配** — 客户端和服务端的 `short_id` 不一致
3. **server_name 不匹配** — 客户端和服务端的 SNI 不一致
4. **时间偏差** — 客户端和服务端系统时间差距超过 1 分钟
5. **handshake 目标不通** — 服务端无法连接 handshake 目标站点的 443 端口

解决：重新执行脚本即可，密钥和配置会自动重新生成且保持一致。

## 文件说明

```
singbox/
├── install-singbox.sh          # 一键部署脚本
├── singbox-client-config.json  # 客户端配置模板（供参考，实际使用脚本生成的）
└── README.md                   # 本文档
```

## 兼容性

- 服务端系统：Debian / Ubuntu / CentOS / RHEL 及其衍生版（需 systemd）
- 架构：amd64、arm64、armv7、386
- 服务端 sing-box：1.13.x（脚本自动下载最新稳定版）
- 客户端 sing-box：1.12.x 或 1.13.x 均可
