# sing-box AnyTLS + Reality 一键部署

使用 AnyTLS 协议 + Reality TLS 伪装，一键部署代理服务端并自动生成客户端配置。

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

1. 安装依赖（curl、tar、jq）
2. 下载安装 sing-box **1.12.x** 最新稳定版作为服务端
3. 自动生成 Reality 密钥对和 short_id
4. 写入服务端配置到 `/etc/sing-box/config.json`，并校验
5. 创建 systemd 服务并启动（开机自启）
6. 自动获取服务器公网 IP
7. 在**脚本执行目录**生成 `client-config.json`（已自动填好 IP、密码、公钥等）

## 为什么服务端用 1.12.x

经过源码分析，sing-box 的 Reality 服务端功能（`with_reality_server`）从 v1.12.0 起合并到 `with_utls` build tag 中，1.12.x 和 1.13.x 的官方预编译包都包含此功能。但 **1.13.x 对 Reality TLS 握手处理做了较大重构**（新增 kTLS、ECH 冲突检查、Logger 类型变更等），与部分 handshake 目标站点存在兼容性问题。使用久经验证的 1.12.x 作为服务端更为稳定可靠，且客户端 1.13.x 连接 1.12.x 服务端完全兼容。

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
- TLS 伪装：Reality（handshake 到 www.microsoft.com）
- 配置路径：`/etc/sing-box/config.json`

### 客户端配置

- 入站：TUN 模式（全局代理）
- DNS：Google DoT (8.8.8.8) 走代理，阿里 (223.5.5.5) 直连
- 路由：私有 IP 直连，其余走代理
- TLS：uTLS Chrome 指纹 + Reality

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
- 服务端 sing-box：1.12.x（脚本自动下载最新稳定版）
- 客户端 sing-box：1.12.x 或 1.13.x 均可
