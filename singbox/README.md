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

1. 安装依赖（curl、tar、jq）
2. 下载安装 sing-box 最新稳定版（1.13.x）
3. 自动生成 Reality 密钥对和 short_id
4. 写入服务端配置到 `/etc/sing-box/config.json`，并校验
5. 创建 systemd 服务并启动（开机自启）
6. 自动获取服务器公网 IP
7. 在**脚本执行目录**生成 `client-config.json`（已自动填好 IP、密码、公钥等）

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

> 客户端同样需要 sing-box 1.13.x 版本。

## 配置说明

### 服务端配置

- 协议：AnyTLS
- 端口：443
- TLS 伪装：Reality（handshake 到 www.bing.com）
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
- sing-box 版本：1.13.x（脚本自动下载最新稳定版）
