# Snell Web 管理脚本

这个项目提供了一键安装、管理 Snell Server 以及附带 Web 管理后台的 Shell 脚本。脚本会完成 Snell 二进制、systemd 服务、iptables 流量统计链与 Web 管理面板（类似 3X-UI，包含多用户与订阅功能）的部署。

## 功能特性

- 自动下载并安装指定版本的 Snell Server。
- 基于 systemd 的多实例管理，每个用户独立配置与服务。 
- 通过 iptables 统计各用户端口的流量用量。
- Web 管理面板：
  - 多用户增删改管理。
  - 流量使用情况显示与一键清零。
  - 一键生成订阅链接（`/cgi-bin/subscribe.sh?token=...`）。
  - 支持自定义服务器对外地址，方便在订阅链接中使用域名/公网 IP。
- REST API 均受管理员令牌保护。

## 快速开始

```bash
wget -O Snell.sh --no-check-certificate https://your.domain/Snell.sh
chmod +x Snell.sh
sudo ./Snell.sh install
```

安装过程中脚本会：

1. 安装依赖（curl、jq、busybox、iptables 等）。
2. 下载 Snell Server 二进制并安装至 `/usr/local/bin/snell-server`。
3. 创建 `snell-server@.service` systemd 模板，支持多实例运行。
4. 生成管理目录 `/etc/snell`、`/opt/snell-admin` 以及 Web 静态资源与 CGI 脚本。
5. 初始化 iptables `SNELL-TRACK` 链以统计端口流量。
6. 创建并启动 `snell-admin.service`（基于 busybox httpd），默认监听 `6180` 端口。
7. 生成管理员访问令牌并保存在 `/etc/snell/admin.conf`。

安装成功后，可通过浏览器访问 `http://服务器IP:6180/` 进入管理页面。首次访问需输入脚本输出的管理令牌。

## 常用命令

```bash
./Snell.sh install       # 安装 Snell 及 Web 管理面板
./Snell.sh uninstall     # 卸载所有组件与数据
./Snell.sh list-users    # 查看当前已创建的 Snell 用户
./Snell.sh admin-info    # 再次输出管理端口与令牌
```

> **提示：** Web 面板创建用户时会自动为每个用户生成独立的端口、PSK、订阅令牌，并在 `/etc/snell/users/<username>.conf` 写入配置。

## 面板简介

- “面板设置” 用于设置订阅链接中展示的服务器地址（域名或公网 IP）。
- “新增用户” 表单可设置端口、PSK、流量上限、Obfs 模式、DNS 与备注。
- “用户列表” 中可查看当前流量使用情况、复制订阅链接、重置流量或删除用户。
- 订阅接口：`http://服务器:6180/cgi-bin/subscribe.sh?token=<订阅令牌>`，返回 JSON 格式的 Snell 节点配置。

## 卸载

若需完全删除 Snell 相关文件、服务与防火墙规则，执行：

```bash
sudo ./Snell.sh uninstall
```

该命令会停止所有 Snell 实例、移除管理面板、删除 `/etc/snell`、`/opt/snell-admin`、`/usr/local/bin/snell-server` 以及 `SNELL-TRACK` iptables 链。

## 注意事项

- 请自行在防火墙放行 Snell 用户端口以及管理面板端口（默认 6180）。
- 流量统计依赖 iptables 计数，仅统计入站 TCP 流量，数值可作为参考。若服务器重启或规则刷新后会重新计数。
- 管理令牌存放于 `/etc/snell/admin.conf`，请妥善保管。

## Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=xOS/Snell&type=Date)](https://www.star-history.com/#xOS/Snell&Date)
