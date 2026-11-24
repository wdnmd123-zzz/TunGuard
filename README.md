# TunGuard

轻量级 Windows (x64) 系统托盘守护程序，实时监控 **Clash Verge (Rev)** 的 TUN 模式状态。一旦检测到 TUN 模式关闭、虚拟网卡断开或默认路由消失，立即以毫秒级速度终止所有 **Antigravity** 进程，防止断流期间产生直连请求。

## 核心特性

- **四重联动毫秒级检测**
  1. **配置文件实时监听 (`FileSystemWatcher`)**：监听 `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\verge.yaml` 中的 `enable_tun_mode` 与 `clash-verge.yaml` 的 `tun` 配置；在 Clash Verge 界面点击关闭 TUN 时，虚拟网卡尚未卸载即可在 `< 0.01 ms` 内短路判定并触发拦截。
  2. **内核路由变更回调 (`NotifyRouteChange2`)**：监听 TUN 虚拟网卡的 IPv4 默认路由（`0.0.0.0/0`、`0.0.0.0/1`、`128.0.0.0/1`）移除事件。
  3. **内核网卡状态回调 (`NotifyIpInterfaceChange`)**：捕获 Clash Verge 退出或 `verge-mihomo` 异常崩溃导致的 TUN 网卡断开/销毁。
  4. **高优先级后台巡检线程**：TUN 开启时每 100 ms 通过 `GetIfEntry2` + `GetIpForwardTable2` 复核一次（单次约 `0.13 ms`）；TUN 关闭时切换为 30 ms 高频守护，阻止未开启 TUN 时启动 Antigravity。
- **毫秒级进程终止**
  - 直接调用 Win32 API（`CreateToolhelp32Snapshot` + `TerminateProcess`）同步结束所有 `Antigravity.exe` 以及路径包含 `\antigravity\` 的 `language_server*.exe`，并在 5 ms 后补扫一次以防止子进程竞态拉起。
- **系统托盘与单实例保护**
  - 动态盾牌状态图标：**绿色**（TUN 正常守护中）/ **红色**（TUN 已关闭，禁止启动）/ **灰色**（已暂停监控）。
  - 右键菜单支持查看实时状态与最近一次拦截耗时、临时**暂停/恢复监控**、一键开关**开机自动启动**，以及安全**退出**。
  - 内置单实例互斥锁，重复启动时仅弹出当前状态气泡提示，不会多开进程。
- **零外部依赖**
  - 纯 C# + Win32 P/Invoke，直接使用 Windows 自带 `.NET Framework 4.x` 编译器（`csc.exe`）构建为约 30 KB 的独立 x64 可执行文件。

## 环境要求

- Windows 10 / 11 (x64)
- Windows 内置 `.NET Framework 4.x`（`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`）
- Clash Verge Rev

## 构建与使用

### 1. 编译

在项目目录中执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

构建脚本会自动生成 `TunGuard.ico` 并编译出 `TunGuard.exe`。

### 2. 运行与开机自启

- 双击运行 `TunGuard.exe`，程序将在后台以 `High` 优先级静默启动并在右下角系统托盘显示图标。
- 右键点击托盘图标，勾选 **开机自动启动**，程序会自动注册名为 `ClashTunGuard` 的 Windows 计划任务（登录时以最高权限 `HighestAvailable` 启动、支持电池供电、无 72 小时超时限制）。
- 如需桌面入口，可右键 `TunGuard.exe` 发送桌面快捷方式（建议命名为 `Clash TUN 守护`）。

## 项目结构

| 文件 | 说明 |
| --- | --- |
| `TunGuard.cs` | 完整源代码（TUN 状态监听、Win32 毫秒级进程终止、计划任务自启管理、系统托盘 UI） |
| `app.manifest` | Windows 应用程序清单（`highestAvailable` 权限与 Per-Monitor V2 DPI 感知） |
| `build.ps1` | 生成盾牌图标并调用 `csc.exe` 编译 `TunGuard.exe` 的构建脚本 |
