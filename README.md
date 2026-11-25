# TunGuard

轻量级 Windows (x64) 系统托盘守护工具，实时监控 **Clash Verge (Rev)** 的 **TUN 模式状态** 与可选的 **当前生效代理节点**。一旦检测到 TUN 断开、默认路由消失，或（开启节点守护后）Clash 当前未使用允许列表中的节点，立即以毫秒级速度终止所有 **Antigravity** 进程并阻止重启，防止断流直连或走错节点引发风控。

- **零外部依赖**：纯 C# + Win32 P/Invoke，仅使用 Windows 内置 `.NET Framework 4.x`（`csc.exe`）编译为单个 ~95 KB 的原生 x64 可执行文件。
- **免配置直连 Clash 内核**：自动探测并复用 Clash Verge 的 Windows Named Pipe（`\\.\pipe\verge-mihomo-*`），**无需开启外部 HTTP 控制器**即可读取实时节点状态。
- **极低后台开销**：事件驱动 + HTTP/1.1 Keep-Alive 单组定向查询 + 零反射轻量解析，单次节点巡检 `< 0.5 ms`。

---

## 拦截触发条件

当 **实时监控** 开启时，以下任意条件不满足都会立即触发拦截（终止所有 `Antigravity.exe` 及路径包含 `\antigravity\` 的 `language_server*.exe`，并在 `5 ms` 后补扫一次防止子进程竞态拉起）：

| 检查维度 | 放行条件 | 触发拦截的场景 |
| --- | --- | --- |
| **TUN 模式**（始终启用） | `verge.yaml` 允许 TUN + 虚拟网卡在线 + IPv4 默认路由有效 | 关闭 TUN 开关、退出 Clash Verge、`verge-mihomo` 崩溃、虚拟网卡或默认路由断开 |
| **Clash 节点**（可选启用） | Clash 实际出口节点命中允许列表中的任意一项 | 切换到未授权节点、切到其他订阅、`Direct` 直连模式、`Global` 模式指向非允许节点、代理组不存在或控制接口不可达（Fail-Closed） |

---

## 核心特性

### 1. 四重联动毫秒级 TUN 检测
- **配置文件实时监听（`FileSystemWatcher`）**：监听 `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\` 下的 `verge.yaml`、`clash-verge.yaml`、`config.yaml` 与 `profiles.yaml`。在 Clash Verge 点击关闭 TUN 或切换节点时，`< 1 ms` 即可唤醒复核并短路判定。
- **内核路由变更回调（`NotifyRouteChange2`）**：实时捕获 TUN 虚拟网卡 IPv4 默认路由（`0.0.0.0/0`、`0.0.0.0/1`、`128.0.0.0/1`）移除事件。
- **内核网卡状态回调（`NotifyIpInterfaceChange`）**：捕获 Clash Verge 退出或内核异常崩溃导致的虚拟网卡下线。
- **高优先级后台守护线程**：安全状态下每 `250 ms` 低功耗兜底复核；拦截状态下切换为 `30 ms` 高频进程守卫（采用零分配 PID 快照比对），阻止未满足条件时启动 Antigravity。

### 2. 可配置的 Clash 节点守护 & 全订阅穿梭框
- **全订阅自动扫描**：设置页面自动解析 Clash Verge 的 `profiles.yaml` 与 `profiles\*.yaml`（兼容流式与多行块式 YAML）并合并 Mihomo 实时节点，带 `(mtime, size)` 文件缓存，二次打开 `< 1 ms`。
- **左右穿梭框管理**：双击托盘图标或右键 **「配置允许节点...」** 即可打开图形化设置页：
  - 左侧按订阅下拉筛选 + `80 ms` 防抖实时搜索，支持 `Ctrl` / `Shift` 多选与双击穿梭。
  - 中间提供 `>`（移入选中）、`>>`（当前可见全部移入）、`<`（移出选中）、`<<`（清空右侧）快捷操作。
  - 右侧支持 **一键移入当前正在使用的节点**，并支持手动添加关键词或其他订阅节点。
  - 保存前提供实时命中预览；若保存后会立即触发拦截，弹出二次确认防止误关正在使用的 Antigravity。
- **HTTP/1.1 Keep-Alive 单组定向巡检**：通过 `WaitNamedPipeW` 定向探测命名管道（支持回退到 TCP `external-controller`），巡检热路径复用持久连接，仅请求目标代理组 `GET /proxies/{group}` 并使用零反射轻量 JSON 提取器，即使数百节点的大订阅也保持 `O(1)` 恒定低开销。

### 3. 系统托盘、单实例保护与原生开机自启
- **动态盾牌状态图标**：

| 图标颜色 | 当前状态 | 说明 |
| --- | --- | --- |
| 绿色 | 守护正常 | TUN 已开启（若启用节点守护则当前节点已命中允许列表），允许运行 Antigravity |
| 红色 | 已拦截 | TUN 未开启或当前节点不匹配，已终止 Antigravity 并阻止启动 |
| 灰色 | 已暂停 | 已临时暂停监控与拦截，后台跳过节点轮询 |

- **单实例保护**：内置单实例互斥锁，重复启动时不会多开进程，仅通过气泡提示当前守护状态。
- **原生开机自启**：右键勾选 **开机自动启动**，通过 Windows 原生 **Task Scheduler 2.0 COM API (`Schedule.Service`)** 注册计划任务 `ClashTunGuard`（支持电池供电、无 72 小时超时限制、不拉起隐藏 `schtasks.exe`）。

---

## 节点判定规则说明

启用节点守护后，程序会递归展开嵌套代理组（如 `PROXY -> 自动选择 -> 节点A`，自动防循环引用），并始终以**最终实际出口节点**与允许列表比对（支持 **精确匹配（忽略大小写）** 或 **关键词包含匹配**）：

| Clash 模式 | 监控代理组设置 | 实际校验链路 |
| --- | --- | --- |
| `Rule` | `(自动跟踪默认出口组)`（默认） | 跟踪 `MATCH` 默认规则指向的出口组并递归至最终节点 |
| `Rule` | 手动指定代理组（如 `PROXY` / `AI`） | 校验所选代理组并递归至最终节点（切订阅导致该组不存在时触发拦截） |
| `Global` | 任意 | 强制跟踪 `GLOBAL` 并递归至最终节点（防止切换 Global 模式绕过规则组） |
| `Direct` | 任意 | 直接判定为未命中并触发拦截 |

---

## 快速开始

### 环境要求
- Windows 10 / 11 (x64)
- Windows 内置 `.NET Framework 4.x`（`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`）
- Clash Verge Rev

### 1. 获取程序（下载 Release 或本地编译）
推荐直接从本仓库的 **GitHub Releases** 页面下载最新编译好的 `TunGuard.exe`（或 `TunGuard-vX.Y.Z-win-x64.zip`）；每次推送代码到 `main` 分支都会通过 GitHub Actions 自动构建并发布新版本。

如需本地编译，在项目根目录执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

脚本会自动生成图标 `TunGuard.ico` 并编译出独立的 `TunGuard.exe`。

### 2. 运行与开机自启
1. 双击运行 `TunGuard.exe`，程序将在后台以 `High` 优先级静默启动并在系统托盘显示盾牌图标。
2. 如需开机自启，右键托盘图标勾选 **开机自动启动**（按需创建 `ClashTunGuard` 计划任务）。
3. 如需桌面入口，可右键 `TunGuard.exe` → **发送到 → 桌面快捷方式**。

### 3. 配置允许节点
1. **双击托盘图标**（或右键托盘图标 → **配置允许节点...**）打开穿梭框设置页面。
2. 勾选 **启用 Clash 节点守护**。
3. 在左侧列表中按订阅或关键词筛选，将允许使用的节点移入右侧列表（或直接点击 **一键移入当前节点**）。
4. 代理组保持默认 `(自动跟踪默认出口组)` 或按需指定代理组，选择 **精确匹配** / **关键词包含** 后点击 **保存并生效**。

> 配置会自动保存在程序同目录的 `TunGuard.config.json`（已加入 `.gitignore`，不会随源码提交），外部修改该文件也会在 1 秒内自动热重载。

---

## 常见问题（FAQ）

<details>
<summary><b>Windows Defender 误报并隔离 <code>TunGuard.exe</code>（如 <code>Behavior:Win32/Persistence.A!ml</code>）怎么办？</b></summary>

因为 `TunGuard.exe` 是你在本机现编的**未签名可执行文件**，且程序包含进程终止（`TerminateProcess`）与开机计划任务功能，在重新编译覆盖已有计划任务指向的文件时，容易触发 Windows Defender 机器学习启发式误报。

推荐在编译/运行前将项目目录加入本地排除项：
1. 打开 **Windows 安全中心** → **病毒和威胁防护** → **管理设置** → **排除项** → **添加排除项** → **文件夹**。
2. 添加本机项目目录（例如 `D:\...\TunGuard`），然后重新运行 `.\build.ps1`。

</details>

<details>
<summary><b>需要打开 Clash Verge 的“外部控制器（External Controller）”吗？</b></summary>

不需要。TunGuard 会优先直连 Clash Verge Rev 默认启用的 Windows Named Pipe（`\\.\pipe\verge-mihomo-*`），在 `enable_external_controller: false` 时也可正常工作；如果使用的是自定义 TCP 外部控制器，也会自动回退连接。

</details>

<details>
<summary><b>如何只监控 TUN 模式、不限制节点？</b></summary>

打开 **配置允许节点...** 页面，取消勾选 **启用 Clash 节点守护** 并保存即可（默认即为关闭状态，关闭后后台零 Mihomo API 请求）。

</details>

---

## 项目结构

| 文件 | 说明 |
| --- | --- |
| `TunGuard.cs` | 完整源代码（TUN 检测、Mihomo Keep-Alive IPC 客户端、全订阅解析器、Win32 毫秒级进程守护、Task Scheduler COM 自启管理、系统托盘与穿梭框设置 UI） |
| `app.manifest` | Windows 应用程序清单（`highestAvailable` 权限与 Per-Monitor V2 DPI 感知） |
| `build.ps1` | 生成盾牌图标并调用 `csc.exe` 编译 `TunGuard.exe` 的构建脚本 |
| `.gitignore` | 忽略编译产物（`*.exe`、`*.ico`）及本地节点配置文件（`TunGuard.config.json`） |
| `TunGuard.config.json` | 节点守护本地配置文件（运行时自动生成，不纳入版本控制） |
