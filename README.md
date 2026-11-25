# TunGuard

轻量级 Windows (x64) 系统托盘守护工具，实时监控 **Clash Verge (Rev)** 的 **TUN 模式状态** 与可选的 **当前生效代理节点**，并结合 **Windows Filtering Platform (WFP) 内核级 Kill Switch** 与毫秒级进程守护，保护已勾选的桌面端受控应用（**Antigravity**、**ChatGPT 桌面端**、**Claude 桌面端 / Claude Code**），从内核层到应用层防止断流裸连或走错节点引发风控。

- **零外部依赖**：纯 C# + Win32 P/Invoke（`iphlpapi.dll` / `fwpuclnt.dll` / `userenv.dll`），仅使用 Windows 内置 `.NET Framework 4.x`（`csc.exe`）编译为单个 ~146 KB 的原生 x64 可执行文件。
- **内核级零漏包兜底（WFP）**：在 Windows 内核 `ALE_AUTH_CONNECT`（IPv4 + IPv6）层常驻受控应用出站规则——仅放行 TUN 虚拟网卡与 Loopback，TUN 掉线瞬间**零时间窗**丢弃所有物理网卡直连流量；支持**仅内核断网（保留进程不丢编辑内容）**或**内核断网 + 终止进程双重兜底**。
- **免配置直连 Clash 内核**：自动探测并复用 Clash Verge 的 Windows Named Pipe（`\\.\pipe\verge-mihomo-*`），**无需开启外部 HTTP 控制器**即可读取实时节点状态。
- **极低后台开销**：事件驱动 + HTTP/1.1 Keep-Alive 单组定向查询 + 零反射轻量解析，单次节点巡检 `< 0.5 ms`。

---

## 拦截触发条件与受控应用

当 **实时监控** 开启时，以下任意条件不满足都会立即触发拦截（**WFP 内核层阻断出站**；若开启「拦截时同时终止进程」或 WFP 处于非管理员降级状态，则同步毫秒级终止已勾选的受控应用进程并在 `5 ms` 后补扫一次防止子进程竞态拉起）：

| 受控应用（可在控制面板独立勾选） | 匹配规则（同时用于进程守护与 WFP 内核规则） |
| --- | --- |
| **Antigravity** | `Antigravity.exe` 及路径包含 `\antigravity\` 的 `language_server*.exe` |
| **ChatGPT 桌面端** | `ChatGPT.exe`、OpenAI Windows 桌面端组件及 MSIX/Store 包（`ALE_APP_ID` + `ALE_PACKAGE_ID` 双重保护，不影响独立命令行 CLI） |
| **Claude 桌面端 (Claude Code)** | Claude Desktop `Claude.exe`（WindowsApps / AnthropicClaude / Claude 安装目录）及 MSIX/Store 包（`ALE_APP_ID` + `ALE_PACKAGE_ID` 双重保护，不影响 VS Code 插件或命令行 CLI） |

| 检查维度 | 放行条件 | 触发拦截的场景 |
| --- | --- | --- |
| **TUN 模式**（始终启用） | `verge.yaml` 允许 TUN + 虚拟网卡在线 + IPv4 默认路由有效 | 关闭 TUN 开关、退出 Clash Verge、`verge-mihomo` 崩溃、虚拟网卡或默认路由断开 |
| **Clash 节点**（可选启用） | Clash 实际出口节点命中允许列表中的任意一项 | 切换到未授权节点、切到其他订阅、`Direct` 直连模式、`Global` 模式指向非允许节点、代理组不存在或控制接口不可达（Fail-Closed） |

---

## 核心特性

### 1. WFP 内核级 Kill Switch（预防式零漏包断网）
- **独立 Sublayer + 五级优先级规则（IPv4 & IPv6 双栈覆盖）**：在 TunGuard 专属 WFP Provider / Sublayer 内通过事务原子维护以下规则（数值越大优先级越高）：
  1. 权重 `14`（仅拦截态生效）：阻断受控应用经 Loopback 访问 Clash 本地代理端口（`mixed-port` / `port` / `socks-port`），防止系统代理旁路绕过 TUN；
  2. 权重 `12`（常驻）：放行 `IS_LOOPBACK`（`127.0.0.1` / `::1`），保障 Antigravity `language_server` 与 Electron 本地 IPC 正常通信；
  3. 权重 `11`（仅开启全局 DNS 53 保护时）：放行 `verge-mihomo*.exe` 出站 53 端口，确保 Clash 上游节点域名解析不受阻断；
  4. 权重 `10`（仅安全态且 TUN 在线）：按 `MIB_IF_ROW2` 直取的 TUN `InterfaceLuid` 放行出站（TUN 掉线瞬间自动失配；切错节点时单事务撤除触发 ALE Reauthorization 秒断网；网卡重建换 LUID 时单事务先加后删零断流）；
  5. 权重 `1`（常驻兜底）：阻断受控应用所有非 Loopback、非 TUN 的 IPv4/IPv6 出站连接。
- **双模式可选 + 自动安全降级**：
  - 勾选 **拦截时同时终止进程**（默认）：WFP 内核零窗口阻断 + `TerminateProcess` 双重兜底；
  - 取消勾选：进入**纯内核无损断网模式**，掉线或切错节点时受控应用仅断网挂起、**不丢失正在编辑的内容**，合规后自动恢复联网；
  - 若以非管理员标准权限运行导致 WFP 降级，程序自动回退为强杀模式，杜绝保护真空。
- **三层路径解析 + MSIX 版本升级免疫**：启动扫描注册表（`AppModel` / `AppxAllUserStore` / `Uninstall`）与常见安装目录 + 零分配运行时进程热发现 + 本地路径缓存；同时为 WindowsApps / MSIX 应用附加 `ALE_PACKAGE_ID`（AppContainer SID）规则，自动免疫商店静默升级换目录。
- **可选全局防 DNS 泄漏（53 端口）**：勾选后阻断系统 `dnscache` (`svchost.exe`) 等所有进程经非 TUN 网卡发出的 UDP/TCP 53 端口查询（自动放行 Loopback、TUN 与 Mihomo 内核；建议仅在 Clash TUN 开启 DNS 劫持时启用）。
- **防砖机安全生命周期**：采用 `FWPM_SESSION_FLAG_DYNAMIC` 动态会话，无论正常退出、异常崩溃还是暂停监控，Windows 内核（BFE）均自动清空全部规则，绝不锁死用户网络。

### 2. 四重联动毫秒级 TUN 检测
- **配置文件实时监听（`FileSystemWatcher`）**：监听 `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\` 下的 `verge.yaml`、`clash-verge.yaml`、`config.yaml` 与 `profiles.yaml`。在 Clash Verge 点击关闭 TUN 或切换节点时，`< 1 ms` 即可唤醒复核并短路判定。
- **内核路由变更回调（`NotifyRouteChange2`）**：实时捕获 TUN 虚拟网卡 IPv4 默认路由（`0.0.0.0/0`、`0.0.0.0/1`、`128.0.0.0/1`）移除事件。
- **内核网卡状态回调（`NotifyIpInterfaceChange`）**：捕获 Clash Verge 退出或内核异常崩溃导致的虚拟网卡下线，并直接从 `MIB_IF_ROW2` 偏移 `0` 读取 `InterfaceLuid` 同步给 WFP。
- **高优先级后台守护线程**：安全状态下每 `250 ms` 低功耗兜底复核；强杀拦截状态下切换为 `30 ms` 高频进程守卫（零分配 PID 快照比对），并每 `2 s` 被动热发现新启动的受控应用路径纳入 WFP 保护。

### 3. 受控应用独立开关、可配置的 Clash 节点守护 & 全订阅穿梭框
- **受控应用与 WFP 策略一站式配置**：双击托盘图标（或右键 **「打开控制面板...」**）可在控制面板顶部独立勾选受控应用、开关 WFP 内核断网保护、切换「拦截时同时终止进程」与「全局防 DNS 泄漏 (53 端口)」，并实时查看 WFP 内核状态与 TUN LUID；也可通过托盘右键菜单 **「受控应用」** 子菜单快速切换并立即生效。
- **全订阅自动扫描**：控制面板自动解析 Clash Verge 的 `profiles.yaml` 与 `profiles\*.yaml`（兼容流式与多行块式 YAML）并合并 Mihomo 实时节点，带 `(mtime, size)` 文件缓存，二次打开 `< 1 ms`。
- **左右穿梭框管理**：
  - 左侧按订阅下拉筛选 + `80 ms` 防抖实时搜索，支持 `Ctrl` / `Shift` 多选与双击穿梭。
  - 中间提供 `>`（移入选中）、`>>`（当前可见全部移入）、`<`（移出选中）、`<<`（清空右侧）快捷操作。
  - 右侧支持 **一键移入当前正在使用的节点**，并支持手动添加关键词或其他订阅节点。
  - 保存前提供实时命中预览；若保存后会立即触发拦截，弹出二次确认防止误断/误关正在使用的受控应用。
- **HTTP/1.1 Keep-Alive 单组定向巡检**：通过 `WaitNamedPipeW` 定向探测命名管道（支持回退到 TCP `external-controller`），巡检热路径复用持久连接，仅请求目标代理组 `GET /proxies/{group}` 并使用零反射轻量 JSON 提取器，即使数百节点的大订阅也保持 `O(1)` 恒定低开销。

### 4. 系统托盘、单实例保护与原生开机自启
- **动态盾牌状态图标与内核状态展示**：

| 图标颜色 | 当前状态 | 说明 |
| --- | --- | --- |
| 绿色 | 守护正常 | TUN 已开启（若启用节点守护则当前节点已命中允许列表），允许运行受控应用；启用 WFP 时悬浮提示带 `[WFP]` 标识 |
| 红色 | 已拦截 | TUN 未开启或当前节点不匹配，已通过 WFP 内核阻断出站（及按配置终止受控应用进程） |
| 灰色 | 已暂停 | 已临时暂停监控与拦截，自动清空 WFP 内核规则并跳过节点轮询 |

- **单实例保护**：内置单实例互斥锁，重复启动时不会多开进程，仅通过气泡提示当前守护与 WFP 内核状态。
- **原生开机自启**：右键勾选 **开机自动启动**，通过 Windows 原生 **Task Scheduler 2.0 COM API (`Schedule.Service`)** 注册计划任务 `ClashTunGuard`（支持电池供电、无 72 小时超时限制、`<RunLevel>HighestAvailable</RunLevel>` 自动提权激活 WFP、不拉起隐藏 `schtasks.exe`）。

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
- 管理员权限（用于启用 WFP 内核断网保护与注册开机计划任务；标准权限下会自动降级为应用层进程守护）

### 1. 获取程序（下载 Release 或本地编译）
推荐直接从本仓库的 **GitHub Releases** 页面下载最新编译好的 `TunGuard.exe`（或 `TunGuard-vX.Y.Z-win-x64.zip`）；每次推送代码到 `main` 分支都会通过 GitHub Actions 自动构建并发布新版本。

如需本地编译，在项目根目录执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

脚本会自动生成图标 `TunGuard.ico` 并编译出独立的 `TunGuard.exe`。

### 2. 运行与开机自启
1. **以管理员权限运行** `TunGuard.exe`（程序清单已声明 `highestAvailable`），将在后台以 `High` 优先级静默启动、自动激活 WFP 内核断网并在系统托盘显示盾牌图标。
2. 如需开机自启，右键托盘图标勾选 **开机自动启动**（按需创建 `ClashTunGuard` 高权限计划任务）。
3. 如需桌面入口，可右键 `TunGuard.exe` → **发送到 → 桌面快捷方式**。

### 3. 配置受控应用、WFP 内核保护与允许节点
1. **双击托盘图标**（或右键托盘图标 → **打开控制面板...**）打开控制面板。
2. 在顶部 **受控应用** 栏勾选需要守护的应用（**Antigravity** / **ChatGPT 桌面端** / **Claude 桌面端 (Claude Code)**），也可以在托盘右键菜单 **受控应用** 子菜单中随时快速开关。
3. 在 **内核断网** 栏确认 **启用 WFP 内核断网保护 (零漏包)** 已勾选，并按需调整：
   - 保持勾选 **拦截时同时终止进程** 获得“内核断网 + 强杀”双重兜底，或取消勾选获得“仅断网保留进程”无损体验；
   - 如 Clash TUN 已开启 DNS 劫持且需要彻底阻断系统 `dnscache` DNS 泄漏，可勾选 **全局防 DNS 泄漏 (53 端口)**。
4. 如需限制出口节点，勾选 **启用 Clash 节点守护**，在左侧列表中按订阅或关键词筛选，将允许使用的节点移入右侧列表（或直接点击 **一键移入当前节点**）。
5. 代理组保持默认 `(自动跟踪默认出口组)` 或按需指定代理组，选择 **精确匹配** / **关键词包含** 后点击 **保存并生效**。

> 配置会自动保存在程序同目录的 `TunGuard.config.json`（已加入 `.gitignore`，不会随源码提交），包含受控应用、WFP 选项、允许节点及自动发现的可执行文件路径缓存，外部修改也会在 1 秒内自动热重载。

---

## 常见问题（FAQ）

<details>
<summary><b>如何验证 WFP 内核规则确实生效，以及退出后不会残留？</b></summary>

在管理员 PowerShell 中运行以下命令导出当前系统 WFP 过滤器并检索 TunGuard 规则：

```powershell
netsh wfp show filters file=wfp_filters.xml
Select-String -Path .\wfp_filters.xml -Pattern "TunGuard WFP Kill Switch"
```

- TunGuard 正常运行且处于监控状态时，应能看到对应的 Provider、Sublayer 与 Filter 记录；
- 暂停监控或退出 `TunGuard.exe` 后再次运行上述命令，结果应为空（DYNAMIC 会话由 Windows BFE 自动清空，零残留）。

</details>

<details>
<summary><b>为什么托盘菜单提示 <code>内核断网: 已降级 (需管理员权限)</code>？</b></summary>

向 Windows Base Filtering Engine (BFE) 写入 WFP 过滤规则强制需要管理员权限。如果当前账户不是管理员、或拒绝了 UAC 提权，TunGuard 会优雅降级为应用层进程终止模式继续保护（即使取消勾选了「拦截时同时终止进程」也会自动回退强杀，确保安全）。右键 `TunGuard.exe` 选择 **以管理员身份运行** 即可激活 WFP。

</details>

<details>
<summary><b>Windows Defender 误报并隔离 <code>TunGuard.exe</code>（如 <code>Behavior:Win32/Persistence.A!ml</code>）怎么办？</b></summary>

因为 `TunGuard.exe` 是**未签名的单文件可执行程序**，且包含 WFP 底层网络过滤（`fwpuclnt.dll`）、进程终止（`TerminateProcess`）与开机计划任务功能，在重新编译覆盖时容易触发 Windows Defender 机器学习启发式误报。

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

打开 **控制面板** 页面，取消勾选 **启用 Clash 节点守护** 并保存即可（默认即为关闭状态，关闭后后台零 Mihomo API 请求，TUN 检测与 WFP 内核断网保护仍正常生效）。

</details>

---

## 项目结构

| 文件 | 说明 |
| --- | --- |
| `TunGuard.cs` | 完整源代码（WFP 内核 Kill Switch、三层受控应用路径与 MSIX 包解析器、TUN 检测、Mihomo Keep-Alive IPC 客户端、全订阅解析器、Win32 毫秒级进程守护、Task Scheduler COM 自启管理、系统托盘与控制面板 UI） |
| `app.manifest` | Windows 应用程序清单（`highestAvailable` 权限与 Per-Monitor V2 DPI 感知） |
| `build.ps1` | 生成盾牌图标并调用 `csc.exe` 编译 `TunGuard.exe` 的构建脚本 |
| `update.md` | WFP 内核级 Kill Switch 方案架构设计与 Windows x64 ABI 参考文档 |
| `.gitignore` | 忽略编译产物（`*.exe`、`*.ico`）及本地节点配置文件（`TunGuard.config.json`） |
| `TunGuard.config.json` | 本地守护配置与已发现路径缓存文件（运行时自动生成，不纳入版本控制） |
