# WFP 内核级 Kill Switch 方案（修订版）

> 目标：在 TunGuard 现有的"状态检测 → 杀进程"（反应式）基础上，引入 **Windows Filtering Platform (WFP)** 内核级出站过滤层（预防式），实现：
> 1. **TUN 突然掉线瞬间零真实 IP 泄漏窗口**（内核直接丢弃受控应用经物理网卡的新出站连接）；
> 2. **节点违规 / 切错模式时支持非破坏性断网**（动态撤除放行规则，受控应用挂起不丢编辑内容，强杀进程变为可选兜底）。
>
> 本文已对照 Windows SDK (`fwpmu.h` / `fwpmtypes.h` / `fwptypes.h`) 与现有 [TunGuard.cs](TunGuard.cs) 逐项核校：涵盖架构取舍、工程盲区对策、x64 精确对齐的 C# P/Invoke 与结构体定义，以及分阶段验证路径。

---

## 1. 现有机制的边界与升级定位

现有 `TunMonitor`（[TunGuard.cs:4698](TunGuard.cs#L4698)）已通过四重机制把反应式检测压缩到极限：

```text
触发源（FileSystemWatcher / NotifyRouteChange2 / NotifyIpInterfaceChange < 1ms；安全态兜底轮询 250ms；拦截态进程防重启扫描 30ms；节点巡检 250ms）
  → EvaluateAndEnforce → 枚举进程 → OpenProcess → TerminateProcess
```

即便触发延迟 `< 1ms`，纯应用层杀进程仍有两类无法根除的限制：

1. **TUN 掉线瞬间存在非零泄漏窗口**：从路由/网卡变化到 `TerminateProcess` 生效之间，应用可能已向物理网卡发出 TCP SYN 或 UDP 包；已离开网卡的包无法撤回。
2. **强杀具备破坏性**：`TerminateProcess` 会导致受控应用正在编辑的内容丢失，且对"短暂切换节点或重启 Clash"场景过于粗暴。

### 升级后的分工定位（互补而非简单替代）

| 风险场景 | WFP 内核层能做到什么 | 现有监控层继续负责什么 |
| --- | --- | --- |
| **TUN 网卡断开 / 默认路由消失** | **预防式、零时间窗**：TUN LUID 失效后放行规则自动失配，内核直接 `BLOCK` 经物理网卡的新出站连接 | 检测状态变化、更新托盘提示；按用户策略决定是否二次强杀（兜底未绑源 IP 的 UDP/QUIC） |
| **Clash 切错节点 / Direct / Global 违规** | **非破坏性快速断网**：收到信号后在事务内撤除 TUN `PERMIT`，触发 ALE Reauthorization 切断流量 | 仍依赖 `MihomoClient` + 文件监听（**此场景仍为反应式，无法做到零窗口**） |

> **关键认知**：常驻 WFP 接口规则**只能**对"TUN 掉线"做到零时间窗；当 TUN 依然在线但 Clash 切到不允许节点或 `Direct` 模式时，出口仍是 TUN 网卡，必须靠现有节点守护主动下发撤权动作。

---

## 2. WFP 规则模型（三段式 + 独立 Sublayer）

### 2.1 为什么必须建独立 Sublayer 且 `PERMIT` 高于 `BLOCK`

WFP 的仲裁顺序为：`Layer → Sublayer（按子层 weight 降序）→ Filter（同子层内按 filter weight 降序，首个 Terminating 动作终止本子层评估）`。

- **必须注册专属 `FWPM_PROVIDER0` 与 `FWPM_SUBLAYER0`**：不能直接塞进默认 `FWPM_SUBLAYER_UNIVERSAL`，否则会与 Windows Defender Firewall 规则权重互相干扰；在独立子层内的 `PERMIT` 只表示"本子层放行"，不会破坏系统防火墙原有拦截规则。
- **同一子层内必须 `PERMIT` 权重严格大于 `BLOCK`**：否则兜底 `BLOCK` 会先命中终止，导致 TUN 在线时也被拦死。

### 2.2 按应用方案（推荐主线）：三段式规则表

在 `FWPM_LAYER_ALE_AUTH_CONNECT_V4` 和 `FWPM_LAYER_ALE_AUTH_CONNECT_V6` 两层同时安装，全部归属于 TunGuard 专属子层：

| 优先级 | `weight` (`FWP_UINT8`) | 匹配条件（同 filter 内为 AND） | 动作 | 生命周期与作用 |
| --- | --- | --- | --- | --- |
| 1（最高） | `12` | `ALE_APP_ID == 受控应用` **AND** `FWPM_CONDITION_FLAGS` (`FWP_MATCH_FLAGS_ALL_SET`) `FWP_CONDITION_FLAG_IS_LOOPBACK` | `FWP_ACTION_PERMIT` | **常驻**：放行 `127.0.0.1` / `::1` 本地通信，避免 Antigravity `language_server` 与 Electron IPC 瘫痪 |
| 2（中） | `10` | `ALE_APP_ID == 受控应用` **AND** `IP_LOCAL_INTERFACE == tunLuid` | `FWP_ACTION_PERMIT` | **动态**：仅在 `IsGuardSafe == true`（TUN 有效且节点合规）时安装；TUN 掉线自动失配，节点违规时主动移除 |
| 3（兜底） | `1` | `ALE_APP_ID == 受控应用` | `FWP_ACTION_BLOCK` | **常驻**：阻断受控应用所有非 Loopback、非 TUN 的出站连接（含物理网卡 IPv4/IPv6） |

运行效果：
- **TUN 在线且节点合规**：本地通信命中规则 1 放行；外网通信走 TUN 命中规则 2 放行；任何试图走物理网卡或 IPv6 裸连的流量落入规则 3 被内核丢弃。
- **TUN 突然掉线**：TUN 网卡及 LUID 消失 → 规则 2 立刻无法匹配 → 所有非 Loopback 新出站流量**零时间窗**落入规则 3 被 `BLOCK`。
- **Clash 切错节点 / Direct**：`TunMonitor` 判定 `IsGuardSafe == false` → 在单个 WFP 事务内删除规则 2 → 受控应用连 TUN 出口也被规则 3 封死（触发 ALE Reauthorization），节点恢复后事务重装规则 2。

### 2.3 备选方案：全局整机 Kill Switch（如何正确豁免 Clash）

如果未来提供"锁整机"模式（不区分 `ALE_APP_ID`，整机只许走 TUN），**切勿**尝试解析节点 `server:port` 做上游豁免（原因：现有 `MihomoClient` 未解析 `server`/`port`，且节点 `server` 往往是动态域名/CDN 多 IP，还会破坏 `URLTest` 测速与链式代理）。

正确的上游豁免方式（同 OpenVPN / WireGuard / Mullvad 标准实践）：
- 直接用 `FwpmGetAppIdFromFileName0` 获取 `verge-mihomo.exe`（或当前运行中的 Mihomo 内核 exe 路径）的 `ALE_APP_ID`，在专属子层内给予高权重 `PERMIT`；
- 外加 Loopback `PERMIT`、TUN LUID `PERMIT`（及按需 DHCP/LAN 放行），最后低权重全局 `BLOCK`。

---

## 3. 五个必须处理的工程盲区

### 3.1 Loopback 放行与本地代理端口（`127.0.0.1:7897`）的权衡

- **为什么必须放行 Loopback**：Antigravity 的 `Antigravity.exe` ↔ `language_server*.exe`、Claude / ChatGPT 桌面端的 Electron 内部进程通信与本地 MCP Server 均依赖 `127.0.0.1`。不放行 Loopback 会导致受控应用即使在 TUN 正常时也彻底不可用。
- **已知权衡**：放行 Loopback 后，若用户同时开启了 Clash 的系统代理（`http://127.0.0.1:7897`）且受控应用显式读取了该代理，则关闭 TUN 但保留 Clash 运行时，应用流量可能通过 Loopback 进入 Clash 代理端口而非被 WFP 阻断。
- **缓解措施**：
  - 在安全判定失败（`!IsGuardSafe`）时，若开启了"严格断网"，可额外检查并阻断发往 Clash `mixed-port` 的 Loopback 连接（`IP_REMOTE_PORT == mixedPort`），或在强杀模式下仍由 `TargetProcessKiller` 终止进程。

### 3.2 系统 DNS 泄漏（`dnscache` / `svchost.exe` 盲区）

Windows 应用调用标准域名解析（`getaddrinfo`）时，真实向外发 UDP/TCP 53 包的往往是系统 **DNS Client 服务（`dnscache`，运行在 `svchost.exe` 内）**，在 `ALE_AUTH_CONNECT` 层看到的 `ALE_APP_ID` 是 `svchost.exe` 而非受控应用本身。

因此必须明确二选一产品策略：
1. **默认模式（纯按应用隔离）**：不干预系统 `svchost.exe`，可零窗口阻断受控应用自身发起的所有 TCP/UDP/HTTPS/QUIC 直连，但**无法阻止系统 DNS Client 经物理网卡泄露域名查询**（需在 UI/文档中如实说明）。
2. **可选增强（全局防 DNS 泄漏，参考 OpenVPN `block-outside-dns`）**：在独立子层中额外加一组针对 `IP_REMOTE_PORT == 53`（UDP/TCP）的规则：
   - 高权 `PERMIT`：Loopback、TUN LUID、`verge-mihomo.exe`（确保 Clash 自身解析上游节点域名不被拦）；
   - 低权 `BLOCK`：`IP_REMOTE_PORT == 53`（V4 + V6）。
   - *前提*：要求 Clash TUN 正常开启 DNS hijack（Mihomo 默认开启），否则全机 DNS 会受影响。

### 3.3 动态应用路径、子进程与 MSIX（`WindowsApps`）版本更新

现有 [TargetProcessKiller](TunGuard.cs#L4555-L4695) 通过进程名与模糊路径匹配目标，但 WFP `ALE_APP_ID` **不支持通配符**，也不自动继承给子进程，且 `FwpmGetAppIdFromFileName0` 要求文件在磁盘上真实存在。特别需要注意 **ChatGPT / Claude Desktop 的 WindowsApps (MSIX) 版本在自动更新后，安装目录中的版本号会改变**，导致旧路径的 `ALE_APP_ID` 规则静默失效。

工程落地必须采用**三层路径解析**：
1. **启动预扫描**：根据用户勾选的 `GuardedAppFlags`，扫描已知安装目录（如 `%LOCALAPPDATA%\Programs\...`、`%ProgramFiles%\WindowsApps\OpenAI.*`、`WindowsApps\Claude*`、Antigravity 安装目录下的 `Antigravity.exe` 与 `language_server*.exe`）及本地缓存路径，预先装好 WFP 规则。
2. **运行时动态发现与热追加**：在监控循环发现匹配 [MatchTargetImagePath](TunGuard.cs#L4609) 的新 exe 路径（例如应用刚自动升级了 MSIX 版本号，或首次启动了某个 `language_server_*.exe`）时，立即调用 `FwpmGetAppIdFromFileName0` 热追加该路径的 WFP 规则，并写入本地路径缓存。
3. **MSIX 进阶增强（二期可选）**：对 MSIX/Store 打包应用，提取其 AppContainer Package SID，额外按 `FWPM_CONDITION_ALE_PACKAGE_ID`（`FWP_SID`）建规则，从根本上免疫 MSIX 版本号路径变更。

### 3.4 已建立连接（TCP vs UDP/QUIC）与强杀策略配合

- **已建立 TCP 连接**：Windows 默认采用 Strong Host Model，原连接绑定 TUN 虚拟 IP（如 `198.18.0.1`），TUN 网卡断开后不会自动切到物理网卡继续发包；应用随后发起的重连会经过 `ALE_AUTH_CONNECT` 被 WFP 拦死。
- **未绑定源 IP 的 UDP / QUIC（HTTP/3）**：现代桌面端广泛使用 QUIC；未显式 `bind` 特定源 IP 的 UDP socket 在路由瞬变时若未触发 ALE Reauthorization，可能存在极短缝隙。
- **节点违规时的既有流**：通过 WFP 事务删除规则 2（`TUN PERMIT`）属于层策略变更，会触发 WFP 的 **ALE Reauthorization**，使既有受控流在下次收发时重新评估并命中 `BLOCK`。
- **推荐策略配置**：
  - `仅内核断网`（默认可选）：WFP 阻断所有出站，不杀进程，保护编辑现场；
  - `内核断网 + 终止进程`（最高安全级别）：WFP 做零窗口兜底，触发拦截后依然执行 `TargetProcessKiller.KillAllNow()`，彻底封堵 UDP/QUIC 残留及派生子进程。

### 3.5 生命周期、防砖机、权限降级与 AV 误报

- **严禁在 `DYNAMIC` 会话中写入 `PERSISTENT` 规则**：WFP 明确禁止两者混用，否则返回 `FWP_E_DYNAMIC_SESSION_IN_PROGRESS`（`0x8032002E`）。
- **推荐默认形态：`FWPM_SESSION_FLAG_DYNAMIC`（非持久化）**：
  - 托盘程序打开动态会话，Provider、Sublayer、Filter 均不设持久化标志。
  - **核心收益（防砖机）**：一旦 TunGuard 正常退出、崩溃、被用户直接删除或被杀软隔离，Windows Base Filtering Engine (BFE) 会**自动、立即清除全部规则**，绝不会把受控应用或整机永久锁死断网。
  - 若未来需要"退出托盘仍常驻保护"，应拆分为独立 **Windows Service** 维护动态会话，而不是让托盘程序往内核写 `FWPM_FILTER_FLAG_PERSISTENT` 规则。
- **权限与降级**：
  - WFP 写操作强制需要管理员权限。虽然 [app.manifest](app.manifest#L8) 已配置 `highestAvailable` 且 [StartupManager](TunGuard.cs#L6595) 配置了 `<RunLevel>HighestAvailable</RunLevel>`，但标准非管理员账户无法提权。
  - 当 `FwpmEngineOpen0` 返回 `ERROR_ACCESS_DENIED` (`5`) 时，必须**优雅降级**为现有进程监控模式，并在托盘与控制面板明确提示"内核断网未启用（需管理员权限）"。
- **Defender 误报提示**：未签名自编译程序同时调用 `TerminateProcess` + `fwpuclnt.dll` 写入 WFP 规则，可能提高启发式误报率，沿用 [README.md](README.md#L109-L115) 中的文件夹排除项说明即可。

---

## 4. 已验证的 WFP 常量与 x64 精确对齐 C# 定义

> 适用目标：`build.ps1` 编译为 `/platform:x64`（`.NET Framework 4.x`，无外部依赖）。以下常量、签名与结构体布局已按 Windows SDK `fwpmu.h` / `fwpmtypes.h` / `fwptypes.h` 及 Windows x64 ABI 逐项核校。

### 4.1 常量与枚举

```csharp
// 过滤层（fwpmu.h）
static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 =
    new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 =
    new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

// 过滤条件字段（fwpmu.h）
static readonly Guid FWPM_CONDITION_ALE_APP_ID =
    new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");   // FWP_BYTE_BLOB_TYPE（必须由 FwpmGetAppIdFromFileName0 获取）
static readonly Guid FWPM_CONDITION_ALE_PACKAGE_ID =
    new Guid("71bc78fa-f17c-4997-a602-6abb261f351c");   // FWP_SID（MSIX/AppContainer 可选用）
static readonly Guid FWPM_CONDITION_IP_LOCAL_INTERFACE =
    new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");   // FWP_UINT64（NET_LUID，注意 FWP_CONDITION_VALUE0 中传指针！）
static readonly Guid FWPM_CONDITION_FLAGS =
    new Guid("632ce23b-5167-435c-86d7-e903684aa80c");   // FWP_UINT32（位标志）
static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT =
    new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");   // FWP_UINT16（可选：53 端口 DNS 拦截 / 代理端口）
static readonly Guid FWPM_CONDITION_IP_PROTOCOL =
    new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");   // FWP_UINT8（6=TCP, 17=UDP）

// 条件标志（FWPM_CONDITION_FLAGS 用）
const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;

// 会话标志（fwpmtypes.h）
const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;      // 进程退出/崩溃后 BFE 自动清理全部对象

// 动作类型（fwptypes.h：低位动作 | FWP_ACTION_FLAG_TERMINATING 0x00001000）
const uint FWP_ACTION_BLOCK  = 0x00001001;
const uint FWP_ACTION_PERMIT = 0x00001002;

// 鉴权服务与事务标志
const uint RPC_C_AUTHN_WINNT = 10;
const uint FWPM_TXN_WRITE    = 0;                       // 0 = 读写事务，1 = FWPM_TXN_READ_ONLY

// 匹配类型（fwptypes.h）
enum FWP_MATCH_TYPE : uint
{
    FWP_MATCH_EQUAL                  = 0,
    FWP_MATCH_GREATER                = 1,
    FWP_MATCH_LESS                   = 2,
    FWP_MATCH_GREATER_OR_EQUAL       = 3,
    FWP_MATCH_LESS_OR_EQUAL          = 4,
    FWP_MATCH_RANGE                  = 5,
    FWP_MATCH_FLAGS_ALL_SET          = 6,
    FWP_MATCH_FLAGS_ANY_SET          = 7,
    FWP_MATCH_FLAGS_NONE_SET         = 8,
    FWP_MATCH_EQUAL_CASE_INSENSITIVE = 9,
    FWP_MATCH_NOT_EQUAL              = 10,
    FWP_MATCH_PREFIX                 = 11,
    FWP_MATCH_NOT_PREFIX             = 12,
}

// 数据类型（fwptypes.h）
enum FWP_DATA_TYPE : uint
{
    FWP_EMPTY = 0, FWP_UINT8 = 1, FWP_UINT16 = 2, FWP_UINT32 = 3, FWP_UINT64 = 4,
    FWP_INT8 = 5, FWP_INT16 = 6, FWP_INT32 = 7, FWP_INT64 = 8,
    FWP_FLOAT = 9, FWP_DOUBLE = 10, FWP_BYTE_ARRAY16_TYPE = 11, FWP_BYTE_BLOB_TYPE = 12,
    FWP_SID = 13, FWP_SECURITY_DESCRIPTOR_TYPE = 14, FWP_TOKEN_INFORMATION_TYPE = 15,
    FWP_TOKEN_ACCESS_INFORMATION_TYPE = 16, FWP_UNICODE_STRING_TYPE = 17,
    FWP_BYTE_ARRAY6_TYPE = 18, FWP_SINGLE_DATA_TYPE_MAX = 0xFF,
    FWP_V4_ADDR_MASK = 0x100, FWP_V6_ADDR_MASK = 0x101, FWP_RANGE_TYPE = 0x102,
}
```

### 4.2 P/Invoke 声明（`fwpuclnt.dll`）

```csharp
[DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
static extern uint FwpmEngineOpen0(
    string serverName,                  // null 表示本机 BFE（注意：不是 securityDescriptor！）
    uint authnService,                  // RPC_C_AUTHN_WINNT (10)
    IntPtr authIdentity,                // IntPtr.Zero
    ref FWPM_SESSION0 session,
    out IntPtr engineHandle);

[DllImport("fwpuclnt.dll")]
static extern uint FwpmEngineClose0(IntPtr engineHandle);

[DllImport("fwpuclnt.dll")]
static extern uint FwpmProviderAdd0(
    IntPtr engineHandle,
    ref FWPM_PROVIDER0 provider,
    IntPtr sd);

[DllImport("fwpuclnt.dll")]
static extern uint FwpmSubLayerAdd0(
    IntPtr engineHandle,
    ref FWPM_SUBLAYER0 subLayer,
    IntPtr sd);

[DllImport("fwpuclnt.dll")]
static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

[DllImport("fwpuclnt.dll")]
static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

[DllImport("fwpuclnt.dll")]
static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

[DllImport("fwpuclnt.dll")]
static extern uint FwpmFilterAdd0(
    IntPtr engineHandle,
    ref FWPM_FILTER0 filter,
    IntPtr sd,
    out ulong filterId);

[DllImport("fwpuclnt.dll")]
static extern uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);

[DllImport("fwpuclnt.dll")]
static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);

[DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

[DllImport("fwpuclnt.dll")]
static extern void FwpmFreeMemory0(ref IntPtr p);
```

### 4.3 精确对齐的 x64 结构体定义

> **两个最易踩的 ABI 陷阱（已在下方结构体中修复）**：
> 1. `FWP_VALUE0` / `FWP_CONDITION_VALUE0` 中 `FWP_UINT64` 成员在 C 头文件里是 **`UINT64 *uint64`（指针）**，不能直接填 `ulong` 值，必须写入非托管内存后传 `IntPtr`！
> 2. `FWPM_FILTER0` 中 `action`（20 字节，结束于偏移 `148`）后紧跟 `union { UINT64 rawContext; GUID providerContextKey; }`，因为含 `UINT64` 所以对齐为 8（起始偏移 `152`）。C# 必须使用包含 `ulong` 的联合体包装结构 `FWPM_FILTER_CONTEXT0`，不能只写一个 `Guid` 字段，否则 `reserved`、`filterId`、`effectiveWeight` 会整体前移 4 字节导致内存越界！

```csharp
// x64 size = 16
[StructLayout(LayoutKind.Sequential)]
struct FWP_BYTE_BLOB
{
    public uint size;
    public IntPtr data;
}

// x64 size = 16
[StructLayout(LayoutKind.Sequential)]
struct FWPM_DISPLAY_DATA0
{
    public IntPtr name;        // wchar_t*
    public IntPtr description; // wchar_t*
}

// 兼容 FWP_VALUE0 与 FWP_CONDITION_VALUE0，x64 size = 16
[StructLayout(LayoutKind.Explicit, Size = 16)]
struct FWP_VALUE0
{
    [FieldOffset(0)] public FWP_DATA_TYPE type;
    [FieldOffset(8)] public byte uint8;
    [FieldOffset(8)] public ushort uint16;
    [FieldOffset(8)] public uint uint32;
    [FieldOffset(8)] public IntPtr uint64Ptr;  // 关键：指向非托管 ulong 的指针（FWP_UINT64）
    [FieldOffset(8)] public IntPtr byteBlob;   // FWP_BYTE_BLOB*（如 FwpmGetAppIdFromFileName0 返回值）
    [FieldOffset(8)] public IntPtr sid;        // SID*（FWP_SID）
}

// x64 size = 40 (fieldKey:0, matchType:16, conditionValue:24)
[StructLayout(LayoutKind.Sequential)]
struct FWPM_FILTER_CONDITION0
{
    public Guid fieldKey;
    public FWP_MATCH_TYPE matchType;
    public FWP_VALUE0 conditionValue;
}

// x64 size = 20 (type:0, filterType/calloutKey:4)
[StructLayout(LayoutKind.Sequential)]
struct FWPM_ACTION0
{
    public uint type;
    public Guid filterType;    // union { GUID filterType; GUID calloutKey; }
}

// x64 size = 16, align = 8（必须保留 ulong 成员以强制 8 字节对齐）
[StructLayout(LayoutKind.Explicit, Size = 16)]
struct FWPM_FILTER_CONTEXT0
{
    [FieldOffset(0)] public ulong rawContext;
    [FieldOffset(0)] public Guid providerContextKey;
}

// x64 size = 72
[StructLayout(LayoutKind.Sequential)]
struct FWPM_SESSION0
{
    public Guid sessionKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public uint txnWaitTimeoutInMSec;
    public uint processId;
    public IntPtr sid;
    public IntPtr username;
    public int kernelMode;     // Win32 BOOL
}

// x64 size = 64
[StructLayout(LayoutKind.Sequential)]
struct FWPM_PROVIDER0
{
    public Guid providerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public FWP_BYTE_BLOB providerData;
    public IntPtr serviceName;
}

// x64 size = 72
[StructLayout(LayoutKind.Sequential)]
struct FWPM_SUBLAYER0
{
    public Guid subLayerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey; // GUID*
    public FWP_BYTE_BLOB providerData;
    public ushort weight;
}

// x64 size = 200
[StructLayout(LayoutKind.Sequential)]
struct FWPM_FILTER0
{
    public Guid filterKey;                     // offset 0
    public FWPM_DISPLAY_DATA0 displayData;     // offset 16
    public uint flags;                         // offset 32
    public IntPtr providerKey;                 // offset 40 (GUID*)
    public FWP_BYTE_BLOB providerData;         // offset 48
    public Guid layerKey;                      // offset 64
    public Guid subLayerKey;                   // offset 80
    public FWP_VALUE0 weight;                  // offset 96
    public uint numFilterConditions;           // offset 112
    public IntPtr filterCondition;             // offset 120 (FWPM_FILTER_CONDITION0*)
    public FWPM_ACTION0 action;                // offset 128 (size 20)
    public FWPM_FILTER_CONTEXT0 context;       // offset 152 (4B padding 后 8 字节对齐)
    public IntPtr reserved;                    // offset 168 (GUID*)
    public ulong filterId;                     // offset 176
    public FWP_VALUE0 effectiveWeight;         // offset 184
}
```

> **实现自检断言**：在 `WfpKillSwitch` 静态构造函数中校验 `Marshal.SizeOf`（`FWP_VALUE0 == 16`、`FWPM_FILTER_CONDITION0 == 40`、`FWPM_ACTION0 == 20`、`FWPM_SESSION0 == 72`、`FWPM_PROVIDER0 == 64`、`FWPM_SUBLAYER0 == 72`、`FWPM_FILTER0 == 200`）与 `Marshal.OffsetOf(typeof(FWPM_FILTER0), "context") == 152`，任何偏差立即中止并降级。

---

## 5. `WfpKillSwitch` 模块核心状态机

为了做到**切换状态无闪烁、无竞态、零内存泄漏**，模块应采用“声明式差量同步 + WFP 事务原子提交”设计：

```csharp
sealed class WfpKillSwitch : IDisposable
{
    // 固定 GUID（标识本程序专属 Provider 与 Sublayer）
    static readonly Guid ProviderKey = new Guid("...");
    static readonly Guid SubLayerKey = new Guid("...");

    IntPtr _engine;
    bool _available;

    // 追踪已安装的规则 ID，便于差量增删
    // 1. 每个受控 exe 路径 -> (BlockV4, BlockV6, LoopbackV4, LoopbackV6)
    readonly Dictionary<string, BaseAppFilters> _baseFilters = new Dictionary<string, BaseAppFilters>(StringComparer.OrdinalIgnoreCase);
    // 2. 当前生效的 TUN PERMIT 规则（仅当 IsGuardSafe && tunLuid != 0 时存在）
    readonly Dictionary<string, TunPermitFilters> _tunPermitFilters = new Dictionary<string, TunPermitFilters>(StringComparer.OrdinalIgnoreCase);
    ulong _activeTunLuid;

    public bool TryInitialize(out string errorReason)
    {
        // 1. 仅支持 64 位进程 + 结构体尺寸自检
        // 2. 用 FWPM_SESSION_FLAG_DYNAMIC 调用 FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, ...)
        //    若返回 ERROR_ACCESS_DENIED (5) -> _available = false，优雅降级
        // 3. 在事务内调用 FwpmProviderAdd0 + FwpmSubLayerAdd0（weight = 0xFFFF 或高优先级）
    }

    // 由 TunMonitor 单线程调用，实现幂等差量同步
    public void SyncState(
        bool monitoringEnabled,
        bool isGuardSafe,
        ulong tunLuid,
        IEnumerable<string> guardedExePaths)
    {
        if (!_available) return;

        // 1. 若 !monitoringEnabled（用户暂停监控）：
        //    在单事务内删除所有 _baseFilters 与 _tunPermitFilters，恢复完全放行
        // 2. 差量更新 _baseFilters（每个新增 exe 用 FwpmGetAppIdFromFileName0 获取 blob）：
        //    - 新增路径：事务内添加 V4/V6 Loopback PERMIT (12) + V4/V6 全接口 BLOCK (1)
        //    - 移除路径：事务内删除对应 base + tunPermit filterId
        //    - 注意：FwpmFilterAdd0 返回后立即 FwpmFreeMemory0 释放 appId 与非托管条件内存
        // 3. 同步 _tunPermitFilters：
        //    - 目标允许放行条件：shouldPermitTun = isGuardSafe && tunLuid != 0
        //    - 若 !shouldPermitTun：在单事务内删除所有 _tunPermitFilters（节点违规瞬间断网）
        //    - 若 shouldPermitTun 且 (tunLuid != _activeTunLuid 或有新增路径)：
        //      在单事务内先添加新 LUID 的 V4/V6 PERMIT (10)，再删除旧 LUID 的 PERMIT，
        //      提交原子生效，避免 TUN 网卡重建期间出现瞬间误断
    }

    public void Dispose()
    {
        // FwpmEngineClose0(_engine) 自动清除 DYNAMIC 会话下的全部 Provider/Sublayer/Filter
    }
}
```

---

## 6. 与现有 [TunGuard.cs](TunGuard.cs) 的精确集成点

| 现有位置 | 改造与复用方式 |
| --- | --- |
| `TunMonitor` 的 `MIB_IF_ROW2`（[TunGuard.cs:4704-4714](TunGuard.cs#L4704-L4714)、[L5586-5666](TunGuard.cs#L5586-L5666)） | `MIB_IF_ROW2` 偏移 `0` 处直接就是 8 字节 `InterfaceLuid`，无需额外调用 `ConvertInterfaceIndexToLuid`；在 `TunStatus` 增加 `public ulong AdapterLuid;` |
| `TargetProcessKiller`（[TunGuard.cs:4555-4695](TunGuard.cs#L4555-L4695)） | 复用 `MatchTargetImagePath` 与路径规则，新增 `GuardedAppPathResolver`（启动扫描常见目录 + MSIX `WindowsApps` + 运行时新进程路径回调热追加） |
| `TunMonitor.EvaluateAndEnforce`（[TunGuard.cs:5433-5455](TunGuard.cs#L5433-L5455)） | 在判定 `next.IsGuardSafe` 后，**第一时间**调用 `_wfp.SyncState(_monitoringEnabled, next.IsGuardSafe, next.AdapterLuid, resolvedPaths)`；随后按配置决定是否执行 `_killer.KillAllNow()` |
| `NodeGuardConfig`（[TunGuard.cs:207-235](TunGuard.cs#L207-L235)） | 新增配置项：`wfpEnabled`（默认开启）、`wfpKillOnBlock`（阻断时是否同时强杀进程）、`wfpBlockNonTunDns`（可选全局防 53 端口 DNS 泄漏）、以及已发现 exe 路径缓存 |
| `TrayApplication`（[TunGuard.cs:8036](TunGuard.cs#L8036)） | 托盘菜单与状态提示增加 WFP 运行状态（`内核断网已启用` / `已降级：需管理员权限` / `已暂停`） |

---

## 7. 分阶段落地与验证清单

### 阶段 1：独立最小原型验证（先不改动主文件）
1. 编译最小 x64 验证程序，断言所有结构体 `Marshal.SizeOf` 与 `Marshal.OffsetOf`。
2. 测试 `FwpmEngineOpen0`（`DYNAMIC`）→ 注册 Provider/Sublayer → `FwpmGetAppIdFromFileName0` → 安装三段式规则。
3. 运行 `netsh wfp show filters` 导出 XML，肉眼核对：
   - Sublayer GUID、filter weight（`12 / 10 / 1`）是否准确；
   - `ALE_APP_ID` 是否为正确的小写 NT 设备路径；
   - `IP_LOCAL_INTERFACE` 数值是否与 `Get-NetAdapter | Select Name, InterfaceLuid` 一致。
4. 实测 4 个场景：
   - **Loopback 连通性**：受控应用访问 `127.0.0.1` 正常；
   - **TUN 正常走代理**：受控应用外网访问正常；
   - **拔掉/关闭 TUN 瞬间**：抓包（Wireshark/pktmon）确认物理网卡上受控应用 **0 个 IPv4/IPv6 包流出**；
   - **进程强杀/退出测试**：直接任务管理器杀掉原型进程，再次执行 `netsh wfp show filters` 确认所有规则已由 BFE 自动清空。

### 阶段 2：合入 [TunGuard.cs](TunGuard.cs)
- 集成 `WfpKillSwitch`、`GuardedAppPathResolver`、`TunStatus.AdapterLuid` 与优雅降级逻辑；
- 串联 `MonitoringEnabled` 暂停/恢复、节点违规事务撤权、配置热更新与托盘 UI 状态展示。

### 阶段 3（按需增强）
- MSIX 应用补加 `FWPM_CONDITION_ALE_PACKAGE_ID`（包 SID）免疫版本更新换目录；
- 按需增加全局 53 端口 DNS 泄漏防护开关；
- 如确需"无托盘进程也常驻锁死"，再演进为独立 Windows Service。

---

## 8. 诚实边界

这套方案能做到的是 **"TUN 掉线时受控应用零真实 IP 出站泄漏"** 与 **"节点违规时无损秒断网"**，但仍存在以下固有边界：

- **节点违规仍存在反应式检测延迟**（毫秒级，取决于 Clash 控制接口响应与轮询间隔），无法像 TUN 接口消失那样由内核瞬时感知。
- **不开启全局 53 端口规则时，无法阻断系统 `dnscache` (`svchost.exe`) 的 DNS 查询泄漏**。
- **无法仅靠网络层保证"不被目标服务风控"**：出口节点 IP 信誉、账号注册/支付地区与历史记录、客户端时区/语言/TLS 指纹均属于网络层之外的风控维度。

---

## 参考资料

- [Filtering Layer Identifiers (`fwpmu.h`)](https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-)
- [Filtering Condition Identifiers (`fwpmu.h`)](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)
- [Filter Arbitration (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)
- [ALE Reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-reauthorization)
- [FwpmEngineOpen0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0) / [FwpmGetAppIdFromFileName0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0)
- [FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0) / [FWPM_SESSION0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0) / [FWP_VALUE0](https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_value0)
- [OpenVPN `wfp_block.c` 参考实现](https://build.openvpn.net/doxygen/wfp__block_8c_source.html)
