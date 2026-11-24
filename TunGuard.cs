using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace TunGuard
{
    internal static class Program
    {
        private const string MutexName = "Local\\ClashVergeTunGuard_SingleInstance_v1";
        private const string PingEventName = "Local\\ClashVergeTunGuard_Ping_v1";

        [STAThread]
        private static void Main()
        {
            bool createdNew;
            using (Mutex mutex = new Mutex(true, MutexName, out createdNew))
            {
                if (!createdNew)
                {
                    SignalExistingInstance();
                    return;
                }

                try
                {
                    Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High;
                }
                catch
                {
                    // Ignore if OS restricts priority elevation
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                using (TrayApplication app = new TrayApplication(PingEventName))
                {
                    Application.Run(app);
                }
            }
        }

        private static void SignalExistingInstance()
        {
            try
            {
                using (EventWaitHandle ev = EventWaitHandle.OpenExisting(PingEventName))
                {
                    ev.Set();
                }
            }
            catch
            {
                // Already running; nothing more to do
            }
        }
    }

    internal struct TunStatus
    {
        public bool IsTunActive;
        public bool ConfigEnabled;
        public bool AdapterUp;
        public bool HasDefaultRoute;
        public bool AutoRouteRequired;
        public uint AdapterIndex;
        public string AdapterAlias;
        public string Reason;
    }

    internal struct KillResult
    {
        public int KilledCount;
        public double ElapsedMs;
    }

    internal static class AntigravityKiller
    {
        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private const uint PROCESS_TERMINATE = 0x0001;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32W
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageNameW(
            IntPtr hProcess,
            uint dwFlags,
            StringBuilder lpExeName,
            ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static readonly uint SelfPid = (uint)Process.GetCurrentProcess().Id;

        public static KillResult KillAllNow()
        {
            Stopwatch sw = Stopwatch.StartNew();
            int totalKilled = KillPass();

            // If processes were killed, do one rapid sweep 5ms later to catch any racing child spawn.
            if (totalKilled > 0)
            {
                Thread.Sleep(5);
                totalKilled += KillPass();
            }

            sw.Stop();
            return new KillResult
            {
                KilledCount = totalKilled,
                ElapsedMs = sw.Elapsed.TotalMilliseconds
            };
        }

        private static int KillPass()
        {
            int killed = 0;
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
            {
                return 0;
            }

            try
            {
                PROCESSENTRY32W pe = new PROCESSENTRY32W();
                pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));

                if (!Process32FirstW(snapshot, ref pe))
                {
                    return 0;
                }

                StringBuilder pathBuf = new StringBuilder(512);

                do
                {
                    uint pid = pe.th32ProcessID;
                    if (pid == 0 || pid == SelfPid)
                    {
                        continue;
                    }

                    string exe = pe.szExeFile;
                    if (string.IsNullOrEmpty(exe))
                    {
                        continue;
                    }

                    if (string.Equals(exe, "Antigravity.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        IntPtr hProc = OpenProcess(PROCESS_TERMINATE, false, pid);
                        if (hProc != IntPtr.Zero)
                        {
                            try
                            {
                                if (TerminateProcess(hProc, 1))
                                {
                                    killed++;
                                }
                            }
                            finally
                            {
                                CloseHandle(hProc);
                            }
                        }
                    }
                    else if (exe.StartsWith("language_server", StringComparison.OrdinalIgnoreCase) &&
                             exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        IntPtr hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                        if (hProc != IntPtr.Zero)
                        {
                            try
                            {
                                pathBuf.Clear();
                                uint size = (uint)pathBuf.Capacity;
                                if (QueryFullProcessImageNameW(hProc, 0, pathBuf, ref size))
                                {
                                    string fullPath = pathBuf.ToString();
                                    if (fullPath.IndexOf("\\antigravity\\", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        if (TerminateProcess(hProc, 1))
                                        {
                                            killed++;
                                        }
                                    }
                                }
                            }
                            finally
                            {
                                CloseHandle(hProc);
                            }
                        }
                    }
                }
                while (Process32NextW(snapshot, ref pe));
            }
            finally
            {
                CloseHandle(snapshot);
            }

            return killed;
        }
    }

    internal sealed class TunMonitor : IDisposable
    {
        private const ushort AF_UNSPEC = 0;
        private const ushort AF_INET = 2;
        private const int MibIfTableNormal = 0;

        // Verified x64 Windows MIB_IF_TABLE2 / MIB_IF_ROW2 offsets
        private const int IF_TABLE_ENTRIES_OFFSET = 8;
        private const int IF_ROW_SIZE = 1352;
        private const int IF_ROW_INDEX_OFFSET = 8;
        private const int IF_ROW_ALIAS_OFFSET = 28;
        private const int IF_ROW_DESC_OFFSET = 542;
        private const int IF_ROW_FLAGS_OFFSET = 1152;
        private const int IF_ROW_OPER_STATUS_OFFSET = 1156;
        private const int IF_ROW_MEDIA_STATE_OFFSET = 1164;

        // Verified x64 Windows MIB_IPFORWARD_TABLE2 / MIB_IPFORWARD_ROW2 offsets
        private const int FWD_TABLE_ENTRIES_OFFSET = 8;
        private const int FWD_ROW_SIZE = 104;
        private const int FWD_ROW_IFINDEX_OFFSET = 8;
        private const int FWD_ROW_PREFIXLEN_OFFSET = 40;

        private const int MIB_NOTIFICATION_DELETE = 2;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void IpInterfaceChangeCallback(IntPtr callerContext, IntPtr row, int notificationType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void IpForwardChangeCallback(IntPtr callerContext, IntPtr row, int notificationType);

        [DllImport("iphlpapi.dll")]
        private static extern uint GetIfEntry2(IntPtr row);

        [DllImport("iphlpapi.dll")]
        private static extern uint GetIfTable2Ex(int level, out IntPtr table);

        [DllImport("iphlpapi.dll")]
        private static extern uint GetIpForwardTable2(ushort family, out IntPtr table);

        [DllImport("iphlpapi.dll")]
        private static extern void FreeMibTable(IntPtr memory);

        [DllImport("iphlpapi.dll")]
        private static extern uint NotifyIpInterfaceChange(
            ushort family,
            IpInterfaceChangeCallback callback,
            IntPtr callerContext,
            [MarshalAs(UnmanagedType.U1)] bool initialNotification,
            out IntPtr notificationHandle);

        [DllImport("iphlpapi.dll")]
        private static extern uint NotifyRouteChange2(
            ushort family,
            IpForwardChangeCallback callback,
            IntPtr callerContext,
            [MarshalAs(UnmanagedType.U1)] bool initialNotification,
            out IntPtr notificationHandle);

        [DllImport("iphlpapi.dll")]
        private static extern uint CancelMibChangeNotify2(IntPtr notificationHandle);

        private readonly string _configDir;
        private readonly string _vergeYamlPath;
        private readonly string _clashYamlPath;

        // Keep delegates rooted so GC never collects native callbacks
        private readonly IpInterfaceChangeCallback _ifaceCallback;
        private readonly IpForwardChangeCallback _routeCallback;
        private IntPtr _ifaceNotifyHandle = IntPtr.Zero;
        private IntPtr _routeNotifyHandle = IntPtr.Zero;
        private FileSystemWatcher _watcher;

        private readonly object _evalLock = new object();
        private volatile bool _evalPending;
        private volatile bool _running;
        private volatile bool _monitoringEnabled = true;

        // Cached parsed config values (guarded by _configLock)
        private readonly object _configLock = new object();
        private bool? _vergeEnableTun;
        private bool _clashAutoRoute = true;
        private string _customTunDevice;

        private volatile bool _isTunActive;
        private uint _lastKnownTunIfIndex;
        private TunStatus _currentStatus;
        private Thread _watchdogThread;
        private ManualResetEventSlim _stopEvent = new ManualResetEventSlim(false);

        public event Action<TunStatus> StatusChanged;
        public event Action<KillResult, string> AntigravityKilled;

        public bool MonitoringEnabled
        {
            get { return _monitoringEnabled; }
            set
            {
                _monitoringEnabled = value;
                if (value)
                {
                    TriggerImmediateCheck("恢复监控");
                }
            }
        }

        public TunStatus CurrentStatus
        {
            get
            {
                lock (_evalLock)
                {
                    return _currentStatus;
                }
            }
        }

        public TunMonitor()
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            _configDir = Path.Combine(appData, "io.github.clash-verge-rev.clash-verge-rev");
            _vergeYamlPath = Path.Combine(_configDir, "verge.yaml");
            _clashYamlPath = Path.Combine(_configDir, "clash-verge.yaml");

            _ifaceCallback = OnIpInterfaceChanged;
            _routeCallback = OnRouteChanged;
        }

        public void Start()
        {
            if (_running)
            {
                return;
            }
            _running = true;

            RefreshConfigFiles();
            EvaluateAndEnforce("初始检查", true);

            // 1. Kernel IP interface change notification (< 1ms)
            NotifyIpInterfaceChange(AF_UNSPEC, _ifaceCallback, IntPtr.Zero, false, out _ifaceNotifyHandle);

            // 2. Kernel IPv4 route change notification (< 1ms)
            NotifyRouteChange2(AF_INET, _routeCallback, IntPtr.Zero, false, out _routeNotifyHandle);

            // 3. Clash Verge config watcher (< 1ms on UI toggle, often BEFORE adapter teardown)
            StartConfigWatcher();

            // 4. Dedicated high-priority watchdog thread (immune to UI/menu message loops)
            _watchdogThread = new Thread(WatchdogLoop)
            {
                Name = "TunWatchdog",
                IsBackground = true,
                Priority = ThreadPriority.Highest
            };
            _watchdogThread.Start();
        }

        private void StartConfigWatcher()
        {
            if (!Directory.Exists(_configDir))
            {
                return;
            }

            try
            {
                _watcher = new FileSystemWatcher(_configDir)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime,
                    IncludeSubdirectories = false
                };
                _watcher.Changed += OnConfigFileEvent;
                _watcher.Created += OnConfigFileEvent;
                _watcher.Renamed += OnConfigFileRenamed;
                _watcher.EnableRaisingEvents = true;
            }
            catch
            {
                // Kernel adapter/route monitoring still works even if FileSystemWatcher cannot attach
            }
        }

        private void OnConfigFileEvent(object sender, FileSystemEventArgs e)
        {
            if (!IsRelevantConfigFile(e.Name))
            {
                return;
            }
            HandleConfigFileChange(e.Name);
        }

        private void OnConfigFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!IsRelevantConfigFile(e.Name))
            {
                return;
            }
            HandleConfigFileChange(e.Name);
        }

        private static bool IsRelevantConfigFile(string name)
        {
            return string.Equals(name, "verge.yaml", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "clash-verge.yaml", StringComparison.OrdinalIgnoreCase);
        }

        private void HandleConfigFileChange(string fileName)
        {
            if (!_running)
            {
                return;
            }

            if (string.Equals(fileName, "verge.yaml", StringComparison.OrdinalIgnoreCase))
            {
                ReadVergeYamlSafe();
            }
            else
            {
                ReadClashYamlSafe();
            }

            TriggerImmediateCheck("配置变更: " + fileName);
        }

        private void OnIpInterfaceChanged(IntPtr callerContext, IntPtr row, int notificationType)
        {
            if (!_running)
            {
                return;
            }
            TriggerImmediateCheck("网卡状态变更");
        }

        private void OnRouteChanged(IntPtr callerContext, IntPtr row, int notificationType)
        {
            if (!_running)
            {
                return;
            }

            // Fast-path filter: only react immediately when the TUN route changes or when TUN is currently down
            if (row != IntPtr.Zero && _isTunActive && _lastKnownTunIfIndex != 0)
            {
                uint ifIdx = (uint)Marshal.ReadInt32(row, FWD_ROW_IFINDEX_OFFSET);
                byte prefixLen = Marshal.ReadByte(row, FWD_ROW_PREFIXLEN_OFFSET);
                if (ifIdx != _lastKnownTunIfIndex)
                {
                    return;
                }
                if (prefixLen > 1 && notificationType != MIB_NOTIFICATION_DELETE)
                {
                    return;
                }
            }

            TriggerImmediateCheck("路由表变更");
        }

        private void WatchdogLoop()
        {
            int configTick = 0;
            while (_running)
            {
                bool active = _isTunActive;
                // 100ms safety net when TUN is ON (~0.02% CPU); 30ms fast guard when TUN is OFF
                int intervalMs = active ? 100 : 30;
                if (_stopEvent.Wait(intervalMs))
                {
                    break;
                }

                // Periodically re-read config files (~1s) in case FileSystemWatcher missed a replace
                configTick++;
                if (configTick >= (active ? 10 : 30))
                {
                    configTick = 0;
                    RefreshConfigFiles();
                }

                EvaluateAndEnforce("定时巡检", false);
            }
        }

        private void TriggerImmediateCheck(string triggerSource)
        {
            if (!_running)
            {
                return;
            }
            EvaluateAndEnforce(triggerSource, false);
        }

        private void EvaluateAndEnforce(string triggerSource, bool forceNotify)
        {
            if (!Monitor.TryEnter(_evalLock))
            {
                _evalPending = true;
                return;
            }

            try
            {
                do
                {
                    _evalPending = false;
                    TunStatus next = QueryTunStatus();

                    if (next.AdapterUp && next.AdapterIndex != 0)
                    {
                        _lastKnownTunIfIndex = next.AdapterIndex;
                    }

                    // Enforce BEFORE firing UI events so zero milliseconds are wasted on UI updates
                    KillResult killRes = default(KillResult);
                    if (_monitoringEnabled && !next.IsTunActive)
                    {
                        killRes = AntigravityKiller.KillAllNow();
                    }

                    bool changed = forceNotify ||
                                   next.IsTunActive != _currentStatus.IsTunActive ||
                                   !string.Equals(next.AdapterAlias, _currentStatus.AdapterAlias, StringComparison.Ordinal) ||
                                   !string.Equals(next.Reason, _currentStatus.Reason, StringComparison.Ordinal);

                    _isTunActive = next.IsTunActive;
                    _currentStatus = next;
                    forceNotify = false;

                    if (killRes.KilledCount > 0)
                    {
                        Action<KillResult, string> killedHandler = AntigravityKilled;
                        if (killedHandler != null)
                        {
                            killedHandler(killRes, triggerSource);
                        }
                    }

                    if (changed)
                    {
                        Action<TunStatus> statusHandler = StatusChanged;
                        if (statusHandler != null)
                        {
                            statusHandler(next);
                        }
                    }
                }
                while (_evalPending && _running);
            }
            finally
            {
                Monitor.Exit(_evalLock);
            }
        }

        private TunStatus QueryTunStatus()
        {
            bool? vergeEnable;
            bool autoRoute;
            string customDevice;

            lock (_configLock)
            {
                vergeEnable = _vergeEnableTun;
                autoRoute = _clashAutoRoute;
                customDevice = _customTunDevice;
            }

            // verge.yaml explicitly says enable_tun_mode: false -> short-circuit in <0.01ms to kill immediately
            bool configAllows = (vergeEnable != false);
            if (!configAllows)
            {
                return new TunStatus
                {
                    IsTunActive = false,
                    ConfigEnabled = false,
                    AdapterUp = false,
                    HasDefaultRoute = false,
                    AutoRouteRequired = autoRoute,
                    AdapterIndex = 0,
                    AdapterAlias = string.Empty,
                    Reason = "Clash Verge 配置已关闭 TUN"
                };
            }

            uint tunIfIndex;
            string tunAlias;
            bool adapterUp = TryCheckCachedTunAdapter(_lastKnownTunIfIndex, customDevice, out tunIfIndex, out tunAlias) ||
                             FindActiveTunAdapter(customDevice, out tunIfIndex, out tunAlias);

            bool hasRoute = true;
            if (adapterUp && autoRoute)
            {
                hasRoute = HasDefaultRouteOnInterface(tunIfIndex);
            }

            bool isActive = configAllows && adapterUp && (!autoRoute || hasRoute);
            string reason;
            if (isActive)
            {
                reason = "TUN 正常 (" + tunAlias + ")";
            }
            else if (!configAllows)
            {
                reason = "Clash Verge 配置已关闭 TUN";
            }
            else if (!adapterUp)
            {
                reason = "TUN 虚拟网卡未启动";
            }
            else
            {
                reason = "TUN 默认路由已断开";
            }

            return new TunStatus
            {
                IsTunActive = isActive,
                ConfigEnabled = configAllows,
                AdapterUp = adapterUp,
                HasDefaultRoute = hasRoute,
                AutoRouteRequired = autoRoute,
                AdapterIndex = tunIfIndex,
                AdapterAlias = tunAlias ?? string.Empty,
                Reason = reason
            };
        }

        private static bool TryCheckCachedTunAdapter(uint cachedIfIndex, string customDevice, out uint ifIndex, out string alias)
        {
            ifIndex = 0;
            alias = string.Empty;
            if (cachedIfIndex == 0)
            {
                return false;
            }

            IntPtr row = Marshal.AllocHGlobal(IF_ROW_SIZE);
            try
            {
                // Zero-initialize LUID (offset 0..7) and set InterfaceIndex (offset 8..11)
                Marshal.WriteInt64(row, 0, 0L);
                Marshal.WriteInt32(row, IF_ROW_INDEX_OFFSET, (int)cachedIfIndex);

                if (GetIfEntry2(row) != 0)
                {
                    return false;
                }

                byte flags = Marshal.ReadByte(row, IF_ROW_FLAGS_OFFSET);
                if ((flags & 0x02) != 0)
                {
                    return false;
                }

                int operStatus = Marshal.ReadInt32(row, IF_ROW_OPER_STATUS_OFFSET);
                int mediaState = Marshal.ReadInt32(row, IF_ROW_MEDIA_STATE_OFFSET);
                if (operStatus != 1 || mediaState != 1)
                {
                    return false;
                }

                string rowAlias = Marshal.PtrToStringUni(IntPtr.Add(row, IF_ROW_ALIAS_OFFSET)) ?? string.Empty;
                string rowDesc = Marshal.PtrToStringUni(IntPtr.Add(row, IF_ROW_DESC_OFFSET)) ?? string.Empty;
                if (!IsClashTunAdapter(rowAlias, rowDesc, customDevice))
                {
                    return false;
                }

                ifIndex = cachedIfIndex;
                alias = rowAlias;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(row);
            }
        }

        private static bool FindActiveTunAdapter(string customDevice, out uint ifIndex, out string alias)
        {
            ifIndex = 0;
            alias = string.Empty;

            IntPtr pTable;
            if (GetIfTable2Ex(MibIfTableNormal, out pTable) != 0 || pTable == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                uint count = (uint)Marshal.ReadInt32(pTable, 0);
                IntPtr rowBase = IntPtr.Add(pTable, IF_TABLE_ENTRIES_OFFSET);

                for (int i = 0; i < count; i++)
                {
                    IntPtr row = IntPtr.Add(rowBase, i * IF_ROW_SIZE);

                    // Bit 1 (0x02) = FilterInterface; skip NDIS lightweight filter pseudo-interfaces
                    byte flags = Marshal.ReadByte(row, IF_ROW_FLAGS_OFFSET);
                    if ((flags & 0x02) != 0)
                    {
                        continue;
                    }

                    // IfOperStatusUp = 1, MediaConnectStateConnected = 1
                    int operStatus = Marshal.ReadInt32(row, IF_ROW_OPER_STATUS_OFFSET);
                    if (operStatus != 1)
                    {
                        continue;
                    }

                    int mediaState = Marshal.ReadInt32(row, IF_ROW_MEDIA_STATE_OFFSET);
                    if (mediaState != 1)
                    {
                        continue;
                    }

                    string rowAlias = Marshal.PtrToStringUni(IntPtr.Add(row, IF_ROW_ALIAS_OFFSET)) ?? string.Empty;
                    string rowDesc = Marshal.PtrToStringUni(IntPtr.Add(row, IF_ROW_DESC_OFFSET)) ?? string.Empty;

                    if (IsClashTunAdapter(rowAlias, rowDesc, customDevice))
                    {
                        ifIndex = (uint)Marshal.ReadInt32(row, IF_ROW_INDEX_OFFSET);
                        alias = rowAlias;
                        return true;
                    }
                }
            }
            finally
            {
                FreeMibTable(pTable);
            }

            return false;
        }

        private static bool IsClashTunAdapter(string alias, string desc, string customDevice)
        {
            if (!string.IsNullOrEmpty(customDevice) &&
                string.Equals(alias, customDevice, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.Equals(alias, "Meta", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(alias, "Mihomo", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(alias, "Clash", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(alias, "Clash Verge", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (desc.IndexOf("Meta Tunnel", StringComparison.OrdinalIgnoreCase) >= 0 ||
                desc.IndexOf("Mihomo", StringComparison.OrdinalIgnoreCase) >= 0 ||
                desc.IndexOf("Clash Tunnel", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            return false;
        }

        private static bool HasDefaultRouteOnInterface(uint targetIfIndex)
        {
            if (targetIfIndex == 0)
            {
                return false;
            }

            IntPtr pTable;
            if (GetIpForwardTable2(AF_INET, out pTable) != 0 || pTable == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                uint count = (uint)Marshal.ReadInt32(pTable, 0);
                IntPtr rowBase = IntPtr.Add(pTable, FWD_TABLE_ENTRIES_OFFSET);

                for (int i = 0; i < count; i++)
                {
                    IntPtr row = IntPtr.Add(rowBase, i * FWD_ROW_SIZE);
                    uint ifIdx = (uint)Marshal.ReadInt32(row, FWD_ROW_IFINDEX_OFFSET);
                    if (ifIdx != targetIfIndex)
                    {
                        continue;
                    }

                    // PrefixLength 0 => 0.0.0.0/0, PrefixLength 1 => 0.0.0.0/1 or 128.0.0.0/1
                    byte prefixLen = Marshal.ReadByte(row, FWD_ROW_PREFIXLEN_OFFSET);
                    if (prefixLen <= 1)
                    {
                        return true;
                    }
                }
            }
            finally
            {
                FreeMibTable(pTable);
            }

            return false;
        }

        private void RefreshConfigFiles()
        {
            ReadVergeYamlSafe();
            ReadClashYamlSafe();
        }

        private void ReadVergeYamlSafe()
        {
            if (!File.Exists(_vergeYamlPath))
            {
                return;
            }

            string content = ReadAllTextRetry(_vergeYamlPath);
            if (string.IsNullOrEmpty(content))
            {
                return; // Keep previous value during transient atomic write
            }

            using (StringReader sr = new StringReader(content))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith("enable_tun_mode:", StringComparison.OrdinalIgnoreCase))
                    {
                        string val = StripYamlComment(trimmed.Substring("enable_tun_mode:".Length)).Trim();
                        bool parsed;
                        if (bool.TryParse(val, out parsed))
                        {
                            lock (_configLock)
                            {
                                _vergeEnableTun = parsed;
                            }
                        }
                        return;
                    }
                }
            }
        }

        private void ReadClashYamlSafe()
        {
            if (!File.Exists(_clashYamlPath))
            {
                return;
            }

            string content = ReadAllTextRetry(_clashYamlPath);
            if (string.IsNullOrEmpty(content))
            {
                return;
            }

            bool inTun = false;
            bool? autoRouteVal = null;
            string deviceVal = null;

            using (StringReader sr = new StringReader(content))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    int indent = CountLeadingSpaces(line);
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith("#"))
                    {
                        continue;
                    }

                    if (indent == 0)
                    {
                        if (inTun)
                        {
                            break;
                        }
                        if (string.Equals(trimmed, "tun:", StringComparison.OrdinalIgnoreCase))
                        {
                            inTun = true;
                        }
                        continue;
                    }

                    if (!inTun)
                    {
                        continue;
                    }

                    if (trimmed.StartsWith("auto-route:", StringComparison.OrdinalIgnoreCase))
                    {
                        bool b;
                        if (bool.TryParse(StripYamlComment(trimmed.Substring("auto-route:".Length)).Trim(), out b))
                        {
                            autoRouteVal = b;
                        }
                    }
                    else if (trimmed.StartsWith("device:", StringComparison.OrdinalIgnoreCase))
                    {
                        string dev = StripYamlComment(trimmed.Substring("device:".Length)).Trim().Trim('\'', '"');
                        if (!string.IsNullOrEmpty(dev))
                        {
                            deviceVal = dev;
                        }
                    }
                }
            }

            if (inTun)
            {
                lock (_configLock)
                {
                    if (autoRouteVal.HasValue)
                    {
                        _clashAutoRoute = autoRouteVal.Value;
                    }
                    _customTunDevice = deviceVal;
                }
            }
        }

        private static string ReadAllTextRetry(string path)
        {
            for (int attempt = 0; attempt < 6; attempt++)
            {
                try
                {
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        string text = sr.ReadToEnd();
                        if (text.Length > 0)
                        {
                            return text;
                        }
                    }
                }
                catch
                {
                    // File might be mid-write by Clash Verge
                }
                Thread.Sleep(5);
            }
            return null;
        }

        private static int CountLeadingSpaces(string s)
        {
            int count = 0;
            while (count < s.Length && s[count] == ' ')
            {
                count++;
            }
            return count;
        }

        private static string StripYamlComment(string s)
        {
            int idx = s.IndexOf('#');
            return idx >= 0 ? s.Substring(0, idx) : s;
        }

        public void Dispose()
        {
            _running = false;
            _stopEvent.Set();

            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }

            if (_ifaceNotifyHandle != IntPtr.Zero)
            {
                CancelMibChangeNotify2(_ifaceNotifyHandle);
                _ifaceNotifyHandle = IntPtr.Zero;
            }

            if (_routeNotifyHandle != IntPtr.Zero)
            {
                CancelMibChangeNotify2(_routeNotifyHandle);
                _routeNotifyHandle = IntPtr.Zero;
            }

            if (_watchdogThread != null && _watchdogThread.IsAlive)
            {
                _watchdogThread.Join(300);
            }

            _stopEvent.Dispose();
        }
    }

    internal static class StartupManager
    {
        public const string TaskName = "ClashTunGuard";

        public static bool IsAutoStartEnabled()
        {
            return RunSchtasks("/Query /TN \"" + TaskName + "\"") == 0;
        }

        public static bool SetAutoStart(bool enable)
        {
            if (enable)
            {
                string exePath = Application.ExecutablePath;
                string workDir = Path.GetDirectoryName(exePath) ?? string.Empty;
                string userId = WindowsIdentity.GetCurrent().Name;
                string xmlPath = Path.Combine(Path.GetTempPath(), "ClashTunGuard_task_" + Guid.NewGuid().ToString("N") + ".xml");

                try
                {
                    string xml = string.Format(
@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo>
    <Description>Monitor Clash Verge TUN mode and immediately terminate Antigravity when TUN is disabled.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{0}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id=""Author"">
      <UserId>{0}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>{1}</Command>
      <WorkingDirectory>{2}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>",
                        System.Security.SecurityElement.Escape(userId),
                        System.Security.SecurityElement.Escape(exePath),
                        System.Security.SecurityElement.Escape(workDir));

                    File.WriteAllText(xmlPath, xml, Encoding.Unicode);
                    return RunSchtasks("/Create /TN \"" + TaskName + "\" /XML \"" + xmlPath + "\" /F") == 0;
                }
                finally
                {
                    try
                    {
                        if (File.Exists(xmlPath))
                        {
                            File.Delete(xmlPath);
                        }
                    }
                    catch
                    {
                    }
                }
            }
            else
            {
                int rc = RunSchtasks("/Delete /TN \"" + TaskName + "\" /F");
                return rc == 0 || !IsAutoStartEnabled();
            }
        }

        private static int RunSchtasks(string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using (Process p = Process.Start(psi))
                {
                    if (p == null)
                    {
                        return -1;
                    }
                    p.WaitForExit(5000);
                    return p.ExitCode;
                }
            }
            catch
            {
                return -1;
            }
        }
    }

    internal static class TrayIconFactory
    {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr hIcon);

        public static Icon CreateStatusIcon(Color fillColor, Color borderColor)
        {
            using (Bitmap bmp = new Bitmap(32, 32))
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);

                // Shield polygon
                PointF[] shield = new PointF[]
                {
                    new PointF(16f, 2f),
                    new PointF(28f, 6.5f),
                    new PointF(26.5f, 18.5f),
                    new PointF(16f, 30f),
                    new PointF(5.5f, 18.5f),
                    new PointF(4f, 6.5f)
                };

                using (SolidBrush brush = new SolidBrush(fillColor))
                using (Pen pen = new Pen(borderColor, 2.2f))
                {
                    g.FillPolygon(brush, shield);
                    g.DrawPolygon(pen, shield);
                }

                // Crisp white 'T' glyph in center
                using (Pen glyphPen = new Pen(Color.White, 3.0f))
                {
                    glyphPen.StartCap = LineCap.Round;
                    glyphPen.EndCap = LineCap.Round;
                    g.DrawLine(glyphPen, 10.5f, 11f, 21.5f, 11f);
                    g.DrawLine(glyphPen, 16f, 11f, 16f, 22f);
                }

                IntPtr hIcon = bmp.GetHicon();
                try
                {
                    using (Icon temp = Icon.FromHandle(hIcon))
                    {
                        return (Icon)temp.Clone();
                    }
                }
                finally
                {
                    DestroyIcon(hIcon);
                }
            }
        }
    }

    internal sealed class TrayApplication : ApplicationContext
    {
        private readonly SynchronizationContext _uiSync;
        private readonly TunMonitor _monitor;
        private readonly NotifyIcon _trayIcon;
        private readonly ToolStripMenuItem _statusItem;
        private readonly ToolStripMenuItem _lastKillItem;
        private readonly ToolStripMenuItem _toggleMonitorItem;
        private readonly ToolStripMenuItem _autoStartItem;

        private readonly Icon _iconSafe;
        private readonly Icon _iconAlert;
        private readonly Icon _iconPaused;

        private readonly EventWaitHandle _pingEvent;
        private readonly ManualResetEventSlim _pingStop = new ManualResetEventSlim(false);
        private readonly Thread _pingThread;

        private int _totalKills;
        private bool _disposed;

        public TrayApplication(string pingEventName)
        {
            // Ensure WindowsFormsSynchronizationContext is initialized on the UI thread
            using (Control init = new Control())
            {
                IntPtr unused = init.Handle;
            }
            _uiSync = SynchronizationContext.Current;

            _iconSafe = TrayIconFactory.CreateStatusIcon(Color.FromArgb(22, 163, 74), Color.FromArgb(15, 118, 52));
            _iconAlert = TrayIconFactory.CreateStatusIcon(Color.FromArgb(220, 38, 38), Color.FromArgb(153, 27, 27));
            _iconPaused = TrayIconFactory.CreateStatusIcon(Color.FromArgb(107, 114, 128), Color.FromArgb(75, 85, 99));

            _statusItem = new ToolStripMenuItem("状态: 正在检测...") { Enabled = false };
            _lastKillItem = new ToolStripMenuItem("拦截记录: 暂无") { Enabled = false };

            _toggleMonitorItem = new ToolStripMenuItem("启用实时监控") { Checked = true };
            _toggleMonitorItem.Click += OnToggleMonitorClick;

            _autoStartItem = new ToolStripMenuItem("开机自动启动") { Checked = StartupManager.IsAutoStartEnabled() };
            _autoStartItem.Click += OnToggleAutoStartClick;

            ToolStripMenuItem exitItem = new ToolStripMenuItem("退出");
            exitItem.Click += OnExitClick;

            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add(_statusItem);
            menu.Items.Add(_lastKillItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(_toggleMonitorItem);
            menu.Items.Add(_autoStartItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(exitItem);

            _trayIcon = new NotifyIcon
            {
                Icon = _iconSafe,
                Text = "Clash TUN 守护 | 初始化中...",
                ContextMenuStrip = menu,
                Visible = true
            };
            _trayIcon.DoubleClick += OnTrayDoubleClick;

            // Listen for duplicate-launch ping so clicking the desktop shortcut shows status
            _pingEvent = CreatePingEvent(pingEventName);
            _pingThread = new Thread(PingListenerLoop) { IsBackground = true, Name = "PingListener" };
            _pingThread.Start();

            SystemEvents.SessionEnding += OnSessionEnding;

            _monitor = new TunMonitor();
            _monitor.StatusChanged += OnMonitorStatusChanged;
            _monitor.AntigravityKilled += OnAntigravityKilled;
            _monitor.Start();
        }

        private static EventWaitHandle CreatePingEvent(string name)
        {
            try
            {
                EventWaitHandleSecurity sec = new EventWaitHandleSecurity();
                SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
                if (user != null)
                {
                    sec.AddAccessRule(new EventWaitHandleAccessRule(
                        user,
                        EventWaitHandleRights.Modify | EventWaitHandleRights.Synchronize,
                        AccessControlType.Allow));
                }
                bool created;
                return new EventWaitHandle(false, EventResetMode.AutoReset, name, out created, sec);
            }
            catch
            {
                return new EventWaitHandle(false, EventResetMode.AutoReset, name);
            }
        }

        private void PingListenerLoop()
        {
            WaitHandle[] handles = new WaitHandle[] { _pingEvent, _pingStop.WaitHandle };
            while (WaitHandle.WaitAny(handles) == 0)
            {
                PostToUi(() => ShowStatusBalloon("Clash TUN 守护已在后台运行"));
            }
        }

        private void OnMonitorStatusChanged(TunStatus status)
        {
            PostToUi(() => UpdateTrayUi(status));
        }

        private void OnAntigravityKilled(KillResult result, string trigger)
        {
            int count = Interlocked.Increment(ref _totalKills);
            string timeText = DateTime.Now.ToString("HH:mm:ss");
            PostToUi(() =>
            {
                _lastKillItem.Text = string.Format("上次拦截: {0} ({1}进程, {2:F1}ms)", timeText, result.KilledCount, result.ElapsedMs);
                _trayIcon.ShowBalloonTip(
                    2500,
                    "TUN 已关闭 — 已终止 Antigravity",
                    string.Format("触发源: {0}\n已终止 {1} 个进程，耗时 {2:F2} ms (累计拦截 {3} 次)", trigger, result.KilledCount, result.ElapsedMs, count),
                    ToolTipIcon.Warning);
            });
        }

        private void UpdateTrayUi(TunStatus status)
        {
            if (_disposed)
            {
                return;
            }

            if (!_monitor.MonitoringEnabled)
            {
                _trayIcon.Icon = _iconPaused;
                _trayIcon.Text = "Clash TUN 守护 | 已暂停监控";
                _statusItem.Text = "状态: 已暂停 (" + status.Reason + ")";
                return;
            }

            if (status.IsTunActive)
            {
                _trayIcon.Icon = _iconSafe;
                string tip = "Clash TUN 守护 | TUN: 已开启 (" + status.AdapterAlias + ")";
                _trayIcon.Text = tip.Length > 63 ? tip.Substring(0, 63) : tip;
                _statusItem.Text = "状态: TUN 已开启 (" + status.AdapterAlias + ")";
            }
            else
            {
                _trayIcon.Icon = _iconAlert;
                _trayIcon.Text = "Clash TUN 守护 | TUN: 已关闭 (禁止启动)";
                _statusItem.Text = "状态: TUN 已关闭 (" + status.Reason + ")";
            }
        }

        private void OnTrayDoubleClick(object sender, EventArgs e)
        {
            ShowStatusBalloon("Clash TUN 守护状态");
        }

        private void ShowStatusBalloon(string title)
        {
            if (_disposed)
            {
                return;
            }
            TunStatus s = _monitor.CurrentStatus;
            string mode = _monitor.MonitoringEnabled ? "实时监控中" : "已暂停监控";
            string state = s.IsTunActive ? ("TUN 已开启 (" + s.AdapterAlias + ")") : ("TUN 已关闭 (" + s.Reason + ")");
            _trayIcon.ShowBalloonTip(2000, title, mode + "\n" + state, s.IsTunActive ? ToolTipIcon.Info : ToolTipIcon.Warning);
        }

        private void OnToggleMonitorClick(object sender, EventArgs e)
        {
            bool next = !_monitor.MonitoringEnabled;
            _monitor.MonitoringEnabled = next;
            _toggleMonitorItem.Checked = next;
            UpdateTrayUi(_monitor.CurrentStatus);
        }

        private void OnToggleAutoStartClick(object sender, EventArgs e)
        {
            bool target = !_autoStartItem.Checked;
            bool ok = StartupManager.SetAutoStart(target);
            _autoStartItem.Checked = StartupManager.IsAutoStartEnabled();
            if (!ok)
            {
                _trayIcon.ShowBalloonTip(2500, "开机自启设置失败", "请以管理员权限运行后重试。", ToolTipIcon.Error);
            }
        }

        private void OnSessionEnding(object sender, SessionEndingEventArgs e)
        {
            ExitCleanly();
        }

        private void OnExitClick(object sender, EventArgs e)
        {
            ExitCleanly();
        }

        private void ExitCleanly()
        {
            Dispose(true);
            ExitThread();
        }

        private void PostToUi(Action action)
        {
            if (_disposed)
            {
                return;
            }
            try
            {
                _uiSync.Post(_ =>
                {
                    if (!_disposed)
                    {
                        action();
                    }
                }, null);
            }
            catch
            {
                // Ignore during teardown
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;
                if (disposing)
                {
                    SystemEvents.SessionEnding -= OnSessionEnding;
                    _pingStop.Set();
                    _monitor.Dispose();
                    if (_trayIcon != null)
                    {
                        _trayIcon.Visible = false;
                        _trayIcon.Dispose();
                    }
                    _iconSafe.Dispose();
                    _iconAlert.Dispose();
                    _iconPaused.Dispose();
                    _pingEvent.Dispose();
                    _pingStop.Dispose();
                }
            }
            base.Dispose(disposing);
        }
    }
}
