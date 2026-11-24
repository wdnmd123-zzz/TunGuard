using System;
using System.Collections.Generic;
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
            Mutex mutex;
            if (!TryAcquireSingleInstanceMutex(out mutex))
            {
                SignalExistingInstance();
                return;
            }

            using (mutex)
            {
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

        private static bool TryAcquireSingleInstanceMutex(out Mutex mutex)
        {
            mutex = null;
            bool createdNew;
            try
            {
                try
                {
                    MutexSecurity sec = new MutexSecurity();
                    SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
                    if (user != null)
                    {
                        sec.AddAccessRule(new MutexAccessRule(
                            user,
                            MutexRights.FullControl,
                            AccessControlType.Allow));
                    }
                    mutex = new Mutex(true, MutexName, out createdNew, sec);
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch
                {
                    mutex = new Mutex(true, MutexName, out createdNew);
                }

                if (!createdNew)
                {
                    mutex.Dispose();
                    mutex = null;
                    return false;
                }
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                // Existing instance likely runs at a higher integrity level
                if (mutex != null)
                {
                    mutex.Dispose();
                    mutex = null;
                }
                return false;
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
        public int AccessDeniedCount;
        public double FirstPassMs;
        public double TotalElapsedMs;
    }

    internal sealed class AntigravityKiller
    {
        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private const uint PROCESS_TERMINATE = 0x0001;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const int ERROR_ACCESS_DENIED = 5;

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
        private static extern bool K32EnumProcesses(
            [Out] uint[] lpidProcess,
            uint cb,
            out uint lpcbNeeded);

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

        // Reusable buffers (used exclusively by the single TunMonitor evaluation thread)
        private readonly StringBuilder _pathBuf = new StringBuilder(2048);
        private readonly List<uint> _langServerCandidates = new List<uint>(16);
        private uint[] _pidBuffer = new uint[1024];
        private HashSet<uint> _prevBenignPids = new HashSet<uint>();
        private HashSet<uint> _nextBenignPids = new HashSet<uint>();
        private bool _benignCacheValid;

        public void InvalidateCache()
        {
            _benignCacheValid = false;
            _prevBenignPids.Clear();
            _nextBenignPids.Clear();
        }

        public KillResult KillAllNow()
        {
            Stopwatch sw = Stopwatch.StartNew();
            int accessDenied;
            int totalKilled = KillFullPass(true, out accessDenied);
            double firstPassMs = sw.Elapsed.TotalMilliseconds;

            // If processes were killed, do one rapid sweep 5ms later to catch any racing child spawn.
            if (totalKilled > 0)
            {
                Thread.Sleep(5);
                int followUpDenied;
                totalKilled += KillFullPass(true, out followUpDenied);
                accessDenied += followUpDenied;
            }

            sw.Stop();
            return new KillResult
            {
                KilledCount = totalKilled,
                AccessDeniedCount = accessDenied,
                FirstPassMs = firstPassMs,
                TotalElapsedMs = sw.Elapsed.TotalMilliseconds
            };
        }

        public KillResult KillNewProcesses()
        {
            if (!_benignCacheValid)
            {
                return KillAllNow();
            }

            Stopwatch sw = Stopwatch.StartNew();
            int pidCount;
            if (!EnumerateProcessIds(out pidCount))
            {
                // Fallback to full snapshot if K32EnumProcesses fails
                return KillAllNow();
            }

            int killed = 0;
            int accessDenied = 0;
            _nextBenignPids.Clear();

            for (int i = 0; i < pidCount; i++)
            {
                uint pid = _pidBuffer[i];
                if (pid == 0 || pid == SelfPid)
                {
                    continue;
                }

                if (_prevBenignPids.Contains(pid))
                {
                    _nextBenignPids.Add(pid);
                    continue;
                }

                bool isBenign;
                InspectAndKillPid(pid, false, true, ref killed, ref accessDenied, out isBenign);
                if (isBenign)
                {
                    _nextBenignPids.Add(pid);
                }
            }

            HashSet<uint> swap = _prevBenignPids;
            _prevBenignPids = _nextBenignPids;
            _nextBenignPids = swap;

            double firstPassMs = sw.Elapsed.TotalMilliseconds;

            // If any new target process was killed, do a full follow-up sweep 5ms later for racing children.
            if (killed > 0)
            {
                Thread.Sleep(5);
                int followUpDenied;
                killed += KillFullPass(true, out followUpDenied);
                accessDenied += followUpDenied;
            }

            sw.Stop();
            return new KillResult
            {
                KilledCount = killed,
                AccessDeniedCount = accessDenied,
                FirstPassMs = firstPassMs,
                TotalElapsedMs = sw.Elapsed.TotalMilliseconds
            };
        }

        private bool EnumerateProcessIds(out int count)
        {
            count = 0;
            for (int attempt = 0; attempt < 4; attempt++)
            {
                uint cb = (uint)(_pidBuffer.Length * sizeof(uint));
                uint needed;
                if (!K32EnumProcesses(_pidBuffer, cb, out needed))
                {
                    return false;
                }

                if (needed < cb || _pidBuffer.Length >= 65536)
                {
                    count = (int)(needed / sizeof(uint));
                    return true;
                }

                _pidBuffer = new uint[Math.Min(_pidBuffer.Length * 2, 65536)];
            }
            return false;
        }

        private int KillFullPass(bool updateBenignCache, out int accessDenied)
        {
            int killed = 0;
            accessDenied = 0;
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
            {
                return 0;
            }

            _langServerCandidates.Clear();
            if (updateBenignCache)
            {
                _nextBenignPids.Clear();
            }

            try
            {
                PROCESSENTRY32W pe = new PROCESSENTRY32W();
                pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));

                if (!Process32FirstW(snapshot, ref pe))
                {
                    return 0;
                }

                // Pass 1: terminate Antigravity.exe immediately (parent/main before child language servers)
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
                        TryTerminateKnownTarget(pid, ref killed, ref accessDenied);
                    }
                    else if (IsLanguageServerExeName(exe))
                    {
                        _langServerCandidates.Add(pid);
                    }
                    else if (updateBenignCache)
                    {
                        _nextBenignPids.Add(pid);
                    }
                }
                while (Process32NextW(snapshot, ref pe));
            }
            finally
            {
                CloseHandle(snapshot);
            }

            // Pass 2: verify and terminate language_server*.exe belonging to Antigravity
            for (int i = 0; i < _langServerCandidates.Count; i++)
            {
                uint pid = _langServerCandidates[i];
                bool isBenign;
                InspectAndKillPid(pid, true, false, ref killed, ref accessDenied, out isBenign);
                if (updateBenignCache && isBenign)
                {
                    _nextBenignPids.Add(pid);
                }
            }

            if (updateBenignCache)
            {
                HashSet<uint> swap = _prevBenignPids;
                _prevBenignPids = _nextBenignPids;
                _nextBenignPids = swap;
                _benignCacheValid = true;
            }

            return killed;
        }

        private void TryTerminateKnownTarget(uint pid, ref int killed, ref int accessDenied)
        {
            IntPtr hProc = OpenProcess(PROCESS_TERMINATE, false, pid);
            if (hProc == IntPtr.Zero)
            {
                if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                {
                    accessDenied++;
                }
                return;
            }

            try
            {
                if (TerminateProcess(hProc, 1))
                {
                    killed++;
                }
                else if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                {
                    accessDenied++;
                }
            }
            finally
            {
                CloseHandle(hProc);
            }
        }

        private void InspectAndKillPid(
            uint pid,
            bool languageServerPathOnly,
            bool markProtectedAsBenign,
            ref int killed,
            ref int accessDenied,
            out bool isBenign)
        {
            isBenign = false;
            IntPtr hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProc != IntPtr.Zero)
            {
                try
                {
                    string fullPath = QueryImagePath(hProc);
                    if (fullPath == null)
                    {
                        return;
                    }

                    bool isTarget = languageServerPathOnly ? IsAntigravityPath(fullPath) : IsTargetImagePath(fullPath);
                    if (isTarget)
                    {
                        if (TerminateProcess(hProc, 1))
                        {
                            killed++;
                        }
                        else if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                        {
                            accessDenied++;
                        }
                    }
                    else
                    {
                        isBenign = true;
                    }
                }
                finally
                {
                    CloseHandle(hProc);
                }
                return;
            }

            if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
            {
                IntPtr hQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hQuery != IntPtr.Zero)
                {
                    try
                    {
                        string fullPath = QueryImagePath(hQuery);
                        if (fullPath != null)
                        {
                            bool isTarget = languageServerPathOnly ? IsAntigravityPath(fullPath) : IsTargetImagePath(fullPath);
                            if (isTarget)
                            {
                                accessDenied++;
                            }
                            else
                            {
                                isBenign = true;
                            }
                        }
                    }
                    finally
                    {
                        CloseHandle(hQuery);
                    }
                }
                else if (markProtectedAsBenign && Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                {
                    // System / PPL protected process; mark benign for fast-path (periodic full scan still checks exe name)
                    isBenign = true;
                }
            }
        }

        private string QueryImagePath(IntPtr hProc)
        {
            _pathBuf.Clear();
            uint size = (uint)_pathBuf.Capacity;
            if (!QueryFullProcessImageNameW(hProc, 0, _pathBuf, ref size))
            {
                return null;
            }
            return _pathBuf.ToString();
        }

        private static bool IsLanguageServerExeName(string exe)
        {
            return exe.StartsWith("language_server", StringComparison.OrdinalIgnoreCase) &&
                   exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsAntigravityPath(string fullPath)
        {
            return fullPath.IndexOf("\\antigravity\\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsTargetImagePath(string fullPath)
        {
            int lastSlash = fullPath.LastIndexOf('\\');
            string exe = lastSlash >= 0 ? fullPath.Substring(lastSlash + 1) : fullPath;
            if (string.Equals(exe, "Antigravity.exe", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            return IsLanguageServerExeName(exe) && IsAntigravityPath(fullPath);
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
        private const byte IF_ROW_FLAG_FILTER = 0x02;
        private const byte IF_ROW_FLAG_PAUSED = 0x20;
        private const int IF_ROW_OPER_STATUS_OFFSET = 1156;
        private const int IF_ROW_MEDIA_STATE_OFFSET = 1164;

        // Verified x64 Windows MIB_IPFORWARD_TABLE2 / MIB_IPFORWARD_ROW2 offsets
        private const int FWD_TABLE_ENTRIES_OFFSET = 8;
        private const int FWD_ROW_SIZE = 104;
        private const int FWD_ROW_IFINDEX_OFFSET = 8;
        private const int FWD_ROW_DEST_FAMILY_OFFSET = 12;
        private const int FWD_ROW_DEST_ADDR_OFFSET = 16;
        private const int FWD_ROW_PREFIXLEN_OFFSET = 40;

        private const int ACTIVE_INTERVAL_MS = 100;
        private const int INACTIVE_GUARD_INTERVAL_MS = 30;
        private const int PAUSED_INTERVAL_MS = 500;
        private const int CONFIG_STAT_INTERVAL_MS = 1000;
        private const int INACTIVE_ADAPTER_POLL_MS = 500;
        private const int INACTIVE_FULL_KILL_SCAN_MS = 1500;
        private const int WATCHER_RETRY_INTERVAL_MS = 5000;

        private static readonly byte[] ZeroIfRowTemplate = new byte[IF_ROW_SIZE];
        private static readonly int[] FileRetryDelaysMs = new int[] { 1, 2, 3, 5, 5 };

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

        // Single-threaded monitor/killer resources owned by Start() -> _watchdogThread
        private readonly AntigravityKiller _killer = new AntigravityKiller();
        private IntPtr _ifRowBuffer;

        // Lightweight signal state between callbacks and _watchdogThread (held for nanoseconds)
        private readonly object _signalLock = new object();
        private bool _pendingVergeReload;
        private bool _pendingClashReload;
        private bool _pendingAdapterRecheck;
        private bool _pendingFullProcessScan;
        private bool _watcherNeedsRestart;
        private string _pendingTriggerSource;

        // Cached parsed config values & file metadata (owned by _watchdogThread after Start())
        private bool? _vergeEnableTun;
        private bool _clashAutoRoute = true;
        private string _customTunDevice;
        private bool _vergeStatValid;
        private bool _vergeLastExists;
        private long _vergeLastWriteTicks;
        private long _vergeLastLength;
        private bool _clashStatValid;
        private bool _clashLastExists;
        private long _clashLastWriteTicks;
        private long _clashLastLength;

        private readonly object _statusLock = new object();
        private TunStatus _currentStatus;
        private volatile bool _running;
        private volatile bool _disposed;
        private volatile bool _monitoringEnabled = true;
        private volatile bool _isTunActive;
        private volatile uint _lastKnownTunIfIndex;

        private Thread _watchdogThread;
        private readonly ManualResetEvent _stopEvent = new ManualResetEvent(false);
        private readonly AutoResetEvent _wakeEvent = new AutoResetEvent(false);

        public event Action<TunStatus> StatusChanged;
        public event Action<KillResult, string> AntigravityKilled;
        public event Action<int, string> AccessDenied;

        public bool MonitoringEnabled
        {
            get { return _monitoringEnabled; }
            set
            {
                _monitoringEnabled = value;
                if (value)
                {
                    SignalWake("恢复监控", true, true, true, true);
                }
                else
                {
                    // Wake watchdog so it can immediately switch to low-frequency paused cadence
                    SignalWake(null, false, false, false, false);
                }
            }
        }

        public TunStatus CurrentStatus
        {
            get
            {
                lock (_statusLock)
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
            _ifRowBuffer = Marshal.AllocHGlobal(IF_ROW_SIZE);
        }

        public void Start()
        {
            if (_running || _disposed)
            {
                return;
            }
            _running = true;

            ReadVergeYamlSafe(true);
            ReadClashYamlSafe(true);
            bool unusedFullScan;
            EvaluateAndEnforce("初始检查", true, true, true, out unusedFullScan);

            // 1. Kernel IP interface change notification (< 1ms; callback only signals wake event)
            NotifyIpInterfaceChange(AF_UNSPEC, _ifaceCallback, IntPtr.Zero, false, out _ifaceNotifyHandle);

            // 2. Kernel IPv4 route change notification (< 1ms; callback only signals wake event)
            NotifyRouteChange2(AF_INET, _routeCallback, IntPtr.Zero, false, out _routeNotifyHandle);

            // 3. Clash Verge config watcher (< 1ms on UI toggle, often BEFORE adapter teardown)
            EnsureConfigWatcher();

            // 4. Dedicated high-priority watchdog & event-processing thread (immune to UI loops & NSI deadlocks)
            _watchdogThread = new Thread(WatchdogLoop)
            {
                Name = "TunWatchdog",
                IsBackground = true,
                Priority = ThreadPriority.Highest
            };
            _watchdogThread.Start();
        }

        private void EnsureConfigWatcher()
        {
            DisposeConfigWatcher();

            if (!Directory.Exists(_configDir))
            {
                return;
            }

            try
            {
                FileSystemWatcher watcher = new FileSystemWatcher(_configDir)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime,
                    IncludeSubdirectories = false
                };
                watcher.Changed += OnConfigFileEvent;
                watcher.Created += OnConfigFileEvent;
                watcher.Deleted += OnConfigFileEvent;
                watcher.Renamed += OnConfigFileRenamed;
                watcher.Error += OnConfigWatcherError;
                watcher.EnableRaisingEvents = true;
                _watcher = watcher;
            }
            catch
            {
                // Kernel adapter/route monitoring still works even if FileSystemWatcher cannot attach
            }
        }

        private void DisposeConfigWatcher()
        {
            FileSystemWatcher watcher = _watcher;
            _watcher = null;
            if (watcher != null)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Changed -= OnConfigFileEvent;
                    watcher.Created -= OnConfigFileEvent;
                    watcher.Deleted -= OnConfigFileEvent;
                    watcher.Renamed -= OnConfigFileRenamed;
                    watcher.Error -= OnConfigWatcherError;
                    watcher.Dispose();
                }
                catch
                {
                }
            }
        }

        private void OnConfigFileEvent(object sender, FileSystemEventArgs e)
        {
            if (!_running || !IsRelevantConfigFile(e.Name))
            {
                return;
            }
            SignalConfigFileChange(e.Name);
        }

        private void OnConfigFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!_running)
            {
                return;
            }
            if (IsRelevantConfigFile(e.Name))
            {
                SignalConfigFileChange(e.Name);
            }
            else if (IsRelevantConfigFile(e.OldName))
            {
                SignalConfigFileChange(e.OldName);
            }
        }

        private void OnConfigWatcherError(object sender, ErrorEventArgs e)
        {
            if (!_running)
            {
                return;
            }
            lock (_signalLock)
            {
                _watcherNeedsRestart = true;
                _pendingVergeReload = true;
                _pendingClashReload = true;
                _pendingAdapterRecheck = true;
            }
            TrySetWakeEvent();
        }

        private static bool IsRelevantConfigFile(string name)
        {
            return string.Equals(name, "verge.yaml", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "clash-verge.yaml", StringComparison.OrdinalIgnoreCase);
        }

        private void SignalConfigFileChange(string fileName)
        {
            bool isVerge = string.Equals(fileName, "verge.yaml", StringComparison.OrdinalIgnoreCase);
            SignalWake("配置变更: " + fileName, isVerge, !isVerge, true, false);
        }

        private void OnIpInterfaceChanged(IntPtr callerContext, IntPtr row, int notificationType)
        {
            if (!_running)
            {
                return;
            }
            // Never call IP Helper APIs or block inside NSI notification callbacks; wake watchdog instead.
            SignalWake("网卡状态变更", false, false, true, false);
        }

        private void OnRouteChanged(IntPtr callerContext, IntPtr row, int notificationType)
        {
            if (!_running)
            {
                return;
            }

            // Fast-path filter: ignore non-default routes (> /1) and unrelated interfaces while TUN is active
            if (row != IntPtr.Zero)
            {
                byte prefixLen = Marshal.ReadByte(row, FWD_ROW_PREFIXLEN_OFFSET);
                if (prefixLen > 1)
                {
                    return;
                }

                uint lastIf = _lastKnownTunIfIndex;
                if (_isTunActive && lastIf != 0)
                {
                    uint ifIdx = (uint)Marshal.ReadInt32(row, FWD_ROW_IFINDEX_OFFSET);
                    if (ifIdx != lastIf)
                    {
                        return;
                    }
                }
            }

            SignalWake("路由表变更", false, false, true, false);
        }

        private void SignalWake(
            string triggerSource,
            bool reloadVerge,
            bool reloadClash,
            bool recheckAdapter,
            bool fullProcessScan)
        {
            if (!_running)
            {
                return;
            }

            lock (_signalLock)
            {
                if (reloadVerge) _pendingVergeReload = true;
                if (reloadClash) _pendingClashReload = true;
                if (recheckAdapter) _pendingAdapterRecheck = true;
                if (fullProcessScan) _pendingFullProcessScan = true;
                if (!string.IsNullOrEmpty(triggerSource))
                {
                    _pendingTriggerSource = triggerSource;
                }
            }

            TrySetWakeEvent();
        }

        private void TrySetWakeEvent()
        {
            if (!_running || _disposed)
            {
                return;
            }
            try
            {
                _wakeEvent.Set();
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private void WatchdogLoop()
        {
            WaitHandle[] waitHandles = new WaitHandle[] { _stopEvent, _wakeEvent };
            Stopwatch clock = Stopwatch.StartNew();
            long lastConfigStatMs = 0;
            long lastAdapterCheckMs = 0;
            long lastFullScanMs = 0;
            long lastWatcherRetryMs = 0;

            while (_running)
            {
                bool monitoring = _monitoringEnabled;
                bool active = _isTunActive;
                int intervalMs = !monitoring
                    ? PAUSED_INTERVAL_MS
                    : (active ? ACTIVE_INTERVAL_MS : INACTIVE_GUARD_INTERVAL_MS);

                int waited;
                try
                {
                    waited = WaitHandle.WaitAny(waitHandles, intervalMs);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                if (waited == 0 || !_running)
                {
                    break;
                }

                long nowMs = clock.ElapsedMilliseconds;

                bool reloadVerge;
                bool reloadClash;
                bool recheckAdapter;
                bool forceFullScan;
                bool restartWatcher;
                string triggerSource;

                lock (_signalLock)
                {
                    reloadVerge = _pendingVergeReload;
                    reloadClash = _pendingClashReload;
                    recheckAdapter = _pendingAdapterRecheck;
                    forceFullScan = _pendingFullProcessScan;
                    restartWatcher = _watcherNeedsRestart;
                    triggerSource = _pendingTriggerSource;

                    _pendingVergeReload = false;
                    _pendingClashReload = false;
                    _pendingAdapterRecheck = false;
                    _pendingFullProcessScan = false;
                    _watcherNeedsRestart = false;
                    _pendingTriggerSource = null;
                }

                if (restartWatcher || (_watcher == null && (nowMs - lastWatcherRetryMs >= WATCHER_RETRY_INTERVAL_MS)))
                {
                    lastWatcherRetryMs = nowMs;
                    EnsureConfigWatcher();
                }

                if (reloadVerge)
                {
                    ReadVergeYamlSafe(true);
                    lastConfigStatMs = nowMs;
                }
                if (reloadClash)
                {
                    ReadClashYamlSafe(true);
                    lastConfigStatMs = nowMs;
                }
                if (!reloadVerge && !reloadClash && (nowMs - lastConfigStatMs >= CONFIG_STAT_INTERVAL_MS))
                {
                    lastConfigStatMs = nowMs;
                    bool vergeChanged = ReadVergeYamlSafe(false);
                    bool clashChanged = ReadClashYamlSafe(false);
                    if (vergeChanged || clashChanged)
                    {
                        recheckAdapter = true;
                    }
                }

                bool shouldCheckAdapter =
                    active ||
                    recheckAdapter ||
                    (nowMs - lastAdapterCheckMs >= INACTIVE_ADAPTER_POLL_MS);

                bool shouldFullScan =
                    forceFullScan ||
                    (monitoring && !active && (nowMs - lastFullScanMs >= INACTIVE_FULL_KILL_SCAN_MS));

                if (shouldCheckAdapter)
                {
                    lastAdapterCheckMs = nowMs;
                }

                string source = !string.IsNullOrEmpty(triggerSource) ? triggerSource : "定时巡检";
                bool ranFullScan;
                EvaluateAndEnforce(source, false, shouldCheckAdapter, shouldFullScan, out ranFullScan);
                if (ranFullScan)
                {
                    lastFullScanMs = nowMs;
                }
            }
        }

        private void EvaluateAndEnforce(
            string triggerSource,
            bool forceNotify,
            bool checkAdapter,
            bool fullProcessScan,
            out bool ranFullScan)
        {
            ranFullScan = false;
            TunStatus prev = _currentStatus;
            bool wasActive = _isTunActive;

            TunStatus next = QueryTunStatus(checkAdapter, prev);

            if (!next.AdapterUp)
            {
                _lastKnownTunIfIndex = 0;
            }
            else if (next.AdapterIndex != 0)
            {
                _lastKnownTunIfIndex = next.AdapterIndex;
            }

            // Enforce BEFORE firing UI events so zero milliseconds are wasted on UI updates
            KillResult killRes = default(KillResult);
            if (_monitoringEnabled && !next.IsTunActive)
            {
                bool becameInactive = wasActive && !next.IsTunActive;
                if (becameInactive || fullProcessScan)
                {
                    killRes = _killer.KillAllNow();
                    ranFullScan = true;
                }
                else
                {
                    killRes = _killer.KillNewProcesses();
                }
            }
            else if (next.IsTunActive && !wasActive)
            {
                _killer.InvalidateCache();
            }

            bool changed = forceNotify ||
                           next.IsTunActive != prev.IsTunActive ||
                           !string.Equals(next.AdapterAlias, prev.AdapterAlias, StringComparison.Ordinal) ||
                           !string.Equals(next.Reason, prev.Reason, StringComparison.Ordinal);

            _isTunActive = next.IsTunActive;
            lock (_statusLock)
            {
                _currentStatus = next;
            }

            if (killRes.KilledCount > 0)
            {
                Action<KillResult, string> killedHandler = AntigravityKilled;
                if (killedHandler != null)
                {
                    killedHandler(killRes, triggerSource);
                }
            }

            if (killRes.AccessDeniedCount > 0)
            {
                Action<int, string> deniedHandler = AccessDenied;
                if (deniedHandler != null)
                {
                    deniedHandler(killRes.AccessDeniedCount, triggerSource);
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

        private TunStatus QueryTunStatus(bool checkAdapter, TunStatus previous)
        {
            bool? vergeEnable = _vergeEnableTun;
            bool autoRoute = _clashAutoRoute;
            string customDevice = _customTunDevice;

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

            // While TUN is already inactive, skip redundant GetIfTable2Ex on 30ms process-guard ticks
            if (!checkAdapter && !previous.IsTunActive && previous.ConfigEnabled)
            {
                return previous;
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

            bool isActive = adapterUp && (!autoRoute || hasRoute);
            string reason;
            if (isActive)
            {
                reason = "TUN 正常 (" + tunAlias + ")";
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
                ConfigEnabled = true,
                AdapterUp = adapterUp,
                HasDefaultRoute = hasRoute,
                AutoRouteRequired = autoRoute,
                AdapterIndex = tunIfIndex,
                AdapterAlias = tunAlias ?? string.Empty,
                Reason = reason
            };
        }

        private bool TryCheckCachedTunAdapter(uint cachedIfIndex, string customDevice, out uint ifIndex, out string alias)
        {
            ifIndex = 0;
            alias = string.Empty;
            if (cachedIfIndex == 0 || _ifRowBuffer == IntPtr.Zero)
            {
                return false;
            }

            // Zero reusable MIB_IF_ROW2 buffer (no heap alloc/free per check) and set InterfaceIndex
            Marshal.Copy(ZeroIfRowTemplate, 0, _ifRowBuffer, IF_ROW_SIZE);
            Marshal.WriteInt32(_ifRowBuffer, IF_ROW_INDEX_OFFSET, (int)cachedIfIndex);

            if (GetIfEntry2(_ifRowBuffer) != 0)
            {
                return false;
            }

            byte flags = Marshal.ReadByte(_ifRowBuffer, IF_ROW_FLAGS_OFFSET);
            if ((flags & (IF_ROW_FLAG_FILTER | IF_ROW_FLAG_PAUSED)) != 0)
            {
                return false;
            }

            int operStatus = Marshal.ReadInt32(_ifRowBuffer, IF_ROW_OPER_STATUS_OFFSET);
            int mediaState = Marshal.ReadInt32(_ifRowBuffer, IF_ROW_MEDIA_STATE_OFFSET);
            if (operStatus != 1 || mediaState != 1)
            {
                return false;
            }

            string rowAlias = Marshal.PtrToStringUni(IntPtr.Add(_ifRowBuffer, IF_ROW_ALIAS_OFFSET)) ?? string.Empty;
            string rowDesc = Marshal.PtrToStringUni(IntPtr.Add(_ifRowBuffer, IF_ROW_DESC_OFFSET)) ?? string.Empty;
            if (!IsClashTunAdapter(rowAlias, rowDesc, customDevice))
            {
                return false;
            }

            ifIndex = cachedIfIndex;
            alias = rowAlias;
            return true;
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

                    // Skip NDIS lightweight filter pseudo-interfaces (0x02) and paused interfaces (0x20)
                    byte flags = Marshal.ReadByte(row, IF_ROW_FLAGS_OFFSET);
                    if ((flags & (IF_ROW_FLAG_FILTER | IF_ROW_FLAG_PAUSED)) != 0)
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
            if (!string.IsNullOrEmpty(customDevice))
            {
                if (MatchesAdapterName(alias, customDevice) ||
                    desc.IndexOf(customDevice + " Tunnel", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            if (MatchesAdapterName(alias, "Meta") ||
                MatchesAdapterName(alias, "Mihomo") ||
                MatchesAdapterName(alias, "Clash") ||
                MatchesAdapterName(alias, "Clash Verge"))
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

        private static bool MatchesAdapterName(string alias, string baseName)
        {
            if (string.IsNullOrEmpty(alias) || string.IsNullOrEmpty(baseName))
            {
                return false;
            }
            if (string.Equals(alias, baseName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            // Match Windows duplicate Wintun adapter naming such as "Mihomo 2", "Meta 3"
            if (alias.Length > baseName.Length + 1 &&
                alias.StartsWith(baseName, StringComparison.OrdinalIgnoreCase) &&
                alias[baseName.Length] == ' ')
            {
                for (int i = baseName.Length + 1; i < alias.Length; i++)
                {
                    char c = alias[i];
                    if (c < '0' || c > '9')
                    {
                        return false;
                    }
                }
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
                bool hasLowerHalf = false;
                bool hasUpperHalf = false;

                for (int i = 0; i < count; i++)
                {
                    IntPtr row = IntPtr.Add(rowBase, i * FWD_ROW_SIZE);
                    uint ifIdx = (uint)Marshal.ReadInt32(row, FWD_ROW_IFINDEX_OFFSET);
                    if (ifIdx != targetIfIndex)
                    {
                        continue;
                    }

                    ushort family = (ushort)Marshal.ReadInt16(row, FWD_ROW_DEST_FAMILY_OFFSET);
                    if (family != AF_INET)
                    {
                        continue;
                    }

                    byte prefixLen = Marshal.ReadByte(row, FWD_ROW_PREFIXLEN_OFFSET);
                    if (prefixLen == 0)
                    {
                        if (Marshal.ReadInt32(row, FWD_ROW_DEST_ADDR_OFFSET) == 0)
                        {
                            return true; // 0.0.0.0/0 covers full IPv4 space
                        }
                    }
                    else if (prefixLen == 1)
                    {
                        byte firstOctet = Marshal.ReadByte(row, FWD_ROW_DEST_ADDR_OFFSET);
                        if (firstOctet == 0)
                        {
                            hasLowerHalf = true; // 0.0.0.0/1
                        }
                        else if (firstOctet == 128)
                        {
                            hasUpperHalf = true; // 128.0.0.0/1
                        }

                        if (hasLowerHalf && hasUpperHalf)
                        {
                            return true; // Both /1 halves present => full IPv4 space covered
                        }
                    }
                }
            }
            finally
            {
                FreeMibTable(pTable);
            }

            return false;
        }

        private bool ReadVergeYamlSafe(bool force)
        {
            bool exists;
            long writeTicks;
            long length;
            GetFileStat(_vergeYamlPath, out exists, out writeTicks, out length);

            if (!force && _vergeStatValid &&
                exists == _vergeLastExists &&
                writeTicks == _vergeLastWriteTicks &&
                length == _vergeLastLength)
            {
                return false;
            }

            if (!exists)
            {
                _vergeStatValid = true;
                _vergeLastExists = false;
                _vergeLastWriteTicks = 0;
                _vergeLastLength = 0;
                bool changed = _vergeEnableTun.HasValue;
                _vergeEnableTun = null;
                return changed;
            }

            string content = ReadAllTextRetry(_vergeYamlPath);
            if (string.IsNullOrEmpty(content))
            {
                return false; // Keep previous value & stat during transient atomic write
            }

            // Re-stat after successful read so cache reflects the read file
            GetFileStat(_vergeYamlPath, out exists, out writeTicks, out length);
            _vergeStatValid = true;
            _vergeLastExists = exists;
            _vergeLastWriteTicks = writeTicks;
            _vergeLastLength = length;

            bool? foundEnable = null;
            using (StringReader sr = new StringReader(content))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (CountLeadingSpaces(line) != 0)
                    {
                        continue;
                    }
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith("enable_tun_mode:", StringComparison.OrdinalIgnoreCase))
                    {
                        string val = StripYamlComment(trimmed.Substring("enable_tun_mode:".Length)).Trim().Trim('\'', '"');
                        bool parsed;
                        if (bool.TryParse(val, out parsed))
                        {
                            foundEnable = parsed;
                        }
                        break;
                    }
                }
            }

            bool valueChanged = (_vergeEnableTun != foundEnable);
            _vergeEnableTun = foundEnable;
            return valueChanged;
        }

        private bool ReadClashYamlSafe(bool force)
        {
            bool exists;
            long writeTicks;
            long length;
            GetFileStat(_clashYamlPath, out exists, out writeTicks, out length);

            if (!force && _clashStatValid &&
                exists == _clashLastExists &&
                writeTicks == _clashLastWriteTicks &&
                length == _clashLastLength)
            {
                return false;
            }

            if (!exists)
            {
                _clashStatValid = true;
                _clashLastExists = false;
                _clashLastWriteTicks = 0;
                _clashLastLength = 0;
                bool changed = (!_clashAutoRoute || _customTunDevice != null);
                _clashAutoRoute = true;
                _customTunDevice = null;
                return changed;
            }

            string content = ReadAllTextRetry(_clashYamlPath);
            if (string.IsNullOrEmpty(content))
            {
                return false;
            }

            GetFileStat(_clashYamlPath, out exists, out writeTicks, out length);
            _clashStatValid = true;
            _clashLastExists = exists;
            _clashLastWriteTicks = writeTicks;
            _clashLastLength = length;

            bool inTun = false;
            int tunChildIndent = -1;
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
                        string topKey = StripYamlComment(trimmed).Trim();
                        if (string.Equals(topKey, "tun:", StringComparison.OrdinalIgnoreCase))
                        {
                            inTun = true;
                        }
                        continue;
                    }

                    if (!inTun)
                    {
                        continue;
                    }

                    if (tunChildIndent < 0)
                    {
                        tunChildIndent = indent;
                    }
                    else if (indent != tunChildIndent)
                    {
                        continue;
                    }

                    if (trimmed.StartsWith("auto-route:", StringComparison.OrdinalIgnoreCase))
                    {
                        bool b;
                        string raw = StripYamlComment(trimmed.Substring("auto-route:".Length)).Trim().Trim('\'', '"');
                        if (bool.TryParse(raw, out b))
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

            // Reset to Clash defaults if tun: section or individual keys were removed
            bool nextAutoRoute = autoRouteVal.HasValue ? autoRouteVal.Value : true;
            string nextDevice = deviceVal;

            bool valueChanged = (_clashAutoRoute != nextAutoRoute) ||
                                !string.Equals(_customTunDevice, nextDevice, StringComparison.Ordinal);
            _clashAutoRoute = nextAutoRoute;
            _customTunDevice = nextDevice;
            return valueChanged;
        }

        private static void GetFileStat(string path, out bool exists, out long writeTicks, out long length)
        {
            try
            {
                FileInfo fi = new FileInfo(path);
                if (fi.Exists)
                {
                    exists = true;
                    writeTicks = fi.LastWriteTimeUtc.Ticks;
                    length = fi.Length;
                    return;
                }
            }
            catch
            {
            }
            exists = false;
            writeTicks = 0;
            length = 0;
        }

        private static string ReadAllTextRetry(string path)
        {
            for (int attempt = 0; attempt <= FileRetryDelaysMs.Length; attempt++)
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

                if (attempt < FileRetryDelaysMs.Length)
                {
                    Thread.Sleep(FileRetryDelaysMs[attempt]);
                }
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
            bool inSingle = false;
            bool inDouble = false;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\'' && !inDouble)
                {
                    inSingle = !inSingle;
                }
                else if (c == '"' && !inSingle)
                {
                    inDouble = !inDouble;
                }
                else if (c == '#' && !inSingle && !inDouble && (i == 0 || char.IsWhiteSpace(s[i - 1])))
                {
                    return s.Substring(0, i);
                }
            }
            return s;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            _running = false;
            _stopEvent.Set();

            DisposeConfigWatcher();

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

            bool watchdogExited = true;
            if (_watchdogThread != null && _watchdogThread.IsAlive)
            {
                watchdogExited = _watchdogThread.Join(1500);
            }

            if (watchdogExited)
            {
                _stopEvent.Dispose();
                _wakeEvent.Dispose();
                if (_ifRowBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(_ifRowBuffer);
                    _ifRowBuffer = IntPtr.Zero;
                }
            }
        }
    }

    internal static class StartupManager
    {
        public const string TaskName = "ClashTunGuard";

        public static bool IsAutoStartEnabled()
        {
            string xml;
            if (RunSchtasks("/Query /TN \"" + TaskName + "\" /XML", out xml) != 0 || string.IsNullOrEmpty(xml))
            {
                return false;
            }

            string command = ExtractXmlElementValue(xml, "Command");
            if (string.IsNullOrEmpty(command))
            {
                return false;
            }

            string taskExe = NormalizePath(command.Trim().Trim('"'));
            string currentExe = NormalizePath(Application.ExecutablePath);
            return string.Equals(taskExe, currentExe, StringComparison.OrdinalIgnoreCase);
        }

        private static bool TaskExists()
        {
            string unused;
            return RunSchtasks("/Query /TN \"" + TaskName + "\"", out unused) == 0;
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
                    string unused;
                    return RunSchtasks("/Create /TN \"" + TaskName + "\" /XML \"" + xmlPath + "\" /F", out unused) == 0;
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
                string unused;
                int rc = RunSchtasks("/Delete /TN \"" + TaskName + "\" /F", out unused);
                return rc == 0 || !TaskExists();
            }
        }

        private static string ExtractXmlElementValue(string xml, string tagName)
        {
            string openTag = "<" + tagName + ">";
            string closeTag = "</" + tagName + ">";
            int start = xml.IndexOf(openTag, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return null;
            }
            start += openTag.Length;
            int end = xml.IndexOf(closeTag, start, StringComparison.OrdinalIgnoreCase);
            if (end < 0)
            {
                return null;
            }
            string raw = xml.Substring(start, end - start);
            return raw
                .Replace("&quot;", "\"")
                .Replace("&apos;", "'")
                .Replace("&lt;", "<")
                .Replace("&gt;", ">")
                .Replace("&amp;", "&");
        }

        private static string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return string.Empty;
            }
            try
            {
                return Path.GetFullPath(path).TrimEnd('\\');
            }
            catch
            {
                return path.Trim();
            }
        }

        private static int RunSchtasks(string arguments, out string stdOut)
        {
            stdOut = string.Empty;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true
                };
                using (Process p = new Process { StartInfo = psi })
                {
                    StringBuilder output = new StringBuilder();
                    p.OutputDataReceived += (sender, e) =>
                    {
                        if (e.Data != null)
                        {
                            output.AppendLine(e.Data);
                        }
                    };

                    if (!p.Start())
                    {
                        return -1;
                    }
                    p.BeginOutputReadLine();

                    if (!p.WaitForExit(5000))
                    {
                        try
                        {
                            p.Kill();
                        }
                        catch
                        {
                        }
                        return -1;
                    }

                    // Ensure asynchronous output callbacks have flushed completely
                    p.WaitForExit();
                    stdOut = output.ToString();
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
        private static readonly long AccessDeniedNotifyCooldownTicks = TimeSpan.FromSeconds(10).Ticks;

        private readonly SynchronizationContext _uiSync;
        private readonly TunMonitor _monitor;
        private readonly ContextMenuStrip _menu;
        private readonly NotifyIcon _trayIcon;
        private readonly ToolStripMenuItem _statusItem;
        private readonly ToolStripMenuItem _lastKillItem;
        private readonly ToolStripMenuItem _toggleMonitorItem;
        private readonly ToolStripMenuItem _autoStartItem;

        private readonly Icon _iconSafe;
        private readonly Icon _iconAlert;
        private readonly Icon _iconPaused;

        private readonly EventWaitHandle _pingEvent;
        private readonly ManualResetEvent _pingStop = new ManualResetEvent(false);
        private readonly Thread _pingThread;

        private int _totalKills;
        private int _autoStartRefreshing;
        private int _autoStartToggling;
        private long _lastAccessDeniedNotifyTicks;
        private volatile bool _disposed;

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

            _autoStartItem = new ToolStripMenuItem("开机自动启动") { Checked = false };
            _autoStartItem.Click += OnToggleAutoStartClick;

            ToolStripMenuItem exitItem = new ToolStripMenuItem("退出");
            exitItem.Click += OnExitClick;

            _menu = new ContextMenuStrip();
            _menu.Items.Add(_statusItem);
            _menu.Items.Add(_lastKillItem);
            _menu.Items.Add(new ToolStripSeparator());
            _menu.Items.Add(_toggleMonitorItem);
            _menu.Items.Add(_autoStartItem);
            _menu.Items.Add(new ToolStripSeparator());
            _menu.Items.Add(exitItem);
            _menu.Opening += OnMenuOpening;

            // Keep tray icon hidden until initial TUN status is evaluated (avoids wrong-color flash)
            _trayIcon = new NotifyIcon
            {
                Icon = _iconPaused,
                Text = "Clash TUN 守护 | 初始化中...",
                ContextMenuStrip = _menu,
                Visible = false
            };
            _trayIcon.DoubleClick += OnTrayDoubleClick;

            // Start monitoring immediately before any slow shell queries (e.g., schtasks.exe)
            _monitor = new TunMonitor();
            _monitor.StatusChanged += OnMonitorStatusChanged;
            _monitor.AntigravityKilled += OnAntigravityKilled;
            _monitor.AccessDenied += OnAccessDenied;
            _monitor.Start();

            UpdateTrayUi(_monitor.CurrentStatus);
            _trayIcon.Visible = true;

            // Listen for duplicate-launch ping so clicking the desktop shortcut shows status
            _pingEvent = CreatePingEvent(pingEventName);
            _pingThread = new Thread(PingListenerLoop) { IsBackground = true, Name = "PingListener" };
            _pingThread.Start();

            SystemEvents.SessionEnding += OnSessionEnding;

            // Query auto-start task asynchronously without delaying protection startup
            RefreshAutoStartStatusAsync();
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
            WaitHandle[] handles = new WaitHandle[] { _pingEvent, _pingStop };
            while (!_disposed)
            {
                int idx;
                try
                {
                    idx = WaitHandle.WaitAny(handles);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                if (idx != 0 || _disposed)
                {
                    break;
                }
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
                _lastKillItem.Text = string.Format("上次拦截: {0} ({1}进程, {2:F2}ms)", timeText, result.KilledCount, result.FirstPassMs);
                _trayIcon.ShowBalloonTip(
                    2500,
                    "TUN 已关闭 — 已终止 Antigravity",
                    string.Format("触发源: {0}\n已终止 {1} 个进程，首轮耗时 {2:F2} ms (累计拦截 {3} 次)", trigger, result.KilledCount, result.FirstPassMs, count),
                    ToolTipIcon.Warning);
            });
        }

        private void OnAccessDenied(int deniedCount, string trigger)
        {
            long nowTicks = DateTime.UtcNow.Ticks;
            long prevTicks = Interlocked.Read(ref _lastAccessDeniedNotifyTicks);
            if (nowTicks - prevTicks < AccessDeniedNotifyCooldownTicks)
            {
                return;
            }
            if (Interlocked.CompareExchange(ref _lastAccessDeniedNotifyTicks, nowTicks, prevTicks) != prevTicks)
            {
                return;
            }

            string timeText = DateTime.Now.ToString("HH:mm:ss");
            PostToUi(() =>
            {
                _lastKillItem.Text = string.Format("权限不足: {0} ({1}进程无法终止)", timeText, deniedCount);
                _trayIcon.ShowBalloonTip(
                    3000,
                    "权限不足 — 无法终止 Antigravity",
                    string.Format("触发源: {0}\n检测到 {1} 个目标进程但无权终止，请以管理员身份运行 TunGuard。", trigger, deniedCount),
                    ToolTipIcon.Error);
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

        private void OnMenuOpening(object sender, System.ComponentModel.CancelEventArgs e)
        {
            RefreshAutoStartStatusAsync();
        }

        private void RefreshAutoStartStatusAsync()
        {
            if (_disposed || Interlocked.CompareExchange(ref _autoStartRefreshing, 1, 0) != 0)
            {
                return;
            }

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    bool enabled = StartupManager.IsAutoStartEnabled();
                    PostToUi(() =>
                    {
                        if (Volatile.Read(ref _autoStartToggling) == 0)
                        {
                            _autoStartItem.Checked = enabled;
                        }
                    });
                }
                finally
                {
                    Interlocked.Exchange(ref _autoStartRefreshing, 0);
                }
            });
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
            if (Interlocked.CompareExchange(ref _autoStartToggling, 1, 0) != 0)
            {
                return;
            }

            bool target = !_autoStartItem.Checked;
            _autoStartItem.Enabled = false;

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    bool ok = StartupManager.SetAutoStart(target);
                    bool actual = StartupManager.IsAutoStartEnabled();
                    PostToUi(() =>
                    {
                        _autoStartItem.Checked = actual;
                        _autoStartItem.Enabled = true;
                        if (!ok)
                        {
                            _trayIcon.ShowBalloonTip(2500, "开机自启设置失败", "请以管理员权限运行后重试。", ToolTipIcon.Error);
                        }
                    });
                }
                finally
                {
                    Interlocked.Exchange(ref _autoStartToggling, 0);
                }
            });
        }

        private void OnSessionEnding(object sender, SessionEndingEventArgs e)
        {
            if (SynchronizationContext.Current == _uiSync)
            {
                ExitCleanly();
            }
            else
            {
                PostToUi(ExitCleanly);
            }
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

                    bool pingExited = true;
                    if (_pingThread != null && _pingThread.IsAlive)
                    {
                        pingExited = _pingThread.Join(500);
                    }

                    if (_trayIcon != null)
                    {
                        _trayIcon.Visible = false;
                        _trayIcon.Dispose();
                    }
                    if (_menu != null)
                    {
                        _menu.Opening -= OnMenuOpening;
                        _menu.Dispose();
                    }
                    _iconSafe.Dispose();
                    _iconAlert.Dispose();
                    _iconPaused.Dispose();

                    if (pingExited)
                    {
                        _pingEvent.Dispose();
                        _pingStop.Dispose();
                    }
                }
            }
            base.Dispose(disposing);
        }
    }
}
