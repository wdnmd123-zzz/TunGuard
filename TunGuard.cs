using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("TunGuard")]
[assembly: AssemblyDescription("Clash Verge TUN and Node Guard for Antigravity, ChatGPT and Claude Desktop")]
[assembly: AssemblyProduct("TunGuard")]
[assembly: AssemblyVersion("1.3.0.0")]
[assembly: AssemblyFileVersion("1.3.0.0")]

namespace TunGuard
{
    internal static class Program
    {
        private const string MutexName = "Local\\ClashVergeTunGuard_SingleInstance_v1";
        private const string PingEventName = "Local\\ClashVergeTunGuard_Ping_v1";
        internal static volatile string PendingRestartExePath;

        [STAThread]
        private static void Main()
        {
            Mutex mutex;
            if (!TryAcquireSingleInstanceMutex(out mutex))
            {
                SignalExistingInstance();
                return;
            }

            try
            {
                AppUpdater.CleanupStaleUpdateFilesAsync();

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

                try
                {
                    using (TrayApplication app = new TrayApplication(PingEventName))
                    {
                        Application.Run(app);
                    }
                }
                finally
                {
                    AppLogger.Shutdown();
                }
            }
            finally
            {
                try
                {
                    mutex.ReleaseMutex();
                }
                catch
                {
                }
                mutex.Dispose();
            }

            string restartPath = PendingRestartExePath;
            if (!string.IsNullOrEmpty(restartPath))
            {
                AppUpdater.LaunchRestartedProcess(restartPath);
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
        public bool IsGuardSafe;
        public bool IsTunActive;
        public bool ConfigEnabled;
        public bool AdapterUp;
        public bool HasDefaultRoute;
        public bool AutoRouteRequired;
        public uint AdapterIndex;
        public ulong AdapterLuid;
        public string AdapterAlias;
        public string Reason;

        public bool NodeGuardEnabled;
        public bool IsNodeAllowed;
        public string ClashMode;
        public string ActiveProxyGroup;
        public string ActiveNodeName;
        public string ActiveNodeChain;
        public string NodeReason;

        public bool WfpEnabled;
        public bool WfpActive;
        public bool WfpDegraded;
        public bool WfpBlockingNow;
        public bool WfpDnsGuardActive;
        public int WfpExeTargetCount;
        public int WfpPackageTargetCount;
        public string WfpStatusText;
    }

    [Flags]
    internal enum GuardedAppFlags
    {
        None = 0,
        Antigravity = 1,
        ChatGPT = 2,
        Claude = 4,
        All = Antigravity | ChatGPT | Claude
    }

    internal static class GuardedAppHelper
    {
        public static string FormatNames(GuardedAppFlags flags)
        {
            if (flags == GuardedAppFlags.None)
            {
                return "无";
            }

            List<string> names = new List<string>(3);
            if ((flags & GuardedAppFlags.Antigravity) != 0)
            {
                names.Add("Antigravity");
            }
            if ((flags & GuardedAppFlags.ChatGPT) != 0)
            {
                names.Add("ChatGPT 桌面端");
            }
            if ((flags & GuardedAppFlags.Claude) != 0)
            {
                names.Add("Claude 桌面端");
            }
            return string.Join("、", names.ToArray());
        }

        public static string FormatShortNames(GuardedAppFlags flags)
        {
            if (flags == GuardedAppFlags.None)
            {
                return "无 (均未勾选)";
            }

            List<string> names = new List<string>(3);
            if ((flags & GuardedAppFlags.Antigravity) != 0)
            {
                names.Add("Antigravity");
            }
            if ((flags & GuardedAppFlags.ChatGPT) != 0)
            {
                names.Add("ChatGPT");
            }
            if ((flags & GuardedAppFlags.Claude) != 0)
            {
                names.Add("Claude");
            }
            return string.Join("、", names.ToArray());
        }
    }

    internal sealed class NodeGuardConfig
    {
        public bool Enabled { get; set; }
        public string ProxyGroup { get; set; }
        public string MatchMode { get; set; }
        public List<string> AllowedNodes { get; set; }
        public bool GuardAntigravity { get; set; }
        public bool GuardChatGPT { get; set; }
        public bool GuardClaude { get; set; }
        public bool WfpEnabled { get; set; }
        public bool WfpKillOnBlock { get; set; }
        public bool WfpBlockNonTunDns { get; set; }
        public bool PopupOnBlock { get; set; }
        public string LogDirectory { get; set; }
        public Dictionary<string, List<string>> CustomAppPaths { get; set; }
        public Dictionary<string, List<string>> DiscoveredAppPaths { get; set; }

        public NodeGuardConfig()
        {
            Enabled = false;
            ProxyGroup = string.Empty;
            MatchMode = "exact";
            AllowedNodes = new List<string>();
            GuardAntigravity = true;
            GuardChatGPT = true;
            GuardClaude = true;
            WfpEnabled = true;
            WfpKillOnBlock = true;
            WfpBlockNonTunDns = false;
            PopupOnBlock = true;
            LogDirectory = string.Empty;
            CustomAppPaths = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            DiscoveredAppPaths = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        }

        public int GetCustomAppPathCount()
        {
            if (CustomAppPaths == null || CustomAppPaths.Count == 0)
            {
                return 0;
            }
            int total = 0;
            foreach (KeyValuePair<string, List<string>> kv in CustomAppPaths)
            {
                if (kv.Value != null)
                {
                    total += kv.Value.Count;
                }
            }
            return total;
        }

        public GuardedAppFlags GetGuardedAppFlags()
        {
            GuardedAppFlags flags = GuardedAppFlags.None;
            if (GuardAntigravity) flags |= GuardedAppFlags.Antigravity;
            if (GuardChatGPT) flags |= GuardedAppFlags.ChatGPT;
            if (GuardClaude) flags |= GuardedAppFlags.Claude;
            return flags;
        }

        public NodeGuardConfig CloneNormalized()
        {
            NodeGuardConfig copy = new NodeGuardConfig();
            copy.Enabled = Enabled;
            copy.ProxyGroup = ProxyGroup != null ? ProxyGroup.Trim() : string.Empty;
            copy.MatchMode = string.Equals(MatchMode, "contains", StringComparison.OrdinalIgnoreCase)
                ? "contains"
                : "exact";
            copy.GuardAntigravity = GuardAntigravity;
            copy.GuardChatGPT = GuardChatGPT;
            copy.GuardClaude = GuardClaude;
            copy.WfpEnabled = WfpEnabled;
            copy.WfpKillOnBlock = WfpKillOnBlock;
            copy.WfpBlockNonTunDns = WfpBlockNonTunDns;
            copy.PopupOnBlock = PopupOnBlock;
            copy.LogDirectory = LogDirectory != null ? LogDirectory.Trim() : string.Empty;

            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (AllowedNodes != null)
            {
                for (int i = 0; i < AllowedNodes.Count; i++)
                {
                    string raw = AllowedNodes[i];
                    if (string.IsNullOrWhiteSpace(raw))
                    {
                        continue;
                    }
                    string trimmed = raw.Trim();
                    if (seen.Add(trimmed))
                    {
                        copy.AllowedNodes.Add(trimmed);
                    }
                }
            }

            CopyNormalizedAppPathMap(CustomAppPaths, copy.CustomAppPaths);
            CopyNormalizedAppPathMap(DiscoveredAppPaths, copy.DiscoveredAppPaths);
            return copy;
        }

        internal static void CopyNormalizedAppPathMap(
            Dictionary<string, List<string>> source,
            Dictionary<string, List<string>> target)
        {
            if (source == null || target == null)
            {
                return;
            }
            string[] knownKeys = new string[] { "antigravity", "chatgpt", "claude" };
            for (int k = 0; k < knownKeys.Length; k++)
            {
                string key = knownKeys[k];
                List<string> srcList;
                if (!source.TryGetValue(key, out srcList) || srcList == null || srcList.Count == 0)
                {
                    continue;
                }
                HashSet<string> seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                List<string> cleanList = new List<string>();
                for (int i = 0; i < srcList.Count; i++)
                {
                    string normalizedPath = NormalizeConfiguredPathEntry(srcList[i]);
                    if (string.IsNullOrEmpty(normalizedPath))
                    {
                        continue;
                    }
                    if (seenPaths.Add(normalizedPath))
                    {
                        cleanList.Add(normalizedPath);
                    }
                }
                if (cleanList.Count > 0)
                {
                    cleanList.Sort(StringComparer.OrdinalIgnoreCase);
                    target[key] = cleanList;
                }
            }
        }

        internal static string NormalizeConfiguredPathEntry(string rawPath)
        {
            if (string.IsNullOrWhiteSpace(rawPath))
            {
                return null;
            }
            string trimmed = rawPath.Trim().Trim('"').Trim();
            if (trimmed.Length == 0)
            {
                return null;
            }
            try
            {
                string full = Path.GetFullPath(trimmed);
                string root = Path.GetPathRoot(full);
                if (!string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
                {
                    full = full.TrimEnd('\\', '/');
                }
                return full;
            }
            catch
            {
                return trimmed;
            }
        }

        public string GetGuardedAppsSummaryText()
        {
            return "受控应用: " + GuardedAppHelper.FormatShortNames(GetGuardedAppFlags());
        }

        public string GetSummaryText()
        {
            if (!Enabled)
            {
                return "节点守护: 未启用";
            }
            string modeLabel = string.Equals(MatchMode, "contains", StringComparison.OrdinalIgnoreCase) ? "关键词" : "精确";
            string groupLabel = string.IsNullOrEmpty(ProxyGroup) ? "自动出口组" : ProxyGroup;
            if (AllowedNodes == null || AllowedNodes.Count == 0)
            {
                return string.Format("节点守护: 已启用 (未配置节点, 组: {0})", groupLabel);
            }
            if (AllowedNodes.Count == 1)
            {
                return string.Format("节点守护: {0} [{1}] ({2})", modeLabel, AllowedNodes[0], groupLabel);
            }
            return string.Format("节点守护: {0} {1}个节点 ({2})", modeLabel, AllowedNodes.Count, groupLabel);
        }
    }

    internal static class NodeGuardConfigStore
    {
        public const string ConfigFileName = "TunGuard.config.json";
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        public static string GetConfigPath()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ConfigFileName);
        }

        public static NodeGuardConfig LoadOrDefault(string path)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return new NodeGuardConfig();
                }

                string text = ReadFileWithRetry(path);
                if (string.IsNullOrWhiteSpace(text))
                {
                    return new NodeGuardConfig();
                }

                return Deserialize(text);
            }
            catch
            {
                return new NodeGuardConfig();
            }
        }

        public static bool TryLoad(string path, out NodeGuardConfig config)
        {
            config = null;
            try
            {
                if (!File.Exists(path))
                {
                    config = new NodeGuardConfig();
                    return true;
                }

                string text = ReadFileWithRetry(path);
                if (string.IsNullOrWhiteSpace(text))
                {
                    return false;
                }

                config = Deserialize(text);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static void Save(string path, NodeGuardConfig config)
        {
            NodeGuardConfig normalized = (config != null ? config : new NodeGuardConfig()).CloneNormalized();
            string json = SerializePretty(normalized);
            string dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            string tmpPath = path + ".tmp." + Process.GetCurrentProcess().Id;
            File.WriteAllText(tmpPath, json, Utf8NoBom);
            if (File.Exists(path))
            {
                try
                {
                    File.Replace(tmpPath, path, null);
                    return;
                }
                catch
                {
                    // Fallback if File.Replace fails across volumes or permissions
                }
            }

            File.Copy(tmpPath, path, true);
            try
            {
                File.Delete(tmpPath);
            }
            catch
            {
            }
        }

        public static NodeGuardConfig Deserialize(string json)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = 4 * 1024 * 1024;
            Dictionary<string, object> obj = serializer.DeserializeObject(json) as Dictionary<string, object>;
            NodeGuardConfig cfg = new NodeGuardConfig();
            if (obj == null)
            {
                return cfg;
            }

            object val;
            bool parsedBool;
            if (TryGetBoolIgnoreCase(obj, "enabled", out parsedBool))
            {
                cfg.Enabled = parsedBool;
            }

            if (TryGetIgnoreCase(obj, "proxyGroup", out val) && val != null)
            {
                cfg.ProxyGroup = val.ToString();
            }

            if (TryGetIgnoreCase(obj, "matchMode", out val) && val != null)
            {
                cfg.MatchMode = val.ToString();
            }

            if (TryGetIgnoreCase(obj, "allowedNodes", out val) && val != null)
            {
                object[] arr = val as object[];
                if (arr != null)
                {
                    for (int i = 0; i < arr.Length; i++)
                    {
                        if (arr[i] != null)
                        {
                            cfg.AllowedNodes.Add(arr[i].ToString());
                        }
                    }
                }
                else
                {
                    System.Collections.IList list = val as System.Collections.IList;
                    if (list != null)
                    {
                        for (int i = 0; i < list.Count; i++)
                        {
                            if (list[i] != null)
                            {
                                cfg.AllowedNodes.Add(list[i].ToString());
                            }
                        }
                    }
                }
            }

            if (TryGetIgnoreCase(obj, "guardedApps", out val) && val != null)
            {
                Dictionary<string, object> appsObj = val as Dictionary<string, object>;
                if (appsObj != null)
                {
                    if (TryGetBoolIgnoreCase(appsObj, "antigravity", out parsedBool))
                    {
                        cfg.GuardAntigravity = parsedBool;
                    }
                    if (TryGetBoolIgnoreCase(appsObj, "chatgpt", out parsedBool))
                    {
                        cfg.GuardChatGPT = parsedBool;
                    }
                    if (TryGetBoolIgnoreCase(appsObj, "claude", out parsedBool))
                    {
                        cfg.GuardClaude = parsedBool;
                    }
                }
            }

            if (TryGetBoolIgnoreCase(obj, "wfpEnabled", out parsedBool))
            {
                cfg.WfpEnabled = parsedBool;
            }
            if (TryGetBoolIgnoreCase(obj, "wfpKillOnBlock", out parsedBool))
            {
                cfg.WfpKillOnBlock = parsedBool;
            }
            if (TryGetBoolIgnoreCase(obj, "wfpBlockNonTunDns", out parsedBool))
            {
                cfg.WfpBlockNonTunDns = parsedBool;
            }
            if (TryGetBoolIgnoreCase(obj, "popupOnBlock", out parsedBool))
            {
                cfg.PopupOnBlock = parsedBool;
            }
            if (TryGetIgnoreCase(obj, "logDirectory", out val) && val != null)
            {
                cfg.LogDirectory = val.ToString();
            }

            ReadAppPathMapFromObject(obj, "customAppPaths", cfg.CustomAppPaths);
            ReadAppPathMapFromObject(obj, "discoveredAppPaths", cfg.DiscoveredAppPaths);

            return cfg.CloneNormalized();
        }

        private static void ReadAppPathMapFromObject(
            Dictionary<string, object> obj,
            string fieldName,
            Dictionary<string, List<string>> target)
        {
            object val;
            if (!TryGetIgnoreCase(obj, fieldName, out val) || val == null)
            {
                return;
            }
            Dictionary<string, object> pathsObj = val as Dictionary<string, object>;
            if (pathsObj == null)
            {
                return;
            }
            foreach (KeyValuePair<string, object> kv in pathsObj)
            {
                if (string.IsNullOrWhiteSpace(kv.Key) || kv.Value == null)
                {
                    continue;
                }
                List<string> pathList = new List<string>();
                object[] arr = kv.Value as object[];
                if (arr != null)
                {
                    for (int i = 0; i < arr.Length; i++)
                    {
                        if (arr[i] != null)
                        {
                            pathList.Add(arr[i].ToString());
                        }
                    }
                }
                else
                {
                    System.Collections.IList list = kv.Value as System.Collections.IList;
                    if (list != null)
                    {
                        for (int i = 0; i < list.Count; i++)
                        {
                            if (list[i] != null)
                            {
                                pathList.Add(list[i].ToString());
                            }
                        }
                    }
                }
                if (pathList.Count > 0)
                {
                    target[kv.Key] = pathList;
                }
            }
        }

        public static string SerializePretty(NodeGuardConfig config)
        {
            NodeGuardConfig cfg = (config != null ? config : new NodeGuardConfig()).CloneNormalized();
            StringBuilder sb = new StringBuilder(512);
            sb.AppendLine("{");
            sb.Append("  \"enabled\": ").Append(cfg.Enabled ? "true" : "false").AppendLine(",");
            sb.Append("  \"proxyGroup\": ").Append(EscapeJsonString(cfg.ProxyGroup)).AppendLine(",");
            sb.Append("  \"matchMode\": ").Append(EscapeJsonString(cfg.MatchMode)).AppendLine(",");
            sb.Append("  \"allowedNodes\": [");
            if (cfg.AllowedNodes.Count > 0)
            {
                sb.AppendLine();
                for (int i = 0; i < cfg.AllowedNodes.Count; i++)
                {
                    sb.Append("    ").Append(EscapeJsonString(cfg.AllowedNodes[i]));
                    if (i < cfg.AllowedNodes.Count - 1)
                    {
                        sb.Append(",");
                    }
                    sb.AppendLine();
                }
                sb.Append("  ");
            }
            sb.AppendLine("],");
            sb.AppendLine("  \"guardedApps\": {");
            sb.Append("    \"antigravity\": ").Append(cfg.GuardAntigravity ? "true" : "false").AppendLine(",");
            sb.Append("    \"chatgpt\": ").Append(cfg.GuardChatGPT ? "true" : "false").AppendLine(",");
            sb.Append("    \"claude\": ").Append(cfg.GuardClaude ? "true" : "false").AppendLine();
            sb.AppendLine("  },");
            sb.Append("  \"wfpEnabled\": ").Append(cfg.WfpEnabled ? "true" : "false").AppendLine(",");
            sb.Append("  \"wfpKillOnBlock\": ").Append(cfg.WfpKillOnBlock ? "true" : "false").AppendLine(",");
            sb.Append("  \"wfpBlockNonTunDns\": ").Append(cfg.WfpBlockNonTunDns ? "true" : "false").AppendLine(",");
            sb.Append("  \"popupOnBlock\": ").Append(cfg.PopupOnBlock ? "true" : "false").AppendLine(",");
            sb.Append("  \"logDirectory\": ").Append(EscapeJsonString(cfg.LogDirectory));

            bool hasCustom = cfg.CustomAppPaths != null && cfg.CustomAppPaths.Count > 0;
            bool hasDiscovered = cfg.DiscoveredAppPaths != null && cfg.DiscoveredAppPaths.Count > 0;
            if (hasCustom)
            {
                sb.AppendLine(",");
                AppendAppPathMapJson(sb, "customAppPaths", cfg.CustomAppPaths);
            }
            if (hasDiscovered)
            {
                sb.AppendLine(",");
                AppendAppPathMapJson(sb, "discoveredAppPaths", cfg.DiscoveredAppPaths);
            }
            sb.AppendLine();
            sb.AppendLine("}");
            return sb.ToString();
        }

        private static void AppendAppPathMapJson(
            StringBuilder sb,
            string fieldName,
            Dictionary<string, List<string>> map)
        {
            sb.Append("  ").Append(EscapeJsonString(fieldName)).AppendLine(": {");
            List<string> keys = new List<string>(map.Keys);
            keys.Sort(StringComparer.OrdinalIgnoreCase);
            for (int k = 0; k < keys.Count; k++)
            {
                string key = keys[k];
                List<string> paths = map[key];
                sb.Append("    ").Append(EscapeJsonString(key)).Append(": [");
                if (paths != null && paths.Count > 0)
                {
                    sb.AppendLine();
                    for (int i = 0; i < paths.Count; i++)
                    {
                        sb.Append("      ").Append(EscapeJsonString(paths[i]));
                        if (i < paths.Count - 1)
                        {
                            sb.Append(",");
                        }
                        sb.AppendLine();
                    }
                    sb.Append("    ");
                }
                sb.Append("]");
                if (k < keys.Count - 1)
                {
                    sb.Append(",");
                }
                sb.AppendLine();
            }
            sb.Append("  }");
        }

        private static bool TryGetBoolIgnoreCase(Dictionary<string, object> dict, string key, out bool result)
        {
            result = false;
            object val;
            if (!TryGetIgnoreCase(dict, key, out val) || val == null)
            {
                return false;
            }
            if (val is bool)
            {
                result = (bool)val;
                return true;
            }
            if (val is string)
            {
                return bool.TryParse((string)val, out result);
            }
            return false;
        }

        private static string EscapeJsonString(string s)
        {
            if (s == null)
            {
                return "\"\"";
            }
            StringBuilder sb = new StringBuilder(s.Length + 2);
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                        {
                            sb.AppendFormat("\\u{0:x4}", (int)c);
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        private static bool TryGetIgnoreCase(Dictionary<string, object> dict, string key, out object value)
        {
            if (dict.TryGetValue(key, out value))
            {
                return true;
            }
            foreach (KeyValuePair<string, object> kv in dict)
            {
                if (string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase))
                {
                    value = kv.Value;
                    return true;
                }
            }
            value = null;
            return false;
        }

        private static string ReadFileWithRetry(string path)
        {
            int[] delays = new int[] { 2, 5, 10 };
            for (int i = 0; i <= delays.Length; i++)
            {
                try
                {
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        return sr.ReadToEnd();
                    }
                }
                catch
                {
                    if (i < delays.Length)
                    {
                        Thread.Sleep(delays[i]);
                    }
                }
            }
            return null;
        }
    }

    internal enum LogLevel
    {
        Info = 0,
        Warn = 1,
        Error = 2
    }

    internal struct LogEntry
    {
        public DateTime Timestamp;
        public LogLevel Level;
        public string Category;
        public string Message;
        public string FormattedLine;
    }

    internal static class AppLogger
    {
        private const string DefaultSubDirName = "logs";
        public const string LogFilePrefix = "TunGuard-";
        public const string LogFileExtension = ".log";
        private const int MaxQueueSize = 4096;
        private const int MaxRecentEntries = 1000;

        private struct QueuedWrite
        {
            public string Directory;
            public DateTime Timestamp;
            public string Line;
        }

        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);
        private static readonly object LockObj = new object();
        private static readonly Queue<QueuedWrite> WriteQueue = new Queue<QueuedWrite>(64);
        private static readonly Queue<LogEntry> RecentEntries = new Queue<LogEntry>(128);
        private static readonly AutoResetEvent WriteSignal = new AutoResetEvent(false);
        private static readonly ManualResetEvent DrainedSignal = new ManualResetEvent(true);
        private static readonly ManualResetEvent StopSignal = new ManualResetEvent(false);

        private static Thread _writerThread;
        private static bool _started;
        private static bool _shutdown;
        private static string _configuredDir = string.Empty;
        private static string _effectiveDir = DefaultLogDirectory;
        private static string _lastWriteError = string.Empty;

        public static event Action<LogEntry> EntryLogged;

        public static string DefaultLogDirectory
        {
            get
            {
                return NormalizeDirPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, DefaultSubDirName));
            }
        }

        public static string ConfiguredLogDirectory
        {
            get
            {
                lock (LockObj)
                {
                    return _configuredDir;
                }
            }
        }

        public static string EffectiveLogDirectory
        {
            get
            {
                lock (LockObj)
                {
                    return _effectiveDir;
                }
            }
        }

        public static bool IsUsingDefaultDirectory
        {
            get
            {
                lock (LockObj)
                {
                    return string.IsNullOrEmpty(_configuredDir) ||
                           PathsEqual(_effectiveDir, DefaultLogDirectory);
                }
            }
        }

        public static string LastWriteError
        {
            get
            {
                lock (LockObj)
                {
                    return _lastWriteError;
                }
            }
        }

        public static void Initialize(string configuredDir)
        {
            lock (LockObj)
            {
                if (_shutdown)
                {
                    return;
                }

                string normalized;
                string err;
                if (TryValidateWritableDirectory(configuredDir, out normalized, out err))
                {
                    _configuredDir = string.IsNullOrWhiteSpace(configuredDir) || PathsEqual(normalized, DefaultLogDirectory)
                        ? string.Empty
                        : normalized;
                    _effectiveDir = normalized;
                    _lastWriteError = string.Empty;
                }
                else
                {
                    _configuredDir = string.Empty;
                    _effectiveDir = DefaultLogDirectory;
                    _lastWriteError = err ?? string.Empty;
                    TryEnsureDirectoryExists(_effectiveDir);
                }

                if (!_started)
                {
                    _started = true;
                    _writerThread = new Thread(WriterLoop)
                    {
                        Name = "TunGuardLogWriter",
                        IsBackground = true,
                        Priority = ThreadPriority.BelowNormal
                    };
                    _writerThread.Start();
                }
            }
        }

        public static void ConfigureDirectoryQuiet(string configuredDir)
        {
            string trimmed = configuredDir != null ? configuredDir.Trim() : string.Empty;
            string normalized;
            string err;
            if (!TryValidateWritableDirectory(trimmed, out normalized, out err))
            {
                Warn("LOG", "配置中的日志目录无效或不可写，继续使用当前目录 (" + EffectiveLogDirectory + "): " + trimmed + " | " + err);
                return;
            }

            string prevDir;
            bool changed;
            lock (LockObj)
            {
                prevDir = _effectiveDir;
                changed = !PathsEqual(prevDir, normalized);
                _configuredDir = string.IsNullOrEmpty(trimmed) || PathsEqual(normalized, DefaultLogDirectory)
                    ? string.Empty
                    : normalized;
                if (changed)
                {
                    _effectiveDir = normalized;
                    _lastWriteError = string.Empty;
                }
            }

            if (changed)
            {
                Info("LOG", "日志存放目录已更新: " + prevDir + " -> " + normalized);
            }
        }

        public static bool SetLogDirectory(string rawConfiguredDir, bool migrateExisting, out int migratedCount, out string effectivePath, out string error)
        {
            migratedCount = 0;
            effectivePath = EffectiveLogDirectory;
            error = null;

            string trimmed = rawConfiguredDir != null ? rawConfiguredDir.Trim() : string.Empty;
            string normalized;
            if (!TryValidateWritableDirectory(trimmed, out normalized, out error))
            {
                return false;
            }

            string oldDir = EffectiveLogDirectory;
            bool dirChanged = !PathsEqual(oldDir, normalized);
            string nextConfigured = string.IsNullOrEmpty(trimmed) || PathsEqual(normalized, DefaultLogDirectory)
                ? string.Empty
                : normalized;

            if (!dirChanged)
            {
                lock (LockObj)
                {
                    _configuredDir = nextConfigured;
                    _effectiveDir = normalized;
                    _lastWriteError = string.Empty;
                }
                effectivePath = normalized;
                return true;
            }

            Info("LOG", "准备变更日志存放目录: " + oldDir + " -> " + normalized);
            Flush(1500);

            if (migrateExisting)
            {
                string migrateErr;
                MigrateLogFiles(oldDir, normalized, out migratedCount, out migrateErr);
                if (!string.IsNullOrEmpty(migrateErr))
                {
                    Warn("LOG", "迁移历史日志时部分文件未完成: " + migrateErr);
                }
            }

            lock (LockObj)
            {
                _configuredDir = nextConfigured;
                _effectiveDir = normalized;
                _lastWriteError = string.Empty;
            }

            effectivePath = normalized;
            string suffix = migratedCount > 0 ? (" (已迁移 " + migratedCount + " 个历史日志文件)") : string.Empty;
            Info("LOG", "日志存放目录已切换为: " + normalized + " (原目录: " + oldDir + ")" + suffix);
            Flush(1000);
            return true;
        }

        public static string ResolveEffectiveDirectory(string configuredDir)
        {
            if (string.IsNullOrWhiteSpace(configuredDir))
            {
                return DefaultLogDirectory;
            }
            try
            {
                string expanded = Environment.ExpandEnvironmentVariables(configuredDir.Trim().Trim('"'));
                if (string.IsNullOrWhiteSpace(expanded))
                {
                    return DefaultLogDirectory;
                }
                return NormalizeDirPath(Path.GetFullPath(expanded));
            }
            catch
            {
                return DefaultLogDirectory;
            }
        }

        public static bool TryValidateWritableDirectory(string rawPath, out string normalizedPath, out string error)
        {
            normalizedPath = null;
            error = null;
            try
            {
                string target = string.IsNullOrWhiteSpace(rawPath)
                    ? DefaultLogDirectory
                    : NormalizeDirPath(Path.GetFullPath(Environment.ExpandEnvironmentVariables(rawPath.Trim().Trim('"'))));

                if (!Directory.Exists(target))
                {
                    Directory.CreateDirectory(target);
                }

                string probeFile = Path.Combine(target, ".tunguard_write_probe_" + Process.GetCurrentProcess().Id + "_" + Environment.TickCount + ".tmp");
                using (FileStream fs = new FileStream(probeFile, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    fs.WriteByte(0x20);
                }
                try
                {
                    File.Delete(probeFile);
                }
                catch
                {
                }

                normalizedPath = target;
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        public static string GetLogFilePathForDate(string directory, DateTime date)
        {
            string dir = string.IsNullOrWhiteSpace(directory) ? DefaultLogDirectory : directory;
            return Path.Combine(dir, LogFilePrefix + date.ToString("yyyy-MM-dd") + LogFileExtension);
        }

        public static string GetCurrentLogFilePath()
        {
            return GetLogFilePathForDate(EffectiveLogDirectory, DateTime.Now);
        }

        public static List<string> ListLogFiles(string directory)
        {
            List<string> result = new List<string>();
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            {
                return result;
            }
            try
            {
                string[] files = Directory.GetFiles(directory, LogFilePrefix + "*" + LogFileExtension, SearchOption.TopDirectoryOnly);
                Array.Sort(files, (a, b) => string.Compare(Path.GetFileName(b), Path.GetFileName(a), StringComparison.OrdinalIgnoreCase));
                for (int i = 0; i < files.Length; i++)
                {
                    result.Add(files[i]);
                }
            }
            catch
            {
            }
            return result;
        }

        public static int CountLogFiles(string directory)
        {
            return ListLogFiles(directory).Count;
        }

        public static void MigrateLogFiles(string sourceDir, string destDir, out int migratedCount, out string firstError)
        {
            migratedCount = 0;
            firstError = null;
            if (string.IsNullOrWhiteSpace(sourceDir) || string.IsNullOrWhiteSpace(destDir) || PathsEqual(sourceDir, destDir))
            {
                return;
            }
            List<string> files = ListLogFiles(sourceDir);
            if (files.Count == 0)
            {
                return;
            }
            TryEnsureDirectoryExists(destDir);
            for (int i = 0; i < files.Count; i++)
            {
                string src = files[i];
                string fileName = Path.GetFileName(src);
                if (string.IsNullOrEmpty(fileName))
                {
                    continue;
                }
                string dst = Path.Combine(destDir, fileName);
                try
                {
                    if (File.Exists(dst))
                    {
                        string baseName = Path.GetFileNameWithoutExtension(fileName);
                        dst = Path.Combine(destDir, baseName + "-migrated-" + DateTime.Now.ToString("HHmmss") + LogFileExtension);
                    }
                    try
                    {
                        File.Move(src, dst);
                    }
                    catch
                    {
                        File.Copy(src, dst, false);
                        try
                        {
                            File.Delete(src);
                        }
                        catch
                        {
                        }
                    }
                    migratedCount++;
                }
                catch (Exception ex)
                {
                    if (firstError == null)
                    {
                        firstError = fileName + ": " + ex.Message;
                    }
                }
            }
        }

        public static string[] ReadLogFileLinesSafe(string filePath, int maxTailLines, out int totalLines, out long fileBytes)
        {
            totalLines = 0;
            fileBytes = 0;
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return new string[0];
            }

            int cap = maxTailLines > 0 ? maxTailLines : 2000;
            string[] ring = new string[cap];
            int writeIdx = 0;
            int count = 0;

            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    fileBytes = fs.Length;
                    using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            totalLines++;
                            ring[writeIdx] = line;
                            writeIdx = (writeIdx + 1) % cap;
                            if (count < cap)
                            {
                                count++;
                            }
                        }
                    }
                }
            }
            catch
            {
                return new string[0];
            }

            string[] output = new string[count];
            int start = (count < cap) ? 0 : writeIdx;
            for (int i = 0; i < count; i++)
            {
                output[i] = ring[(start + i) % cap];
            }
            return output;
        }

        public static bool TryClearLogFile(string filePath, out string error)
        {
            error = null;
            if (string.IsNullOrWhiteSpace(filePath))
            {
                error = "未指定日志文件";
                return false;
            }
            Flush(1000);
            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                    // Truncated to 0 bytes
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        public static void Info(string category, string message)
        {
            Log(LogLevel.Info, category, message);
        }

        public static void Warn(string category, string message)
        {
            Log(LogLevel.Warn, category, message);
        }

        public static void Error(string category, string message)
        {
            Log(LogLevel.Error, category, message);
        }

        public static void Log(LogLevel level, string category, string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                return;
            }

            DateTime now = DateTime.Now;
            string cat = string.IsNullOrWhiteSpace(category) ? "APP" : category.Trim().ToUpperInvariant();
            string cleanMsg = SanitizeSingleLine(message);
            string levelTag = level == LogLevel.Error ? "ERROR" : (level == LogLevel.Warn ? "WARN " : "INFO ");
            string formatted = string.Format(
                "{0:yyyy-MM-dd HH:mm:ss.fff} [{1}] [{2,-6}] {3}",
                now,
                levelTag,
                cat,
                cleanMsg);

            LogEntry entry = new LogEntry
            {
                Timestamp = now,
                Level = level,
                Category = cat,
                Message = cleanMsg,
                FormattedLine = formatted
            };

            lock (LockObj)
            {
                if (_shutdown)
                {
                    return;
                }
                if (!_started)
                {
                    _started = true;
                    _writerThread = new Thread(WriterLoop)
                    {
                        Name = "TunGuardLogWriter",
                        IsBackground = true,
                        Priority = ThreadPriority.BelowNormal
                    };
                    _writerThread.Start();
                }

                if (RecentEntries.Count >= MaxRecentEntries)
                {
                    RecentEntries.Dequeue();
                }
                RecentEntries.Enqueue(entry);

                if (WriteQueue.Count < MaxQueueSize)
                {
                    WriteQueue.Enqueue(new QueuedWrite
                    {
                        Directory = _effectiveDir,
                        Timestamp = now,
                        Line = formatted
                    });
                    DrainedSignal.Reset();
                    try
                    {
                        WriteSignal.Set();
                    }
                    catch
                    {
                    }
                }
            }

            Action<LogEntry> handler = EntryLogged;
            if (handler != null)
            {
                try
                {
                    handler(entry);
                }
                catch
                {
                }
            }
        }

        public static void Flush(int timeoutMs)
        {
            lock (LockObj)
            {
                if (!_started || _shutdown)
                {
                    return;
                }
            }
            try
            {
                WriteSignal.Set();
                DrainedSignal.WaitOne(timeoutMs);
            }
            catch
            {
            }
        }

        public static void Shutdown()
        {
            Thread threadToJoin;
            lock (LockObj)
            {
                if (_shutdown)
                {
                    return;
                }
                _shutdown = true;
                threadToJoin = _writerThread;
                _writerThread = null;
            }

            try
            {
                StopSignal.Set();
                WriteSignal.Set();
            }
            catch
            {
            }

            if (threadToJoin != null && threadToJoin.IsAlive)
            {
                threadToJoin.Join(1500);
            }
        }

        private static void WriterLoop()
        {
            WaitHandle[] handles = new WaitHandle[] { StopSignal, WriteSignal };
            List<QueuedWrite> batch = new List<QueuedWrite>(64);

            while (true)
            {
                DrainBatchToDisk(batch);

                bool isStopping;
                lock (LockObj)
                {
                    isStopping = _shutdown && WriteQueue.Count == 0;
                }
                if (isStopping)
                {
                    break;
                }

                try
                {
                    WaitHandle.WaitAny(handles, 2000);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
            }

            DrainBatchToDisk(batch);
        }

        private static void DrainBatchToDisk(List<QueuedWrite> batch)
        {
            while (true)
            {
                batch.Clear();
                lock (LockObj)
                {
                    if (WriteQueue.Count == 0)
                    {
                        DrainedSignal.Set();
                        return;
                    }
                    while (WriteQueue.Count > 0 && batch.Count < 256)
                    {
                        batch.Add(WriteQueue.Dequeue());
                    }
                }

                WriteBatchGrouped(batch);
            }
        }

        private static void WriteBatchGrouped(List<QueuedWrite> batch)
        {
            int idx = 0;
            while (idx < batch.Count)
            {
                string dir = batch[idx].Directory;
                string filePath = GetLogFilePathForDate(dir, batch[idx].Timestamp);
                StringBuilder sb = new StringBuilder(batch.Count * 96);
                sb.AppendLine(batch[idx].Line);
                idx++;

                while (idx < batch.Count)
                {
                    string nextPath = GetLogFilePathForDate(batch[idx].Directory, batch[idx].Timestamp);
                    if (!string.Equals(nextPath, filePath, StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }
                    sb.AppendLine(batch[idx].Line);
                    idx++;
                }

                try
                {
                    TryEnsureDirectoryExists(dir);
                    using (FileStream fs = new FileStream(filePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                    using (StreamWriter sw = new StreamWriter(fs, Utf8NoBom))
                    {
                        sw.Write(sb.ToString());
                    }
                    lock (LockObj)
                    {
                        _lastWriteError = string.Empty;
                    }
                }
                catch (Exception ex)
                {
                    lock (LockObj)
                    {
                        _lastWriteError = ex.Message;
                    }
                }
            }
        }

        private static void TryEnsureDirectoryExists(string dir)
        {
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
        }

        private static string SanitizeSingleLine(string s)
        {
            if (s.IndexOf('\n') < 0 && s.IndexOf('\r') < 0)
            {
                return s;
            }
            return s.Replace("\r\n", " | ").Replace('\n', ' ').Replace('\r', ' ');
        }

        private static string NormalizeDirPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }
            string full = path.Trim();
            if (full.Length > 3)
            {
                full = full.TrimEnd('\\', '/');
            }
            return full;
        }

        public static bool PathsEqual(string a, string b)
        {
            return string.Equals(NormalizeDirPath(a), NormalizeDirPath(b), StringComparison.OrdinalIgnoreCase);
        }
    }

    internal sealed class ClashProxyEntry
    {
        public string Name;
        public string Type;
        public string Now;
        public List<string> All;
        public bool IsGroup;
    }

    internal sealed class ClashSnapshot
    {
        public bool Connected;
        public string Error;
        public string Endpoint;
        public string Mode;
        public string MatchRuleProxy;
        public Dictionary<string, ClashProxyEntry> Proxies;

        public ClashSnapshot()
        {
            Proxies = new Dictionary<string, ClashProxyEntry>(StringComparer.Ordinal);
        }

        public bool TryGetProxy(string name, out ClashProxyEntry entry)
        {
            entry = null;
            if (string.IsNullOrEmpty(name) || Proxies == null)
            {
                return false;
            }
            if (Proxies.TryGetValue(name, out entry))
            {
                return true;
            }
            foreach (KeyValuePair<string, ClashProxyEntry> kv in Proxies)
            {
                if (string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase))
                {
                    entry = kv.Value;
                    return true;
                }
            }
            return false;
        }
    }

    internal struct NodeEvaluationResult
    {
        public bool IsAllowed;
        public string ClashMode;
        public string TargetGroup;
        public string ActiveNode;
        public string ResolutionChain;
        public string Reason;
    }

    internal static class NodeGuardEvaluator
    {
        private static readonly HashSet<string> GroupTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Selector",
            "URLTest",
            "Fallback",
            "LoadBalance",
            "Relay",
            "Smart"
        };

        private static readonly HashSet<string> BuiltinNodeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "DIRECT",
            "REJECT",
            "REJECT-DROP",
            "PASS",
            "PASS-RULE",
            "COMPATIBLE"
        };

        public static bool IsGroupType(string type)
        {
            return !string.IsNullOrEmpty(type) && GroupTypes.Contains(type);
        }

        public static bool IsBuiltinNode(string name)
        {
            return !string.IsNullOrEmpty(name) && BuiltinNodeNames.Contains(name);
        }

        public static NodeEvaluationResult Evaluate(NodeGuardConfig config, ClashSnapshot snapshot)
        {
            NodeEvaluationResult res = new NodeEvaluationResult
            {
                IsAllowed = false,
                ClashMode = snapshot != null && snapshot.Mode != null ? snapshot.Mode : string.Empty,
                TargetGroup = string.Empty,
                ActiveNode = string.Empty,
                ResolutionChain = string.Empty,
                Reason = string.Empty
            };

            if (config == null || !config.Enabled)
            {
                res.IsAllowed = true;
                res.Reason = "未启用节点守护";
                return res;
            }

            if (config.AllowedNodes == null || config.AllowedNodes.Count == 0)
            {
                res.IsAllowed = false;
                res.Reason = "已启用节点守护但未配置允许节点";
                return res;
            }

            if (snapshot == null || !snapshot.Connected)
            {
                res.IsAllowed = false;
                res.Reason = (snapshot != null && !string.IsNullOrEmpty(snapshot.Error))
                    ? snapshot.Error
                    : "无法连接 Clash 控制接口";
                return res;
            }

            string mode = snapshot.Mode ?? string.Empty;
            if (string.Equals(mode, "direct", StringComparison.OrdinalIgnoreCase))
            {
                res.IsAllowed = false;
                res.ActiveNode = "DIRECT";
                res.ResolutionChain = "DIRECT";
                res.Reason = "Clash 处于 Direct 直连模式";
                return res;
            }

            string entryName;
            if (string.Equals(mode, "global", StringComparison.OrdinalIgnoreCase))
            {
                entryName = "GLOBAL";
            }
            else
            {
                if (!string.IsNullOrEmpty(config.ProxyGroup))
                {
                    entryName = config.ProxyGroup;
                }
                else if (!string.IsNullOrEmpty(snapshot.MatchRuleProxy))
                {
                    entryName = snapshot.MatchRuleProxy;
                }
                else
                {
                    ClashProxyEntry fallbackProxy;
                    if (snapshot.TryGetProxy("PROXY", out fallbackProxy))
                    {
                        entryName = fallbackProxy.Name;
                    }
                    else
                    {
                        res.IsAllowed = false;
                        res.Reason = "未找到 MATCH 默认出口规则，请在设置中指定代理组";
                        return res;
                    }
                }
            }

            ClashProxyEntry entry;
            if (!snapshot.TryGetProxy(entryName, out entry))
            {
                res.IsAllowed = false;
                res.TargetGroup = entryName;
                res.Reason = "未找到代理组: " + entryName;
                return res;
            }

            List<string> chain = new List<string>(4);
            HashSet<string> visited = new HashSet<string>(StringComparer.Ordinal);
            chain.Add(entry.Name);
            visited.Add(entry.Name);

            ClashProxyEntry cur = entry;
            while (cur != null && cur.IsGroup)
            {
                if (string.IsNullOrEmpty(cur.Now))
                {
                    res.IsAllowed = false;
                    res.TargetGroup = entry.Name;
                    res.ResolutionChain = string.Join(" -> ", chain.ToArray());
                    res.Reason = "代理组无当前选中节点: " + cur.Name;
                    return res;
                }

                string nextName = cur.Now;
                if (!visited.Add(nextName) || chain.Count >= 16)
                {
                    res.IsAllowed = false;
                    res.TargetGroup = entry.Name;
                    res.ResolutionChain = string.Join(" -> ", chain.ToArray());
                    res.Reason = "代理组存在循环引用: " + nextName;
                    return res;
                }

                chain.Add(nextName);
                ClashProxyEntry nextEntry;
                if (snapshot.TryGetProxy(nextName, out nextEntry))
                {
                    cur = nextEntry;
                }
                else
                {
                    cur = null;
                }
            }

            string leafNode = chain[chain.Count - 1];
            string chainText = string.Join(" -> ", chain.ToArray());
            return BuildMatchResult(config, mode, entry.Name, leafNode, chainText);
        }

        public static NodeEvaluationResult BuildMatchResult(
            NodeGuardConfig config,
            string clashMode,
            string targetGroup,
            string leafNode,
            string chainText)
        {
            NodeEvaluationResult res = new NodeEvaluationResult
            {
                ClashMode = clashMode ?? string.Empty,
                TargetGroup = targetGroup ?? string.Empty,
                ActiveNode = leafNode ?? string.Empty,
                ResolutionChain = chainText ?? string.Empty
            };

            bool containsMode = string.Equals(config.MatchMode, "contains", StringComparison.OrdinalIgnoreCase);
            bool matched = false;
            if (!string.IsNullOrEmpty(leafNode) && config.AllowedNodes != null)
            {
                for (int i = 0; i < config.AllowedNodes.Count; i++)
                {
                    string rule = config.AllowedNodes[i];
                    if (string.IsNullOrWhiteSpace(rule))
                    {
                        continue;
                    }
                    if (containsMode)
                    {
                        if (leafNode.IndexOf(rule, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            matched = true;
                            break;
                        }
                    }
                    else
                    {
                        if (string.Equals(leafNode, rule, StringComparison.OrdinalIgnoreCase))
                        {
                            matched = true;
                            break;
                        }
                    }
                }
            }

            res.IsAllowed = matched;
            if (matched)
            {
                res.Reason = "节点正常 (" + leafNode + ")";
            }
            else if (string.Equals(clashMode, "global", StringComparison.OrdinalIgnoreCase))
            {
                res.Reason = "Global 节点不匹配: " + leafNode;
            }
            else
            {
                res.Reason = "节点不匹配: " + leafNode + " (组: " + targetGroup + ")";
            }

            return res;
        }
    }

    internal sealed class MihomoClient : IDisposable
    {
        private const int CONNECT_TIMEOUT_MS = 180;
        private const int READ_TIMEOUT_MS = 350;
        private const int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
        private const int RULES_CACHE_TTL_MS = 60000;

        private sealed class EndpointInfo
        {
            public bool IsPipe;
            public string PipeName;
            public string Host;
            public int Port;
            public string Display;
        }

        private sealed class PersistentConnection : IDisposable
        {
            public EndpointInfo Endpoint;
            public NamedPipeClientStream Pipe;
            public TcpClient Tcp;
            public Stream Stream;
            public bool UseAsync;
            public readonly byte[] ReadBuf = new byte[8192];
            public int BufPos;
            public int BufLen;

            public void Dispose()
            {
                if (Stream != null && !ReferenceEquals(Stream, Pipe))
                {
                    try { Stream.Dispose(); } catch { }
                }
                Stream = null;
                if (Pipe != null)
                {
                    try { Pipe.Dispose(); } catch { }
                    Pipe = null;
                }
                if (Tcp != null)
                {
                    try { Tcp.Close(); } catch { }
                    Tcp = null;
                }
                Endpoint = null;
                BufPos = 0;
                BufLen = 0;
            }
        }

        private readonly object _lock = new object();
        private readonly object _kaLock = new object();
        private string _configuredPipe;
        private string _configuredController;
        private string _fallbackController;
        private string _secret;
        private EndpointInfo _cachedEndpoint;
        private string _cachedMatchProxy;
        private long _lastRulesFetchTicks;

        // Reusable watchdog hot-path connection & buffers (guarded by _kaLock)
        private PersistentConnection _kaConn;
        private readonly MemoryStream _kaHeaderAndBodyMs = new MemoryStream(8192);
        private readonly MemoryStream _kaChunkMs = new MemoryStream(4096);
        private readonly StringBuilder _kaReqSb = new StringBuilder(192);
        private readonly List<string> _evalChainBuf = new List<string>(8);
        private readonly HashSet<string> _evalVisitedBuf = new HashSet<string>(StringComparer.Ordinal);
        private byte[] _cachedConfigsReqBytes;
        private string _cachedConfigsReqSecret;
        private bool _disposed;

        public void UpdateConnectionConfig(
            string configuredPipe,
            string configuredController,
            string fallbackController,
            string secret)
        {
            bool changed;
            lock (_lock)
            {
                changed = !string.Equals(_configuredPipe, configuredPipe, StringComparison.OrdinalIgnoreCase) ||
                          !string.Equals(_configuredController, configuredController, StringComparison.OrdinalIgnoreCase) ||
                          !string.Equals(_fallbackController, fallbackController, StringComparison.OrdinalIgnoreCase) ||
                          !string.Equals(_secret, secret, StringComparison.Ordinal);
                _configuredPipe = configuredPipe ?? string.Empty;
                _configuredController = configuredController ?? string.Empty;
                _fallbackController = fallbackController ?? string.Empty;
                _secret = secret ?? string.Empty;
                if (changed)
                {
                    _cachedEndpoint = null;
                    _lastRulesFetchTicks = 0;
                }
            }
            if (changed)
            {
                CloseKeepAliveConnection();
            }
        }

        public void InvalidateRulesCache()
        {
            lock (_lock)
            {
                _lastRulesFetchTicks = 0;
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            CloseKeepAliveConnection();
            lock (_kaLock)
            {
                _kaHeaderAndBodyMs.Dispose();
                _kaChunkMs.Dispose();
            }
        }

        private void CloseKeepAliveConnection()
        {
            lock (_kaLock)
            {
                if (_kaConn != null)
                {
                    _kaConn.Dispose();
                    _kaConn = null;
                }
            }
        }

        // Fast hot-path evaluation for WatchdogLoop: reuses Keep-Alive pipe, queries only target group(s), zero JavaScriptSerializer
        public NodeEvaluationResult EvaluateNodeFast(NodeGuardConfig config, bool forceRulesRefresh)
        {
            NodeEvaluationResult res = new NodeEvaluationResult
            {
                IsAllowed = false,
                ClashMode = string.Empty,
                TargetGroup = string.Empty,
                ActiveNode = string.Empty,
                ResolutionChain = string.Empty,
                Reason = string.Empty
            };

            if (config == null || !config.Enabled)
            {
                res.IsAllowed = true;
                res.Reason = "未启用节点守护";
                return res;
            }

            if (config.AllowedNodes == null || config.AllowedNodes.Count == 0)
            {
                res.IsAllowed = false;
                res.Reason = "已启用节点守护但未配置允许节点";
                return res;
            }

            string secret;
            string cachedMatch;
            long lastRulesTicks;
            lock (_lock)
            {
                secret = _secret ?? string.Empty;
                cachedMatch = _cachedMatchProxy;
                lastRulesTicks = _lastRulesFetchTicks;
            }

            lock (_kaLock)
            {
                if (_disposed)
                {
                    res.Reason = "监控器已停止";
                    return res;
                }

                // 1. Query /configs over Keep-Alive pipe for live mode
                int statusCode;
                string configsBody;
                if (!TryKeepAliveGet("/configs", secret, out statusCode, out configsBody) || statusCode < 200 || statusCode >= 300)
                {
                    res.Reason = "无法连接 Clash 控制接口 (Named Pipe / External Controller)";
                    return res;
                }

                string mode;
                if (!TryExtractTopLevelJsonString(configsBody, "mode", out mode) || string.IsNullOrEmpty(mode))
                {
                    mode = "rule";
                }
                res.ClashMode = mode;

                if (string.Equals(mode, "direct", StringComparison.OrdinalIgnoreCase))
                {
                    res.ActiveNode = "DIRECT";
                    res.ResolutionChain = "DIRECT";
                    res.Reason = "Clash 处于 Direct 直连模式";
                    return res;
                }

                // 2. Determine entry group (GLOBAL / explicit config.ProxyGroup / MATCH rule target)
                string entryName;
                bool isAutoMatch = false;
                if (string.Equals(mode, "global", StringComparison.OrdinalIgnoreCase))
                {
                    entryName = "GLOBAL";
                }
                else if (!string.IsNullOrEmpty(config.ProxyGroup))
                {
                    entryName = config.ProxyGroup;
                }
                else
                {
                    isAutoMatch = true;
                    long nowTicks = DateTime.UtcNow.Ticks;
                    bool ttlExpired = (lastRulesTicks == 0) ||
                                      ((nowTicks - lastRulesTicks) >= TimeSpan.FromMilliseconds(RULES_CACHE_TTL_MS).Ticks);
                    if (forceRulesRefresh || ttlExpired || string.IsNullOrEmpty(cachedMatch))
                    {
                        string fetchedMatch = RefreshMatchRuleKeepAlive(secret, nowTicks);
                        if (!string.IsNullOrEmpty(fetchedMatch))
                        {
                            cachedMatch = fetchedMatch;
                        }
                    }

                    entryName = !string.IsNullOrEmpty(cachedMatch) ? cachedMatch : "PROXY";
                }

                // 3. Query entry group via GET /proxies/{escaped}
                string entryBody;
                int entryStatus;
                if (!TryKeepAliveGet("/proxies/" + Uri.EscapeDataString(entryName), secret, out entryStatus, out entryBody))
                {
                    res.Reason = "无法读取 Clash 代理组状态";
                    return res;
                }

                // If auto MATCH target returned 404 (profile just switched), refresh /rules once and retry
                if (entryStatus == 404 && isAutoMatch)
                {
                    string refreshedMatch = RefreshMatchRuleKeepAlive(secret, DateTime.UtcNow.Ticks);
                    if (!string.IsNullOrEmpty(refreshedMatch) &&
                        !string.Equals(refreshedMatch, entryName, StringComparison.Ordinal))
                    {
                        entryName = refreshedMatch;
                        if (!TryKeepAliveGet("/proxies/" + Uri.EscapeDataString(entryName), secret, out entryStatus, out entryBody))
                        {
                            res.Reason = "无法读取 Clash 代理组状态";
                            return res;
                        }
                    }
                }

                if (entryStatus == 404)
                {
                    res.TargetGroup = entryName;
                    res.Reason = isAutoMatch
                        ? "未找到 MATCH 默认出口规则，请在设置中指定代理组"
                        : ("未找到代理组: " + entryName);
                    return res;
                }
                if (entryStatus < 200 || entryStatus >= 300)
                {
                    res.Reason = "读取 Clash 代理组失败 (HTTP " + entryStatus + ")";
                    return res;
                }

                // 4. Walk group chain using targeted single-item GET /proxies/{next}
                string canonicalEntryName;
                if (!TryExtractTopLevelJsonString(entryBody, "name", out canonicalEntryName) || string.IsNullOrEmpty(canonicalEntryName))
                {
                    canonicalEntryName = entryName;
                }

                _evalChainBuf.Clear();
                _evalVisitedBuf.Clear();
                _evalChainBuf.Add(canonicalEntryName);
                _evalVisitedBuf.Add(canonicalEntryName);

                string curName = canonicalEntryName;
                string curBody = entryBody;
                while (true)
                {
                    string curType;
                    TryExtractTopLevelJsonString(curBody, "type", out curType);
                    bool isGroup = HasTopLevelJsonKey(curBody, "all") || NodeGuardEvaluator.IsGroupType(curType);
                    if (!isGroup)
                    {
                        break;
                    }

                    string nextName;
                    if (!TryExtractTopLevelJsonString(curBody, "now", out nextName) || string.IsNullOrEmpty(nextName))
                    {
                        res.TargetGroup = canonicalEntryName;
                        res.ResolutionChain = string.Join(" -> ", _evalChainBuf.ToArray());
                        res.Reason = "代理组无当前选中节点: " + curName;
                        return res;
                    }

                    if (!_evalVisitedBuf.Add(nextName) || _evalChainBuf.Count >= 16)
                    {
                        res.TargetGroup = canonicalEntryName;
                        res.ResolutionChain = string.Join(" -> ", _evalChainBuf.ToArray());
                        res.Reason = "代理组存在循环引用: " + nextName;
                        return res;
                    }

                    _evalChainBuf.Add(nextName);
                    if (NodeGuardEvaluator.IsBuiltinNode(nextName))
                    {
                        break;
                    }

                    int nextStatus;
                    string nextBody;
                    if (!TryKeepAliveGet("/proxies/" + Uri.EscapeDataString(nextName), secret, out nextStatus, out nextBody) ||
                        nextStatus < 200 || nextStatus >= 300)
                    {
                        // Treat as resolved leaf node name if not queryable as a separate entry
                        break;
                    }

                    curName = nextName;
                    curBody = nextBody;
                }

                string leafNode = _evalChainBuf[_evalChainBuf.Count - 1];
                string chainText = string.Join(" -> ", _evalChainBuf.ToArray());
                return NodeGuardEvaluator.BuildMatchResult(config, mode, canonicalEntryName, leafNode, chainText);
            }
        }

        private string RefreshMatchRuleKeepAlive(string secret, long nowTicks)
        {
            int statusCode;
            string rulesBody;
            if (!TryKeepAliveGet("/rules", secret, out statusCode, out rulesBody) || statusCode < 200 || statusCode >= 300)
            {
                return string.Empty;
            }
            string matchProxy = ExtractMatchRuleProxy(rulesBody);
            if (!string.IsNullOrEmpty(matchProxy))
            {
                lock (_lock)
                {
                    _cachedMatchProxy = matchProxy;
                    _lastRulesFetchTicks = nowTicks;
                }
            }
            return matchProxy;
        }

        private bool TryKeepAliveGet(string path, string secret, out int statusCode, out string body)
        {
            statusCode = 0;
            body = null;

            // Attempt 1: existing Keep-Alive connection
            if (_kaConn != null)
            {
                if (TrySendAndReceiveKeepAlive(_kaConn, path, secret, out statusCode, out body))
                {
                    return true;
                }
                _kaConn.Dispose();
                _kaConn = null;
            }

            // Attempt 2: reconnect using cached endpoint
            EndpointInfo cached;
            lock (_lock)
            {
                cached = _cachedEndpoint;
            }
            if (cached != null)
            {
                PersistentConnection conn = OpenPersistentConnection(cached);
                if (conn != null)
                {
                    if (TrySendAndReceiveKeepAlive(conn, path, secret, out statusCode, out body))
                    {
                        _kaConn = conn;
                        return true;
                    }
                    conn.Dispose();
                }
            }

            // Attempt 3: full endpoint discovery
            List<EndpointInfo> candidates = BuildCandidateEndpoints();
            for (int i = 0; i < candidates.Count; i++)
            {
                EndpointInfo ep = candidates[i];
                PersistentConnection conn = OpenPersistentConnection(ep);
                if (conn == null)
                {
                    continue;
                }
                if (TrySendAndReceiveKeepAlive(conn, path, secret, out statusCode, out body))
                {
                    lock (_lock)
                    {
                        _cachedEndpoint = ep;
                    }
                    _kaConn = conn;
                    return true;
                }
                conn.Dispose();
            }

            return false;
        }

        private static PersistentConnection OpenPersistentConnection(EndpointInfo ep)
        {
            if (ep == null)
            {
                return null;
            }

            try
            {
                if (ep.IsPipe)
                {
                    NamedPipeClientStream pipe = new NamedPipeClientStream(
                        ".",
                        ep.PipeName,
                        PipeDirection.InOut,
                        PipeOptions.Asynchronous);
                    try
                    {
                        pipe.Connect(CONNECT_TIMEOUT_MS);
                        return new PersistentConnection
                        {
                            Endpoint = ep,
                            Pipe = pipe,
                            Stream = pipe,
                            UseAsync = true
                        };
                    }
                    catch
                    {
                        pipe.Dispose();
                        return null;
                    }
                }
                else
                {
                    TcpClient tcp = new TcpClient();
                    try
                    {
                        tcp.NoDelay = true;
                        IAsyncResult ar = tcp.BeginConnect(ep.Host, ep.Port, null, null);
                        if (!ar.AsyncWaitHandle.WaitOne(CONNECT_TIMEOUT_MS))
                        {
                            tcp.Close();
                            return null;
                        }
                        tcp.EndConnect(ar);
                        NetworkStream ns = tcp.GetStream();
                        ns.ReadTimeout = READ_TIMEOUT_MS;
                        ns.WriteTimeout = READ_TIMEOUT_MS;
                        return new PersistentConnection
                        {
                            Endpoint = ep,
                            Tcp = tcp,
                            Stream = ns,
                            UseAsync = false
                        };
                    }
                    catch
                    {
                        tcp.Close();
                        return null;
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        private byte[] BuildKeepAliveRequestBytes(string path, string secret)
        {
            if (string.Equals(path, "/configs", StringComparison.Ordinal) &&
                _cachedConfigsReqBytes != null &&
                string.Equals(_cachedConfigsReqSecret, secret, StringComparison.Ordinal))
            {
                return _cachedConfigsReqBytes;
            }

            _kaReqSb.Clear();
            _kaReqSb.Append("GET ").Append(path).Append(" HTTP/1.1\r\n");
            _kaReqSb.Append("Host: localhost\r\n");
            _kaReqSb.Append("Connection: keep-alive\r\n");
            if (!string.IsNullOrEmpty(secret))
            {
                _kaReqSb.Append("Authorization: Bearer ").Append(secret).Append("\r\n");
            }
            _kaReqSb.Append("\r\n");
            byte[] bytes = Encoding.ASCII.GetBytes(_kaReqSb.ToString());

            if (string.Equals(path, "/configs", StringComparison.Ordinal))
            {
                _cachedConfigsReqBytes = bytes;
                _cachedConfigsReqSecret = secret;
            }
            return bytes;
        }

        private bool TrySendAndReceiveKeepAlive(
            PersistentConnection conn,
            string path,
            string secret,
            out int statusCode,
            out string body)
        {
            statusCode = 0;
            body = null;

            try
            {
                byte[] reqBytes = BuildKeepAliveRequestBytes(path, secret);
                if (!WriteAllWithTimeout(conn.Stream, reqBytes, READ_TIMEOUT_MS, conn.UseAsync))
                {
                    return false;
                }

                long deadlineTicks = Stopwatch.GetTimestamp() + (long)(READ_TIMEOUT_MS * (Stopwatch.Frequency / 1000.0));
                _kaHeaderAndBodyMs.SetLength(0);

                // Read until \r\n\r\n header delimiter
                int headerEnd = -1;
                while (headerEnd < 0)
                {
                    if (conn.BufPos >= conn.BufLen)
                    {
                        int n = ReadSomeFromConn(conn, deadlineTicks);
                        if (n <= 0)
                        {
                            return false;
                        }
                    }

                    int avail = conn.BufLen - conn.BufPos;
                    int prevLen = (int)_kaHeaderAndBodyMs.Length;
                    if (prevLen + avail > MAX_RESPONSE_BYTES)
                    {
                        return false;
                    }
                    _kaHeaderAndBodyMs.Write(conn.ReadBuf, conn.BufPos, avail);
                    conn.BufPos = conn.BufLen;

                    int totalLen = (int)_kaHeaderAndBodyMs.Length;
                    int searchStart = Math.Max(0, prevLen - 3);
                    headerEnd = FindHeaderBodySeparator(_kaHeaderAndBodyMs.GetBuffer(), searchStart, totalLen);
                }

                byte[] buf = _kaHeaderAndBodyMs.GetBuffer();
                int totalBuffered = (int)_kaHeaderAndBodyMs.Length;
                int contentLength;
                bool isChunked;
                bool connectionClose;
                if (!ParseHttpHeadersFromBytes(buf, headerEnd, out statusCode, out contentLength, out isChunked, out connectionClose))
                {
                    return false;
                }

                int bodyStart = headerEnd + 4;
                int bufferedBodyLen = totalBuffered - bodyStart;

                if (contentLength >= 0)
                {
                    if (contentLength > MAX_RESPONSE_BYTES)
                    {
                        return false;
                    }

                    if (bufferedBodyLen > contentLength)
                    {
                        // Push any trailing bytes (pipelined) back into conn.ReadBuf
                        int extra = bufferedBodyLen - contentLength;
                        if (extra <= conn.ReadBuf.Length)
                        {
                            Buffer.BlockCopy(buf, bodyStart + contentLength, conn.ReadBuf, 0, extra);
                            conn.BufPos = 0;
                            conn.BufLen = extra;
                        }
                        else
                        {
                            connectionClose = true;
                        }
                        body = Encoding.UTF8.GetString(buf, bodyStart, contentLength);
                    }
                    else
                    {
                        int remaining = contentLength - bufferedBodyLen;
                        while (remaining > 0)
                        {
                            if (conn.BufPos >= conn.BufLen)
                            {
                                int n = ReadSomeFromConn(conn, deadlineTicks);
                                if (n <= 0)
                                {
                                    return false;
                                }
                            }
                            int take = Math.Min(remaining, conn.BufLen - conn.BufPos);
                            _kaHeaderAndBodyMs.Write(conn.ReadBuf, conn.BufPos, take);
                            conn.BufPos += take;
                            remaining -= take;
                        }

                        byte[] finalBuf = _kaHeaderAndBodyMs.GetBuffer();
                        body = Encoding.UTF8.GetString(finalBuf, bodyStart, contentLength);
                    }
                }
                else if (isChunked)
                {
                    // Move any already-buffered chunk bytes back to conn or read chunked cleanly
                    if (!ReadChunkedBodyFromKeepAlive(conn, buf, bodyStart, bufferedBodyLen, deadlineTicks, out body))
                    {
                        return false;
                    }
                }
                else
                {
                    // No Content-Length and not chunked: read to EOF and close connection
                    connectionClose = true;
                    while (true)
                    {
                        int n = ReadSomeFromConn(conn, deadlineTicks);
                        if (n <= 0)
                        {
                            break;
                        }
                        int avail = conn.BufLen - conn.BufPos;
                        if (_kaHeaderAndBodyMs.Length + avail > MAX_RESPONSE_BYTES)
                        {
                            return false;
                        }
                        _kaHeaderAndBodyMs.Write(conn.ReadBuf, conn.BufPos, avail);
                        conn.BufPos = conn.BufLen;
                    }
                    byte[] finalBuf = _kaHeaderAndBodyMs.GetBuffer();
                    int finalLen = (int)_kaHeaderAndBodyMs.Length - bodyStart;
                    body = finalLen > 0 ? Encoding.UTF8.GetString(finalBuf, bodyStart, finalLen) : string.Empty;
                }

                if (connectionClose && ReferenceEquals(_kaConn, conn))
                {
                    _kaConn.Dispose();
                    _kaConn = null;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool ReadChunkedBodyFromKeepAlive(
            PersistentConnection conn,
            byte[] initialBuf,
            int initialOffset,
            int initialLen,
            long deadlineTicks,
            out string body)
        {
            body = null;
            _kaChunkMs.SetLength(0);

            // Accumulate raw chunked bytes in _kaHeaderAndBodyMs starting at initialOffset
            int pos = initialOffset;
            int end = initialOffset + initialLen;

            while (true)
            {
                // Find chunk-size line ending \r\n
                int lineEnd;
                while ((lineEnd = FindCrLf(_kaHeaderAndBodyMs.GetBuffer(), pos, end)) < 0)
                {
                    int n = ReadSomeFromConn(conn, deadlineTicks);
                    if (n <= 0) return false;
                    int avail = conn.BufLen - conn.BufPos;
                    if (_kaHeaderAndBodyMs.Length + avail > MAX_RESPONSE_BYTES) return false;
                    _kaHeaderAndBodyMs.Write(conn.ReadBuf, conn.BufPos, avail);
                    conn.BufPos = conn.BufLen;
                    end = (int)_kaHeaderAndBodyMs.Length;
                }

                int chunkSize;
                if (!TryParseHexChunkSize(_kaHeaderAndBodyMs.GetBuffer(), pos, lineEnd - pos, out chunkSize) || chunkSize < 0)
                {
                    return false;
                }

                pos = lineEnd + 2;
                if (chunkSize == 0)
                {
                    // Consume trailing \r\n after 0-chunk
                    while (end - pos < 2)
                    {
                        int n = ReadSomeFromConn(conn, deadlineTicks);
                        if (n <= 0) break;
                        int avail = conn.BufLen - conn.BufPos;
                        _kaHeaderAndBodyMs.Write(conn.ReadBuf, conn.BufPos, avail);
                        conn.BufPos = conn.BufLen;
                        end = (int)_kaHeaderAndBodyMs.Length;
                    }
                    body = Encoding.UTF8.GetString(_kaChunkMs.GetBuffer(), 0, (int)_kaChunkMs.Length);
                    return true;
                }

                int needEnd = pos + chunkSize + 2;
                while (end < needEnd)
                {
                    int n = ReadSomeFromConn(conn, deadlineTicks);
                    if (n <= 0) return false;
                    int avail = conn.BufLen - conn.BufPos;
                    if (_kaHeaderAndBodyMs.Length + avail > MAX_RESPONSE_BYTES) return false;
                    _kaHeaderAndBodyMs.Write(conn.ReadBuf, conn.BufPos, avail);
                    conn.BufPos = conn.BufLen;
                    end = (int)_kaHeaderAndBodyMs.Length;
                }

                _kaChunkMs.Write(_kaHeaderAndBodyMs.GetBuffer(), pos, chunkSize);
                pos = needEnd;
            }
        }

        private static int ReadSomeFromConn(PersistentConnection conn, long deadlineTicks)
        {
            long remTicks = deadlineTicks - Stopwatch.GetTimestamp();
            int remainingMs = (int)(remTicks * 1000L / Stopwatch.Frequency);
            if (remainingMs <= 0)
            {
                try { conn.Stream.Close(); } catch { }
                return -1;
            }

            int n;
            if (conn.UseAsync)
            {
                IAsyncResult ar = conn.Stream.BeginRead(conn.ReadBuf, 0, conn.ReadBuf.Length, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(remainingMs))
                {
                    try { conn.Stream.Close(); } catch { }
                    return -1;
                }
                n = conn.Stream.EndRead(ar);
            }
            else
            {
                conn.Stream.ReadTimeout = remainingMs;
                n = conn.Stream.Read(conn.ReadBuf, 0, conn.ReadBuf.Length);
            }

            conn.BufPos = 0;
            conn.BufLen = n > 0 ? n : 0;
            return n;
        }

        private static bool ParseHttpHeadersFromBytes(
            byte[] data,
            int headerEnd,
            out int statusCode,
            out int contentLength,
            out bool isChunked,
            out bool connectionClose)
        {
            statusCode = 0;
            contentLength = -1;
            isChunked = false;
            connectionClose = false;

            int lineEnd = FindCrLf(data, 0, headerEnd);
            int statusLineEnd = lineEnd >= 0 ? lineEnd : headerEnd;

            // Parse status code from "HTTP/1.x NNN ..."
            int sp = Array.IndexOf(data, (byte)' ', 0, statusLineEnd);
            if (sp < 0)
            {
                return false;
            }
            while (sp < statusLineEnd && data[sp] == (byte)' ')
            {
                sp++;
            }
            if (sp + 3 > statusLineEnd)
            {
                return false;
            }
            int d0 = data[sp] - '0';
            int d1 = data[sp + 1] - '0';
            int d2 = data[sp + 2] - '0';
            if (d0 < 0 || d0 > 9 || d1 < 0 || d1 > 9 || d2 < 0 || d2 > 9)
            {
                return false;
            }
            statusCode = d0 * 100 + d1 * 10 + d2;

            if (lineEnd < 0)
            {
                return true;
            }

            int pos = lineEnd + 2;
            while (pos < headerEnd)
            {
                int nextEnd = FindCrLf(data, pos, headerEnd);
                if (nextEnd < 0)
                {
                    nextEnd = headerEnd;
                }

                int colon = Array.IndexOf(data, (byte)':', pos, nextEnd - pos);
                if (colon > pos)
                {
                    int nameLen = colon - pos;
                    int valStart = colon + 1;
                    while (valStart < nextEnd && (data[valStart] == (byte)' ' || data[valStart] == (byte)'\t'))
                    {
                        valStart++;
                    }
                    int valEnd = nextEnd;
                    while (valEnd > valStart && (data[valEnd - 1] == (byte)' ' || data[valEnd - 1] == (byte)'\t'))
                    {
                        valEnd--;
                    }
                    int valLen = valEnd - valStart;

                    if (BytesEqualsAsciiIgnoreCase(data, pos, nameLen, "Content-Length"))
                    {
                        int parsedLen;
                        if (TryParseAsciiInt(data, valStart, valLen, out parsedLen) && parsedLen >= 0)
                        {
                            contentLength = parsedLen;
                        }
                    }
                    else if (BytesEqualsAsciiIgnoreCase(data, pos, nameLen, "Transfer-Encoding"))
                    {
                        if (BytesContainsAsciiIgnoreCase(data, valStart, valLen, "chunked"))
                        {
                            isChunked = true;
                        }
                    }
                    else if (BytesEqualsAsciiIgnoreCase(data, pos, nameLen, "Connection"))
                    {
                        if (BytesContainsAsciiIgnoreCase(data, valStart, valLen, "close"))
                        {
                            connectionClose = true;
                        }
                    }
                }

                pos = nextEnd + 2;
            }

            return true;
        }

        private static int FindCrLf(byte[] data, int start, int end)
        {
            for (int i = start; i <= end - 2; i++)
            {
                if (data[i] == 13 && data[i + 1] == 10)
                {
                    return i;
                }
            }
            return -1;
        }

        private static bool BytesEqualsAsciiIgnoreCase(byte[] data, int offset, int len, string ascii)
        {
            if (len != ascii.Length)
            {
                return false;
            }
            for (int i = 0; i < len; i++)
            {
                int a = data[offset + i];
                if (a >= 'A' && a <= 'Z') a += 32;
                int b = ascii[i];
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b)
                {
                    return false;
                }
            }
            return true;
        }

        private static bool BytesContainsAsciiIgnoreCase(byte[] data, int offset, int len, string needle)
        {
            if (needle.Length == 0 || len < needle.Length)
            {
                return false;
            }
            int limit = offset + len - needle.Length;
            for (int i = offset; i <= limit; i++)
            {
                if (BytesEqualsAsciiIgnoreCase(data, i, needle.Length, needle))
                {
                    return true;
                }
            }
            return false;
        }

        private static bool TryParseAsciiInt(byte[] data, int offset, int len, out int value)
        {
            value = 0;
            if (len <= 0)
            {
                return false;
            }
            long acc = 0;
            for (int i = 0; i < len; i++)
            {
                int d = data[offset + i] - '0';
                if (d < 0 || d > 9)
                {
                    return false;
                }
                acc = acc * 10 + d;
                if (acc > int.MaxValue)
                {
                    return false;
                }
            }
            value = (int)acc;
            return true;
        }

        private static bool TryParseHexChunkSize(byte[] data, int offset, int len, out int value)
        {
            value = 0;
            int end = offset + len;
            while (offset < end && (data[offset] == ' ' || data[offset] == '\t')) offset++;
            int acc = 0;
            bool any = false;
            while (offset < end)
            {
                byte b = data[offset];
                if (b == ';' || b == ' ' || b == '\t')
                {
                    break;
                }
                int hex;
                if (b >= '0' && b <= '9') hex = b - '0';
                else if (b >= 'a' && b <= 'f') hex = b - 'a' + 10;
                else if (b >= 'A' && b <= 'F') hex = b - 'A' + 10;
                else return false;
                acc = (acc << 4) | hex;
                any = true;
                offset++;
            }
            value = acc;
            return any;
        }

        public static bool TryExtractTopLevelJsonString(string json, string targetKey, out string value)
        {
            value = null;
            if (string.IsNullOrEmpty(json) || string.IsNullOrEmpty(targetKey))
            {
                return false;
            }

            int pos = 0;
            int len = json.Length;
            SkipJsonWs(json, ref pos);
            if (pos >= len || json[pos] != '{')
            {
                return false;
            }
            pos++; // enter root object

            while (pos < len)
            {
                SkipJsonWs(json, ref pos);
                if (pos >= len || json[pos] == '}')
                {
                    break;
                }
                if (json[pos] == ',')
                {
                    pos++;
                    continue;
                }
                if (json[pos] != '"')
                {
                    return false;
                }

                string key;
                if (!ReadJsonString(json, ref pos, out key))
                {
                    return false;
                }

                SkipJsonWs(json, ref pos);
                if (pos >= len || json[pos] != ':')
                {
                    return false;
                }
                pos++;
                SkipJsonWs(json, ref pos);

                if (string.Equals(key, targetKey, StringComparison.Ordinal))
                {
                    if (pos < len && json[pos] == '"')
                    {
                        return ReadJsonString(json, ref pos, out value);
                    }
                    return false;
                }

                if (!SkipJsonValue(json, ref pos))
                {
                    return false;
                }
            }

            return false;
        }

        public static bool HasTopLevelJsonKey(string json, string targetKey)
        {
            if (string.IsNullOrEmpty(json) || string.IsNullOrEmpty(targetKey))
            {
                return false;
            }

            int pos = 0;
            int len = json.Length;
            SkipJsonWs(json, ref pos);
            if (pos >= len || json[pos] != '{')
            {
                return false;
            }
            pos++;

            while (pos < len)
            {
                SkipJsonWs(json, ref pos);
                if (pos >= len || json[pos] == '}')
                {
                    break;
                }
                if (json[pos] == ',')
                {
                    pos++;
                    continue;
                }
                if (json[pos] != '"')
                {
                    return false;
                }

                string key;
                if (!ReadJsonString(json, ref pos, out key))
                {
                    return false;
                }

                SkipJsonWs(json, ref pos);
                if (pos >= len || json[pos] != ':')
                {
                    return false;
                }
                pos++;
                SkipJsonWs(json, ref pos);

                if (string.Equals(key, targetKey, StringComparison.Ordinal))
                {
                    // Return true if value is non-null
                    return pos < len && json[pos] != 'n';
                }

                if (!SkipJsonValue(json, ref pos))
                {
                    return false;
                }
            }

            return false;
        }

        private static void SkipJsonWs(string s, ref int pos)
        {
            int len = s.Length;
            while (pos < len)
            {
                char c = s[pos];
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
                {
                    break;
                }
                pos++;
            }
        }

        private static bool ReadJsonString(string s, ref int pos, out string result)
        {
            result = null;
            int len = s.Length;
            if (pos >= len || s[pos] != '"')
            {
                return false;
            }
            pos++; // skip opening quote
            int start = pos;
            bool hasEscape = false;

            while (pos < len)
            {
                char c = s[pos];
                if (c == '"')
                {
                    if (!hasEscape)
                    {
                        result = s.Substring(start, pos - start);
                        pos++;
                        return true;
                    }
                    break;
                }
                if (c == '\\')
                {
                    hasEscape = true;
                    pos += 2;
                    continue;
                }
                pos++;
            }

            if (pos >= len)
            {
                return false;
            }

            int end = pos;
            pos++; // skip closing quote
            StringBuilder sb = new StringBuilder(end - start);
            for (int i = start; i < end; i++)
            {
                char c = s[i];
                if (c != '\\' || i + 1 >= end)
                {
                    sb.Append(c);
                    continue;
                }
                char esc = s[++i];
                switch (esc)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (i + 4 < end)
                        {
                            int code;
                            if (int.TryParse(s.Substring(i + 1, 4), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out code))
                            {
                                sb.Append((char)code);
                                i += 4;
                                break;
                            }
                        }
                        sb.Append("\\u");
                        break;
                    default:
                        sb.Append(esc);
                        break;
                }
            }
            result = sb.ToString();
            return true;
        }

        private static bool SkipJsonValue(string s, ref int pos)
        {
            int len = s.Length;
            if (pos >= len)
            {
                return false;
            }

            char c = s[pos];
            if (c == '"')
            {
                pos++;
                while (pos < len)
                {
                    char ch = s[pos++];
                    if (ch == '\\')
                    {
                        if (pos < len) pos++;
                    }
                    else if (ch == '"')
                    {
                        return true;
                    }
                }
                return false;
            }

            if (c == '{' || c == '[')
            {
                int depth = 0;
                bool inStr = false;
                while (pos < len)
                {
                    char ch = s[pos++];
                    if (inStr)
                    {
                        if (ch == '\\')
                        {
                            if (pos < len) pos++;
                        }
                        else if (ch == '"')
                        {
                            inStr = false;
                        }
                        continue;
                    }
                    if (ch == '"')
                    {
                        inStr = true;
                    }
                    else if (ch == '{' || ch == '[')
                    {
                        depth++;
                    }
                    else if (ch == '}' || ch == ']')
                    {
                        depth--;
                        if (depth == 0)
                        {
                            return true;
                        }
                    }
                }
                return false;
            }

            while (pos < len)
            {
                char ch = s[pos];
                if (ch == ',' || ch == '}' || ch == ']' || ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
                {
                    return true;
                }
                pos++;
            }
            return true;
        }

        public ClashSnapshot QuerySnapshot(bool needMatchRule, bool forceRulesRefresh)
        {
            ClashSnapshot snap = new ClashSnapshot();
            string secret;
            string cachedMatch;
            long lastRulesTicks;

            lock (_lock)
            {
                secret = _secret ?? string.Empty;
                cachedMatch = _cachedMatchProxy;
                lastRulesTicks = _lastRulesFetchTicks;
            }

            string configsBody;
            EndpointInfo ep;
            if (!TryGetJsonWithDiscovery("/configs", secret, out configsBody, out ep))
            {
                snap.Connected = false;
                snap.Error = "无法连接 Clash 控制接口 (Named Pipe / External Controller)";
                return snap;
            }

            string proxiesBody;
            if (!TryGetJsonOnEndpoint(ep, "/proxies", secret, out proxiesBody))
            {
                // Endpoint may have just restarted; clear cache and retry once via discovery
                lock (_lock)
                {
                    _cachedEndpoint = null;
                }
                if (!TryGetJsonWithDiscovery("/proxies", secret, out proxiesBody, out ep))
                {
                    snap.Connected = false;
                    snap.Error = "无法读取 Clash 节点列表 (/proxies)";
                    return snap;
                }
            }

            string mode = ParseModeFromConfigsJson(configsBody);
            Dictionary<string, ClashProxyEntry> proxies = ParseProxiesJson(proxiesBody);
            if (proxies == null)
            {
                snap.Connected = false;
                snap.Error = "解析 Clash 节点列表失败";
                return snap;
            }

            snap.Connected = true;
            snap.Endpoint = ep.Display;
            snap.Mode = string.IsNullOrEmpty(mode) ? "rule" : mode;
            snap.Proxies = proxies;

            if (needMatchRule && !string.Equals(snap.Mode, "global", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(snap.Mode, "direct", StringComparison.OrdinalIgnoreCase))
            {
                long nowTicks = DateTime.UtcNow.Ticks;
                bool ttlExpired = (lastRulesTicks == 0) ||
                                  ((nowTicks - lastRulesTicks) >= TimeSpan.FromMilliseconds(RULES_CACHE_TTL_MS).Ticks);
                bool cachedMissing = !string.IsNullOrEmpty(cachedMatch) && !proxies.ContainsKey(cachedMatch);

                if (forceRulesRefresh || ttlExpired || string.IsNullOrEmpty(cachedMatch) || cachedMissing)
                {
                    string rulesBody;
                    if (TryGetJsonOnEndpoint(ep, "/rules", secret, out rulesBody))
                    {
                        string matchProxy = ExtractMatchRuleProxy(rulesBody);
                        if (!string.IsNullOrEmpty(matchProxy))
                        {
                            cachedMatch = matchProxy;
                            lock (_lock)
                            {
                                _cachedMatchProxy = matchProxy;
                                _lastRulesFetchTicks = nowTicks;
                            }
                        }
                    }
                }

                snap.MatchRuleProxy = cachedMatch ?? string.Empty;
            }
            else
            {
                snap.MatchRuleProxy = cachedMatch ?? string.Empty;
            }

            return snap;
        }

        private bool TryGetJsonWithDiscovery(string path, string secret, out string body, out EndpointInfo usedEndpoint)
        {
            EndpointInfo cached;
            lock (_lock)
            {
                cached = _cachedEndpoint;
            }

            if (cached != null && TryGetJsonOnEndpoint(cached, path, secret, out body))
            {
                usedEndpoint = cached;
                return true;
            }

            List<EndpointInfo> candidates = BuildCandidateEndpoints();
            for (int i = 0; i < candidates.Count; i++)
            {
                EndpointInfo ep = candidates[i];
                if (TryGetJsonOnEndpoint(ep, path, secret, out body))
                {
                    lock (_lock)
                    {
                        _cachedEndpoint = ep;
                    }
                    usedEndpoint = ep;
                    return true;
                }
            }

            body = null;
            usedEndpoint = null;
            return false;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WaitNamedPipeW(string lpNamedPipeName, uint nTimeOut);

        private List<EndpointInfo> BuildCandidateEndpoints()
        {
            string configuredPipe;
            string configuredController;
            string fallbackController;
            lock (_lock)
            {
                configuredPipe = _configuredPipe ?? string.Empty;
                configuredController = _configuredController ?? string.Empty;
                fallbackController = _fallbackController ?? string.Empty;
            }

            List<EndpointInfo> list = new List<EndpointInfo>(4);
            HashSet<string> addedPipes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string configuredPipeName = StripPipePrefix(configuredPipe);
            string configuredSuffix = ExtractTrailingHash(configuredPipeName);

            // 1. Direct fast-path probe using configured & derived pipe names (avoids enumerating all system pipes)
            List<string> directProbes = new List<string>(3);
            if (!string.IsNullOrEmpty(configuredSuffix))
            {
                directProbes.Add("verge-mihomo-production-" + configuredSuffix);
                directProbes.Add("verge-mihomo-service-" + configuredSuffix);
            }
            if (!string.IsNullOrEmpty(configuredPipeName))
            {
                directProbes.Add(configuredPipeName);
            }
            for (int i = 0; i < directProbes.Count; i++)
            {
                string candidate = directProbes[i];
                if (!addedPipes.Contains(candidate) && PipeIsAvailableFast(candidate))
                {
                    addedPipes.Add(candidate);
                    list.Add(new EndpointInfo
                    {
                        IsPipe = true,
                        PipeName = candidate,
                        Display = @"\\.\pipe\" + candidate
                    });
                }
            }

            // 2. Only scan \\.\pipe\ if direct probes did not find an active Mihomo pipe
            if (list.Count == 0)
            {
                string[] existingPipes = null;
                try
                {
                    existingPipes = Directory.GetFiles(@"\\.\pipe\");
                }
                catch
                {
                }

                if (existingPipes != null)
                {
                    List<string> matchedPipes = new List<string>();
                    for (int i = 0; i < existingPipes.Length; i++)
                    {
                        string name = StripPipePrefix(existingPipes[i]);
                        if (string.IsNullOrEmpty(name))
                        {
                            continue;
                        }
                        if ((!string.IsNullOrEmpty(configuredPipeName) &&
                             string.Equals(name, configuredPipeName, StringComparison.OrdinalIgnoreCase)) ||
                            name.IndexOf("verge-mihomo", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            name.IndexOf("clash-mihomo", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            matchedPipes.Add(name);
                        }
                    }

                    matchedPipes.Sort((a, b) => ScorePipeCandidate(b, configuredPipeName, configuredSuffix)
                        .CompareTo(ScorePipeCandidate(a, configuredPipeName, configuredSuffix)));

                    for (int i = 0; i < matchedPipes.Count; i++)
                    {
                        string pipeName = matchedPipes[i];
                        if (addedPipes.Add(pipeName))
                        {
                            list.Add(new EndpointInfo
                            {
                                IsPipe = true,
                                PipeName = pipeName,
                                Display = @"\\.\pipe\" + pipeName
                            });
                        }
                    }
                }
                else if (!string.IsNullOrEmpty(configuredPipeName) && addedPipes.Add(configuredPipeName))
                {
                    list.Add(new EndpointInfo
                    {
                        IsPipe = true,
                        PipeName = configuredPipeName,
                        Display = @"\\.\pipe\" + configuredPipeName
                    });
                }
            }

            // 3. Fallback to TCP external-controller (clash-verge.yaml first, then config.yaml)
            TryAddTcpCandidate(list, configuredController);
            TryAddTcpCandidate(list, fallbackController);

            return list;
        }

        private static bool PipeIsAvailableFast(string pipeName)
        {
            if (string.IsNullOrEmpty(pipeName))
            {
                return false;
            }
            try
            {
                return WaitNamedPipeW(@"\\.\pipe\" + pipeName, 1);
            }
            catch
            {
                return false;
            }
        }

        private static int ScorePipeCandidate(string pipeName, string configuredPipeName, string configuredSuffix)
        {
            int score = 0;
            if (!string.IsNullOrEmpty(configuredPipeName) &&
                string.Equals(pipeName, configuredPipeName, StringComparison.OrdinalIgnoreCase))
            {
                score += 100;
            }
            if (!string.IsNullOrEmpty(configuredSuffix) &&
                pipeName.EndsWith(configuredSuffix, StringComparison.OrdinalIgnoreCase))
            {
                score += 50;
            }
            if (pipeName.IndexOf("production", StringComparison.OrdinalIgnoreCase) >= 0 ||
                pipeName.IndexOf("service", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                score += 20;
            }
            return score;
        }

        private static string StripPipePrefix(string pipePath)
        {
            if (string.IsNullOrWhiteSpace(pipePath))
            {
                return string.Empty;
            }
            string s = pipePath.Trim().Trim('\'', '"');
            const string prefix = @"\\.\pipe\";
            if (s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return s.Substring(prefix.Length);
            }
            return s;
        }

        private static string ExtractTrailingHash(string pipeName)
        {
            if (string.IsNullOrEmpty(pipeName))
            {
                return string.Empty;
            }
            int idx = pipeName.LastIndexOf('-');
            if (idx >= 0 && pipeName.Length - idx - 1 >= 16)
            {
                return pipeName.Substring(idx + 1);
            }
            return string.Empty;
        }

        private static void TryAddTcpCandidate(List<EndpointInfo> list, string rawController)
        {
            if (string.IsNullOrWhiteSpace(rawController))
            {
                return;
            }
            string s = rawController.Trim().Trim('\'', '"');
            if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                s = s.Substring("http://".Length);
            }
            else if (s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                s = s.Substring("https://".Length);
            }
            int slashIdx = s.IndexOf('/');
            if (slashIdx >= 0)
            {
                s = s.Substring(0, slashIdx);
            }

            string host;
            int port;
            int colonIdx = s.LastIndexOf(':');
            if (colonIdx < 0)
            {
                return;
            }
            host = s.Substring(0, colonIdx).Trim().Trim('[', ']');
            if (!int.TryParse(s.Substring(colonIdx + 1).Trim(), out port) || port <= 0 || port > 65535)
            {
                return;
            }
            if (string.IsNullOrEmpty(host) || host == "0.0.0.0" || host == "::" || host == "*")
            {
                host = "127.0.0.1";
            }

            string display = "http://" + host + ":" + port;
            for (int i = 0; i < list.Count; i++)
            {
                if (!list[i].IsPipe && string.Equals(list[i].Display, display, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            list.Add(new EndpointInfo
            {
                IsPipe = false,
                Host = host,
                Port = port,
                Display = display
            });
        }

        private static bool TryGetJsonOnEndpoint(EndpointInfo ep, string path, string secret, out string body)
        {
            body = null;
            if (ep == null)
            {
                return false;
            }

            if (ep.IsPipe)
            {
                return TryHttpGetOverPipe(ep.PipeName, path, secret, out body);
            }
            return TryHttpGetOverTcp(ep.Host, ep.Port, path, secret, out body);
        }

        private static bool TryHttpGetOverPipe(string pipeName, string path, string secret, out string body)
        {
            body = null;
            try
            {
                using (NamedPipeClientStream pipe = new NamedPipeClientStream(
                    ".",
                    pipeName,
                    PipeDirection.InOut,
                    PipeOptions.Asynchronous))
                {
                    pipe.Connect(CONNECT_TIMEOUT_MS);
                    byte[] reqBytes = BuildHttpGetRequest(path, secret);
                    if (!WriteAllWithTimeout(pipe, reqBytes, READ_TIMEOUT_MS, true))
                    {
                        return false;
                    }
                    int statusCode;
                    if (!ReadHttpResponse(pipe, READ_TIMEOUT_MS, true, out statusCode, out body))
                    {
                        return false;
                    }
                    return statusCode >= 200 && statusCode < 300;
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool TryHttpGetOverTcp(string host, int port, string path, string secret, out string body)
        {
            body = null;
            try
            {
                using (TcpClient tcp = new TcpClient())
                {
                    IAsyncResult ar = tcp.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(CONNECT_TIMEOUT_MS))
                    {
                        return false;
                    }
                    tcp.EndConnect(ar);

                    using (NetworkStream ns = tcp.GetStream())
                    {
                        ns.ReadTimeout = READ_TIMEOUT_MS;
                        ns.WriteTimeout = READ_TIMEOUT_MS;
                        byte[] reqBytes = BuildHttpGetRequest(path, secret);
                        ns.Write(reqBytes, 0, reqBytes.Length);
                        ns.Flush();

                        int statusCode;
                        if (!ReadHttpResponse(ns, READ_TIMEOUT_MS, false, out statusCode, out body))
                        {
                            return false;
                        }
                        return statusCode >= 200 && statusCode < 300;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        private static byte[] BuildHttpGetRequest(string path, string secret)
        {
            StringBuilder sb = new StringBuilder(160);
            sb.Append("GET ").Append(path).Append(" HTTP/1.0\r\n");
            sb.Append("Host: localhost\r\n");
            sb.Append("Connection: close\r\n");
            if (!string.IsNullOrEmpty(secret))
            {
                sb.Append("Authorization: Bearer ").Append(secret).Append("\r\n");
            }
            sb.Append("\r\n");
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        private static bool WriteAllWithTimeout(Stream stream, byte[] data, int timeoutMs, bool useAsync)
        {
            if (!useAsync)
            {
                stream.Write(data, 0, data.Length);
                stream.Flush();
                return true;
            }

            IAsyncResult ar = stream.BeginWrite(data, 0, data.Length, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
            {
                try { stream.Close(); } catch { }
                return false;
            }
            stream.EndWrite(ar);
            return true;
        }

        private static bool ReadHttpResponse(
            Stream stream,
            int timeoutMs,
            bool useAsync,
            out int statusCode,
            out string body)
        {
            statusCode = 0;
            body = null;

            byte[] raw;
            int rawLen;
            using (MemoryStream ms = new MemoryStream(8192))
            {
                byte[] buf = new byte[8192];
                Stopwatch sw = Stopwatch.StartNew();

                while (true)
                {
                    int remaining = timeoutMs - (int)sw.ElapsedMilliseconds;
                    if (remaining <= 0)
                    {
                        try { stream.Close(); } catch { }
                        return false;
                    }

                    int n;
                    if (useAsync)
                    {
                        IAsyncResult ar = stream.BeginRead(buf, 0, buf.Length, null, null);
                        if (!ar.AsyncWaitHandle.WaitOne(remaining))
                        {
                            try { stream.Close(); } catch { }
                            return false;
                        }
                        n = stream.EndRead(ar);
                    }
                    else
                    {
                        stream.ReadTimeout = remaining;
                        n = stream.Read(buf, 0, buf.Length);
                    }

                    if (n <= 0)
                    {
                        break;
                    }

                    if (ms.Length + n > MAX_RESPONSE_BYTES)
                    {
                        return false;
                    }
                    ms.Write(buf, 0, n);
                }

                raw = ms.GetBuffer();
                rawLen = (int)ms.Length;
            }

            int headerEnd = FindHeaderBodySeparator(raw, 0, rawLen);
            if (headerEnd < 0)
            {
                return false;
            }

            int unusedContentLen;
            bool isChunked;
            bool unusedClose;
            if (!ParseHttpHeadersFromBytes(raw, headerEnd, out statusCode, out unusedContentLen, out isChunked, out unusedClose))
            {
                return false;
            }

            int bodyOffset = headerEnd + 4;
            int bodyLen = rawLen - bodyOffset;
            if (bodyLen <= 0)
            {
                body = string.Empty;
                return true;
            }

            if (isChunked)
            {
                byte[] decoded;
                if (!TryDecodeChunkedBody(raw, bodyOffset, bodyLen, out decoded))
                {
                    return false;
                }
                body = Encoding.UTF8.GetString(decoded);
            }
            else
            {
                body = Encoding.UTF8.GetString(raw, bodyOffset, bodyLen);
            }

            return true;
        }

        private static int FindHeaderBodySeparator(byte[] data, int start, int length)
        {
            for (int i = start; i <= length - 4; i++)
            {
                if (data[i] == 13 && data[i + 1] == 10 && data[i + 2] == 13 && data[i + 3] == 10)
                {
                    return i;
                }
            }
            return -1;
        }

        private static bool TryDecodeChunkedBody(byte[] raw, int offset, int length, out byte[] decoded)
        {
            decoded = null;
            int pos = offset;
            int end = offset + length;
            using (MemoryStream ms = new MemoryStream(length))
            {
                while (pos < end)
                {
                    int lineEnd = -1;
                    for (int i = pos; i <= end - 2; i++)
                    {
                        if (raw[i] == 13 && raw[i + 1] == 10)
                        {
                            lineEnd = i;
                            break;
                        }
                    }
                    if (lineEnd < 0)
                    {
                        return false;
                    }

                    string sizeText = Encoding.ASCII.GetString(raw, pos, lineEnd - pos).Trim();
                    int semi = sizeText.IndexOf(';');
                    if (semi >= 0)
                    {
                        sizeText = sizeText.Substring(0, semi).Trim();
                    }

                    int chunkSize;
                    if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out chunkSize) || chunkSize < 0)
                    {
                        return false;
                    }

                    pos = lineEnd + 2;
                    if (chunkSize == 0)
                    {
                        decoded = ms.ToArray();
                        return true;
                    }

                    if (pos + chunkSize > end)
                    {
                        return false;
                    }

                    ms.Write(raw, pos, chunkSize);
                    pos += chunkSize;
                    if (pos + 2 <= end && raw[pos] == 13 && raw[pos + 1] == 10)
                    {
                        pos += 2;
                    }
                }
                decoded = ms.ToArray();
                return true;
            }
        }

        public static string ParseModeFromConfigsJson(string configsJson)
        {
            string mode;
            if (TryExtractTopLevelJsonString(configsJson, "mode", out mode) && !string.IsNullOrEmpty(mode))
            {
                return mode.Trim();
            }
            return string.Empty;
        }

        public static Dictionary<string, ClashProxyEntry> ParseProxiesJson(string proxiesJson)
        {
            if (string.IsNullOrWhiteSpace(proxiesJson))
            {
                return null;
            }
            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                serializer.MaxJsonLength = MAX_RESPONSE_BYTES;
                Dictionary<string, object> root = serializer.DeserializeObject(proxiesJson) as Dictionary<string, object>;
                if (root == null)
                {
                    return null;
                }

                object proxiesObj;
                if (!root.TryGetValue("proxies", out proxiesObj))
                {
                    return null;
                }

                Dictionary<string, object> proxiesDict = proxiesObj as Dictionary<string, object>;
                if (proxiesDict == null)
                {
                    return null;
                }

                Dictionary<string, ClashProxyEntry> result = new Dictionary<string, ClashProxyEntry>(proxiesDict.Count, StringComparer.Ordinal);
                foreach (KeyValuePair<string, object> kv in proxiesDict)
                {
                    Dictionary<string, object> item = kv.Value as Dictionary<string, object>;
                    if (item == null)
                    {
                        continue;
                    }

                    ClashProxyEntry entry = new ClashProxyEntry();
                    entry.Name = kv.Key;

                    object typeObj;
                    if (item.TryGetValue("type", out typeObj) && typeObj != null)
                    {
                        entry.Type = typeObj.ToString();
                    }

                    object nowObj;
                    if (item.TryGetValue("now", out nowObj) && nowObj != null)
                    {
                        entry.Now = nowObj.ToString();
                    }

                    object allObj;
                    if (item.TryGetValue("all", out allObj) && allObj != null)
                    {
                        object[] allArr = allObj as object[];
                        if (allArr != null)
                        {
                            entry.All = new List<string>(allArr.Length);
                            for (int i = 0; i < allArr.Length; i++)
                            {
                                if (allArr[i] != null)
                                {
                                    entry.All.Add(allArr[i].ToString());
                                }
                            }
                        }
                    }

                    entry.IsGroup = (entry.All != null) || NodeGuardEvaluator.IsGroupType(entry.Type);
                    result[kv.Key] = entry;
                }

                return result;
            }
            catch
            {
                return null;
            }
        }

        public static string ExtractMatchRuleProxy(string rulesJson)
        {
            if (string.IsNullOrWhiteSpace(rulesJson))
            {
                return string.Empty;
            }

            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                int searchFrom = rulesJson.Length - 1;
                while (searchFrom >= 0)
                {
                    int matchIdx = rulesJson.LastIndexOf("\"Match\"", searchFrom, StringComparison.OrdinalIgnoreCase);
                    if (matchIdx < 0)
                    {
                        break;
                    }

                    string objJson = ExtractEnclosingJsonObject(rulesJson, matchIdx, 8192);
                    if (!string.IsNullOrEmpty(objJson))
                    {
                        try
                        {
                            Dictionary<string, object> ruleObj = serializer.DeserializeObject(objJson) as Dictionary<string, object>;
                            if (ruleObj != null)
                            {
                                object typeObj;
                                object proxyObj;
                                if (ruleObj.TryGetValue("type", out typeObj) &&
                                    typeObj != null &&
                                    string.Equals(typeObj.ToString(), "Match", StringComparison.OrdinalIgnoreCase) &&
                                    ruleObj.TryGetValue("proxy", out proxyObj) &&
                                    proxyObj != null)
                                {
                                    string proxy = proxyObj.ToString().Trim();
                                    if (!string.IsNullOrEmpty(proxy))
                                    {
                                        return proxy;
                                    }
                                }
                            }
                        }
                        catch
                        {
                        }
                    }

                    searchFrom = matchIdx - 1;
                }
            }
            catch
            {
            }

            return string.Empty;
        }

        private static string ExtractEnclosingJsonObject(string json, int pos, int maxLen)
        {
            int depth = 0;
            bool inString = false;
            int objStart = -1;
            int minStart = Math.Max(0, pos - maxLen);

            for (int i = pos - 1; i >= minStart; i--)
            {
                char c = json[i];
                if (c == '"' && !IsEscapedQuote(json, i))
                {
                    inString = !inString;
                    continue;
                }
                if (inString)
                {
                    continue;
                }
                if (c == '}')
                {
                    depth++;
                }
                else if (c == '{')
                {
                    if (depth == 0)
                    {
                        objStart = i;
                        break;
                    }
                    depth--;
                }
            }

            if (objStart < 0)
            {
                return null;
            }

            depth = 0;
            inString = false;
            int maxEnd = Math.Min(json.Length, objStart + maxLen);
            for (int i = objStart; i < maxEnd; i++)
            {
                char c = json[i];
                if (c == '"' && !IsEscapedQuote(json, i))
                {
                    inString = !inString;
                    continue;
                }
                if (inString)
                {
                    continue;
                }
                if (c == '{')
                {
                    depth++;
                }
                else if (c == '}')
                {
                    depth--;
                    if (depth == 0)
                    {
                        return json.Substring(objStart, i - objStart + 1);
                    }
                }
            }

            return null;
        }

        private static bool IsEscapedQuote(string s, int quoteIndex)
        {
            int backslashes = 0;
            for (int i = quoteIndex - 1; i >= 0 && s[i] == '\\'; i--)
            {
                backslashes++;
            }
            return (backslashes & 1) == 1;
        }
    }

    internal sealed class SubscriptionNodeInfo
    {
        public string Name;
        public string Type;
        public string ProfileUid;
        public string ProfileName;
        public bool IsFromCurrentProfile;
    }

    internal sealed class SubscriptionProfileInfo
    {
        public string Uid;
        public string Name;
        public string FileName;
        public bool IsCurrent;
        public List<SubscriptionNodeInfo> Nodes;

        public SubscriptionProfileInfo()
        {
            Nodes = new List<SubscriptionNodeInfo>();
        }
    }

    internal sealed class ClashCatalogData
    {
        public ClashSnapshot LiveSnapshot;
        public List<SubscriptionProfileInfo> Profiles;
        public List<SubscriptionNodeInfo> AllUniqueNodes;

        public ClashCatalogData()
        {
            Profiles = new List<SubscriptionProfileInfo>();
            AllUniqueNodes = new List<SubscriptionNodeInfo>();
        }
    }

    internal static class ClashProfileCatalog
    {
        private sealed class CachedProfileFile
        {
            public long WriteTicks;
            public long Length;
            public List<SubscriptionNodeInfo> Nodes;
        }

        private static readonly object ProfileCacheLock = new object();
        private static readonly Dictionary<string, CachedProfileFile> ProfileFileCache =
            new Dictionary<string, CachedProfileFile>(StringComparer.OrdinalIgnoreCase);

        public static ClashCatalogData LoadAll(string clashVergeConfigDir, ClashSnapshot liveSnapshot)
        {
            ClashCatalogData catalog = new ClashCatalogData();
            catalog.LiveSnapshot = liveSnapshot;

            string profilesYamlPath = !string.IsNullOrEmpty(clashVergeConfigDir)
                ? Path.Combine(clashVergeConfigDir, "profiles.yaml")
                : string.Empty;
            string profilesDir = !string.IsNullOrEmpty(clashVergeConfigDir)
                ? Path.Combine(clashVergeConfigDir, "profiles")
                : string.Empty;

            List<SubscriptionProfileInfo> profiles = ReadProfilesIndex(profilesYamlPath);
            for (int i = 0; i < profiles.Count; i++)
            {
                SubscriptionProfileInfo prof = profiles[i];
                if (string.IsNullOrEmpty(prof.FileName) || string.IsNullOrEmpty(profilesDir))
                {
                    continue;
                }
                string filePath = Path.Combine(profilesDir, prof.FileName);
                List<SubscriptionNodeInfo> parsedNodes = ParseProfileNodesFromFile(filePath, prof);
                prof.Nodes.AddRange(parsedNodes);
            }

            // Merge live Mihomo nodes (covers proxy-providers, merge/script injected nodes, or missing profiles.yaml)
            if (liveSnapshot != null && liveSnapshot.Connected && liveSnapshot.Proxies != null)
            {
                SubscriptionProfileInfo currentProf = null;
                for (int i = 0; i < profiles.Count; i++)
                {
                    if (profiles[i].IsCurrent)
                    {
                        currentProf = profiles[i];
                        break;
                    }
                }

                List<ClashProxyEntry> liveLeafs = new List<ClashProxyEntry>();
                foreach (KeyValuePair<string, ClashProxyEntry> kv in liveSnapshot.Proxies)
                {
                    ClashProxyEntry entry = kv.Value;
                    if (entry != null && !entry.IsGroup && !NodeGuardEvaluator.IsBuiltinNode(entry.Name))
                    {
                        liveLeafs.Add(entry);
                    }
                }
                liveLeafs.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name));

                if (currentProf == null && liveLeafs.Count > 0)
                {
                    currentProf = new SubscriptionProfileInfo
                    {
                        Uid = "__live__",
                        Name = "当前运行订阅",
                        IsCurrent = true
                    };
                    profiles.Insert(0, currentProf);
                }

                if (currentProf != null)
                {
                    Dictionary<string, SubscriptionNodeInfo> existingByName = new Dictionary<string, SubscriptionNodeInfo>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < currentProf.Nodes.Count; i++)
                    {
                        if (!existingByName.ContainsKey(currentProf.Nodes[i].Name))
                        {
                            existingByName[currentProf.Nodes[i].Name] = currentProf.Nodes[i];
                        }
                    }

                    for (int i = 0; i < liveLeafs.Count; i++)
                    {
                        ClashProxyEntry entry = liveLeafs[i];
                        SubscriptionNodeInfo existing;
                        if (existingByName.TryGetValue(entry.Name, out existing))
                        {
                            if (string.IsNullOrEmpty(existing.Type) && !string.IsNullOrEmpty(entry.Type))
                            {
                                existing.Type = entry.Type;
                            }
                        }
                        else
                        {
                            SubscriptionNodeInfo added = new SubscriptionNodeInfo
                            {
                                Name = entry.Name,
                                Type = entry.Type ?? string.Empty,
                                ProfileUid = currentProf.Uid,
                                ProfileName = currentProf.Name,
                                IsFromCurrentProfile = true
                            };
                            currentProf.Nodes.Add(added);
                            existingByName[added.Name] = added;
                        }
                    }
                }
            }

            // Order profiles: current profile first, preserve original order for remaining profiles
            profiles.Sort((a, b) =>
            {
                if (a.IsCurrent != b.IsCurrent)
                {
                    return a.IsCurrent ? -1 : 1;
                }
                return 0;
            });

            // Build deduplicated AllUniqueNodes preserving profile order and native node order
            Dictionary<string, SubscriptionNodeInfo> uniqueMap = new Dictionary<string, SubscriptionNodeInfo>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < profiles.Count; i++)
            {
                SubscriptionProfileInfo prof = profiles[i];
                catalog.Profiles.Add(prof);

                for (int j = 0; j < prof.Nodes.Count; j++)
                {
                    SubscriptionNodeInfo n = prof.Nodes[j];
                    SubscriptionNodeInfo merged;
                    if (!uniqueMap.TryGetValue(n.Name, out merged))
                    {
                        merged = new SubscriptionNodeInfo
                        {
                            Name = n.Name,
                            Type = n.Type ?? string.Empty,
                            ProfileUid = prof.Uid,
                            ProfileName = prof.Name,
                            IsFromCurrentProfile = prof.IsCurrent
                        };
                        uniqueMap[n.Name] = merged;
                        catalog.AllUniqueNodes.Add(merged);
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(merged.Type) && !string.IsNullOrEmpty(n.Type))
                        {
                            merged.Type = n.Type;
                        }
                        if (prof.IsCurrent)
                        {
                            merged.IsFromCurrentProfile = true;
                        }
                        if (!string.IsNullOrEmpty(prof.Name) &&
                            merged.ProfileName.IndexOf(prof.Name, StringComparison.OrdinalIgnoreCase) < 0)
                        {
                            merged.ProfileName = merged.ProfileName + " / " + prof.Name;
                        }
                    }
                }
            }

            return catalog;
        }

        public static List<SubscriptionProfileInfo> ReadProfilesIndex(string profilesYamlPath)
        {
            List<SubscriptionProfileInfo> list = new List<SubscriptionProfileInfo>();
            if (string.IsNullOrEmpty(profilesYamlPath) || !File.Exists(profilesYamlPath))
            {
                return list;
            }

            string content = ReadTextSafe(profilesYamlPath);
            if (string.IsNullOrEmpty(content))
            {
                return list;
            }

            string currentUid = string.Empty;
            bool inItems = false;
            int itemDashIndent = -1;
            int itemPropIndent = -1;

            string curUid = null;
            string curType = null;
            string curName = null;
            string curFile = null;

            using (StringReader sr = new StringReader(content))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith("#"))
                    {
                        continue;
                    }

                    int indent = CountLeadingSpaces(line);
                    if (indent == 0 && !trimmed.StartsWith("-"))
                    {
                        if (inItems)
                        {
                            FlushProfileItem(list, curUid, curType, curName, curFile, currentUid);
                            curUid = curType = curName = curFile = null;
                            inItems = false;
                        }

                        if (trimmed.StartsWith("current:", StringComparison.OrdinalIgnoreCase))
                        {
                            currentUid = ParseYamlScalar(trimmed.Substring("current:".Length));
                        }
                        else if (trimmed.StartsWith("items:", StringComparison.OrdinalIgnoreCase))
                        {
                            inItems = true;
                            itemDashIndent = -1;
                            itemPropIndent = -1;
                        }
                        continue;
                    }

                    if (!inItems)
                    {
                        continue;
                    }

                    bool isDashLine = trimmed.StartsWith("-") && (trimmed.Length == 1 || char.IsWhiteSpace(trimmed[1]));
                    if (isDashLine && (itemDashIndent < 0 || indent == itemDashIndent))
                    {
                        FlushProfileItem(list, curUid, curType, curName, curFile, currentUid);
                        curUid = curType = curName = curFile = null;
                        itemDashIndent = indent;
                        itemPropIndent = -1;

                        string afterDash = trimmed.Length > 1 ? trimmed.Substring(1).TrimStart() : string.Empty;
                        if (afterDash.Length > 0)
                        {
                            ApplyProfileField(afterDash, ref curUid, ref curType, ref curName, ref curFile);
                        }
                        continue;
                    }

                    if (itemDashIndent < 0 || indent <= itemDashIndent)
                    {
                        continue;
                    }

                    if (itemPropIndent < 0)
                    {
                        itemPropIndent = indent;
                    }

                    if (indent == itemPropIndent)
                    {
                        ApplyProfileField(trimmed, ref curUid, ref curType, ref curName, ref curFile);
                    }
                }
            }

            FlushProfileItem(list, curUid, curType, curName, curFile, currentUid);
            return list;
        }

        private static void ApplyProfileField(string line, ref string uid, ref string type, ref string name, ref string file)
        {
            if (line.StartsWith("uid:", StringComparison.OrdinalIgnoreCase))
            {
                uid = ParseYamlScalar(line.Substring("uid:".Length));
            }
            else if (line.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
            {
                type = ParseYamlScalar(line.Substring("type:".Length));
            }
            else if (line.StartsWith("name:", StringComparison.OrdinalIgnoreCase))
            {
                string val = ParseYamlScalar(line.Substring("name:".Length));
                if (!string.Equals(val, "null", StringComparison.OrdinalIgnoreCase) && val != "~")
                {
                    name = val;
                }
            }
            else if (line.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
            {
                file = ParseYamlScalar(line.Substring("file:".Length));
            }
        }

        private static void FlushProfileItem(
            List<SubscriptionProfileInfo> list,
            string uid,
            string type,
            string name,
            string file,
            string currentUid)
        {
            if (string.IsNullOrEmpty(uid) || string.IsNullOrEmpty(file))
            {
                return;
            }
            if (!string.Equals(type, "remote", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(type, "local", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            string displayName = !string.IsNullOrEmpty(name) ? name : uid;
            list.Add(new SubscriptionProfileInfo
            {
                Uid = uid,
                Name = displayName,
                FileName = file,
                IsCurrent = string.Equals(uid, currentUid, StringComparison.Ordinal)
            });
        }

        public static List<SubscriptionNodeInfo> ParseProfileNodesFromFile(string filePath, SubscriptionProfileInfo profile)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                return new List<SubscriptionNodeInfo>();
            }

            long writeTicks = 0;
            long length = 0;
            try
            {
                FileInfo fi = new FileInfo(filePath);
                if (!fi.Exists)
                {
                    return new List<SubscriptionNodeInfo>();
                }
                writeTicks = fi.LastWriteTimeUtc.Ticks;
                length = fi.Length;
            }
            catch
            {
                return new List<SubscriptionNodeInfo>();
            }

            lock (ProfileCacheLock)
            {
                CachedProfileFile cached;
                if (ProfileFileCache.TryGetValue(filePath, out cached) &&
                    cached.WriteTicks == writeTicks &&
                    cached.Length == length &&
                    cached.Nodes != null)
                {
                    return CloneNodesForProfile(cached.Nodes, profile);
                }
            }

            string content = ReadTextSafe(filePath);
            if (string.IsNullOrEmpty(content))
            {
                return new List<SubscriptionNodeInfo>();
            }

            List<SubscriptionNodeInfo> parsed = ParseProxyNodesFromYaml(content, profile);
            lock (ProfileCacheLock)
            {
                ProfileFileCache[filePath] = new CachedProfileFile
                {
                    WriteTicks = writeTicks,
                    Length = length,
                    Nodes = CloneNodesForProfile(parsed, profile)
                };
            }
            return parsed;
        }

        private static List<SubscriptionNodeInfo> CloneNodesForProfile(
            List<SubscriptionNodeInfo> source,
            SubscriptionProfileInfo profile)
        {
            List<SubscriptionNodeInfo> copy = new List<SubscriptionNodeInfo>(source.Count);
            string uid = profile != null ? profile.Uid : string.Empty;
            string pName = profile != null ? profile.Name : string.Empty;
            bool isCur = profile != null && profile.IsCurrent;

            for (int i = 0; i < source.Count; i++)
            {
                SubscriptionNodeInfo n = source[i];
                copy.Add(new SubscriptionNodeInfo
                {
                    Name = n.Name,
                    Type = n.Type,
                    ProfileUid = uid,
                    ProfileName = pName,
                    IsFromCurrentProfile = isCur
                });
            }
            return copy;
        }

        public static List<SubscriptionNodeInfo> ParseProxyNodesFromYaml(string yamlContent, SubscriptionProfileInfo profile)
        {
            List<SubscriptionNodeInfo> nodes = new List<SubscriptionNodeInfo>();
            if (string.IsNullOrEmpty(yamlContent))
            {
                return nodes;
            }

            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool inProxies = false;
            int itemDashIndent = -1;
            int itemPropIndent = -1;
            string curName = null;
            string curType = null;

            bool inFlowMapping = false;
            int flowDepth = 0;
            StringBuilder flowBuf = new StringBuilder(256);

            using (StringReader sr = new StringReader(yamlContent))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    string trimmed = line.Trim();
                    if (!inFlowMapping && trimmed.StartsWith("#"))
                    {
                        continue;
                    }

                    int indent = CountLeadingSpaces(line);

                    if (!inProxies)
                    {
                        if (indent == 0 && trimmed.StartsWith("proxies:", StringComparison.OrdinalIgnoreCase))
                        {
                            string rest = StripYamlComment(trimmed.Substring("proxies:".Length)).Trim();
                            if (rest == "[]" || string.Equals(rest, "null", StringComparison.OrdinalIgnoreCase) || rest == "~")
                            {
                                break;
                            }
                            inProxies = true;
                        }
                        continue;
                    }

                    if (inFlowMapping)
                    {
                        flowBuf.Append(' ').Append(trimmed);
                        flowDepth += ComputeFlowBraceDelta(trimmed);
                        if (flowDepth <= 0)
                        {
                            inFlowMapping = false;
                            string flowName;
                            string flowType;
                            ParseFlowProxyMapping(flowBuf.ToString(), out flowName, out flowType);
                            flowBuf.Clear();
                            AddParsedNode(nodes, seen, flowName, flowType, profile);
                        }
                        continue;
                    }

                    // Exit proxies: when hitting next top-level key (not a '-' sequence item)
                    if (indent == 0 && !trimmed.StartsWith("-"))
                    {
                        break;
                    }

                    bool isDashLine = trimmed.StartsWith("-") &&
                                      (trimmed.Length == 1 || char.IsWhiteSpace(trimmed[1]) || trimmed[1] == '{');

                    if (isDashLine && (itemDashIndent < 0 || indent == itemDashIndent))
                    {
                        AddParsedNode(nodes, seen, curName, curType, profile);
                        curName = null;
                        curType = null;
                        itemDashIndent = indent;
                        itemPropIndent = -1;

                        string afterDash = trimmed.Length > 1 ? trimmed.Substring(1).TrimStart() : string.Empty;
                        if (afterDash.StartsWith("{"))
                        {
                            int delta = ComputeFlowBraceDelta(afterDash);
                            if (delta <= 0)
                            {
                                string flowName;
                                string flowType;
                                ParseFlowProxyMapping(afterDash, out flowName, out flowType);
                                AddParsedNode(nodes, seen, flowName, flowType, profile);
                            }
                            else
                            {
                                inFlowMapping = true;
                                flowDepth = delta;
                                flowBuf.Clear();
                                flowBuf.Append(afterDash);
                            }
                        }
                        else if (afterDash.Length > 0)
                        {
                            ApplyBlockProxyField(afterDash, ref curName, ref curType);
                        }
                        continue;
                    }

                    if (itemDashIndent < 0 || indent <= itemDashIndent)
                    {
                        continue;
                    }

                    if (itemPropIndent < 0)
                    {
                        itemPropIndent = indent;
                    }

                    if (indent == itemPropIndent)
                    {
                        ApplyBlockProxyField(trimmed, ref curName, ref curType);
                    }
                }
            }

            AddParsedNode(nodes, seen, curName, curType, profile);
            return nodes;
        }

        private static void ApplyBlockProxyField(string trimmedLine, ref string name, ref string type)
        {
            if (IsYamlKeyMatch(trimmedLine, "name"))
            {
                name = ParseYamlScalar(trimmedLine.Substring(trimmedLine.IndexOf(':') + 1));
            }
            else if (IsYamlKeyMatch(trimmedLine, "type"))
            {
                type = ParseYamlScalar(trimmedLine.Substring(trimmedLine.IndexOf(':') + 1));
            }
        }

        private static bool IsYamlKeyMatch(string trimmedLine, string expectedKey)
        {
            int colon = trimmedLine.IndexOf(':');
            if (colon <= 0)
            {
                return false;
            }
            string key = trimmedLine.Substring(0, colon).Trim().Trim('\'', '"');
            return string.Equals(key, expectedKey, StringComparison.OrdinalIgnoreCase);
        }

        private static int ComputeFlowBraceDelta(string s)
        {
            int delta = 0;
            bool inSingle = false;
            bool inDouble = false;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (inSingle)
                {
                    if (c == '\'')
                    {
                        if (i + 1 < s.Length && s[i + 1] == '\'')
                        {
                            i++;
                        }
                        else
                        {
                            inSingle = false;
                        }
                    }
                    continue;
                }
                if (inDouble)
                {
                    if (c == '\\' && i + 1 < s.Length)
                    {
                        i++;
                    }
                    else if (c == '"')
                    {
                        inDouble = false;
                    }
                    continue;
                }
                if (c == '\'')
                {
                    inSingle = true;
                }
                else if (c == '"')
                {
                    inDouble = true;
                }
                else if (c == '#' && (i == 0 || char.IsWhiteSpace(s[i - 1])))
                {
                    break;
                }
                else if (c == '{')
                {
                    delta++;
                }
                else if (c == '}')
                {
                    delta--;
                }
            }
            return delta;
        }

        private static void ParseFlowProxyMapping(string text, out string name, out string type)
        {
            name = null;
            type = null;
            if (string.IsNullOrEmpty(text))
            {
                return;
            }

            int start = text.IndexOf('{');
            if (start < 0)
            {
                return;
            }

            int pos = start + 1;
            int len = text.Length;
            while (pos < len)
            {
                while (pos < len && (char.IsWhiteSpace(text[pos]) || text[pos] == ','))
                {
                    pos++;
                }
                if (pos >= len || text[pos] == '}')
                {
                    break;
                }

                // Read key at depth 0
                string key = ReadFlowToken(text, ref pos, true);
                while (pos < len && char.IsWhiteSpace(text[pos]))
                {
                    pos++;
                }
                if (pos >= len || text[pos] != ':')
                {
                    SkipFlowValue(text, ref pos);
                    continue;
                }
                pos++; // consume ':'

                while (pos < len && char.IsWhiteSpace(text[pos]))
                {
                    pos++;
                }

                bool wantName = string.Equals(key, "name", StringComparison.OrdinalIgnoreCase);
                bool wantType = string.Equals(key, "type", StringComparison.OrdinalIgnoreCase);
                if (wantName || wantType)
                {
                    string val = ReadFlowToken(text, ref pos, false);
                    if (wantName) name = val;
                    else if (wantType) type = val;
                    if (name != null && type != null)
                    {
                        break;
                    }
                }
                else
                {
                    SkipFlowValue(text, ref pos);
                }
            }
        }

        private static string ReadFlowToken(string s, ref int pos, bool isKey)
        {
            int len = s.Length;
            if (pos >= len)
            {
                return string.Empty;
            }

            char first = s[pos];
            if (first == '\'' || first == '"')
            {
                int start = pos;
                pos++;
                if (first == '\'')
                {
                    while (pos < len)
                    {
                        if (s[pos] == '\'')
                        {
                            if (pos + 1 < len && s[pos + 1] == '\'')
                            {
                                pos += 2;
                                continue;
                            }
                            pos++;
                            break;
                        }
                        pos++;
                    }
                }
                else
                {
                    while (pos < len)
                    {
                        if (s[pos] == '\\' && pos + 1 < len)
                        {
                            pos += 2;
                            continue;
                        }
                        if (s[pos] == '"')
                        {
                            pos++;
                            break;
                        }
                        pos++;
                    }
                }
                return ParseYamlScalar(s.Substring(start, pos - start));
            }

            int rawStart = pos;
            int nested = 0;
            while (pos < len)
            {
                char c = s[pos];
                if (c == '{' || c == '[')
                {
                    nested++;
                }
                else if (c == '}' || c == ']')
                {
                    if (nested == 0)
                    {
                        break;
                    }
                    nested--;
                }
                else if (nested == 0 && (c == ',' || (isKey && c == ':')))
                {
                    break;
                }
                pos++;
            }
            return s.Substring(rawStart, pos - rawStart).Trim();
        }

        private static void SkipFlowValue(string s, ref int pos)
        {
            int len = s.Length;
            int nested = 0;
            bool inSingle = false;
            bool inDouble = false;
            while (pos < len)
            {
                char c = s[pos];
                if (inSingle)
                {
                    if (c == '\'')
                    {
                        if (pos + 1 < len && s[pos + 1] == '\'')
                        {
                            pos += 2;
                            continue;
                        }
                        inSingle = false;
                    }
                    pos++;
                    continue;
                }
                if (inDouble)
                {
                    if (c == '\\' && pos + 1 < len)
                    {
                        pos += 2;
                        continue;
                    }
                    if (c == '"')
                    {
                        inDouble = false;
                    }
                    pos++;
                    continue;
                }
                if (c == '\'')
                {
                    inSingle = true;
                }
                else if (c == '"')
                {
                    inDouble = true;
                }
                else if (c == '{' || c == '[')
                {
                    nested++;
                }
                else if (c == '}' || c == ']')
                {
                    if (nested == 0)
                    {
                        break;
                    }
                    nested--;
                }
                else if (nested == 0 && c == ',')
                {
                    break;
                }
                pos++;
            }
        }

        private static void AddParsedNode(
            List<SubscriptionNodeInfo> nodes,
            HashSet<string> seen,
            string name,
            string type,
            SubscriptionProfileInfo profile)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return;
            }
            string trimmed = name.Trim();
            if (NodeGuardEvaluator.IsBuiltinNode(trimmed))
            {
                return;
            }
            if (!seen.Add(trimmed))
            {
                return;
            }
            nodes.Add(new SubscriptionNodeInfo
            {
                Name = trimmed,
                Type = type != null ? type.Trim() : string.Empty,
                ProfileUid = profile != null ? profile.Uid : string.Empty,
                ProfileName = profile != null ? profile.Name : string.Empty,
                IsFromCurrentProfile = profile != null && profile.IsCurrent
            });
        }

        public static string ParseYamlScalar(string raw)
        {
            if (string.IsNullOrEmpty(raw))
            {
                return string.Empty;
            }
            string s = StripYamlComment(raw).Trim();
            if (s.Length >= 2 && s[0] == '\'' && s[s.Length - 1] == '\'')
            {
                return s.Substring(1, s.Length - 2).Replace("''", "'");
            }
            if (s.Length >= 2 && s[0] == '"' && s[s.Length - 1] == '"')
            {
                return UnescapeDoubleQuotedYaml(s.Substring(1, s.Length - 2));
            }
            return s;
        }

        private static string UnescapeDoubleQuotedYaml(string inner)
        {
            if (inner.IndexOf('\\') < 0)
            {
                return inner;
            }
            StringBuilder sb = new StringBuilder(inner.Length);
            for (int i = 0; i < inner.Length; i++)
            {
                char c = inner[i];
                if (c != '\\' || i + 1 >= inner.Length)
                {
                    sb.Append(c);
                    continue;
                }
                char next = inner[++i];
                switch (next)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (i + 4 < inner.Length)
                        {
                            int code;
                            if (int.TryParse(inner.Substring(i + 1, 4), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out code))
                            {
                                sb.Append((char)code);
                                i += 4;
                                break;
                            }
                        }
                        sb.Append("\\u");
                        break;
                    case 'U':
                        if (i + 8 < inner.Length)
                        {
                            int codePoint;
                            if (int.TryParse(inner.Substring(i + 1, 8), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out codePoint))
                            {
                                try
                                {
                                    sb.Append(char.ConvertFromUtf32(codePoint));
                                    i += 8;
                                    break;
                                }
                                catch
                                {
                                }
                            }
                        }
                        sb.Append("\\U");
                        break;
                    default:
                        sb.Append(next);
                        break;
                }
            }
            return sb.ToString();
        }

        private static string ReadTextSafe(string path)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                {
                    return sr.ReadToEnd();
                }
            }
            catch
            {
                return null;
            }
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
    }

    internal struct KillResult
    {
        public int KilledCount;
        public int AccessDeniedCount;
        public GuardedAppFlags KilledApps;
        public GuardedAppFlags DeniedApps;
        public double FirstPassMs;
        public double TotalElapsedMs;
    }

    internal sealed class TargetMatchRules
    {
        public static readonly TargetMatchRules Empty = new TargetMatchRules(
            new Dictionary<string, GuardedAppFlags>(StringComparer.OrdinalIgnoreCase),
            new List<KeyValuePair<string, GuardedAppFlags>>(),
            new List<KeyValuePair<string, GuardedAppFlags>>(),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            GuardedAppFlags.None,
            string.Empty);

        public readonly Dictionary<string, GuardedAppFlags> CustomExePaths;
        public readonly List<KeyValuePair<string, GuardedAppFlags>> CustomDirPrefixes;
        public readonly List<KeyValuePair<string, GuardedAppFlags>> TrustedRootPrefixes;
        public readonly HashSet<string> CustomExeNames;
        public readonly GuardedAppFlags CustomDirAppMask;
        public readonly string Signature;

        public TargetMatchRules(
            Dictionary<string, GuardedAppFlags> customExePaths,
            List<KeyValuePair<string, GuardedAppFlags>> customDirPrefixes,
            List<KeyValuePair<string, GuardedAppFlags>> trustedRootPrefixes,
            HashSet<string> customExeNames,
            GuardedAppFlags customDirAppMask,
            string signature)
        {
            CustomExePaths = customExePaths;
            CustomDirPrefixes = customDirPrefixes;
            TrustedRootPrefixes = trustedRootPrefixes;
            CustomExeNames = customExeNames;
            CustomDirAppMask = customDirAppMask;
            Signature = signature ?? string.Empty;
        }

        public bool HasCustomDirectoriesFor(GuardedAppFlags enabledApps)
        {
            return (CustomDirAppMask & enabledApps) != GuardedAppFlags.None;
        }
    }

    internal sealed class TargetProcessKiller
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
        private readonly List<uint> _pathVerifyCandidates = new List<uint>(32);
        private uint[] _pidBuffer = new uint[1024];
        private uint[] _lastPidSnapshot = new uint[1024];
        private int _lastPidSnapshotCount;
        private bool _lastPidSnapshotValid;
        private HashSet<uint> _prevBenignPids = new HashSet<uint>();
        private HashSet<uint> _nextBenignPids = new HashSet<uint>();
        private bool _benignCacheValid;
        private GuardedAppFlags _enabledApps = GuardedAppFlags.All;
        private volatile TargetMatchRules _matchRules = TargetMatchRules.Empty;

        public Action<string> MatchedImagePathCallback { get; set; }

        public void SetMatchRules(TargetMatchRules rules)
        {
            TargetMatchRules next = rules ?? TargetMatchRules.Empty;
            TargetMatchRules current = _matchRules;
            if (current != null && string.Equals(current.Signature, next.Signature, StringComparison.Ordinal))
            {
                return;
            }
            _matchRules = next;
            InvalidateCache();
        }

        private void NotifyMatchedImagePath(string fullPath)
        {
            Action<string> cb = MatchedImagePathCallback;
            if (cb != null && !string.IsNullOrEmpty(fullPath))
            {
                cb(fullPath);
            }
        }

        // Independent fast-path buffers for passive running-path discovery (WFP hot-add)
        private uint[] _discoverPidBuffer = new uint[1024];
        private uint[] _discoverLastSnapshot = new uint[1024];
        private int _discoverLastSnapshotCount;
        private bool _discoverLastSnapshotValid;
        private HashSet<uint> _discoverPrevSeenPids = new HashSet<uint>();
        private HashSet<uint> _discoverNextSeenPids = new HashSet<uint>();
        private readonly StringBuilder _discoverPathBuf = new StringBuilder(2048);

        // Independent fast-path buffers for detecting newly opened guarded apps in WFP-only mode
        private uint[] _launchPidBuffer = new uint[1024];
        private uint[] _launchLastSnapshot = new uint[1024];
        private int _launchLastSnapshotCount;
        private bool _launchLastSnapshotValid;
        private HashSet<uint> _launchPrevSeenPids = new HashSet<uint>();
        private HashSet<uint> _launchNextSeenPids = new HashSet<uint>();
        private readonly StringBuilder _launchPathBuf = new StringBuilder(2048);

        public void ResetLaunchDetectCache()
        {
            _launchLastSnapshotValid = false;
            _launchLastSnapshotCount = 0;
            _launchPrevSeenPids.Clear();
            _launchNextSeenPids.Clear();
        }

        // Zero-allocation fast-path scan to detect running or newly launched guarded apps without killing them
        public GuardedAppFlags DetectGuardedApps(bool resetBaseline)
        {
            GuardedAppFlags enabledApps = _enabledApps;
            if (enabledApps == GuardedAppFlags.None)
            {
                return GuardedAppFlags.None;
            }

            if (resetBaseline)
            {
                ResetLaunchDetectCache();
            }

            int pidCount;
            if (!EnumerateProcessIdsInto(ref _launchPidBuffer, out pidCount))
            {
                return GuardedAppFlags.None;
            }

            if (!resetBaseline && _launchLastSnapshotValid && pidCount == _launchLastSnapshotCount)
            {
                bool identical = true;
                for (int i = 0; i < pidCount; i++)
                {
                    if (_launchPidBuffer[i] != _launchLastSnapshot[i])
                    {
                        identical = false;
                        break;
                    }
                }
                if (identical)
                {
                    return GuardedAppFlags.None;
                }
            }

            _launchNextSeenPids.Clear();
            GuardedAppFlags matchedApps = GuardedAppFlags.None;
            for (int i = 0; i < pidCount; i++)
            {
                uint pid = _launchPidBuffer[i];
                if (pid == 0 || pid == SelfPid)
                {
                    continue;
                }

                if (!resetBaseline && _launchPrevSeenPids.Contains(pid))
                {
                    _launchNextSeenPids.Add(pid);
                    continue;
                }

                IntPtr hQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hQuery != IntPtr.Zero)
                {
                    try
                    {
                        _launchPathBuf.Clear();
                        uint size = (uint)_launchPathBuf.Capacity;
                        if (QueryFullProcessImageNameW(hQuery, 0, _launchPathBuf, ref size) && size > 0)
                        {
                            string fullPath = _launchPathBuf.ToString();
                            GuardedAppFlags app = MatchTargetImagePath(fullPath, enabledApps, _matchRules);
                            if (app != GuardedAppFlags.None)
                            {
                                matchedApps |= app;
                                NotifyMatchedImagePath(fullPath);
                            }
                        }
                    }
                    finally
                    {
                        CloseHandle(hQuery);
                    }
                    _launchNextSeenPids.Add(pid);
                }
                else if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                {
                    _launchNextSeenPids.Add(pid);
                }
            }

            HashSet<uint> swap = _launchPrevSeenPids;
            _launchPrevSeenPids = _launchNextSeenPids;
            _launchNextSeenPids = swap;

            if (_launchLastSnapshot.Length < pidCount)
            {
                _launchLastSnapshot = new uint[_launchPidBuffer.Length];
            }
            Array.Copy(_launchPidBuffer, _launchLastSnapshot, pidCount);
            _launchLastSnapshotCount = pidCount;
            _launchLastSnapshotValid = true;
            return matchedApps;
        }

        public void ResetDiscoveryCache()
        {
            _discoverLastSnapshotValid = false;
            _discoverLastSnapshotCount = 0;
            _discoverPrevSeenPids.Clear();
            _discoverNextSeenPids.Clear();
        }

        // Zero-allocation fast-path scan of newly spawned processes to discover exe paths for WFP
        public bool DiscoverNewProcessPaths(
            bool forceFullRescan,
            Action<string> onImagePathFound)
        {
            if (onImagePathFound == null)
            {
                return false;
            }

            if (forceFullRescan)
            {
                ResetDiscoveryCache();
            }

            int pidCount;
            if (!EnumerateProcessIdsInto(ref _discoverPidBuffer, out pidCount))
            {
                return false;
            }

            if (_discoverLastSnapshotValid && pidCount == _discoverLastSnapshotCount)
            {
                bool identical = true;
                for (int i = 0; i < pidCount; i++)
                {
                    if (_discoverPidBuffer[i] != _discoverLastSnapshot[i])
                    {
                        identical = false;
                        break;
                    }
                }
                if (identical)
                {
                    return false;
                }
            }

            _discoverNextSeenPids.Clear();
            bool inspectedAny = false;
            for (int i = 0; i < pidCount; i++)
            {
                uint pid = _discoverPidBuffer[i];
                if (pid == 0 || pid == SelfPid)
                {
                    continue;
                }

                if (_discoverPrevSeenPids.Contains(pid))
                {
                    _discoverNextSeenPids.Add(pid);
                    continue;
                }

                inspectedAny = true;
                IntPtr hQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hQuery != IntPtr.Zero)
                {
                    try
                    {
                        _discoverPathBuf.Clear();
                        uint size = (uint)_discoverPathBuf.Capacity;
                        if (QueryFullProcessImageNameW(hQuery, 0, _discoverPathBuf, ref size) && size > 0)
                        {
                            onImagePathFound(_discoverPathBuf.ToString());
                        }
                    }
                    finally
                    {
                        CloseHandle(hQuery);
                    }
                    _discoverNextSeenPids.Add(pid);
                }
                else if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                {
                    // Protected/system process we cannot query; skip until PID recycles
                    _discoverNextSeenPids.Add(pid);
                }
            }

            HashSet<uint> swap = _discoverPrevSeenPids;
            _discoverPrevSeenPids = _discoverNextSeenPids;
            _discoverNextSeenPids = swap;

            if (_discoverLastSnapshot.Length < pidCount)
            {
                _discoverLastSnapshot = new uint[_discoverPidBuffer.Length];
            }
            Array.Copy(_discoverPidBuffer, _discoverLastSnapshot, pidCount);
            _discoverLastSnapshotCount = pidCount;
            _discoverLastSnapshotValid = true;
            return inspectedAny;
        }

        private static bool EnumerateProcessIdsInto(ref uint[] buffer, out int count)
        {
            count = 0;
            for (int attempt = 0; attempt < 4; attempt++)
            {
                uint cb = (uint)(buffer.Length * sizeof(uint));
                uint needed;
                if (!K32EnumProcesses(buffer, cb, out needed))
                {
                    return false;
                }

                if (needed < cb || buffer.Length >= 65536)
                {
                    count = (int)(needed / sizeof(uint));
                    return true;
                }

                buffer = new uint[Math.Min(buffer.Length * 2, 65536)];
            }
            return false;
        }

        // Thread-safe one-shot snapshot scan (uses local buffers; safe to call from UI/ThreadPool)
        internal static GuardedAppFlags ScanRunningProcessesSnapshot(
            TargetMatchRules rules,
            Action<string> onImagePathFound)
        {
            uint[] pidBuf = new uint[1024];
            int pidCount;
            if (!EnumerateProcessIdsInto(ref pidBuf, out pidCount))
            {
                return GuardedAppFlags.None;
            }

            GuardedAppFlags runningApps = GuardedAppFlags.None;
            StringBuilder pathBuf = new StringBuilder(2048);
            for (int i = 0; i < pidCount; i++)
            {
                uint pid = pidBuf[i];
                if (pid == 0 || pid == SelfPid)
                {
                    continue;
                }

                IntPtr hQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hQuery == IntPtr.Zero)
                {
                    continue;
                }

                try
                {
                    pathBuf.Clear();
                    uint size = (uint)pathBuf.Capacity;
                    if (QueryFullProcessImageNameW(hQuery, 0, pathBuf, ref size) && size > 0)
                    {
                        string fullPath = pathBuf.ToString();
                        if (onImagePathFound != null)
                        {
                            onImagePathFound(fullPath);
                        }
                        GuardedAppFlags hit = MatchTargetImagePath(fullPath, GuardedAppFlags.All, rules);
                        if (hit != GuardedAppFlags.None)
                        {
                            runningApps |= hit;
                        }
                    }
                }
                finally
                {
                    CloseHandle(hQuery);
                }
            }
            return runningApps;
        }

        // Returns true if any previously disabled target app was newly enabled
        public bool SetEnabledApps(GuardedAppFlags apps)
        {
            if (_enabledApps == apps)
            {
                return false;
            }
            bool expanded = ((apps & ~_enabledApps) != GuardedAppFlags.None);
            _enabledApps = apps;
            InvalidateCache();
            return expanded;
        }

        public void InvalidateCache()
        {
            _benignCacheValid = false;
            _lastPidSnapshotValid = false;
            _lastPidSnapshotCount = 0;
            _prevBenignPids.Clear();
            _nextBenignPids.Clear();
            ResetLaunchDetectCache();
        }

        public KillResult KillAllNow()
        {
            if (_enabledApps == GuardedAppFlags.None)
            {
                return default(KillResult);
            }

            Stopwatch sw = Stopwatch.StartNew();
            int accessDenied;
            GuardedAppFlags killedApps;
            GuardedAppFlags deniedApps;
            int totalKilled = KillFullPass(true, out accessDenied, out killedApps, out deniedApps);
            double firstPassMs = sw.Elapsed.TotalMilliseconds;

            // If processes were killed, do one rapid sweep 5ms later to catch any racing child spawn.
            if (totalKilled > 0)
            {
                Thread.Sleep(5);
                int followUpDenied;
                GuardedAppFlags followUpKilledApps;
                GuardedAppFlags followUpDeniedApps;
                totalKilled += KillFullPass(true, out followUpDenied, out followUpKilledApps, out followUpDeniedApps);
                accessDenied += followUpDenied;
                killedApps |= followUpKilledApps;
                deniedApps |= followUpDeniedApps;
            }

            sw.Stop();
            return new KillResult
            {
                KilledCount = totalKilled,
                AccessDeniedCount = accessDenied,
                KilledApps = killedApps,
                DeniedApps = deniedApps,
                FirstPassMs = firstPassMs,
                TotalElapsedMs = sw.Elapsed.TotalMilliseconds
            };
        }

        public KillResult KillNewProcesses()
        {
            if (_enabledApps == GuardedAppFlags.None)
            {
                return default(KillResult);
            }

            if (!_benignCacheValid)
            {
                return KillAllNow();
            }

            int pidCount;
            if (!EnumerateProcessIds(out pidCount))
            {
                // Fallback to full snapshot if K32EnumProcesses fails
                return KillAllNow();
            }

            // Zero-allocation fast path: if kernel PID list is completely unchanged since last benign sweep, skip HashSet rebuild
            if (_lastPidSnapshotValid && pidCount == _lastPidSnapshotCount)
            {
                bool identical = true;
                for (int i = 0; i < pidCount; i++)
                {
                    if (_pidBuffer[i] != _lastPidSnapshot[i])
                    {
                        identical = false;
                        break;
                    }
                }
                if (identical)
                {
                    return default(KillResult);
                }
            }

            long startTs = Stopwatch.GetTimestamp();
            int killed = 0;
            int accessDenied = 0;
            bool hadUnresolved = false;
            GuardedAppFlags killedApps = GuardedAppFlags.None;
            GuardedAppFlags deniedApps = GuardedAppFlags.None;
            GuardedAppFlags enabledApps = _enabledApps;
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

                int killedBefore = killed;
                int deniedBefore = accessDenied;
                bool isBenign;
                InspectAndKillPid(pid, enabledApps, true, ref killed, ref accessDenied, ref killedApps, ref deniedApps, out isBenign);
                if (isBenign)
                {
                    _nextBenignPids.Add(pid);
                }
                else if (killed == killedBefore && accessDenied == deniedBefore)
                {
                    hadUnresolved = true;
                }
            }

            HashSet<uint> swap = _prevBenignPids;
            _prevBenignPids = _nextBenignPids;
            _nextBenignPids = swap;

            if (killed == 0 && accessDenied == 0 && !hadUnresolved)
            {
                if (_lastPidSnapshot.Length < pidCount)
                {
                    _lastPidSnapshot = new uint[_pidBuffer.Length];
                }
                Array.Copy(_pidBuffer, _lastPidSnapshot, pidCount);
                _lastPidSnapshotCount = pidCount;
                _lastPidSnapshotValid = true;
            }
            else
            {
                _lastPidSnapshotValid = false;
            }

            double firstPassMs = (Stopwatch.GetTimestamp() - startTs) * 1000.0 / Stopwatch.Frequency;

            // If any new target process was killed, do a full follow-up sweep 5ms later for racing children.
            if (killed > 0)
            {
                Thread.Sleep(5);
                int followUpDenied;
                GuardedAppFlags followUpKilledApps;
                GuardedAppFlags followUpDeniedApps;
                killed += KillFullPass(true, out followUpDenied, out followUpKilledApps, out followUpDeniedApps);
                accessDenied += followUpDenied;
                killedApps |= followUpKilledApps;
                deniedApps |= followUpDeniedApps;
            }

            double totalMs = (Stopwatch.GetTimestamp() - startTs) * 1000.0 / Stopwatch.Frequency;
            return new KillResult
            {
                KilledCount = killed,
                AccessDeniedCount = accessDenied,
                KilledApps = killedApps,
                DeniedApps = deniedApps,
                FirstPassMs = firstPassMs,
                TotalElapsedMs = totalMs
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

        private int KillFullPass(
            bool updateBenignCache,
            out int accessDenied,
            out GuardedAppFlags killedApps,
            out GuardedAppFlags deniedApps)
        {
            int killed = 0;
            accessDenied = 0;
            killedApps = GuardedAppFlags.None;
            deniedApps = GuardedAppFlags.None;
            GuardedAppFlags enabledApps = _enabledApps;
            if (enabledApps == GuardedAppFlags.None)
            {
                return 0;
            }

            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
            {
                return 0;
            }

            _pathVerifyCandidates.Clear();
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

                // Pass 1: terminate unambiguous desktop app executables immediately before path-verified helpers
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

                    GuardedAppFlags directApp = MatchDirectExeName(exe, enabledApps);
                    if (directApp != GuardedAppFlags.None)
                    {
                        TryTerminateKnownTarget(pid, directApp, ref killed, ref accessDenied, ref killedApps, ref deniedApps);
                    }
                    else if (NeedsPathVerification(exe, enabledApps, _matchRules))
                    {
                        _pathVerifyCandidates.Add(pid);
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

            // Pass 2: verify full image paths for executables shared with non-target tools (e.g. Claude Desktop vs CLI/IDE)
            for (int i = 0; i < _pathVerifyCandidates.Count; i++)
            {
                uint pid = _pathVerifyCandidates[i];
                bool isBenign;
                InspectAndKillPid(pid, enabledApps, false, ref killed, ref accessDenied, ref killedApps, ref deniedApps, out isBenign);
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
                _lastPidSnapshotValid = false;
            }

            return killed;
        }

        private void TryTerminateKnownTarget(
            uint pid,
            GuardedAppFlags appFlag,
            ref int killed,
            ref int accessDenied,
            ref GuardedAppFlags killedApps,
            ref GuardedAppFlags deniedApps)
        {
            bool canQuery = true;
            IntPtr hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProc == IntPtr.Zero && Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
            {
                canQuery = false;
                hProc = OpenProcess(PROCESS_TERMINATE, false, pid);
            }
            if (hProc == IntPtr.Zero)
            {
                if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                {
                    accessDenied++;
                    deniedApps |= appFlag;
                    if (MatchedImagePathCallback != null)
                    {
                        IntPtr hQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                        if (hQuery != IntPtr.Zero)
                        {
                            try
                            {
                                string deniedPath = QueryImagePath(hQuery);
                                if (deniedPath != null)
                                {
                                    NotifyMatchedImagePath(deniedPath);
                                }
                            }
                            finally
                            {
                                CloseHandle(hQuery);
                            }
                        }
                    }
                }
                return;
            }

            try
            {
                if (TerminateProcess(hProc, 1))
                {
                    killed++;
                    killedApps |= appFlag;
                }
                else if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                {
                    accessDenied++;
                    deniedApps |= appFlag;
                }

                if (canQuery && MatchedImagePathCallback != null)
                {
                    string fullPath = QueryImagePath(hProc);
                    if (fullPath != null)
                    {
                        NotifyMatchedImagePath(fullPath);
                    }
                }
            }
            finally
            {
                CloseHandle(hProc);
            }
        }

        private void InspectAndKillPid(
            uint pid,
            GuardedAppFlags enabledApps,
            bool markProtectedAsBenign,
            ref int killed,
            ref int accessDenied,
            ref GuardedAppFlags killedApps,
            ref GuardedAppFlags deniedApps,
            out bool isBenign)
        {
            isBenign = false;
            TargetMatchRules rules = _matchRules;
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

                    GuardedAppFlags matched = MatchTargetImagePath(fullPath, enabledApps, rules);
                    if (matched != GuardedAppFlags.None)
                    {
                        if (TerminateProcess(hProc, 1))
                        {
                            killed++;
                            killedApps |= matched;
                        }
                        else if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                        {
                            accessDenied++;
                            deniedApps |= matched;
                        }
                        NotifyMatchedImagePath(fullPath);
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
                            GuardedAppFlags matched = MatchTargetImagePath(fullPath, enabledApps, rules);
                            if (matched != GuardedAppFlags.None)
                            {
                                accessDenied++;
                                deniedApps |= matched;
                                NotifyMatchedImagePath(fullPath);
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

        internal static GuardedAppFlags MatchDirectExeName(string exe, GuardedAppFlags enabledApps)
        {
            if (enabledApps == GuardedAppFlags.None || string.IsNullOrEmpty(exe))
            {
                return GuardedAppFlags.None;
            }

            if ((enabledApps & GuardedAppFlags.Antigravity) != 0 &&
                string.Equals(exe, "Antigravity.exe", StringComparison.OrdinalIgnoreCase))
            {
                return GuardedAppFlags.Antigravity;
            }

            if ((enabledApps & GuardedAppFlags.ChatGPT) != 0 &&
                string.Equals(exe, "ChatGPT.exe", StringComparison.OrdinalIgnoreCase))
            {
                return GuardedAppFlags.ChatGPT;
            }

            if ((enabledApps & GuardedAppFlags.Claude) != 0 &&
                IsClaudeDesktopDirectExeName(exe))
            {
                return GuardedAppFlags.Claude;
            }

            return GuardedAppFlags.None;
        }

        internal static bool NeedsPathVerification(string exe, GuardedAppFlags enabledApps)
        {
            return NeedsPathVerification(exe, enabledApps, null);
        }

        internal static bool NeedsPathVerification(string exe, GuardedAppFlags enabledApps, TargetMatchRules rules)
        {
            if (enabledApps == GuardedAppFlags.None || string.IsNullOrEmpty(exe))
            {
                return false;
            }

            if ((enabledApps & GuardedAppFlags.Antigravity) != 0 && IsLanguageServerExeName(exe))
            {
                return true;
            }

            if ((enabledApps & GuardedAppFlags.ChatGPT) != 0 && IsChatGPTAuxiliaryExeName(exe))
            {
                return true;
            }

            if ((enabledApps & GuardedAppFlags.Claude) != 0 && IsClaudeAuxiliaryExeName(exe))
            {
                return true;
            }

            if (rules != null)
            {
                if (rules.HasCustomDirectoriesFor(enabledApps))
                {
                    return !IsIgnoredInstallerExeName(exe);
                }
                if (rules.CustomExeNames.Count > 0 && rules.CustomExeNames.Contains(exe))
                {
                    return true;
                }
            }

            return false;
        }

        internal static GuardedAppFlags MatchTargetImagePath(string fullPath, GuardedAppFlags enabledApps)
        {
            return MatchTargetImagePath(fullPath, enabledApps, null);
        }

        internal static GuardedAppFlags MatchTargetImagePath(string fullPath, GuardedAppFlags enabledApps, TargetMatchRules rules)
        {
            if (enabledApps == GuardedAppFlags.None || string.IsNullOrEmpty(fullPath))
            {
                return GuardedAppFlags.None;
            }

            int lastSlash = fullPath.LastIndexOf('\\');
            string exe = lastSlash >= 0 ? fullPath.Substring(lastSlash + 1) : fullPath;

            GuardedAppFlags direct = MatchDirectExeName(exe, enabledApps);
            if (direct != GuardedAppFlags.None)
            {
                return direct;
            }

            if ((enabledApps & GuardedAppFlags.Antigravity) != 0 &&
                IsLanguageServerExeName(exe) &&
                (IsAntigravityPath(fullPath) || MatchesTrustedRoot(fullPath, GuardedAppFlags.Antigravity, rules)))
            {
                return GuardedAppFlags.Antigravity;
            }

            if ((enabledApps & GuardedAppFlags.ChatGPT) != 0 &&
                IsChatGPTAuxiliaryExeName(exe) &&
                (IsChatGPTDesktopPath(fullPath) || MatchesTrustedRoot(fullPath, GuardedAppFlags.ChatGPT, rules)))
            {
                return GuardedAppFlags.ChatGPT;
            }

            if ((enabledApps & GuardedAppFlags.Claude) != 0 &&
                IsClaudeAuxiliaryExeName(exe) &&
                (IsClaudeDesktopPath(fullPath) || MatchesTrustedRoot(fullPath, GuardedAppFlags.Claude, rules)))
            {
                return GuardedAppFlags.Claude;
            }

            if (rules != null)
            {
                GuardedAppFlags customExactFlag;
                if (rules.CustomExePaths.Count > 0 &&
                    rules.CustomExePaths.TryGetValue(fullPath, out customExactFlag))
                {
                    GuardedAppFlags hit = customExactFlag & enabledApps;
                    if (hit != GuardedAppFlags.None)
                    {
                        return hit;
                    }
                }

                if (rules.CustomDirPrefixes.Count > 0 && !IsIgnoredInstallerExeName(exe))
                {
                    GuardedAppFlags dirHits = GuardedAppFlags.None;
                    for (int i = 0; i < rules.CustomDirPrefixes.Count; i++)
                    {
                        KeyValuePair<string, GuardedAppFlags> entry = rules.CustomDirPrefixes[i];
                        if ((entry.Value & enabledApps) != 0 &&
                            fullPath.StartsWith(entry.Key, StringComparison.OrdinalIgnoreCase))
                        {
                            dirHits |= (entry.Value & enabledApps);
                        }
                    }
                    if (dirHits != GuardedAppFlags.None)
                    {
                        return dirHits;
                    }
                }
            }

            return GuardedAppFlags.None;
        }

        internal static GuardedAppFlags MatchTargetExeInTrustedFolder(string fullPath, GuardedAppFlags appFlag)
        {
            if (appFlag == GuardedAppFlags.None || string.IsNullOrEmpty(fullPath))
            {
                return GuardedAppFlags.None;
            }

            int lastSlash = fullPath.LastIndexOf('\\');
            string exe = lastSlash >= 0 ? fullPath.Substring(lastSlash + 1) : fullPath;

            GuardedAppFlags direct = MatchDirectExeName(exe, appFlag);
            if (direct != GuardedAppFlags.None)
            {
                return direct;
            }

            if ((appFlag & GuardedAppFlags.Antigravity) != 0 && IsLanguageServerExeName(exe))
            {
                return GuardedAppFlags.Antigravity;
            }

            if ((appFlag & GuardedAppFlags.ChatGPT) != 0 && IsChatGPTAuxiliaryExeName(exe))
            {
                return GuardedAppFlags.ChatGPT;
            }

            if ((appFlag & GuardedAppFlags.Claude) != 0 && IsClaudeAuxiliaryExeName(exe))
            {
                return GuardedAppFlags.Claude;
            }

            return GuardedAppFlags.None;
        }

        private static bool MatchesTrustedRoot(string fullPath, GuardedAppFlags appFlag, TargetMatchRules rules)
        {
            if (rules == null || rules.TrustedRootPrefixes.Count == 0)
            {
                return false;
            }
            for (int i = 0; i < rules.TrustedRootPrefixes.Count; i++)
            {
                KeyValuePair<string, GuardedAppFlags> entry = rules.TrustedRootPrefixes[i];
                if ((entry.Value & appFlag) != 0 &&
                    fullPath.StartsWith(entry.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        internal static bool IsIgnoredInstallerExeName(string exe)
        {
            if (string.IsNullOrEmpty(exe))
            {
                return true;
            }
            return exe.StartsWith("unins", StringComparison.OrdinalIgnoreCase) ||
                   exe.StartsWith("Uninstall", StringComparison.OrdinalIgnoreCase) ||
                   exe.EndsWith("-backup.exe", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(exe, "elevate.exe", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(exe, "elevation_service.exe", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(exe, "elevated_tracing_service.exe", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsLanguageServerExeName(string exe)
        {
            return !IsIgnoredInstallerExeName(exe) &&
                   exe.StartsWith("language_server", StringComparison.OrdinalIgnoreCase) &&
                   exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsAntigravityPath(string fullPath)
        {
            return fullPath.IndexOf("\\antigravity\\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsChatGPTAuxiliaryExeName(string exe)
        {
            if (IsIgnoredInstallerExeName(exe) || !exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            return exe.StartsWith("ChatGPT", StringComparison.OrdinalIgnoreCase) ||
                   exe.StartsWith("Codex", StringComparison.OrdinalIgnoreCase) ||
                   exe.StartsWith("OpenAI", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsChatGPTDesktopPath(string fullPath)
        {
            return fullPath.IndexOf("\\WindowsApps\\OpenAI", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\WindowsApps\\ChatGPT", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\ChatGPT\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\OpenAI\\ChatGPT\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\OpenAI\\Codex\\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsClaudeDesktopDirectExeName(string exe)
        {
            return string.Equals(exe, "ClaudeDesktop.exe", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(exe, "Claude Desktop.exe", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(exe, "ClaudeCode.exe", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(exe, "Claude Code.exe", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsClaudeAuxiliaryExeName(string exe)
        {
            if (IsIgnoredInstallerExeName(exe) || !exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            return exe.StartsWith("Claude", StringComparison.OrdinalIgnoreCase) ||
                   exe.StartsWith("Anthropic", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(exe, "cowork-svc.exe", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsClaudeDesktopPath(string fullPath)
        {
            return fullPath.IndexOf("\\WindowsApps\\Claude", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\WindowsApps\\Anthropic", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\AnthropicClaude\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\Anthropic\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\Claude\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\Claude-3p\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\Claude-zh", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\Claude-CN\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\Claude-Desktop\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\Claude Desktop\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\Claude Code\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   fullPath.IndexOf("\\ClaudeCode\\", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }

    internal sealed class AppPathDiagnostics
    {
        public List<string> AntigravityExes = new List<string>();
        public List<string> ChatGptExes = new List<string>();
        public List<string> ClaudeExes = new List<string>();
        public List<string> ChatGptPackages = new List<string>();
        public List<string> ClaudePackages = new List<string>();
        public GuardedAppFlags RunningApps;
        public DateTime ScannedAt;
    }

    internal sealed class GuardedAppPathResolver
    {
        private const int DefaultScanMaxDepth = 5;
        private const int MaxCustomDirExes = 64;

        private static readonly HashSet<string> SkipDirNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "node_modules", ".git", "cache", "gpucache", "code cache", "locales",
            "blob_storage", "indexeddb", "local storage", "session storage", "crashpad", "logs"
        };

        private readonly object _lock = new object();
        private readonly HashSet<string> _antigravityPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _chatGptPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _claudePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _chatGptPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _claudePackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _mihomoPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private readonly HashSet<string> _trustedAntigravityRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _trustedChatGptRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _trustedClaudeRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private readonly List<string> _customAntigravityEntries = new List<string>();
        private readonly List<string> _customChatGptEntries = new List<string>();
        private readonly List<string> _customClaudeEntries = new List<string>();

        private readonly HashSet<string> _customAntigravityExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _customChatGptExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _customClaudeExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private volatile TargetMatchRules _matchRules = TargetMatchRules.Empty;
        private bool _cacheDirty;

        public bool HasDirtyCache
        {
            get
            {
                lock (_lock)
                {
                    return _cacheDirty;
                }
            }
        }

        public TargetMatchRules GetMatchRules()
        {
            return _matchRules;
        }

        public void ApplyCustomPathsFromConfig(NodeGuardConfig cfg)
        {
            List<string> antiEntries = ExtractConfigPathList(cfg != null ? cfg.CustomAppPaths : null, "antigravity");
            List<string> chatEntries = ExtractConfigPathList(cfg != null ? cfg.CustomAppPaths : null, "chatgpt");
            List<string> claudeEntries = ExtractConfigPathList(cfg != null ? cfg.CustomAppPaths : null, "claude");

            List<string> antiExes = ResolveCustomEntriesToExes(antiEntries);
            List<string> chatExes = ResolveCustomEntriesToExes(chatEntries);
            List<string> claudeExes = ResolveCustomEntriesToExes(claudeEntries);

            lock (_lock)
            {
                ReplaceListLocked(_customAntigravityEntries, antiEntries);
                ReplaceListLocked(_customChatGptEntries, chatEntries);
                ReplaceListLocked(_customClaudeEntries, claudeEntries);

                ReplaceSetLocked(_customAntigravityExes, antiExes);
                ReplaceSetLocked(_customChatGptExes, chatExes);
                ReplaceSetLocked(_customClaudeExes, claudeExes);

                RebuildMatchRulesLocked();

                TargetMatchRules rules = _matchRules;
                if (PruneUnmatchedPathsLocked(_antigravityPaths, GuardedAppFlags.Antigravity, rules)) _cacheDirty = true;
                if (PruneUnmatchedPathsLocked(_chatGptPaths, GuardedAppFlags.ChatGPT, rules)) _cacheDirty = true;
                if (PruneUnmatchedPathsLocked(_claudePaths, GuardedAppFlags.Claude, rules)) _cacheDirty = true;
            }
        }

        private static bool PruneUnmatchedPathsLocked(HashSet<string> set, GuardedAppFlags appFlag, TargetMatchRules rules)
        {
            List<string> stale = null;
            foreach (string path in set)
            {
                if (!File.Exists(path) ||
                    TargetProcessKiller.MatchTargetImagePath(path, appFlag, rules) == GuardedAppFlags.None)
                {
                    if (stale == null) stale = new List<string>();
                    stale.Add(path);
                }
            }
            if (stale == null)
            {
                return false;
            }
            for (int i = 0; i < stale.Count; i++)
            {
                set.Remove(stale[i]);
            }
            return true;
        }

        public void LoadFromConfigCache(NodeGuardConfig cfg)
        {
            ApplyCustomPathsFromConfig(cfg);
            if (cfg == null || cfg.DiscoveredAppPaths == null)
            {
                return;
            }

            TargetMatchRules rules = _matchRules;
            lock (_lock)
            {
                bool hadStale = false;
                if (LoadCachedKeyLocked(cfg.DiscoveredAppPaths, "antigravity", GuardedAppFlags.Antigravity, rules, _antigravityPaths)) hadStale = true;
                if (LoadCachedKeyLocked(cfg.DiscoveredAppPaths, "chatgpt", GuardedAppFlags.ChatGPT, rules, _chatGptPaths)) hadStale = true;
                if (LoadCachedKeyLocked(cfg.DiscoveredAppPaths, "claude", GuardedAppFlags.Claude, rules, _claudePaths)) hadStale = true;
                if (hadStale)
                {
                    _cacheDirty = true;
                }
            }
        }

        private static bool LoadCachedKeyLocked(
            Dictionary<string, List<string>> map,
            string key,
            GuardedAppFlags appFlag,
            TargetMatchRules rules,
            HashSet<string> targetSet)
        {
            List<string> list;
            if (!map.TryGetValue(key, out list) || list == null)
            {
                return false;
            }
            bool hadStale = false;
            for (int i = 0; i < list.Count; i++)
            {
                string norm = NormalizeExistingFile(list[i]);
                if (norm != null && TargetProcessKiller.MatchTargetImagePath(norm, appFlag, rules) != GuardedAppFlags.None)
                {
                    targetSet.Add(norm);
                }
                else
                {
                    hadStale = true;
                }
            }
            return hadStale;
        }

        public void ScanStaticInstallations()
        {
            List<string> foundAnti = new List<string>();
            List<string> foundChat = new List<string>();
            List<string> foundClaude = new List<string>();
            List<string> foundChatPkg = new List<string>();
            List<string> foundClaudePkg = new List<string>();
            List<string> foundMihomo = new List<string>();
            List<string> foundAntiRoots = new List<string>();
            List<string> foundChatRoots = new List<string>();
            List<string> foundClaudeRoots = new List<string>();

            // 1. MSIX / AppModel registry packages (Claude Desktop & ChatGPT Desktop)
            ScanAppxPackages(foundChat, foundClaude, foundChatPkg, foundClaudePkg, foundChatRoots, foundClaudeRoots);

            // 2. Standard desktop installation directories
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            string[] antiDirs = new string[]
            {
                CombineSafe(localAppData, "Programs\\antigravity"),
                CombineSafe(localAppData, "Antigravity"),
                CombineSafe(progFiles, "Antigravity"),
                CombineSafe(progFilesX86, "Antigravity")
            };
            for (int i = 0; i < antiDirs.Length; i++)
            {
                ScanDirectoryForApp(antiDirs[i], GuardedAppFlags.Antigravity, DefaultScanMaxDepth, false, foundAnti);
            }

            string[] chatDirs = new string[]
            {
                CombineSafe(localAppData, "Programs\\ChatGPT"),
                CombineSafe(localAppData, "ChatGPT"),
                CombineSafe(localAppData, "OpenAI\\Codex"),
                CombineSafe(progFiles, "ChatGPT"),
                CombineSafe(progFiles, "OpenAI\\ChatGPT")
            };
            for (int i = 0; i < chatDirs.Length; i++)
            {
                ScanDirectoryForApp(chatDirs[i], GuardedAppFlags.ChatGPT, DefaultScanMaxDepth, false, foundChat);
            }

            string[] claudeDirs = new string[]
            {
                CombineSafe(localAppData, "AnthropicClaude"),
                CombineSafe(localAppData, "Anthropic"),
                CombineSafe(localAppData, "Programs\\Claude"),
                CombineSafe(localAppData, "Programs\\AnthropicClaude"),
                CombineSafe(localAppData, "Claude"),
                CombineSafe(localAppData, "Claude-3p"),
                CombineSafe(progFiles, "Claude"),
                CombineSafe(progFiles, "AnthropicClaude"),
                CombineSafe(progFiles, "Anthropic")
            };
            for (int i = 0; i < claudeDirs.Length; i++)
            {
                ScanDirectoryForApp(claudeDirs[i], GuardedAppFlags.Claude, DefaultScanMaxDepth, false, foundClaude);
            }

            string[] clashDirs = new string[]
            {
                CombineSafe(progFiles, "Clash Verge"),
                CombineSafe(progFilesX86, "Clash Verge"),
                CombineSafe(localAppData, "Programs\\Clash Verge")
            };
            for (int i = 0; i < clashDirs.Length; i++)
            {
                ScanDirectoryForMihomo(clashDirs[i], foundMihomo);
            }

            // 3. Uninstall registry entries (captures custom drive installs like D:\Program Files...)
            ScanUninstallRegistry(foundAnti, foundChat, foundClaude, foundMihomo, foundAntiRoots, foundChatRoots, foundClaudeRoots);

            // 4. Desktop & Start Menu shortcuts (.lnk) — captures portable/custom-location installs
            ScanShortcutsForApps(foundAnti, foundChat, foundClaude, foundAntiRoots, foundChatRoots, foundClaudeRoots);

            // 5. Refresh resolved exes for user-configured custom directories (picks up updated binaries inside custom folders)
            List<string> customAntiSnapshot;
            List<string> customChatSnapshot;
            List<string> customClaudeSnapshot;
            lock (_lock)
            {
                customAntiSnapshot = new List<string>(_customAntigravityEntries);
                customChatSnapshot = new List<string>(_customChatGptEntries);
                customClaudeSnapshot = new List<string>(_customClaudeEntries);
            }
            List<string> customAntiExes = ResolveCustomEntriesToExes(customAntiSnapshot);
            List<string> customChatExes = ResolveCustomEntriesToExes(customChatSnapshot);
            List<string> customClaudeExes = ResolveCustomEntriesToExes(customClaudeSnapshot);

            lock (_lock)
            {
                AddRangeMarkDirtyLocked(_antigravityPaths, foundAnti, false);
                AddRangeMarkDirtyLocked(_chatGptPaths, foundChat, false);
                AddRangeMarkDirtyLocked(_claudePaths, foundClaude, false);
                for (int i = 0; i < foundChatPkg.Count; i++) _chatGptPackages.Add(foundChatPkg[i]);
                for (int i = 0; i < foundClaudePkg.Count; i++) _claudePackages.Add(foundClaudePkg[i]);
                for (int i = 0; i < foundMihomo.Count; i++) _mihomoPaths.Add(foundMihomo[i]);

                bool rulesChanged = false;
                if (AddRootsLocked(_trustedAntigravityRoots, foundAntiRoots)) rulesChanged = true;
                if (AddRootsLocked(_trustedChatGptRoots, foundChatRoots)) rulesChanged = true;
                if (AddRootsLocked(_trustedClaudeRoots, foundClaudeRoots)) rulesChanged = true;
                if (ReplaceSetLocked(_customAntigravityExes, customAntiExes)) rulesChanged = true;
                if (ReplaceSetLocked(_customChatGptExes, customChatExes)) rulesChanged = true;
                if (ReplaceSetLocked(_customClaudeExes, customClaudeExes)) rulesChanged = true;
                if (rulesChanged)
                {
                    RebuildMatchRulesLocked();
                }
            }
        }

        public bool RecordRunningImagePath(string fullPath)
        {
            string norm = NormalizeExistingFile(fullPath);
            if (norm == null)
            {
                return false;
            }

            bool changed = false;
            TargetMatchRules rules = _matchRules;
            GuardedAppFlags matched = TargetProcessKiller.MatchTargetImagePath(norm, GuardedAppFlags.All, rules);
            if (matched != GuardedAppFlags.None)
            {
                int slashIdx = norm.LastIndexOf('\\');
                string exeName = slashIdx >= 0 ? norm.Substring(slashIdx + 1) : norm;
                GuardedAppFlags directMatched = TargetProcessKiller.MatchDirectExeName(exeName, matched);
                string parentDir = Path.GetDirectoryName(norm);
                string trustedRootDir = (directMatched != GuardedAppFlags.None && IsSafeRootDirectory(parentDir))
                    ? NormalizeDirectoryPath(parentDir)
                    : null;

                List<string> siblingAnti = null;
                List<string> siblingChat = null;
                List<string> siblingClaude = null;
                if (!string.IsNullOrEmpty(trustedRootDir))
                {
                    if ((directMatched & GuardedAppFlags.Antigravity) != 0)
                    {
                        siblingAnti = new List<string>();
                        ScanDirectoryForApp(trustedRootDir, GuardedAppFlags.Antigravity, 3, true, siblingAnti);
                    }
                    if ((directMatched & GuardedAppFlags.ChatGPT) != 0)
                    {
                        siblingChat = new List<string>();
                        ScanDirectoryForApp(trustedRootDir, GuardedAppFlags.ChatGPT, 3, true, siblingChat);
                    }
                    if ((directMatched & GuardedAppFlags.Claude) != 0)
                    {
                        siblingClaude = new List<string>();
                        ScanDirectoryForApp(trustedRootDir, GuardedAppFlags.Claude, 3, true, siblingClaude);
                    }
                }

                lock (_lock)
                {
                    bool rulesChanged = false;
                    if ((matched & GuardedAppFlags.Antigravity) != 0)
                    {
                        if (_antigravityPaths.Add(norm))
                        {
                            _cacheDirty = true;
                            changed = true;
                        }
                        if (siblingAnti != null && AddRangeMarkDirtyLocked(_antigravityPaths, siblingAnti, true))
                        {
                            changed = true;
                        }
                        if (!string.IsNullOrEmpty(trustedRootDir) &&
                            (directMatched & GuardedAppFlags.Antigravity) != 0 &&
                            _trustedAntigravityRoots.Add(trustedRootDir))
                        {
                            rulesChanged = true;
                        }
                    }
                    if ((matched & GuardedAppFlags.ChatGPT) != 0)
                    {
                        if (_chatGptPaths.Add(norm))
                        {
                            _cacheDirty = true;
                            changed = true;
                        }
                        if (siblingChat != null && AddRangeMarkDirtyLocked(_chatGptPaths, siblingChat, true))
                        {
                            changed = true;
                        }
                        if (!string.IsNullOrEmpty(trustedRootDir) &&
                            (directMatched & GuardedAppFlags.ChatGPT) != 0 &&
                            _trustedChatGptRoots.Add(trustedRootDir))
                        {
                            rulesChanged = true;
                        }
                    }
                    if ((matched & GuardedAppFlags.Claude) != 0)
                    {
                        if (_claudePaths.Add(norm))
                        {
                            _cacheDirty = true;
                            changed = true;
                        }
                        if (siblingClaude != null && AddRangeMarkDirtyLocked(_claudePaths, siblingClaude, true))
                        {
                            changed = true;
                        }
                        if (!string.IsNullOrEmpty(trustedRootDir) &&
                            (directMatched & GuardedAppFlags.Claude) != 0 &&
                            _trustedClaudeRoots.Add(trustedRootDir))
                        {
                            rulesChanged = true;
                        }
                    }
                    if (rulesChanged)
                    {
                        RebuildMatchRulesLocked();
                    }
                }
                return changed;
            }

            int lastSlash = norm.LastIndexOf('\\');
            string exe = lastSlash >= 0 ? norm.Substring(lastSlash + 1) : norm;
            if (IsMihomoExeName(exe))
            {
                lock (_lock)
                {
                    if (_mihomoPaths.Add(norm))
                    {
                        changed = true;
                    }
                }
                return changed;
            }

            if (string.Equals(exe, "clash-verge.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(exe, "clash-verge-service.exe", StringComparison.OrdinalIgnoreCase))
            {
                string dir = Path.GetDirectoryName(norm);
                if (!string.IsNullOrEmpty(dir))
                {
                    List<string> nearby = new List<string>();
                    ScanDirectoryForMihomo(dir, nearby);
                    if (nearby.Count > 0)
                    {
                        lock (_lock)
                        {
                            for (int i = 0; i < nearby.Count; i++)
                            {
                                if (_mihomoPaths.Add(nearby[i]))
                                {
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }

            return changed;
        }

        public void BuildTargets(
            GuardedAppFlags enabledApps,
            out List<string> exePaths,
            out List<string> packageFamilies,
            out List<string> mihomoPaths)
        {
            HashSet<string> exeSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> pkgSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> mihomoSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            lock (_lock)
            {
                if ((enabledApps & GuardedAppFlags.Antigravity) != 0)
                {
                    if (CopyExistingFilesLocked(_antigravityPaths, exeSet)) _cacheDirty = true;
                    CopyExistingFilesLocked(_customAntigravityExes, exeSet);
                }
                if ((enabledApps & GuardedAppFlags.ChatGPT) != 0)
                {
                    if (CopyExistingFilesLocked(_chatGptPaths, exeSet)) _cacheDirty = true;
                    CopyExistingFilesLocked(_customChatGptExes, exeSet);
                    foreach (string p in _chatGptPackages) pkgSet.Add(p);
                }
                if ((enabledApps & GuardedAppFlags.Claude) != 0)
                {
                    if (CopyExistingFilesLocked(_claudePaths, exeSet)) _cacheDirty = true;
                    CopyExistingFilesLocked(_customClaudeExes, exeSet);
                    foreach (string p in _claudePackages) pkgSet.Add(p);
                }
                CopyExistingFilesLocked(_mihomoPaths, mihomoSet);
            }

            exePaths = new List<string>(exeSet);
            exePaths.Sort(StringComparer.OrdinalIgnoreCase);
            packageFamilies = new List<string>(pkgSet);
            packageFamilies.Sort(StringComparer.OrdinalIgnoreCase);
            mihomoPaths = new List<string>(mihomoSet);
            mihomoPaths.Sort(StringComparer.OrdinalIgnoreCase);
        }

        public AppPathDiagnostics GetDiagnostics()
        {
            AppPathDiagnostics diag = new AppPathDiagnostics();
            HashSet<string> antiSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> chatSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> claudeSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            lock (_lock)
            {
                CopyExistingFilesLocked(_antigravityPaths, antiSet);
                CopyExistingFilesLocked(_customAntigravityExes, antiSet);
                CopyExistingFilesLocked(_chatGptPaths, chatSet);
                CopyExistingFilesLocked(_customChatGptExes, chatSet);
                CopyExistingFilesLocked(_claudePaths, claudeSet);
                CopyExistingFilesLocked(_customClaudeExes, claudeSet);

                diag.ChatGptPackages.AddRange(_chatGptPackages);
                diag.ClaudePackages.AddRange(_claudePackages);
            }

            diag.AntigravityExes.AddRange(antiSet);
            diag.ChatGptExes.AddRange(chatSet);
            diag.ClaudeExes.AddRange(claudeSet);
            diag.AntigravityExes.Sort(StringComparer.OrdinalIgnoreCase);
            diag.ChatGptExes.Sort(StringComparer.OrdinalIgnoreCase);
            diag.ClaudeExes.Sort(StringComparer.OrdinalIgnoreCase);
            diag.ChatGptPackages.Sort(StringComparer.OrdinalIgnoreCase);
            diag.ClaudePackages.Sort(StringComparer.OrdinalIgnoreCase);
            diag.ScannedAt = DateTime.Now;
            return diag;
        }

        public bool MergeIntoConfig(NodeGuardConfig config, bool clearDirtyFlag)
        {
            if (config == null)
            {
                return false;
            }
            if (config.DiscoveredAppPaths == null)
            {
                config.DiscoveredAppPaths = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            }

            bool changedAny = false;
            lock (_lock)
            {
                TargetMatchRules rules = _matchRules;
                if (MergeAppSetLocked(config.DiscoveredAppPaths, "antigravity", GuardedAppFlags.Antigravity, rules, _antigravityPaths)) changedAny = true;
                if (MergeAppSetLocked(config.DiscoveredAppPaths, "chatgpt", GuardedAppFlags.ChatGPT, rules, _chatGptPaths)) changedAny = true;
                if (MergeAppSetLocked(config.DiscoveredAppPaths, "claude", GuardedAppFlags.Claude, rules, _claudePaths)) changedAny = true;
                if (clearDirtyFlag)
                {
                    _cacheDirty = false;
                }
            }
            return changedAny;
        }

        private static bool MergeAppSetLocked(
            Dictionary<string, List<string>> targetMap,
            string key,
            GuardedAppFlags appFlag,
            TargetMatchRules rules,
            HashSet<string> source)
        {
            List<string> existingList;
            bool hadExisting = targetMap.TryGetValue(key, out existingList) && existingList != null && existingList.Count > 0;

            HashSet<string> cleanSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (hadExisting)
            {
                for (int i = 0; i < existingList.Count; i++)
                {
                    string norm = NormalizeExistingFile(existingList[i]);
                    if (norm != null &&
                        TargetProcessKiller.MatchTargetImagePath(norm, appFlag, rules) != GuardedAppFlags.None)
                    {
                        cleanSet.Add(norm);
                    }
                }
            }

            List<string> staleSource = null;
            foreach (string path in source)
            {
                if (File.Exists(path))
                {
                    cleanSet.Add(path);
                }
                else
                {
                    if (staleSource == null) staleSource = new List<string>();
                    staleSource.Add(path);
                }
            }
            if (staleSource != null)
            {
                for (int i = 0; i < staleSource.Count; i++)
                {
                    source.Remove(staleSource[i]);
                }
            }

            List<string> cleanList = new List<string>(cleanSet);
            cleanList.Sort(StringComparer.OrdinalIgnoreCase);

            if (!hadExisting && cleanList.Count == 0)
            {
                targetMap.Remove(key);
                return false;
            }

            bool same = hadExisting && existingList.Count == cleanList.Count;
            if (same)
            {
                for (int i = 0; i < cleanList.Count; i++)
                {
                    if (!string.Equals(existingList[i], cleanList[i], StringComparison.OrdinalIgnoreCase))
                    {
                        same = false;
                        break;
                    }
                }
            }

            if (same)
            {
                return false;
            }

            if (cleanList.Count > 0)
            {
                targetMap[key] = cleanList;
            }
            else
            {
                targetMap.Remove(key);
            }
            return true;
        }

        private static bool CopyExistingFilesLocked(HashSet<string> source, HashSet<string> dest)
        {
            List<string> stale = null;
            foreach (string path in source)
            {
                if (File.Exists(path))
                {
                    dest.Add(path);
                }
                else
                {
                    if (stale == null) stale = new List<string>();
                    stale.Add(path);
                }
            }
            if (stale != null)
            {
                for (int i = 0; i < stale.Count; i++)
                {
                    source.Remove(stale[i]);
                }
                return true;
            }
            return false;
        }

        private bool AddRangeMarkDirtyLocked(HashSet<string> target, List<string> items, bool markDirty)
        {
            bool changed = false;
            for (int i = 0; i < items.Count; i++)
            {
                if (target.Add(items[i]))
                {
                    changed = true;
                    if (markDirty)
                    {
                        _cacheDirty = true;
                    }
                }
            }
            return changed;
        }

        private static bool AddRootsLocked(HashSet<string> target, List<string> roots)
        {
            bool changed = false;
            for (int i = 0; i < roots.Count; i++)
            {
                string norm = NormalizeDirectoryPath(roots[i]);
                if (!string.IsNullOrEmpty(norm) && IsSafeRootDirectory(norm) && target.Add(norm))
                {
                    changed = true;
                }
            }
            return changed;
        }

        private static void ReplaceListLocked(List<string> target, List<string> items)
        {
            target.Clear();
            if (items != null)
            {
                target.AddRange(items);
            }
        }

        private static bool ReplaceSetLocked(HashSet<string> target, List<string> items)
        {
            HashSet<string> next = new HashSet<string>(items ?? new List<string>(), StringComparer.OrdinalIgnoreCase);
            if (target.Count == next.Count && target.SetEquals(next))
            {
                return false;
            }
            target.Clear();
            foreach (string s in next)
            {
                target.Add(s);
            }
            return true;
        }

        private static List<string> ExtractConfigPathList(Dictionary<string, List<string>> map, string key)
        {
            List<string> result = new List<string>();
            if (map == null)
            {
                return result;
            }
            List<string> raw;
            if (!map.TryGetValue(key, out raw) || raw == null)
            {
                return result;
            }
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < raw.Count; i++)
            {
                string norm = NodeGuardConfig.NormalizeConfiguredPathEntry(raw[i]);
                if (!string.IsNullOrEmpty(norm) && seen.Add(norm))
                {
                    result.Add(norm);
                }
            }
            result.Sort(StringComparer.OrdinalIgnoreCase);
            return result;
        }

        private static List<string> ResolveCustomEntriesToExes(List<string> entries)
        {
            HashSet<string> found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (entries == null || entries.Count == 0)
            {
                return new List<string>();
            }
            for (int i = 0; i < entries.Count; i++)
            {
                string entry = entries[i];
                if (string.IsNullOrEmpty(entry))
                {
                    continue;
                }
                if (entry.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    string normFile = NormalizeExistingFile(entry);
                    if (normFile != null)
                    {
                        found.Add(normFile);
                    }
                }
                else if (Directory.Exists(entry) && IsSafeRootDirectory(entry))
                {
                    List<string> dirExes = new List<string>();
                    ScanCustomDirectoryRecursive(entry, 0, DefaultScanMaxDepth, MaxCustomDirExes, dirExes);
                    for (int j = 0; j < dirExes.Count; j++)
                    {
                        found.Add(dirExes[j]);
                    }
                }
            }
            List<string> list = new List<string>(found);
            list.Sort(StringComparer.OrdinalIgnoreCase);
            return list;
        }

        private static void ScanCustomDirectoryRecursive(string dir, int depth, int maxDepth, int maxFiles, List<string> output)
        {
            if (output.Count >= maxFiles)
            {
                return;
            }
            try
            {
                string[] files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
                for (int i = 0; i < files.Length && output.Count < maxFiles; i++)
                {
                    string exe = Path.GetFileName(files[i]);
                    if (TargetProcessKiller.IsIgnoredInstallerExeName(exe))
                    {
                        continue;
                    }
                    string norm = NormalizeExistingFile(files[i]);
                    if (norm != null)
                    {
                        output.Add(norm);
                    }
                }

                if (depth >= maxDepth || output.Count >= maxFiles)
                {
                    return;
                }

                string[] subDirs = Directory.GetDirectories(dir);
                for (int i = 0; i < subDirs.Length && output.Count < maxFiles; i++)
                {
                    string name = Path.GetFileName(subDirs[i]);
                    if (string.IsNullOrEmpty(name) || SkipDirNames.Contains(name))
                    {
                        continue;
                    }
                    ScanCustomDirectoryRecursive(subDirs[i], depth + 1, maxDepth, maxFiles, output);
                }
            }
            catch
            {
            }
        }

        private void RebuildMatchRulesLocked()
        {
            Dictionary<string, GuardedAppFlags> customExePaths = new Dictionary<string, GuardedAppFlags>(StringComparer.OrdinalIgnoreCase);
            List<KeyValuePair<string, GuardedAppFlags>> customDirPrefixes = new List<KeyValuePair<string, GuardedAppFlags>>();
            List<KeyValuePair<string, GuardedAppFlags>> trustedRootPrefixes = new List<KeyValuePair<string, GuardedAppFlags>>();
            HashSet<string> customExeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            GuardedAppFlags customDirMask = GuardedAppFlags.None;

            CollectCustomRulesForApp(_customAntigravityEntries, _customAntigravityExes, GuardedAppFlags.Antigravity, customExePaths, customDirPrefixes, customExeNames, ref customDirMask);
            CollectCustomRulesForApp(_customChatGptEntries, _customChatGptExes, GuardedAppFlags.ChatGPT, customExePaths, customDirPrefixes, customExeNames, ref customDirMask);
            CollectCustomRulesForApp(_customClaudeEntries, _customClaudeExes, GuardedAppFlags.Claude, customExePaths, customDirPrefixes, customExeNames, ref customDirMask);

            CollectTrustedRootsForApp(_trustedAntigravityRoots, GuardedAppFlags.Antigravity, trustedRootPrefixes);
            CollectTrustedRootsForApp(_trustedChatGptRoots, GuardedAppFlags.ChatGPT, trustedRootPrefixes);
            CollectTrustedRootsForApp(_trustedClaudeRoots, GuardedAppFlags.Claude, trustedRootPrefixes);

            StringBuilder sig = new StringBuilder(256);
            List<string> sortedExeKeys = new List<string>(customExePaths.Keys);
            sortedExeKeys.Sort(StringComparer.OrdinalIgnoreCase);
            sig.Append("E:");
            for (int i = 0; i < sortedExeKeys.Count; i++)
            {
                string k = sortedExeKeys[i];
                sig.Append(k).Append('=').Append((int)customExePaths[k]).Append(';');
            }
            customDirPrefixes.Sort((a, b) => string.Compare(a.Key, b.Key, StringComparison.OrdinalIgnoreCase));
            sig.Append("|D:");
            for (int i = 0; i < customDirPrefixes.Count; i++)
            {
                sig.Append(customDirPrefixes[i].Key).Append('=').Append((int)customDirPrefixes[i].Value).Append(';');
            }
            trustedRootPrefixes.Sort((a, b) => string.Compare(a.Key, b.Key, StringComparison.OrdinalIgnoreCase));
            sig.Append("|R:");
            for (int i = 0; i < trustedRootPrefixes.Count; i++)
            {
                sig.Append(trustedRootPrefixes[i].Key).Append('=').Append((int)trustedRootPrefixes[i].Value).Append(';');
            }

            _matchRules = new TargetMatchRules(
                customExePaths,
                customDirPrefixes,
                trustedRootPrefixes,
                customExeNames,
                customDirMask,
                sig.ToString());
        }

        private static void CollectCustomRulesForApp(
            List<string> entries,
            HashSet<string> resolvedExes,
            GuardedAppFlags appFlag,
            Dictionary<string, GuardedAppFlags> customExePaths,
            List<KeyValuePair<string, GuardedAppFlags>> customDirPrefixes,
            HashSet<string> customExeNames,
            ref GuardedAppFlags customDirMask)
        {
            for (int i = 0; i < entries.Count; i++)
            {
                string entry = entries[i];
                if (string.IsNullOrEmpty(entry))
                {
                    continue;
                }
                if (entry.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    GuardedAppFlags existing;
                    customExePaths.TryGetValue(entry, out existing);
                    customExePaths[entry] = existing | appFlag;
                    string exeName = Path.GetFileName(entry);
                    if (!string.IsNullOrEmpty(exeName))
                    {
                        customExeNames.Add(exeName);
                    }
                }
                else if (IsSafeRootDirectory(entry))
                {
                    string prefix = EnsureTrailingBackslash(entry);
                    if (!string.IsNullOrEmpty(prefix))
                    {
                        customDirPrefixes.Add(new KeyValuePair<string, GuardedAppFlags>(prefix, appFlag));
                        customDirMask |= appFlag;
                    }
                }
            }

            foreach (string exePath in resolvedExes)
            {
                string exeName = Path.GetFileName(exePath);
                if (!string.IsNullOrEmpty(exeName))
                {
                    customExeNames.Add(exeName);
                }
            }
        }

        private static void CollectTrustedRootsForApp(
            HashSet<string> roots,
            GuardedAppFlags appFlag,
            List<KeyValuePair<string, GuardedAppFlags>> output)
        {
            foreach (string root in roots)
            {
                string prefix = EnsureTrailingBackslash(root);
                if (!string.IsNullOrEmpty(prefix))
                {
                    output.Add(new KeyValuePair<string, GuardedAppFlags>(prefix, appFlag));
                }
            }
        }

        private static string EnsureTrailingBackslash(string dir)
        {
            if (string.IsNullOrWhiteSpace(dir))
            {
                return null;
            }
            return dir.EndsWith("\\", StringComparison.Ordinal) ? dir : (dir + "\\");
        }

        private static string NormalizeDirectoryPath(string dir)
        {
            if (string.IsNullOrWhiteSpace(dir))
            {
                return null;
            }
            try
            {
                string full = Path.GetFullPath(dir.Trim().Trim('"'));
                string root = Path.GetPathRoot(full);
                if (!string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
                {
                    full = full.TrimEnd('\\', '/');
                }
                return full;
            }
            catch
            {
                return null;
            }
        }

        internal static bool IsSafeRootDirectory(string dir)
        {
            string unused;
            return IsSafeCustomDirectory(dir, out unused);
        }

        internal static bool IsSafeCustomDirectory(string dir, out string reason)
        {
            reason = string.Empty;
            string norm = NormalizeDirectoryPath(dir);
            if (string.IsNullOrEmpty(norm))
            {
                reason = "目录路径无效。";
                return false;
            }

            string driveRoot = Path.GetPathRoot(norm);
            if (!string.IsNullOrEmpty(driveRoot) &&
                string.Equals(norm.TrimEnd('\\'), driveRoot.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            {
                reason = "不能添加整个磁盘根目录（如 C:\\ 或 D:\\），请选择具体的软件安装目录。";
                return false;
            }

            string winDir = NormalizeDirectoryPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            if (!string.IsNullOrEmpty(winDir) &&
                (string.Equals(norm, winDir, StringComparison.OrdinalIgnoreCase) ||
                 norm.StartsWith(winDir + "\\", StringComparison.OrdinalIgnoreCase)))
            {
                reason = "不能添加 Windows 系统目录或其子目录。";
                return false;
            }

            string progFiles = NormalizeDirectoryPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            string progFilesX86 = NormalizeDirectoryPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            string localAppData = NormalizeDirectoryPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            string appData = NormalizeDirectoryPath(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            string commonAppData = NormalizeDirectoryPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            string userProfile = NormalizeDirectoryPath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            string usersRoot = !string.IsNullOrEmpty(userProfile) ? NormalizeDirectoryPath(Path.GetDirectoryName(userProfile)) : null;
            string desktop = NormalizeDirectoryPath(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            string documents = NormalizeDirectoryPath(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            string localPrograms = !string.IsNullOrEmpty(localAppData) ? NormalizeDirectoryPath(Path.Combine(localAppData, "Programs")) : null;
            string windowsApps = !string.IsNullOrEmpty(progFiles) ? NormalizeDirectoryPath(Path.Combine(progFiles, "WindowsApps")) : null;

            string[] blockedExact = new string[]
            {
                progFiles, progFilesX86, localAppData, appData, commonAppData,
                userProfile, usersRoot, desktop, documents, localPrograms, windowsApps
            };
            for (int i = 0; i < blockedExact.Length; i++)
            {
                if (!string.IsNullOrEmpty(blockedExact[i]) &&
                    string.Equals(norm, blockedExact[i], StringComparison.OrdinalIgnoreCase))
                {
                    reason = "该目录范围过宽（属于系统或用户公共根目录），请选择具体应用所在的子目录。";
                    return false;
                }
            }

            return true;
        }

        private static void ScanAppxPackages(
            List<string> foundChat,
            List<string> foundClaude,
            List<string> foundChatPkg,
            List<string> foundClaudePkg,
            List<string> foundChatRoots,
            List<string> foundClaudeRoots)
        {
            ScanAppxRegistryRoot(
                Registry.CurrentUser,
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
                "PackageRootFolder",
                foundChat,
                foundClaude,
                foundChatPkg,
                foundClaudePkg,
                foundChatRoots,
                foundClaudeRoots);

            ScanAppxRegistryRoot(
                Registry.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications",
                "Path",
                foundChat,
                foundClaude,
                foundChatPkg,
                foundClaudePkg,
                foundChatRoots,
                foundClaudeRoots);
        }

        private static void ScanAppxRegistryRoot(
            RegistryKey hive,
            string subKeyPath,
            string folderValueName,
            List<string> foundChat,
            List<string> foundClaude,
            List<string> foundChatPkg,
            List<string> foundClaudePkg,
            List<string> foundChatRoots,
            List<string> foundClaudeRoots)
        {
            try
            {
                using (RegistryKey root = hive.OpenSubKey(subKeyPath, false))
                {
                    if (root == null)
                    {
                        return;
                    }

                    string[] names = root.GetSubKeyNames();
                    for (int i = 0; i < names.Length; i++)
                    {
                        string pkgFullName = names[i];
                        if (string.IsNullOrEmpty(pkgFullName))
                        {
                            continue;
                        }

                        GuardedAppFlags appFlag = ClassifyAppxPackageName(pkgFullName);
                        if (appFlag == GuardedAppFlags.None)
                        {
                            continue;
                        }

                        string pfn = TryExtractPackageFamilyName(pkgFullName);
                        if (!string.IsNullOrEmpty(pfn))
                        {
                            if ((appFlag & GuardedAppFlags.ChatGPT) != 0) foundChatPkg.Add(pfn);
                            if ((appFlag & GuardedAppFlags.Claude) != 0) foundClaudePkg.Add(pfn);
                        }

                        try
                        {
                            using (RegistryKey pkgKey = root.OpenSubKey(pkgFullName, false))
                            {
                                if (pkgKey == null) continue;
                                string rawRoot = pkgKey.GetValue(folderValueName) as string;
                                if (string.IsNullOrEmpty(rawRoot)) continue;

                                // AppxAllUserStore Path points to AppxManifest.xml; strip filename if needed
                                string folder = rawRoot;
                                if (folder.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                                {
                                    folder = Path.GetDirectoryName(folder);
                                }
                                if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
                                {
                                    continue;
                                }

                                if ((appFlag & GuardedAppFlags.ChatGPT) != 0)
                                {
                                    foundChatRoots.Add(folder);
                                    ScanDirectoryForApp(folder, GuardedAppFlags.ChatGPT, DefaultScanMaxDepth, true, foundChat);
                                }
                                if ((appFlag & GuardedAppFlags.Claude) != 0)
                                {
                                    foundClaudeRoots.Add(folder);
                                    ScanDirectoryForApp(folder, GuardedAppFlags.Claude, DefaultScanMaxDepth, true, foundClaude);
                                }
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch
            {
            }
        }

        internal static GuardedAppFlags ClassifyAppxPackageName(string pkgFullName)
        {
            if (string.IsNullOrEmpty(pkgFullName))
            {
                return GuardedAppFlags.None;
            }
            if (pkgFullName.StartsWith("OpenAI", StringComparison.OrdinalIgnoreCase) ||
                pkgFullName.StartsWith("ChatGPT", StringComparison.OrdinalIgnoreCase))
            {
                return GuardedAppFlags.ChatGPT;
            }
            if (pkgFullName.StartsWith("Claude", StringComparison.OrdinalIgnoreCase) ||
                pkgFullName.StartsWith("Anthropic", StringComparison.OrdinalIgnoreCase))
            {
                return GuardedAppFlags.Claude;
            }
            return GuardedAppFlags.None;
        }

        internal static string TryExtractPackageFamilyName(string packageFullName)
        {
            if (string.IsNullOrEmpty(packageFullName))
            {
                return null;
            }
            int firstUnderscore = packageFullName.IndexOf('_');
            int lastDoubleUnderscore = packageFullName.LastIndexOf("__", StringComparison.Ordinal);
            if (firstUnderscore <= 0 || lastDoubleUnderscore <= firstUnderscore || lastDoubleUnderscore + 2 >= packageFullName.Length)
            {
                return null;
            }
            string name = packageFullName.Substring(0, firstUnderscore);
            string publisherId = packageFullName.Substring(lastDoubleUnderscore + 2);
            return name + "_" + publisherId;
        }

        private static void ScanUninstallRegistry(
            List<string> foundAnti,
            List<string> foundChat,
            List<string> foundClaude,
            List<string> foundMihomo,
            List<string> foundAntiRoots,
            List<string> foundChatRoots,
            List<string> foundClaudeRoots)
        {
            ScanUninstallRoot(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", foundAnti, foundChat, foundClaude, foundMihomo, foundAntiRoots, foundChatRoots, foundClaudeRoots);
            ScanUninstallRoot(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", foundAnti, foundChat, foundClaude, foundMihomo, foundAntiRoots, foundChatRoots, foundClaudeRoots);
            ScanUninstallRoot(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", foundAnti, foundChat, foundClaude, foundMihomo, foundAntiRoots, foundChatRoots, foundClaudeRoots);
        }

        private static void ScanUninstallRoot(
            RegistryKey hive,
            string subKeyPath,
            List<string> foundAnti,
            List<string> foundChat,
            List<string> foundClaude,
            List<string> foundMihomo,
            List<string> foundAntiRoots,
            List<string> foundChatRoots,
            List<string> foundClaudeRoots)
        {
            try
            {
                using (RegistryKey root = hive.OpenSubKey(subKeyPath, false))
                {
                    if (root == null) return;
                    string[] subNames = root.GetSubKeyNames();
                    for (int i = 0; i < subNames.Length; i++)
                    {
                        try
                        {
                            using (RegistryKey entry = root.OpenSubKey(subNames[i], false))
                            {
                                if (entry == null) continue;
                                string displayName = entry.GetValue("DisplayName") as string;
                                if (string.IsNullOrEmpty(displayName)) continue;

                                bool isAnti = displayName.IndexOf("Antigravity", StringComparison.OrdinalIgnoreCase) >= 0;
                                bool isChat = displayName.IndexOf("ChatGPT", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              displayName.IndexOf("Codex", StringComparison.OrdinalIgnoreCase) >= 0;
                                bool isClaude = displayName.IndexOf("Claude", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                displayName.IndexOf("Anthropic", StringComparison.OrdinalIgnoreCase) >= 0;
                                bool isClash = displayName.IndexOf("Clash Verge", StringComparison.OrdinalIgnoreCase) >= 0;
                                if (!isAnti && !isChat && !isClaude && !isClash) continue;

                                string dir = ExtractInstallDirectoryFromUninstall(entry);
                                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;

                                bool trusted = IsSafeRootDirectory(dir);
                                if (isAnti)
                                {
                                    if (trusted) foundAntiRoots.Add(dir);
                                    ScanDirectoryForApp(dir, GuardedAppFlags.Antigravity, DefaultScanMaxDepth, trusted, foundAnti);
                                }
                                if (isChat)
                                {
                                    if (trusted) foundChatRoots.Add(dir);
                                    ScanDirectoryForApp(dir, GuardedAppFlags.ChatGPT, DefaultScanMaxDepth, trusted, foundChat);
                                }
                                if (isClaude)
                                {
                                    if (trusted) foundClaudeRoots.Add(dir);
                                    ScanDirectoryForApp(dir, GuardedAppFlags.Claude, DefaultScanMaxDepth, trusted, foundClaude);
                                }
                                if (isClash) ScanDirectoryForMihomo(dir, foundMihomo);
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private static void ScanShortcutsForApps(
            List<string> foundAnti,
            List<string> foundChat,
            List<string> foundClaude,
            List<string> foundAntiRoots,
            List<string> foundChatRoots,
            List<string> foundClaudeRoots)
        {
            List<KeyValuePair<string, GuardedAppFlags>> candidateShortcuts = new List<KeyValuePair<string, GuardedAppFlags>>();
            string[] shortcutDirs = new string[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                CombineSafe(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs"),
                CombineSafe(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs")
            };

            HashSet<string> visitedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < shortcutDirs.Length; i++)
            {
                string dir = shortcutDirs[i];
                if (string.IsNullOrEmpty(dir) || !visitedDirs.Add(dir) || !Directory.Exists(dir))
                {
                    continue;
                }
                CollectMatchingShortcutsRecursive(dir, 0, 2, candidateShortcuts);
            }

            if (candidateShortcuts.Count == 0)
            {
                return;
            }

            object shell = null;
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null)
                {
                    return;
                }
                shell = Activator.CreateInstance(shellType);
                if (shell == null)
                {
                    return;
                }

                for (int i = 0; i < candidateShortcuts.Count; i++)
                {
                    string lnkPath = candidateShortcuts[i].Key;
                    GuardedAppFlags hintFlag = candidateShortcuts[i].Value;
                    object shortcut = null;
                    try
                    {
                        shortcut = shellType.InvokeMember(
                            "CreateShortcut",
                            BindingFlags.InvokeMethod,
                            null,
                            shell,
                            new object[] { lnkPath });
                        if (shortcut == null)
                        {
                            continue;
                        }
                        string rawTarget = shortcut.GetType().InvokeMember(
                            "TargetPath",
                            BindingFlags.GetProperty,
                            null,
                            shortcut,
                            null) as string;
                        string normExe = NormalizeExistingFile(rawTarget);
                        if (normExe == null || !normExe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        GuardedAppFlags verified = TargetProcessKiller.MatchTargetExeInTrustedFolder(normExe, hintFlag);
                        if (verified == GuardedAppFlags.None)
                        {
                            continue;
                        }

                        string parentDir = Path.GetDirectoryName(normExe);
                        bool trustedDir = IsSafeRootDirectory(parentDir);
                        if ((verified & GuardedAppFlags.Antigravity) != 0)
                        {
                            foundAnti.Add(normExe);
                            if (trustedDir)
                            {
                                foundAntiRoots.Add(parentDir);
                                ScanDirectoryForApp(parentDir, GuardedAppFlags.Antigravity, 3, true, foundAnti);
                            }
                        }
                        if ((verified & GuardedAppFlags.ChatGPT) != 0)
                        {
                            foundChat.Add(normExe);
                            if (trustedDir)
                            {
                                foundChatRoots.Add(parentDir);
                                ScanDirectoryForApp(parentDir, GuardedAppFlags.ChatGPT, 3, true, foundChat);
                            }
                        }
                        if ((verified & GuardedAppFlags.Claude) != 0)
                        {
                            foundClaude.Add(normExe);
                            if (trustedDir)
                            {
                                foundClaudeRoots.Add(parentDir);
                                ScanDirectoryForApp(parentDir, GuardedAppFlags.Claude, 3, true, foundClaude);
                            }
                        }
                    }
                    catch
                    {
                    }
                    finally
                    {
                        if (shortcut != null && Marshal.IsComObject(shortcut))
                        {
                            try { Marshal.FinalReleaseComObject(shortcut); } catch { }
                        }
                    }
                }
            }
            catch
            {
            }
            finally
            {
                if (shell != null && Marshal.IsComObject(shell))
                {
                    try { Marshal.FinalReleaseComObject(shell); } catch { }
                }
            }
        }

        private static void CollectMatchingShortcutsRecursive(
            string dir,
            int depth,
            int maxDepth,
            List<KeyValuePair<string, GuardedAppFlags>> output)
        {
            try
            {
                string[] files = Directory.GetFiles(dir, "*.lnk", SearchOption.TopDirectoryOnly);
                for (int i = 0; i < files.Length; i++)
                {
                    string name = Path.GetFileNameWithoutExtension(files[i]);
                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }
                    GuardedAppFlags hint = GuardedAppFlags.None;
                    if (name.IndexOf("Antigravity", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        hint |= GuardedAppFlags.Antigravity;
                    }
                    if (name.IndexOf("ChatGPT", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Codex", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        hint |= GuardedAppFlags.ChatGPT;
                    }
                    if (name.IndexOf("Claude", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf("Anthropic", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        hint |= GuardedAppFlags.Claude;
                    }
                    if (hint != GuardedAppFlags.None)
                    {
                        output.Add(new KeyValuePair<string, GuardedAppFlags>(files[i], hint));
                    }
                }

                if (depth >= maxDepth)
                {
                    return;
                }

                string[] subDirs = Directory.GetDirectories(dir);
                for (int i = 0; i < subDirs.Length; i++)
                {
                    CollectMatchingShortcutsRecursive(subDirs[i], depth + 1, maxDepth, output);
                }
            }
            catch
            {
            }
        }

        private static string ExtractInstallDirectoryFromUninstall(RegistryKey entry)
        {
            string loc = entry.GetValue("InstallLocation") as string;
            if (!string.IsNullOrWhiteSpace(loc))
            {
                string trimmed = loc.Trim().Trim('"');
                if (Directory.Exists(trimmed))
                {
                    return trimmed;
                }
            }

            string icon = entry.GetValue("DisplayIcon") as string;
            if (!string.IsNullOrWhiteSpace(icon))
            {
                string cleaned = icon.Trim().Trim('"');
                int commaIdx = cleaned.LastIndexOf(',');
                if (commaIdx > 0)
                {
                    cleaned = cleaned.Substring(0, commaIdx).Trim().Trim('"');
                }
                if (File.Exists(cleaned))
                {
                    return Path.GetDirectoryName(cleaned);
                }
            }
            return null;
        }

        private static void ScanDirectoryForApp(string rootDir, GuardedAppFlags appFlag, int maxDepth, bool trustFolderForApp, List<string> output)
        {
            if (string.IsNullOrEmpty(rootDir) || !Directory.Exists(rootDir))
            {
                return;
            }
            ScanDirectoryForAppRecursive(rootDir, appFlag, 0, maxDepth, trustFolderForApp, output);
        }

        private static void ScanDirectoryForAppRecursive(string dir, GuardedAppFlags appFlag, int depth, int maxDepth, bool trustFolderForApp, List<string> output)
        {
            try
            {
                string[] files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
                for (int i = 0; i < files.Length; i++)
                {
                    string norm = NormalizeExistingFile(files[i]);
                    if (norm == null)
                    {
                        continue;
                    }
                    GuardedAppFlags hit = trustFolderForApp
                        ? TargetProcessKiller.MatchTargetExeInTrustedFolder(norm, appFlag)
                        : TargetProcessKiller.MatchTargetImagePath(norm, appFlag);
                    if (hit != GuardedAppFlags.None)
                    {
                        output.Add(norm);
                    }
                }

                if (depth >= maxDepth)
                {
                    return;
                }

                string[] subDirs = Directory.GetDirectories(dir);
                for (int i = 0; i < subDirs.Length; i++)
                {
                    string name = Path.GetFileName(subDirs[i]);
                    if (string.IsNullOrEmpty(name) || SkipDirNames.Contains(name))
                    {
                        continue;
                    }
                    ScanDirectoryForAppRecursive(subDirs[i], appFlag, depth + 1, maxDepth, trustFolderForApp, output);
                }
            }
            catch
            {
            }
        }

        private static void ScanDirectoryForMihomo(string dir, List<string> output)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            {
                return;
            }
            try
            {
                string[] files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
                for (int i = 0; i < files.Length; i++)
                {
                    string exe = Path.GetFileName(files[i]);
                    if (IsMihomoExeName(exe))
                    {
                        string norm = NormalizeExistingFile(files[i]);
                        if (norm != null)
                        {
                            output.Add(norm);
                        }
                    }
                }
            }
            catch
            {
            }
        }

        internal static bool IsMihomoExeName(string exe)
        {
            if (string.IsNullOrEmpty(exe) || !exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            return exe.StartsWith("verge-mihomo", StringComparison.OrdinalIgnoreCase) ||
                   exe.StartsWith("mihomo", StringComparison.OrdinalIgnoreCase) ||
                   exe.StartsWith("clash-meta", StringComparison.OrdinalIgnoreCase);
        }

        private static string CombineSafe(string baseDir, string relative)
        {
            if (string.IsNullOrEmpty(baseDir))
            {
                return null;
            }
            try
            {
                return Path.Combine(baseDir, relative);
            }
            catch
            {
                return null;
            }
        }

        private static string NormalizeExistingFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }
            try
            {
                string full = Path.GetFullPath(path.Trim().Trim('"'));
                return File.Exists(full) ? full : null;
            }
            catch
            {
                return null;
            }
        }
    }

    internal struct WfpStateSnapshot
    {
        public bool Enabled;
        public bool Active;
        public bool Degraded;
        public bool BlockingNow;
        public bool DnsGuardActive;
        public int ExeTargetCount;
        public int PackageTargetCount;
        public int ActiveFilterCount;
        public string StatusText;
    }

    internal sealed class WfpKillSwitch : IDisposable
    {
        // Dedicated TunGuard WFP Provider & Sublayer GUIDs
        private static readonly Guid ProviderKey = new Guid("8d4c5b2a-7e31-4f90-a6c2-19e84b73f501");
        private static readonly Guid SubLayerKey = new Guid("3a9f1d6c-52b8-4c17-9e44-7b0c2d81e602");

        // Verified Windows SDK WFP Layer & Condition GUIDs (fwpmu.h)
        private static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        private static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        private static readonly Guid FWPM_CONDITION_ALE_APP_ID = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        private static readonly Guid FWPM_CONDITION_ALE_PACKAGE_ID = new Guid("71bc78fa-f17c-4997-a602-6abb261f351c");
        private static readonly Guid FWPM_CONDITION_IP_LOCAL_INTERFACE = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
        private static readonly Guid FWPM_CONDITION_FLAGS = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
        private static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");

        private const uint RPC_C_AUTHN_WINNT = 10;
        private const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;
        private const uint FWPM_TXN_WRITE = 0;
        private const uint FWP_ACTION_BLOCK = 0x00001001;
        private const uint FWP_ACTION_PERMIT = 0x00001002;
        private const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;
        private const uint ERROR_ACCESS_DENIED = 5;
        private const uint FWP_E_ALREADY_EXISTS = 0x80320009;
        private const ushort DNS_PORT = 53;

        // Rule priority weights inside TunGuard Sublayer (higher weight evaluated first)
        private const byte WEIGHT_BLOCK_LOCAL_PROXY = 14;
        private const byte WEIGHT_ALLOW_LOOPBACK = 12;
        private const byte WEIGHT_ALLOW_MIHOMO_DNS = 11;
        private const byte WEIGHT_ALLOW_TUN = 10;
        private const byte WEIGHT_BLOCK_ALL = 1;

        private enum FWP_MATCH_TYPE : uint
        {
            FWP_MATCH_EQUAL = 0,
            FWP_MATCH_FLAGS_ALL_SET = 6
        }

        private enum FWP_DATA_TYPE : uint
        {
            FWP_EMPTY = 0,
            FWP_UINT8 = 1,
            FWP_UINT16 = 2,
            FWP_UINT32 = 3,
            FWP_UINT64 = 4,
            FWP_BYTE_BLOB_TYPE = 12,
            FWP_SID = 13
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWP_BYTE_BLOB
        {
            public uint size;
            public IntPtr data;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_DISPLAY_DATA0
        {
            public IntPtr name;
            public IntPtr description;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct FWP_VALUE0
        {
            [FieldOffset(0)] public FWP_DATA_TYPE type;
            [FieldOffset(8)] public byte uint8;
            [FieldOffset(8)] public ushort uint16;
            [FieldOffset(8)] public uint uint32;
            [FieldOffset(8)] public IntPtr uint64Ptr;
            [FieldOffset(8)] public IntPtr byteBlob;
            [FieldOffset(8)] public IntPtr sid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_FILTER_CONDITION0
        {
            public Guid fieldKey;
            public FWP_MATCH_TYPE matchType;
            public FWP_VALUE0 conditionValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_ACTION0
        {
            public uint type;
            public Guid filterType;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct FWPM_FILTER_CONTEXT0
        {
            [FieldOffset(0)] public ulong rawContext;
            [FieldOffset(0)] public Guid providerContextKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_SESSION0
        {
            public Guid sessionKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public uint txnWaitTimeoutInMSec;
            public uint processId;
            public IntPtr sid;
            public IntPtr username;
            public int kernelMode;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_PROVIDER0
        {
            public Guid providerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public FWP_BYTE_BLOB providerData;
            public IntPtr serviceName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_SUBLAYER0
        {
            public Guid subLayerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerKey;
            public FWP_BYTE_BLOB providerData;
            public ushort weight;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_FILTER0
        {
            public Guid filterKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerKey;
            public FWP_BYTE_BLOB providerData;
            public Guid layerKey;
            public Guid subLayerKey;
            public FWP_VALUE0 weight;
            public uint numFilterConditions;
            public IntPtr filterCondition;
            public FWPM_ACTION0 action;
            public FWPM_FILTER_CONTEXT0 context;
            public IntPtr reserved;
            public ulong filterId;
            public FWP_VALUE0 effectiveWeight;
        }

        private sealed class ResolvedIdentity : IDisposable
        {
            public bool IsPackage;
            public IntPtr Handle;

            public void Dispose()
            {
                if (Handle != IntPtr.Zero)
                {
                    if (IsPackage)
                    {
                        FreeSid(Handle);
                    }
                    else
                    {
                        IntPtr p = Handle;
                        FwpmFreeMemory0(ref p);
                    }
                    Handle = IntPtr.Zero;
                }
            }
        }

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        private static extern uint FwpmEngineOpen0(
            string serverName,
            uint authnService,
            IntPtr authIdentity,
            ref FWPM_SESSION0 session,
            out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterAdd0(
            IntPtr engineHandle,
            ref FWPM_FILTER0 filter,
            IntPtr sd,
            out ulong filterId);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        private static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

        [DllImport("fwpuclnt.dll")]
        private static extern void FwpmFreeMemory0(ref IntPtr p);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        private static extern int DeriveAppContainerSidFromAppContainerName(string pszAppContainerName, out IntPtr ppsidAppContainerSid);

        [DllImport("advapi32.dll")]
        private static extern IntPtr FreeSid(IntPtr pSid);

        private readonly object _lock = new object();
        private IntPtr _engine = IntPtr.Zero;
        private IntPtr _providerKeyPtr = IntPtr.Zero;
        private IntPtr _displayNamePtr = IntPtr.Zero;
        private IntPtr _displayDescPtr = IntPtr.Zero;

        private bool _initialized;
        private bool _available;
        private bool _disposed;
        private string _initFailureReason = string.Empty;

        private List<ulong> _baseFilterIds = new List<ulong>();
        private List<ulong> _tunPermitFilterIds = new List<ulong>();
        private List<ulong> _proxyBlockFilterIds = new List<ulong>();

        private string _lastBaseSig = string.Empty;
        private string _lastTunSig = string.Empty;
        private string _lastProxyBlockSig = string.Empty;

        private WfpStateSnapshot _snapshot = new WfpStateSnapshot
        {
            Enabled = false,
            Active = false,
            Degraded = false,
            BlockingNow = false,
            DnsGuardActive = false,
            ExeTargetCount = 0,
            PackageTargetCount = 0,
            ActiveFilterCount = 0,
            StatusText = "未初始化"
        };

        public bool IsActive
        {
            get
            {
                lock (_lock)
                {
                    return _available && _snapshot.Active;
                }
            }
        }

        public WfpStateSnapshot GetSnapshot()
        {
            lock (_lock)
            {
                return _snapshot;
            }
        }

        internal static bool VerifyNativeLayouts(out string error)
        {
            if (IntPtr.Size != 8)
            {
                error = "WFP 仅支持 x64 进程";
                return false;
            }
            if (Marshal.SizeOf(typeof(FWP_BYTE_BLOB)) != 16 ||
                Marshal.SizeOf(typeof(FWPM_DISPLAY_DATA0)) != 16 ||
                Marshal.SizeOf(typeof(FWP_VALUE0)) != 16 ||
                Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0)) != 40 ||
                Marshal.SizeOf(typeof(FWPM_ACTION0)) != 20 ||
                Marshal.SizeOf(typeof(FWPM_FILTER_CONTEXT0)) != 16 ||
                Marshal.SizeOf(typeof(FWPM_SESSION0)) != 72 ||
                Marshal.SizeOf(typeof(FWPM_PROVIDER0)) != 64 ||
                Marshal.SizeOf(typeof(FWPM_SUBLAYER0)) != 72 ||
                Marshal.SizeOf(typeof(FWPM_FILTER0)) != 200 ||
                Marshal.OffsetOf(typeof(FWPM_FILTER0), "context").ToInt32() != 152)
            {
                error = "WFP x64 结构体内存布局校验失败";
                return false;
            }
            error = null;
            return true;
        }

        public bool TryInitialize(out string errorReason)
        {
            lock (_lock)
            {
                if (_disposed)
                {
                    errorReason = "WFP 引擎已释放";
                    return false;
                }
                if (_initialized)
                {
                    errorReason = _initFailureReason;
                    return _available;
                }
                _initialized = true;

                string layoutError;
                if (!VerifyNativeLayouts(out layoutError))
                {
                    _available = false;
                    _initFailureReason = layoutError;
                    errorReason = layoutError;
                    return false;
                }

                _providerKeyPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
                Marshal.StructureToPtr(ProviderKey, _providerKeyPtr, false);
                _displayNamePtr = Marshal.StringToHGlobalUni("TunGuard WFP Kill Switch");
                _displayDescPtr = Marshal.StringToHGlobalUni("Kernel-level outbound tunnel enforcement for TunGuard");

                FWPM_SESSION0 session = new FWPM_SESSION0();
                session.flags = FWPM_SESSION_FLAG_DYNAMIC;
                session.displayData.name = _displayNamePtr;
                session.displayData.description = _displayDescPtr;

                IntPtr handle;
                uint rc = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, ref session, out handle);
                if (rc != 0 || handle == IntPtr.Zero)
                {
                    _available = false;
                    _initFailureReason = FormatWfpError("FwpmEngineOpen0", rc);
                    errorReason = _initFailureReason;
                    FreeStaticNativeBuffersLocked();
                    return false;
                }

                _engine = handle;

                uint txnRc = FwpmTransactionBegin0(_engine, FWPM_TXN_WRITE);
                if (txnRc != 0)
                {
                    FailInitializeCloseEngineLocked(FormatWfpError("FwpmTransactionBegin0", txnRc));
                    errorReason = _initFailureReason;
                    return false;
                }

                FWPM_PROVIDER0 provider = new FWPM_PROVIDER0();
                provider.providerKey = ProviderKey;
                provider.displayData.name = _displayNamePtr;
                provider.displayData.description = _displayDescPtr;

                uint provRc = FwpmProviderAdd0(_engine, ref provider, IntPtr.Zero);
                if (provRc != 0 && provRc != FWP_E_ALREADY_EXISTS)
                {
                    FwpmTransactionAbort0(_engine);
                    FailInitializeCloseEngineLocked(FormatWfpError("FwpmProviderAdd0", provRc));
                    errorReason = _initFailureReason;
                    return false;
                }

                FWPM_SUBLAYER0 subLayer = new FWPM_SUBLAYER0();
                subLayer.subLayerKey = SubLayerKey;
                subLayer.displayData.name = _displayNamePtr;
                subLayer.displayData.description = _displayDescPtr;
                subLayer.providerKey = _providerKeyPtr;
                subLayer.weight = ushort.MaxValue;

                uint subRc = FwpmSubLayerAdd0(_engine, ref subLayer, IntPtr.Zero);
                if (subRc != 0 && subRc != FWP_E_ALREADY_EXISTS)
                {
                    FwpmTransactionAbort0(_engine);
                    FailInitializeCloseEngineLocked(FormatWfpError("FwpmSubLayerAdd0", subRc));
                    errorReason = _initFailureReason;
                    return false;
                }

                uint commitRc = FwpmTransactionCommit0(_engine);
                if (commitRc != 0)
                {
                    FwpmTransactionAbort0(_engine);
                    FailInitializeCloseEngineLocked(FormatWfpError("FwpmTransactionCommit0", commitRc));
                    errorReason = _initFailureReason;
                    return false;
                }

                _available = true;
                _initFailureReason = string.Empty;
                errorReason = string.Empty;
                return true;
            }
        }

        private static string FormatWfpError(string apiName, uint rc)
        {
            if (rc == ERROR_ACCESS_DENIED || rc == 0x80070005u)
            {
                return "需管理员权限";
            }
            return apiName + " 失败 (0x" + rc.ToString("X8") + ")";
        }

        private void FailInitializeCloseEngineLocked(string reason)
        {
            _available = false;
            _initFailureReason = reason;
            if (_engine != IntPtr.Zero)
            {
                FwpmEngineClose0(_engine);
                _engine = IntPtr.Zero;
            }
            FreeStaticNativeBuffersLocked();
        }

        public WfpStateSnapshot SyncState(
            bool monitoringEnabled,
            bool wfpEnabled,
            bool isGuardSafe,
            ulong tunLuid,
            List<string> exePaths,
            List<string> packageFamilies,
            bool blockNonTunDns,
            List<string> mihomoPaths,
            List<ushort> blockedLoopbackPorts)
        {
            lock (_lock)
            {
                if (_disposed)
                {
                    return _snapshot;
                }

                if (!wfpEnabled)
                {
                    if (_available)
                    {
                        ClearAllFiltersLocked();
                    }
                    _snapshot = new WfpStateSnapshot
                    {
                        Enabled = false,
                        Active = false,
                        Degraded = false,
                        BlockingNow = false,
                        DnsGuardActive = false,
                        ExeTargetCount = 0,
                        PackageTargetCount = 0,
                        ActiveFilterCount = 0,
                        StatusText = "未启用"
                    };
                    return _snapshot;
                }

                if (!_initialized)
                {
                    string unusedErr;
                    TryInitialize(out unusedErr);
                }

                if (!_available)
                {
                    _snapshot = new WfpStateSnapshot
                    {
                        Enabled = true,
                        Active = false,
                        Degraded = true,
                        BlockingNow = false,
                        DnsGuardActive = false,
                        ExeTargetCount = 0,
                        PackageTargetCount = 0,
                        ActiveFilterCount = 0,
                        StatusText = "已降级 (" + _initFailureReason + ")"
                    };
                    return _snapshot;
                }

                if (!monitoringEnabled)
                {
                    ClearAllFiltersLocked();
                    _snapshot = new WfpStateSnapshot
                    {
                        Enabled = true,
                        Active = false,
                        Degraded = false,
                        BlockingNow = false,
                        DnsGuardActive = false,
                        ExeTargetCount = 0,
                        PackageTargetCount = 0,
                        ActiveFilterCount = 0,
                        StatusText = "已暂停 (规则已清空)"
                    };
                    return _snapshot;
                }

                List<string> safeExes = exePaths ?? new List<string>();
                List<string> safePkgs = packageFamilies ?? new List<string>();
                List<string> safeMihomo = mihomoPaths ?? new List<string>();
                List<ushort> safeProxyPorts = blockedLoopbackPorts ?? new List<ushort>();

                bool hasAnyTargets = safeExes.Count > 0 || safePkgs.Count > 0 || blockNonTunDns;
                if (!hasAnyTargets)
                {
                    ClearAllFiltersLocked();
                    _snapshot = new WfpStateSnapshot
                    {
                        Enabled = true,
                        Active = true,
                        Degraded = false,
                        BlockingNow = !isGuardSafe,
                        DnsGuardActive = false,
                        ExeTargetCount = 0,
                        PackageTargetCount = 0,
                        ActiveFilterCount = 0,
                        StatusText = "待命中 (未发现受控目标)"
                    };
                    return _snapshot;
                }

                bool shouldPermitTun = isGuardSafe && tunLuid != 0;
                bool shouldBlockLocalProxy = !isGuardSafe && safeProxyPorts.Count > 0 && (safeExes.Count > 0 || safePkgs.Count > 0);

                string baseSig = BuildSignature("B", safeExes, safePkgs, blockNonTunDns, safeMihomo, null, 0, false);
                string tunSig = BuildSignature("T", safeExes, safePkgs, blockNonTunDns, null, null, tunLuid, shouldPermitTun);
                string proxySig = BuildSignature("P", safeExes, safePkgs, false, null, safeProxyPorts, 0, shouldBlockLocalProxy);

                bool needBase = !string.Equals(baseSig, _lastBaseSig, StringComparison.Ordinal);
                bool needTun = !string.Equals(tunSig, _lastTunSig, StringComparison.Ordinal);
                bool needProxy = !string.Equals(proxySig, _lastProxyBlockSig, StringComparison.Ordinal);

                if (needBase || needTun || needProxy)
                {
                    List<ResolvedIdentity> targetIds = ResolveTargetIdentities(safeExes, safePkgs);
                    List<ResolvedIdentity> mihomoIds = (needBase && blockNonTunDns)
                        ? ResolveExeIdentities(safeMihomo)
                        : null;

                    try
                    {
                        uint txnRc = FwpmTransactionBegin0(_engine, FWPM_TXN_WRITE);
                        if (txnRc == 0)
                        {
                            bool ok = true;
                            List<ulong> nextBase = _baseFilterIds;
                            List<ulong> nextTun = _tunPermitFilterIds;
                            List<ulong> nextProxy = _proxyBlockFilterIds;

                            if (needBase)
                            {
                                List<ulong> addedBase = new List<ulong>();
                                ok = InstallBaseFiltersLocked(targetIds, blockNonTunDns, mihomoIds, addedBase);
                                if (ok)
                                {
                                    DeleteFilterIdsLocked(_baseFilterIds);
                                    nextBase = addedBase;
                                }
                            }

                            if (ok && needTun)
                            {
                                List<ulong> addedTun = new List<ulong>();
                                if (shouldPermitTun)
                                {
                                    ok = InstallTunPermitFiltersLocked(targetIds, blockNonTunDns, tunLuid, addedTun);
                                }
                                if (ok)
                                {
                                    DeleteFilterIdsLocked(_tunPermitFilterIds);
                                    nextTun = addedTun;
                                }
                            }

                            if (ok && needProxy)
                            {
                                List<ulong> addedProxy = new List<ulong>();
                                if (shouldBlockLocalProxy)
                                {
                                    ok = InstallLocalProxyBlockFiltersLocked(targetIds, safeProxyPorts, addedProxy);
                                }
                                if (ok)
                                {
                                    DeleteFilterIdsLocked(_proxyBlockFilterIds);
                                    nextProxy = addedProxy;
                                }
                            }

                            if (ok && FwpmTransactionCommit0(_engine) == 0)
                            {
                                _baseFilterIds = nextBase;
                                _tunPermitFilterIds = nextTun;
                                _proxyBlockFilterIds = nextProxy;
                                _lastBaseSig = baseSig;
                                _lastTunSig = tunSig;
                                _lastProxyBlockSig = proxySig;
                            }
                            else
                            {
                                FwpmTransactionAbort0(_engine);
                            }
                        }
                    }
                    finally
                    {
                        DisposeIdentities(targetIds);
                        DisposeIdentities(mihomoIds);
                    }
                }

                int totalFilters = _baseFilterIds.Count + _tunPermitFilterIds.Count + _proxyBlockFilterIds.Count;
                string targetDesc = BuildTargetCountDesc(safeExes.Count, safePkgs.Count, blockNonTunDns);
                string statusText = shouldPermitTun
                    ? ("已启用 · 仅放行 TUN (" + targetDesc + ")")
                    : ("已阻断非本地出站 (" + targetDesc + ")");

                _snapshot = new WfpStateSnapshot
                {
                    Enabled = true,
                    Active = true,
                    Degraded = false,
                    BlockingNow = !shouldPermitTun,
                    DnsGuardActive = blockNonTunDns,
                    ExeTargetCount = safeExes.Count,
                    PackageTargetCount = safePkgs.Count,
                    ActiveFilterCount = totalFilters,
                    StatusText = statusText
                };
                return _snapshot;
            }
        }

        private static string BuildTargetCountDesc(int exeCount, int pkgCount, bool dnsGuard)
        {
            List<string> parts = new List<string>(3);
            if (exeCount > 0) parts.Add(exeCount + "程序");
            if (pkgCount > 0) parts.Add(pkgCount + "MSIX");
            if (dnsGuard) parts.Add("DNS53");
            return parts.Count > 0 ? string.Join("+", parts.ToArray()) : "0目标";
        }

        private void ClearAllFiltersLocked()
        {
            if (_baseFilterIds.Count == 0 && _tunPermitFilterIds.Count == 0 && _proxyBlockFilterIds.Count == 0)
            {
                _lastBaseSig = string.Empty;
                _lastTunSig = string.Empty;
                _lastProxyBlockSig = string.Empty;
                return;
            }

            if (_engine == IntPtr.Zero)
            {
                return;
            }

            if (FwpmTransactionBegin0(_engine, FWPM_TXN_WRITE) != 0)
            {
                return;
            }

            DeleteFilterIdsLocked(_baseFilterIds);
            DeleteFilterIdsLocked(_tunPermitFilterIds);
            DeleteFilterIdsLocked(_proxyBlockFilterIds);

            if (FwpmTransactionCommit0(_engine) == 0)
            {
                _baseFilterIds.Clear();
                _tunPermitFilterIds.Clear();
                _proxyBlockFilterIds.Clear();
                _lastBaseSig = string.Empty;
                _lastTunSig = string.Empty;
                _lastProxyBlockSig = string.Empty;
            }
            else
            {
                FwpmTransactionAbort0(_engine);
            }
        }

        private bool InstallBaseFiltersLocked(
            List<ResolvedIdentity> targets,
            bool blockNonTunDns,
            List<ResolvedIdentity> mihomoIds,
            List<ulong> outIds)
        {
            for (int i = 0; i < targets.Count; i++)
            {
                ResolvedIdentity id = targets[i];
                FWPM_FILTER_CONDITION0 idCond = MakeIdentityCondition(id);
                FWPM_FILTER_CONDITION0 loopbackCond = MakeLoopbackCondition();

                // Weight 12: PERMIT Loopback (V4 + V6)
                if (!AddFilterPairV4V6Locked(FWP_ACTION_PERMIT, WEIGHT_ALLOW_LOOPBACK, new FWPM_FILTER_CONDITION0[] { idCond, loopbackCond }, outIds))
                {
                    return false;
                }

                // Weight 1: BLOCK All interfaces fallback (V4 + V6)
                if (!AddFilterPairV4V6Locked(FWP_ACTION_BLOCK, WEIGHT_BLOCK_ALL, new FWPM_FILTER_CONDITION0[] { idCond }, outIds))
                {
                    return false;
                }
            }

            if (blockNonTunDns)
            {
                FWPM_FILTER_CONDITION0 dnsPortCond = MakeRemotePortCondition(DNS_PORT);
                FWPM_FILTER_CONDITION0 loopbackCond = MakeLoopbackCondition();

                // Weight 12: PERMIT Loopback DNS 53 (V4 + V6)
                if (!AddFilterPairV4V6Locked(FWP_ACTION_PERMIT, WEIGHT_ALLOW_LOOPBACK, new FWPM_FILTER_CONDITION0[] { dnsPortCond, loopbackCond }, outIds))
                {
                    return false;
                }

                // Weight 11: PERMIT Mihomo core DNS 53 (V4 + V6)
                if (mihomoIds != null)
                {
                    for (int i = 0; i < mihomoIds.Count; i++)
                    {
                        FWPM_FILTER_CONDITION0 mihomoCond = MakeIdentityCondition(mihomoIds[i]);
                        if (!AddFilterPairV4V6Locked(FWP_ACTION_PERMIT, WEIGHT_ALLOW_MIHOMO_DNS, new FWPM_FILTER_CONDITION0[] { mihomoCond, dnsPortCond }, outIds))
                        {
                            return false;
                        }
                    }
                }

                // Weight 1: BLOCK all non-TUN DNS 53 (V4 + V6)
                if (!AddFilterPairV4V6Locked(FWP_ACTION_BLOCK, WEIGHT_BLOCK_ALL, new FWPM_FILTER_CONDITION0[] { dnsPortCond }, outIds))
                {
                    return false;
                }
            }

            return true;
        }

        private bool InstallTunPermitFiltersLocked(
            List<ResolvedIdentity> targets,
            bool blockNonTunDns,
            ulong tunLuid,
            List<ulong> outIds)
        {
            IntPtr pLuid = Marshal.AllocHGlobal(sizeof(ulong));
            try
            {
                Marshal.WriteInt64(pLuid, unchecked((long)tunLuid));
                FWPM_FILTER_CONDITION0 tunCond = MakeLocalInterfaceCondition(pLuid);

                for (int i = 0; i < targets.Count; i++)
                {
                    FWPM_FILTER_CONDITION0 idCond = MakeIdentityCondition(targets[i]);
                    // Weight 10: PERMIT TUN interface (V4 + V6)
                    if (!AddFilterPairV4V6Locked(FWP_ACTION_PERMIT, WEIGHT_ALLOW_TUN, new FWPM_FILTER_CONDITION0[] { idCond, tunCond }, outIds))
                    {
                        return false;
                    }
                }

                if (blockNonTunDns)
                {
                    FWPM_FILTER_CONDITION0 dnsPortCond = MakeRemotePortCondition(DNS_PORT);
                    if (!AddFilterPairV4V6Locked(FWP_ACTION_PERMIT, WEIGHT_ALLOW_TUN, new FWPM_FILTER_CONDITION0[] { dnsPortCond, tunCond }, outIds))
                    {
                        return false;
                    }
                }

                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(pLuid);
            }
        }

        private bool InstallLocalProxyBlockFiltersLocked(
            List<ResolvedIdentity> targets,
            List<ushort> proxyPorts,
            List<ulong> outIds)
        {
            FWPM_FILTER_CONDITION0 loopbackCond = MakeLoopbackCondition();
            for (int p = 0; p < proxyPorts.Count; p++)
            {
                FWPM_FILTER_CONDITION0 portCond = MakeRemotePortCondition(proxyPorts[p]);
                for (int i = 0; i < targets.Count; i++)
                {
                    FWPM_FILTER_CONDITION0 idCond = MakeIdentityCondition(targets[i]);
                    // Weight 14 (> Loopback 12): BLOCK local Clash proxy port while unsafe
                    if (!AddFilterPairV4V6Locked(
                        FWP_ACTION_BLOCK,
                        WEIGHT_BLOCK_LOCAL_PROXY,
                        new FWPM_FILTER_CONDITION0[] { idCond, loopbackCond, portCond },
                        outIds))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        private bool AddFilterPairV4V6Locked(uint actionType, byte weight, FWPM_FILTER_CONDITION0[] conditions, List<ulong> outIds)
        {
            ulong idV4;
            if (!AddSingleFilterLocked(FWPM_LAYER_ALE_AUTH_CONNECT_V4, actionType, weight, conditions, out idV4))
            {
                return false;
            }
            outIds.Add(idV4);

            ulong idV6;
            if (!AddSingleFilterLocked(FWPM_LAYER_ALE_AUTH_CONNECT_V6, actionType, weight, conditions, out idV6))
            {
                return false;
            }
            outIds.Add(idV6);
            return true;
        }

        private bool AddSingleFilterLocked(
            Guid layerKey,
            uint actionType,
            byte weight,
            FWPM_FILTER_CONDITION0[] conditions,
            out ulong filterId)
        {
            filterId = 0;
            int condCount = conditions != null ? conditions.Length : 0;
            int condSize = Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0));
            IntPtr condPtr = IntPtr.Zero;

            try
            {
                if (condCount > 0)
                {
                    condPtr = Marshal.AllocHGlobal(condCount * condSize);
                    for (int i = 0; i < condCount; i++)
                    {
                        IntPtr dst = IntPtr.Add(condPtr, i * condSize);
                        Marshal.StructureToPtr(conditions[i], dst, false);
                    }
                }

                FWPM_FILTER0 filter = new FWPM_FILTER0();
                filter.filterKey = Guid.NewGuid();
                filter.displayData.name = _displayNamePtr;
                filter.displayData.description = _displayDescPtr;
                filter.flags = 0;
                filter.providerKey = _providerKeyPtr;
                filter.layerKey = layerKey;
                filter.subLayerKey = SubLayerKey;
                filter.weight.type = FWP_DATA_TYPE.FWP_UINT8;
                filter.weight.uint8 = weight;
                filter.numFilterConditions = (uint)condCount;
                filter.filterCondition = condPtr;
                filter.action.type = actionType;
                filter.action.filterType = Guid.Empty;

                uint rc = FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out filterId);
                return rc == 0;
            }
            finally
            {
                if (condPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(condPtr);
                }
            }
        }

        private void DeleteFilterIdsLocked(List<ulong> ids)
        {
            if (ids == null || ids.Count == 0)
            {
                return;
            }
            for (int i = 0; i < ids.Count; i++)
            {
                FwpmFilterDeleteById0(_engine, ids[i]);
            }
        }

        private static FWPM_FILTER_CONDITION0 MakeIdentityCondition(ResolvedIdentity id)
        {
            FWPM_FILTER_CONDITION0 c = new FWPM_FILTER_CONDITION0();
            c.matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
            if (id.IsPackage)
            {
                c.fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
                c.conditionValue.type = FWP_DATA_TYPE.FWP_SID;
                c.conditionValue.sid = id.Handle;
            }
            else
            {
                c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                c.conditionValue.type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE;
                c.conditionValue.byteBlob = id.Handle;
            }
            return c;
        }

        private static FWPM_FILTER_CONDITION0 MakeLoopbackCondition()
        {
            FWPM_FILTER_CONDITION0 c = new FWPM_FILTER_CONDITION0();
            c.fieldKey = FWPM_CONDITION_FLAGS;
            c.matchType = FWP_MATCH_TYPE.FWP_MATCH_FLAGS_ALL_SET;
            c.conditionValue.type = FWP_DATA_TYPE.FWP_UINT32;
            c.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
            return c;
        }

        private static FWPM_FILTER_CONDITION0 MakeLocalInterfaceCondition(IntPtr luidPtr)
        {
            FWPM_FILTER_CONDITION0 c = new FWPM_FILTER_CONDITION0();
            c.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
            c.matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
            c.conditionValue.type = FWP_DATA_TYPE.FWP_UINT64;
            c.conditionValue.uint64Ptr = luidPtr;
            return c;
        }

        private static FWPM_FILTER_CONDITION0 MakeRemotePortCondition(ushort port)
        {
            FWPM_FILTER_CONDITION0 c = new FWPM_FILTER_CONDITION0();
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            c.matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
            c.conditionValue.type = FWP_DATA_TYPE.FWP_UINT16;
            c.conditionValue.uint16 = port;
            return c;
        }

        private static List<ResolvedIdentity> ResolveTargetIdentities(List<string> exePaths, List<string> packageFamilies)
        {
            List<ResolvedIdentity> list = ResolveExeIdentities(exePaths);
            if (packageFamilies != null)
            {
                for (int i = 0; i < packageFamilies.Count; i++)
                {
                    string pfn = packageFamilies[i];
                    if (string.IsNullOrEmpty(pfn)) continue;
                    IntPtr sid;
                    if (DeriveAppContainerSidFromAppContainerName(pfn, out sid) == 0 && sid != IntPtr.Zero)
                    {
                        list.Add(new ResolvedIdentity { IsPackage = true, Handle = sid });
                    }
                }
            }
            return list;
        }

        private static List<ResolvedIdentity> ResolveExeIdentities(List<string> exePaths)
        {
            List<ResolvedIdentity> list = new List<ResolvedIdentity>();
            if (exePaths == null)
            {
                return list;
            }
            for (int i = 0; i < exePaths.Count; i++)
            {
                string path = exePaths[i];
                if (string.IsNullOrEmpty(path)) continue;
                IntPtr appId;
                if (FwpmGetAppIdFromFileName0(path, out appId) == 0 && appId != IntPtr.Zero)
                {
                    list.Add(new ResolvedIdentity { IsPackage = false, Handle = appId });
                }
            }
            return list;
        }

        private static void DisposeIdentities(List<ResolvedIdentity> list)
        {
            if (list == null) return;
            for (int i = 0; i < list.Count; i++)
            {
                if (list[i] != null)
                {
                    list[i].Dispose();
                }
            }
        }

        private static string BuildSignature(
            string prefix,
            List<string> exes,
            List<string> pkgs,
            bool flagA,
            List<string> extraPaths,
            List<ushort> ports,
            ulong luid,
            bool flagB)
        {
            StringBuilder sb = new StringBuilder(256);
            sb.Append(prefix).Append('|').Append(flagA ? '1' : '0').Append('|').Append(flagB ? '1' : '0').Append('|').Append(luid);
            sb.Append("|E:");
            if (exes != null)
            {
                for (int i = 0; i < exes.Count; i++) sb.Append(exes[i]).Append(';');
            }
            sb.Append("|P:");
            if (pkgs != null)
            {
                for (int i = 0; i < pkgs.Count; i++) sb.Append(pkgs[i]).Append(';');
            }
            if (extraPaths != null)
            {
                sb.Append("|M:");
                for (int i = 0; i < extraPaths.Count; i++) sb.Append(extraPaths[i]).Append(';');
            }
            if (ports != null)
            {
                sb.Append("|R:");
                for (int i = 0; i < ports.Count; i++) sb.Append(ports[i]).Append(',');
            }
            return sb.ToString();
        }

        private void FreeStaticNativeBuffersLocked()
        {
            if (_providerKeyPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_providerKeyPtr);
                _providerKeyPtr = IntPtr.Zero;
            }
            if (_displayNamePtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_displayNamePtr);
                _displayNamePtr = IntPtr.Zero;
            }
            if (_displayDescPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_displayDescPtr);
                _displayDescPtr = IntPtr.Zero;
            }
        }

        public void Dispose()
        {
            lock (_lock)
            {
                if (_disposed)
                {
                    return;
                }
                _disposed = true;
                _available = false;
                if (_engine != IntPtr.Zero)
                {
                    // Closing a DYNAMIC session automatically deletes all filters, sublayer and provider
                    FwpmEngineClose0(_engine);
                    _engine = IntPtr.Zero;
                }
                _baseFilterIds.Clear();
                _tunPermitFilterIds.Clear();
                _proxyBlockFilterIds.Clear();
                FreeStaticNativeBuffersLocked();
            }
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
        private const int IF_ROW_LUID_OFFSET = 0;
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

        private const int ACTIVE_INTERVAL_MS = 250;
        private const int INACTIVE_GUARD_INTERVAL_MS = 30;
        private const int INACTIVE_WFP_WATCH_INTERVAL_MS = 100;
        private const int PAUSED_INTERVAL_MS = 1000;
        private const int CONFIG_STAT_INTERVAL_MS = 1000;
        private const int INACTIVE_ADAPTER_POLL_MS = 500;
        private const int NODE_CHECK_INTERVAL_ACTIVE_MS = 250;
        private const int NODE_CHECK_INTERVAL_INACTIVE_MS = 300;
        private const int INACTIVE_FULL_KILL_SCAN_MS = 3000;
        private const int WATCHER_RETRY_INTERVAL_MS = 5000;
        private const int PATH_DISCOVERY_INTERVAL_MS = 2000;
        private const int STATIC_APP_RESCAN_INTERVAL_MS = 300000;
        private const int CACHE_PERSIST_INTERVAL_MS = 10000;

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
        private readonly string _baseClashYamlPath;
        private readonly string _nodeConfigPath;
        private readonly MihomoClient _mihomoClient = new MihomoClient();

        // Keep delegates rooted so GC never collects native callbacks
        private readonly IpInterfaceChangeCallback _ifaceCallback;
        private readonly IpForwardChangeCallback _routeCallback;
        private IntPtr _ifaceNotifyHandle = IntPtr.Zero;
        private IntPtr _routeNotifyHandle = IntPtr.Zero;
        private FileSystemWatcher _watcher;

        // Single-threaded monitor/killer resources owned by Start() -> _watchdogThread
        private readonly TargetProcessKiller _killer = new TargetProcessKiller();
        private readonly GuardedAppPathResolver _pathResolver = new GuardedAppPathResolver();
        private readonly WfpKillSwitch _wfp = new WfpKillSwitch();
        private IntPtr _ifRowBuffer;

        // Lightweight signal state between callbacks and _watchdogThread (held for nanoseconds)
        private readonly object _signalLock = new object();
        private bool _pendingVergeReload;
        private bool _pendingClashReload;
        private bool _pendingBaseClashReload;
        private bool _pendingAdapterRecheck;
        private bool _pendingNodeRecheck;
        private bool _pendingRulesRefresh;
        private bool _pendingNodeConfigReload;
        private bool _pendingFullProcessScan;
        private bool _pendingPathDiscover;
        private bool _watcherNeedsRestart;
        private string _pendingTriggerSource;

        // Cached parsed config values & file metadata (owned by _watchdogThread after Start())
        private bool? _vergeEnableTun;
        private bool _clashAutoRoute = true;
        private string _customTunDevice;
        private string _clashExternalController;
        private string _clashExternalPipe;
        private string _clashSecret;
        private ushort _clashMixedPort;
        private ushort _clashHttpPort;
        private ushort _clashSocksPort;
        private string _baseExternalController;
        private string _baseExternalPipe;
        private string _baseSecret;
        private ushort _baseMixedPort;
        private ushort _baseHttpPort;
        private ushort _baseSocksPort;
        private readonly List<ushort> _clashLocalProxyPorts = new List<ushort>(3);
        private bool _vergeStatValid;
        private bool _vergeLastExists;
        private long _vergeLastWriteTicks;
        private long _vergeLastLength;
        private bool _clashStatValid;
        private bool _clashLastExists;
        private long _clashLastWriteTicks;
        private long _clashLastLength;
        private bool _baseClashStatValid;
        private bool _baseClashLastExists;
        private long _baseClashLastWriteTicks;
        private long _baseClashLastLength;
        private bool _nodeConfigStatValid;
        private bool _nodeConfigLastExists;
        private long _nodeConfigLastWriteTicks;
        private long _nodeConfigLastLength;

        private volatile NodeGuardConfig _nodeConfig;
        private NodeEvaluationResult _lastNodeEval;
        private bool _hasNodeEval;
        private string _cachedTunOkAlias;
        private string _cachedTunOkReason;

        private readonly object _statusLock = new object();
        private TunStatus _currentStatus;
        private volatile bool _running;
        private volatile bool _disposed;
        private volatile bool _monitoringEnabled = true;
        private volatile bool _isTunActive;
        private volatile bool _isGuardSafe;
        private volatile uint _lastKnownTunIfIndex;

        private Thread _watchdogThread;
        private readonly ManualResetEvent _stopEvent = new ManualResetEvent(false);
        private readonly AutoResetEvent _wakeEvent = new AutoResetEvent(false);
        private long _lastAccessDeniedLogTicks;
        private static readonly long AccessDeniedLogCooldownTicks = TimeSpan.FromSeconds(10).Ticks;

        public event Action<TunStatus> StatusChanged;
        public event Action<KillResult, string, TunStatus> ProcessesKilled;
        public event Action<GuardedAppFlags, string, TunStatus> WfpBlocked;
        public event Action<GuardedAppFlags, TunStatus> GuardedAppLaunchedWhileBlocked;
        public event Action<int, GuardedAppFlags, string> AccessDenied;
        public event Action<NodeGuardConfig> NodeConfigChanged;

        public NodeGuardConfig CurrentNodeConfig
        {
            get { return _nodeConfig; }
        }

        public string NodeConfigPath
        {
            get { return _nodeConfigPath; }
        }

        public bool MonitoringEnabled
        {
            get { return _monitoringEnabled; }
            set
            {
                bool changed = (_monitoringEnabled != value);
                _monitoringEnabled = value;
                if (changed)
                {
                    AppLogger.Info("APP", value ? "已恢复实时监控" : "已暂停实时监控（WFP 内核规则将自动清空）");
                }
                if (value)
                {
                    SignalWake("恢复监控", true, true, true, true, true, true, true, false);
                }
                else
                {
                    // Wake watchdog so it can immediately switch to low-frequency paused cadence
                    SignalWake(null, false, false, false, false, false, false, false, false);
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
            _baseClashYamlPath = Path.Combine(_configDir, "config.yaml");
            _nodeConfigPath = NodeGuardConfigStore.GetConfigPath();
            _nodeConfig = NodeGuardConfigStore.LoadOrDefault(_nodeConfigPath);

            _ifaceCallback = OnIpInterfaceChanged;
            _routeCallback = OnRouteChanged;
            _ifRowBuffer = Marshal.AllocHGlobal(IF_ROW_SIZE);
        }

        public void ApplyNodeGuardConfig(NodeGuardConfig config)
        {
            NodeGuardConfig normalized = (config != null ? config : new NodeGuardConfig()).CloneNormalized();
            _pathResolver.ApplyCustomPathsFromConfig(normalized);
            _pathResolver.MergeIntoConfig(normalized, false);
            _nodeConfig = normalized;
            AppLogger.ConfigureDirectoryQuiet(normalized.LogDirectory);
            AppLogger.Info("CONFIG", FormatConfigSummary(normalized));
            _mihomoClient.InvalidateRulesCache();
            lock (_signalLock)
            {
                _pendingPathDiscover = true;
            }
            SignalWake("守护配置更新", false, false, false, false, true, true, true, true);
        }

        public AppPathDiagnostics GetAppPathDiagnostics(bool rescanNow)
        {
            bool discoveredAnyNew = false;
            if (rescanNow)
            {
                _pathResolver.ScanStaticInstallations();
            }

            GuardedAppFlags runningApps = TargetProcessKiller.ScanRunningProcessesSnapshot(
                _pathResolver.GetMatchRules(),
                path =>
                {
                    if (_pathResolver.RecordRunningImagePath(path))
                    {
                        discoveredAnyNew = true;
                        AppLogger.Info("WFP", "自动检测发现受控应用路径: " + path);
                    }
                });

            if (rescanNow || discoveredAnyNew)
            {
                lock (_signalLock)
                {
                    _pendingPathDiscover = true;
                }
                SignalWake("控制面板自动检测受控应用", false, false, false, false, false, false, false, false);
            }

            AppPathDiagnostics diag = _pathResolver.GetDiagnostics();
            diag.RunningApps = runningApps;
            return diag;
        }

        public ClashSnapshot QueryLiveClashSnapshot()
        {
            return _mihomoClient.QuerySnapshot(true, true);
        }

        public ClashCatalogData QueryClashCatalog()
        {
            ClashSnapshot live = _mihomoClient.QuerySnapshot(true, true);
            return ClashProfileCatalog.LoadAll(_configDir, live);
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
            ReadBaseClashYamlSafe(true);
            SyncMihomoConnectionConfig();
            ReadNodeGuardConfigSafe(true);

            AppLogger.Initialize(_nodeConfig != null ? _nodeConfig.LogDirectory : string.Empty);
            AppLogger.Info("APP", "TunGuard 启动 | 配置: " + FormatConfigSummary(_nodeConfig) + " | 日志目录: " + AppLogger.EffectiveLogDirectory);

            // Prepare WFP engine and pre-discovered app paths BEFORE first evaluation
            _pathResolver.LoadFromConfigCache(_nodeConfig);
            _pathResolver.ScanStaticInstallations();
            _killer.SetMatchRules(_pathResolver.GetMatchRules());
            _killer.DiscoverNewProcessPaths(true, path => _pathResolver.RecordRunningImagePath(path));
            _killer.SetMatchRules(_pathResolver.GetMatchRules());
            if (_nodeConfig != null && _nodeConfig.WfpEnabled)
            {
                string wfpInitErr;
                if (_wfp.TryInitialize(out wfpInitErr))
                {
                    AppLogger.Info("WFP", "WFP 内核过滤引擎初始化成功 (DYNAMIC 动态会话)");
                }
                else
                {
                    AppLogger.Warn("WFP", "WFP 初始化降级: " + (string.IsNullOrEmpty(wfpInitErr) ? "未知原因" : wfpInitErr));
                }
            }

            bool unusedFullScan;
            EvaluateAndEnforce("初始检查", true, true, true, true, true, out unusedFullScan);

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
                _pendingBaseClashReload = true;
                _pendingAdapterRecheck = true;
                _pendingNodeRecheck = true;
                _pendingRulesRefresh = true;
            }
            TrySetWakeEvent();
        }

        private static bool IsRelevantConfigFile(string name)
        {
            return string.Equals(name, "verge.yaml", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "clash-verge.yaml", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "config.yaml", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(name, "profiles.yaml", StringComparison.OrdinalIgnoreCase);
        }

        private void SignalConfigFileChange(string fileName)
        {
            if (string.Equals(fileName, "verge.yaml", StringComparison.OrdinalIgnoreCase))
            {
                SignalWake("配置变更: verge.yaml", true, false, false, true, false, false, false, false);
            }
            else if (string.Equals(fileName, "clash-verge.yaml", StringComparison.OrdinalIgnoreCase))
            {
                SignalWake("配置变更: clash-verge.yaml", false, true, false, true, true, true, false, false);
            }
            else if (string.Equals(fileName, "config.yaml", StringComparison.OrdinalIgnoreCase))
            {
                SignalWake("配置变更: config.yaml", false, false, true, false, true, false, false, false);
            }
            else if (string.Equals(fileName, "profiles.yaml", StringComparison.OrdinalIgnoreCase))
            {
                SignalWake("节点配置变更: profiles.yaml", false, false, false, false, true, true, false, false);
            }
        }

        private void OnIpInterfaceChanged(IntPtr callerContext, IntPtr row, int notificationType)
        {
            if (!_running)
            {
                return;
            }
            // Never call IP Helper APIs or block inside NSI notification callbacks; wake watchdog instead.
            SignalWake("网卡状态变更", false, false, false, true, false, false, false, false);
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

            SignalWake("路由表变更", false, false, false, true, false, false, false, false);
        }

        private void SignalWake(
            string triggerSource,
            bool reloadVerge,
            bool reloadClash,
            bool reloadBaseClash,
            bool recheckAdapter,
            bool recheckNode,
            bool refreshRules,
            bool fullProcessScan,
            bool reloadNodeConfig)
        {
            if (!_running)
            {
                return;
            }

            lock (_signalLock)
            {
                if (reloadVerge) _pendingVergeReload = true;
                if (reloadClash) _pendingClashReload = true;
                if (reloadBaseClash) _pendingBaseClashReload = true;
                if (recheckAdapter) _pendingAdapterRecheck = true;
                if (recheckNode) _pendingNodeRecheck = true;
                if (refreshRules) _pendingRulesRefresh = true;
                if (fullProcessScan) _pendingFullProcessScan = true;
                if (reloadNodeConfig) _pendingNodeConfigReload = true;
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
            long lastNodeCheckMs = 0;
            long lastFullScanMs = 0;
            long lastWatcherRetryMs = 0;
            long lastPathDiscoverMs = 0;
            long lastStaticRescanMs = 0;
            long lastCachePersistMs = 0;
            long followUpRulesRefreshAtMs = 0;

            while (_running)
            {
                bool monitoring = _monitoringEnabled;
                bool safe = _isGuardSafe;
                bool tunActive = _isTunActive;
                NodeGuardConfig loopCfg = _nodeConfig;
                bool hasActiveTargets = loopCfg != null && loopCfg.GetGuardedAppFlags() != GuardedAppFlags.None;
                bool needsFastKillGuard = !safe && hasActiveTargets &&
                                          (loopCfg == null || !loopCfg.WfpEnabled || loopCfg.WfpKillOnBlock || !_wfp.IsActive);
                bool needsWfpLaunchWatch = !safe && hasActiveTargets && !needsFastKillGuard;
                int intervalMs = !monitoring
                    ? PAUSED_INTERVAL_MS
                    : (needsFastKillGuard
                        ? INACTIVE_GUARD_INTERVAL_MS
                        : (needsWfpLaunchWatch ? INACTIVE_WFP_WATCH_INTERVAL_MS : ACTIVE_INTERVAL_MS));

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
                bool reloadBaseClash;
                bool recheckAdapter;
                bool recheckNode;
                bool refreshRules;
                bool reloadNodeConfig;
                bool forceFullScan;
                bool forcePathDiscover;
                bool restartWatcher;
                string triggerSource;

                lock (_signalLock)
                {
                    reloadVerge = _pendingVergeReload;
                    reloadClash = _pendingClashReload;
                    reloadBaseClash = _pendingBaseClashReload;
                    recheckAdapter = _pendingAdapterRecheck;
                    recheckNode = _pendingNodeRecheck;
                    refreshRules = _pendingRulesRefresh;
                    reloadNodeConfig = _pendingNodeConfigReload;
                    forceFullScan = _pendingFullProcessScan;
                    forcePathDiscover = _pendingPathDiscover;
                    restartWatcher = _watcherNeedsRestart;
                    triggerSource = _pendingTriggerSource;

                    _pendingVergeReload = false;
                    _pendingClashReload = false;
                    _pendingBaseClashReload = false;
                    _pendingAdapterRecheck = false;
                    _pendingNodeRecheck = false;
                    _pendingRulesRefresh = false;
                    _pendingNodeConfigReload = false;
                    _pendingFullProcessScan = false;
                    _pendingPathDiscover = false;
                    _watcherNeedsRestart = false;
                    _pendingTriggerSource = null;
                }

                if (restartWatcher || (_watcher == null && (nowMs - lastWatcherRetryMs >= WATCHER_RETRY_INTERVAL_MS)))
                {
                    lastWatcherRetryMs = nowMs;
                    EnsureConfigWatcher();
                }

                bool clashConnChanged = false;
                if (reloadVerge)
                {
                    ReadVergeYamlSafe(true);
                    lastConfigStatMs = nowMs;
                }
                if (reloadClash)
                {
                    if (ReadClashYamlSafe(true))
                    {
                        clashConnChanged = true;
                    }
                    lastConfigStatMs = nowMs;
                }
                if (reloadBaseClash)
                {
                    if (ReadBaseClashYamlSafe(true))
                    {
                        clashConnChanged = true;
                    }
                    lastConfigStatMs = nowMs;
                }
                if (reloadNodeConfig)
                {
                    RefreshNodeConfigStatAfterSave();
                    _pathResolver.LoadFromConfigCache(_nodeConfig);
                    _killer.SetMatchRules(_pathResolver.GetMatchRules());
                    recheckNode = true;
                    refreshRules = true;
                }

                if (!reloadVerge && !reloadClash && !reloadBaseClash && (nowMs - lastConfigStatMs >= CONFIG_STAT_INTERVAL_MS))
                {
                    lastConfigStatMs = nowMs;
                    bool vergeChanged = ReadVergeYamlSafe(false);
                    bool clashChanged = ReadClashYamlSafe(false);
                    bool baseChanged = ReadBaseClashYamlSafe(false);
                    bool nodeCfgChanged = ReadNodeGuardConfigSafe(false);
                    if (vergeChanged || clashChanged)
                    {
                        recheckAdapter = true;
                    }
                    if (clashChanged || baseChanged)
                    {
                        clashConnChanged = true;
                        recheckNode = true;
                        refreshRules = true;
                    }
                    if (nodeCfgChanged)
                    {
                        _pathResolver.LoadFromConfigCache(_nodeConfig);
                        _killer.SetMatchRules(_pathResolver.GetMatchRules());
                        recheckNode = true;
                        refreshRules = true;
                        forceFullScan = true;
                        forcePathDiscover = true;
                        if (string.IsNullOrEmpty(triggerSource))
                        {
                            triggerSource = "配置文件热更新";
                        }
                    }
                }

                if (clashConnChanged)
                {
                    SyncMihomoConnectionConfig();
                }

                NodeGuardConfig nodeCfg = _nodeConfig;
                if (monitoring)
                {
                    bool needDiscover = forcePathDiscover || (nowMs - lastPathDiscoverMs >= PATH_DISCOVERY_INTERVAL_MS);
                    if (needDiscover)
                    {
                        lastPathDiscoverMs = nowMs;
                        _killer.DiscoverNewProcessPaths(forcePathDiscover, path =>
                        {
                            if (_pathResolver.RecordRunningImagePath(path))
                            {
                                AppLogger.Info("WFP", "热发现受控应用路径: " + path);
                            }
                        });
                        _killer.SetMatchRules(_pathResolver.GetMatchRules());
                    }
                    if (nowMs - lastStaticRescanMs >= STATIC_APP_RESCAN_INTERVAL_MS)
                    {
                        lastStaticRescanMs = nowMs;
                        _pathResolver.ScanStaticInstallations();
                        _killer.SetMatchRules(_pathResolver.GetMatchRules());
                    }
                    if (_pathResolver.HasDirtyCache && (nowMs - lastCachePersistMs >= CACHE_PERSIST_INTERVAL_MS))
                    {
                        lastCachePersistMs = nowMs;
                        PersistDiscoveredPathCacheSafe();
                    }
                }

                if (refreshRules)
                {
                    followUpRulesRefreshAtMs = nowMs + 800;
                }
                else if (monitoring && followUpRulesRefreshAtMs > 0 && nowMs >= followUpRulesRefreshAtMs)
                {
                    followUpRulesRefreshAtMs = 0;
                    refreshRules = true;
                    recheckNode = true;
                }

                int adapterPollInterval = !monitoring
                    ? PAUSED_INTERVAL_MS
                    : (tunActive ? ACTIVE_INTERVAL_MS : INACTIVE_ADAPTER_POLL_MS);
                bool shouldCheckAdapter =
                    recheckAdapter ||
                    (nowMs - lastAdapterCheckMs >= adapterPollInterval);

                bool nodeGuardEnabled = nodeCfg != null && nodeCfg.Enabled;
                int nodePollInterval = safe ? NODE_CHECK_INTERVAL_ACTIVE_MS : NODE_CHECK_INTERVAL_INACTIVE_MS;
                bool shouldCheckNode =
                    monitoring &&
                    nodeGuardEnabled &&
                    (recheckNode || !_hasNodeEval || (nowMs - lastNodeCheckMs >= nodePollInterval));

                bool shouldFullScan =
                    forceFullScan ||
                    (monitoring && !safe && (nowMs - lastFullScanMs >= INACTIVE_FULL_KILL_SCAN_MS));

                if (shouldCheckAdapter)
                {
                    lastAdapterCheckMs = nowMs;
                }
                if (shouldCheckNode)
                {
                    lastNodeCheckMs = nowMs;
                }

                string source = !string.IsNullOrEmpty(triggerSource)
                    ? triggerSource
                    : (shouldCheckNode && !shouldCheckAdapter ? "节点状态巡检" : "定时巡检");
                bool ranFullScan;
                EvaluateAndEnforce(source, false, shouldCheckAdapter, shouldCheckNode, refreshRules, shouldFullScan, out ranFullScan);
                if (ranFullScan)
                {
                    lastFullScanMs = nowMs;
                }
            }
        }

        private void PersistDiscoveredPathCacheSafe()
        {
            NodeGuardConfig current = _nodeConfig;
            if (current == null)
            {
                return;
            }
            NodeGuardConfig next = current.CloneNormalized();
            if (!_pathResolver.MergeIntoConfig(next, true))
            {
                return;
            }
            try
            {
                NodeGuardConfigStore.Save(_nodeConfigPath, next);
                _nodeConfig = next;
                RefreshNodeConfigStatAfterSave();
            }
            catch
            {
                // Ignore transient disk write failures
            }
        }

        private void EvaluateAndEnforce(
            string triggerSource,
            bool forceNotify,
            bool checkAdapter,
            bool checkNode,
            bool refreshRules,
            bool fullProcessScan,
            out bool ranFullScan)
        {
            ranFullScan = false;
            TunStatus prev = _currentStatus;
            bool wasSafe = _isGuardSafe;
            NodeGuardConfig nodeCfg = _nodeConfig ?? new NodeGuardConfig();

            TunStatus next = QueryTunStatus(checkAdapter, prev);

            if (!next.AdapterUp)
            {
                _lastKnownTunIfIndex = 0;
            }
            else if (next.AdapterIndex != 0)
            {
                _lastKnownTunIfIndex = next.AdapterIndex;
            }

            next.NodeGuardEnabled = nodeCfg.Enabled;
            if (!nodeCfg.Enabled)
            {
                next.IsNodeAllowed = true;
                next.ClashMode = string.Empty;
                next.ActiveProxyGroup = string.Empty;
                next.ActiveNodeName = string.Empty;
                next.ActiveNodeChain = string.Empty;
                next.NodeReason = "未启用节点守护";
                _hasNodeEval = false;
            }
            else if (!next.IsTunActive)
            {
                // Short-circuit: TUN is already down; skip Clash API query to preserve <1ms kill speed
                next.IsNodeAllowed = false;
                next.ClashMode = prev.ClashMode ?? string.Empty;
                next.ActiveProxyGroup = prev.ActiveProxyGroup ?? string.Empty;
                next.ActiveNodeName = prev.ActiveNodeName ?? string.Empty;
                next.ActiveNodeChain = prev.ActiveNodeChain ?? string.Empty;
                next.NodeReason = "等待 TUN 启动";
                _hasNodeEval = false;
            }
            else
            {
                bool mustQueryNow = _monitoringEnabled &&
                                    (checkNode || !_hasNodeEval || !prev.IsTunActive || !prev.NodeGuardEnabled);
                NodeEvaluationResult nodeEval;
                if (mustQueryNow)
                {
                    nodeEval = _mihomoClient.EvaluateNodeFast(nodeCfg, refreshRules);
                    _lastNodeEval = nodeEval;
                    _hasNodeEval = true;
                }
                else
                {
                    nodeEval = _lastNodeEval;
                }

                next.IsNodeAllowed = nodeEval.IsAllowed;
                next.ClashMode = nodeEval.ClashMode ?? string.Empty;
                next.ActiveProxyGroup = nodeEval.TargetGroup ?? string.Empty;
                next.ActiveNodeName = nodeEval.ActiveNode ?? string.Empty;
                next.ActiveNodeChain = nodeEval.ResolutionChain ?? string.Empty;
                next.NodeReason = nodeEval.Reason ?? string.Empty;
            }

            next.IsGuardSafe = next.IsTunActive && (!next.NodeGuardEnabled || next.IsNodeAllowed);

            // Enforce WFP FIRST (kernel-level atomic commit before process sweep & UI updates)
            GuardedAppFlags guardedApps = nodeCfg.GetGuardedAppFlags();
            List<string> wfpExes;
            List<string> wfpPkgs;
            List<string> wfpMihomo;
            _pathResolver.BuildTargets(guardedApps, out wfpExes, out wfpPkgs, out wfpMihomo);
            WfpStateSnapshot wfpSnap = _wfp.SyncState(
                _monitoringEnabled,
                nodeCfg.WfpEnabled,
                next.IsGuardSafe,
                next.IsTunActive ? next.AdapterLuid : 0UL,
                wfpExes,
                wfpPkgs,
                nodeCfg.WfpBlockNonTunDns,
                wfpMihomo,
                _clashLocalProxyPorts);

            next.WfpEnabled = wfpSnap.Enabled;
            next.WfpActive = wfpSnap.Active;
            next.WfpDegraded = wfpSnap.Degraded;
            next.WfpBlockingNow = wfpSnap.BlockingNow;
            next.WfpDnsGuardActive = wfpSnap.DnsGuardActive;
            next.WfpExeTargetCount = wfpSnap.ExeTargetCount;
            next.WfpPackageTargetCount = wfpSnap.PackageTargetCount;
            next.WfpStatusText = wfpSnap.StatusText ?? string.Empty;

            // Process kill runs if WFP is disabled/degraded (fail-safe fallback) or user enabled KillOnBlock
            bool shouldKillProcesses = !nodeCfg.WfpEnabled || nodeCfg.WfpKillOnBlock || !wfpSnap.Active;
            _killer.SetMatchRules(_pathResolver.GetMatchRules());
            bool appsExpanded = _killer.SetEnabledApps(guardedApps);
            KillResult killRes = default(KillResult);
            bool notifyWfpBlockOnly = false;
            GuardedAppFlags wfpBlockedApps = GuardedAppFlags.None;
            GuardedAppFlags launchedWhileBlockedApps = GuardedAppFlags.None;
            if (_monitoringEnabled && !next.IsGuardSafe && guardedApps != GuardedAppFlags.None)
            {
                bool becameUnsafe = wasSafe && !next.IsGuardSafe;
                bool newlyDiscoveredForWfp = false;
                _killer.MatchedImagePathCallback = matchedPath =>
                {
                    if (_pathResolver.RecordRunningImagePath(matchedPath))
                    {
                        newlyDiscoveredForWfp = true;
                        AppLogger.Info("WFP", "拦截时即时发现受控应用路径: " + matchedPath);
                    }
                };
                try
                {
                    if (shouldKillProcesses)
                    {
                        _killer.ResetLaunchDetectCache();
                        if (becameUnsafe || fullProcessScan || appsExpanded)
                        {
                            killRes = _killer.KillAllNow();
                            ranFullScan = true;
                        }
                        else
                        {
                            killRes = _killer.KillNewProcesses();
                        }
                    }
                    else
                    {
                        if (becameUnsafe || forceNotify || appsExpanded)
                        {
                            wfpBlockedApps = _killer.DetectGuardedApps(true);
                            if (becameUnsafe || wfpBlockedApps != GuardedAppFlags.None)
                            {
                                notifyWfpBlockOnly = true;
                            }
                        }
                        else
                        {
                            launchedWhileBlockedApps = _killer.DetectGuardedApps(false);
                        }
                    }
                }
                finally
                {
                    _killer.MatchedImagePathCallback = null;
                }

                // Immediately commit newly discovered exe paths into WFP in the same tick (eliminates the 2s discovery window)
                if (newlyDiscoveredForWfp)
                {
                    _killer.SetMatchRules(_pathResolver.GetMatchRules());
                    if (nodeCfg.WfpEnabled)
                    {
                        _pathResolver.BuildTargets(guardedApps, out wfpExes, out wfpPkgs, out wfpMihomo);
                        wfpSnap = _wfp.SyncState(
                            _monitoringEnabled,
                            nodeCfg.WfpEnabled,
                            next.IsGuardSafe,
                            next.IsTunActive ? next.AdapterLuid : 0UL,
                            wfpExes,
                            wfpPkgs,
                            nodeCfg.WfpBlockNonTunDns,
                            wfpMihomo,
                            _clashLocalProxyPorts);
                        next.WfpEnabled = wfpSnap.Enabled;
                        next.WfpActive = wfpSnap.Active;
                        next.WfpDegraded = wfpSnap.Degraded;
                        next.WfpBlockingNow = wfpSnap.BlockingNow;
                        next.WfpDnsGuardActive = wfpSnap.DnsGuardActive;
                        next.WfpExeTargetCount = wfpSnap.ExeTargetCount;
                        next.WfpPackageTargetCount = wfpSnap.PackageTargetCount;
                        next.WfpStatusText = wfpSnap.StatusText ?? string.Empty;
                    }
                }
            }
            else if ((next.IsGuardSafe && !wasSafe) || guardedApps == GuardedAppFlags.None || !_monitoringEnabled)
            {
                _killer.InvalidateCache();
            }

            bool changed = forceNotify ||
                           next.IsGuardSafe != prev.IsGuardSafe ||
                           next.IsTunActive != prev.IsTunActive ||
                           next.AdapterLuid != prev.AdapterLuid ||
                           next.NodeGuardEnabled != prev.NodeGuardEnabled ||
                           next.IsNodeAllowed != prev.IsNodeAllowed ||
                           next.WfpEnabled != prev.WfpEnabled ||
                           next.WfpActive != prev.WfpActive ||
                           next.WfpDegraded != prev.WfpDegraded ||
                           next.WfpBlockingNow != prev.WfpBlockingNow ||
                           next.WfpDnsGuardActive != prev.WfpDnsGuardActive ||
                           next.WfpExeTargetCount != prev.WfpExeTargetCount ||
                           next.WfpPackageTargetCount != prev.WfpPackageTargetCount ||
                           !string.Equals(next.WfpStatusText, prev.WfpStatusText, StringComparison.Ordinal) ||
                           !string.Equals(next.AdapterAlias, prev.AdapterAlias, StringComparison.Ordinal) ||
                           !string.Equals(next.Reason, prev.Reason, StringComparison.Ordinal) ||
                           !string.Equals(next.ActiveNodeName, prev.ActiveNodeName, StringComparison.Ordinal) ||
                           !string.Equals(next.ActiveProxyGroup, prev.ActiveProxyGroup, StringComparison.Ordinal) ||
                           !string.Equals(next.NodeReason, prev.NodeReason, StringComparison.Ordinal);

            _isTunActive = next.IsTunActive;
            _isGuardSafe = next.IsGuardSafe;
            lock (_statusLock)
            {
                _currentStatus = next;
            }

            LogStatusTransitions(prev, next, forceNotify, triggerSource);

            if (killRes.KilledCount > 0)
            {
                bool isNodeKill = next.IsTunActive && next.NodeGuardEnabled && !next.IsNodeAllowed;
                string killAppsText = killRes.KilledApps != GuardedAppFlags.None
                    ? GuardedAppHelper.FormatNames(killRes.KilledApps)
                    : "受控应用";
                string killReason = isNodeKill ? next.NodeReason : next.Reason;
                AppLogger.Warn(
                    "GUARD",
                    string.Format(
                        "触发进程拦截 [{0}] | 原因: {1} | 已终止 {2} 共 {3} 个进程 (首轮 {4:F2} ms)",
                        triggerSource,
                        killReason,
                        killAppsText,
                        killRes.KilledCount,
                        killRes.FirstPassMs));

                Action<KillResult, string, TunStatus> killedHandler = ProcessesKilled;
                if (killedHandler != null)
                {
                    killedHandler(killRes, triggerSource, next);
                }
            }
            else if (notifyWfpBlockOnly)
            {
                bool isNodeBlock = next.IsTunActive && next.NodeGuardEnabled && !next.IsNodeAllowed;
                string blockReason = isNodeBlock ? next.NodeReason : next.Reason;
                string runningInfo = wfpBlockedApps != GuardedAppFlags.None
                    ? (" | 运行中受控应用: " + GuardedAppHelper.FormatNames(wfpBlockedApps))
                    : " | 当前无运行中受控应用";
                AppLogger.Warn(
                    "GUARD",
                    string.Format("触发 WFP 内核断网 [{0}] | 原因: {1}{2}", triggerSource, blockReason, runningInfo));

                Action<GuardedAppFlags, string, TunStatus> blockedHandler = WfpBlocked;
                if (blockedHandler != null)
                {
                    blockedHandler(wfpBlockedApps, triggerSource, next);
                }
            }
            else if (launchedWhileBlockedApps != GuardedAppFlags.None)
            {
                bool isNodeBlock = next.IsTunActive && next.NodeGuardEnabled && !next.IsNodeAllowed;
                string blockReason = isNodeBlock ? next.NodeReason : next.Reason;
                AppLogger.Warn(
                    "GUARD",
                    string.Format(
                        "检测到拦截状态下启动受控应用: {0} | 原因: {1} | 已由 WFP 内核阻断联网",
                        GuardedAppHelper.FormatNames(launchedWhileBlockedApps),
                        blockReason));

                Action<GuardedAppFlags, TunStatus> launchedHandler = GuardedAppLaunchedWhileBlocked;
                if (launchedHandler != null)
                {
                    launchedHandler(launchedWhileBlockedApps, next);
                }
            }

            if (killRes.AccessDeniedCount > 0)
            {
                long nowTicks = DateTime.UtcNow.Ticks;
                long prevLogTicks = Interlocked.Read(ref _lastAccessDeniedLogTicks);
                if (nowTicks - prevLogTicks >= AccessDeniedLogCooldownTicks &&
                    Interlocked.CompareExchange(ref _lastAccessDeniedLogTicks, nowTicks, prevLogTicks) == prevLogTicks)
                {
                    AppLogger.Error(
                        "GUARD",
                        string.Format(
                            "权限不足无法终止进程 [{0}] | 应用: {1} ({2} 个进程，请以管理员身份运行)",
                            triggerSource,
                            GuardedAppHelper.FormatNames(killRes.DeniedApps),
                            killRes.AccessDeniedCount));
                }

                Action<int, GuardedAppFlags, string> deniedHandler = AccessDenied;
                if (deniedHandler != null)
                {
                    deniedHandler(killRes.AccessDeniedCount, killRes.DeniedApps, triggerSource);
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

        private static string FormatConfigSummary(NodeGuardConfig cfg)
        {
            if (cfg == null)
            {
                return "(默认配置)";
            }
            string modeDesc = cfg.WfpEnabled
                ? (cfg.WfpKillOnBlock ? "WFP+终止进程" : "仅WFP断网")
                : "仅终止进程";
            return string.Format(
                "受控应用=[{0}], {1}, 策略={2}, DNS53={3}, 弹窗={4}",
                GuardedAppHelper.FormatShortNames(cfg.GetGuardedAppFlags()),
                cfg.GetSummaryText(),
                modeDesc,
                cfg.WfpBlockNonTunDns ? "开" : "关",
                cfg.PopupOnBlock ? "开" : "关");
        }

        private void LogStatusTransitions(TunStatus prev, TunStatus next, bool isInitial, string triggerSource)
        {
            if (isInitial)
            {
                string tunDesc = next.IsTunActive
                    ? string.Format("{0} (LUID=0x{1:X})", next.Reason, next.AdapterLuid)
                    : next.Reason;
                string nodeDesc = next.NodeGuardEnabled
                    ? (string.IsNullOrEmpty(next.ActiveNodeChain) ? next.NodeReason : (next.NodeReason + " [" + next.ActiveNodeChain + "]"))
                    : "未启用";
                AppLogger.Info(
                    "STATUS",
                    string.Format(
                        "初始检测完成 | 安全={0} | TUN={1} | 节点={2} | WFP={3}",
                        next.IsGuardSafe ? "是" : "否",
                        tunDesc,
                        nodeDesc,
                        string.IsNullOrEmpty(next.WfpStatusText) ? "未启用" : next.WfpStatusText));
                return;
            }

            if (prev.IsTunActive != next.IsTunActive ||
                prev.AdapterLuid != next.AdapterLuid ||
                !string.Equals(prev.Reason, next.Reason, StringComparison.Ordinal))
            {
                string luidPart = next.AdapterLuid != 0 ? (" | LUID=0x" + next.AdapterLuid.ToString("X")) : string.Empty;
                if (next.IsTunActive)
                {
                    AppLogger.Info("TUN", string.Format("TUN 状态变更 [{0}]: {1}{2}", triggerSource, next.Reason, luidPart));
                }
                else
                {
                    AppLogger.Warn("TUN", string.Format("TUN 状态异常 [{0}]: {1}", triggerSource, next.Reason));
                }
            }

            if (prev.NodeGuardEnabled != next.NodeGuardEnabled ||
                (next.NodeGuardEnabled &&
                 (prev.IsNodeAllowed != next.IsNodeAllowed ||
                  !string.Equals(prev.ActiveNodeName, next.ActiveNodeName, StringComparison.Ordinal) ||
                  !string.Equals(prev.NodeReason, next.NodeReason, StringComparison.Ordinal))))
            {
                if (!next.NodeGuardEnabled)
                {
                    AppLogger.Info("NODE", "节点守护已关闭");
                }
                else
                {
                    string chain = !string.IsNullOrEmpty(next.ActiveNodeChain) ? (" [" + next.ActiveNodeChain + "]") : string.Empty;
                    if (next.IsNodeAllowed)
                    {
                        AppLogger.Info("NODE", string.Format("节点校验通过 [{0}]: {1}{2}", triggerSource, next.NodeReason, chain));
                    }
                    else
                    {
                        AppLogger.Warn("NODE", string.Format("节点校验未通过 [{0}]: {1}{2}", triggerSource, next.NodeReason, chain));
                    }
                }
            }

            if (prev.WfpActive != next.WfpActive ||
                prev.WfpDegraded != next.WfpDegraded ||
                prev.WfpBlockingNow != next.WfpBlockingNow ||
                !string.Equals(prev.WfpStatusText, next.WfpStatusText, StringComparison.Ordinal))
            {
                if (next.WfpDegraded)
                {
                    AppLogger.Warn("WFP", "内核断网状态变更: " + next.WfpStatusText);
                }
                else
                {
                    AppLogger.Info("WFP", "内核断网状态变更: " + (string.IsNullOrEmpty(next.WfpStatusText) ? "未启用" : next.WfpStatusText));
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
                    AdapterLuid = 0,
                    AdapterAlias = string.Empty,
                    Reason = "Clash Verge 配置已关闭 TUN"
                };
            }

            // Skip redundant adapter/route queries on intermediate 30ms process-guard ticks (kernel callbacks still wake immediately)
            if (!checkAdapter && previous.ConfigEnabled)
            {
                return previous;
            }

            uint tunIfIndex;
            ulong tunIfLuid;
            string tunAlias;
            bool adapterUp = TryCheckCachedTunAdapter(_lastKnownTunIfIndex, customDevice, out tunIfIndex, out tunIfLuid, out tunAlias) ||
                             FindActiveTunAdapter(customDevice, out tunIfIndex, out tunIfLuid, out tunAlias);

            bool hasRoute = true;
            if (adapterUp && autoRoute)
            {
                hasRoute = HasDefaultRouteOnInterface(tunIfIndex);
            }

            bool isActive = adapterUp && (!autoRoute || hasRoute);
            string reason;
            if (isActive)
            {
                if (!string.Equals(_cachedTunOkAlias, tunAlias, StringComparison.Ordinal))
                {
                    _cachedTunOkAlias = tunAlias;
                    _cachedTunOkReason = "TUN 正常 (" + tunAlias + ")";
                }
                reason = _cachedTunOkReason;
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
                AdapterLuid = tunIfLuid,
                AdapterAlias = tunAlias ?? string.Empty,
                Reason = reason
            };
        }

        private bool TryCheckCachedTunAdapter(uint cachedIfIndex, string customDevice, out uint ifIndex, out ulong ifLuid, out string alias)
        {
            ifIndex = 0;
            ifLuid = 0;
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
            ifLuid = unchecked((ulong)Marshal.ReadInt64(_ifRowBuffer, IF_ROW_LUID_OFFSET));
            alias = rowAlias;
            return true;
        }

        private static bool FindActiveTunAdapter(string customDevice, out uint ifIndex, out ulong ifLuid, out string alias)
        {
            ifIndex = 0;
            ifLuid = 0;
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
                        ifLuid = unchecked((ulong)Marshal.ReadInt64(row, IF_ROW_LUID_OFFSET));
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
                bool changed = (!_clashAutoRoute ||
                                _customTunDevice != null ||
                                _clashExternalController != null ||
                                _clashExternalPipe != null ||
                                _clashSecret != null ||
                                _clashMixedPort != 0 ||
                                _clashHttpPort != 0 ||
                                _clashSocksPort != 0);
                _clashAutoRoute = true;
                _customTunDevice = null;
                _clashExternalController = null;
                _clashExternalPipe = null;
                _clashSecret = null;
                _clashMixedPort = 0;
                _clashHttpPort = 0;
                _clashSocksPort = 0;
                return changed;
            }

            bool? autoRouteVal;
            string deviceVal;
            string controllerVal;
            string pipeVal;
            string secretVal;
            ushort mixedPortVal;
            ushort httpPortVal;
            ushort socksPortVal;
            if (!TryReadClashYamlHeaderStream(
                _clashYamlPath,
                out autoRouteVal,
                out deviceVal,
                out controllerVal,
                out pipeVal,
                out secretVal,
                out mixedPortVal,
                out httpPortVal,
                out socksPortVal))
            {
                return false;
            }

            GetFileStat(_clashYamlPath, out exists, out writeTicks, out length);
            _clashStatValid = true;
            _clashLastExists = exists;
            _clashLastWriteTicks = writeTicks;
            _clashLastLength = length;

            // Reset to Clash defaults if tun: section or individual keys were removed
            bool nextAutoRoute = autoRouteVal.HasValue ? autoRouteVal.Value : true;
            string nextDevice = deviceVal;

            bool valueChanged = (_clashAutoRoute != nextAutoRoute) ||
                                !string.Equals(_customTunDevice, nextDevice, StringComparison.Ordinal) ||
                                !string.Equals(_clashExternalController, controllerVal, StringComparison.Ordinal) ||
                                !string.Equals(_clashExternalPipe, pipeVal, StringComparison.Ordinal) ||
                                !string.Equals(_clashSecret, secretVal, StringComparison.Ordinal) ||
                                _clashMixedPort != mixedPortVal ||
                                _clashHttpPort != httpPortVal ||
                                _clashSocksPort != socksPortVal;
            _clashAutoRoute = nextAutoRoute;
            _customTunDevice = nextDevice;
            _clashExternalController = controllerVal;
            _clashExternalPipe = pipeVal;
            _clashSecret = secretVal;
            _clashMixedPort = mixedPortVal;
            _clashHttpPort = httpPortVal;
            _clashSocksPort = socksPortVal;
            return valueChanged;
        }

        // Stream line-by-line and stop early before massive proxies:/rules: sections
        private static bool TryReadClashYamlHeaderStream(
            string path,
            out bool? autoRouteVal,
            out string deviceVal,
            out string controllerVal,
            out string pipeVal,
            out string secretVal,
            out ushort mixedPortVal,
            out ushort httpPortVal,
            out ushort socksPortVal)
        {
            autoRouteVal = null;
            deviceVal = null;
            controllerVal = null;
            pipeVal = null;
            secretVal = null;
            mixedPortVal = 0;
            httpPortVal = 0;
            socksPortVal = 0;

            for (int attempt = 0; attempt <= FileRetryDelaysMs.Length; attempt++)
            {
                try
                {
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        bool anyLine = false;
                        bool inTun = false;
                        bool seenTun = false;
                        int tunChildIndent = -1;
                        bool? parsedAutoRoute = null;
                        string parsedDevice = null;
                        string parsedController = null;
                        string parsedPipe = null;
                        string parsedSecret = null;
                        ushort parsedMixedPort = 0;
                        ushort parsedHttpPort = 0;
                        ushort parsedSocksPort = 0;

                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            anyLine = true;
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
                                inTun = false;
                                tunChildIndent = -1;
                                string topKey = StripYamlComment(trimmed).Trim();
                                if (string.Equals(topKey, "tun:", StringComparison.OrdinalIgnoreCase))
                                {
                                    inTun = true;
                                    seenTun = true;
                                }
                                else if (string.Equals(topKey, "rules:", StringComparison.OrdinalIgnoreCase) ||
                                         string.Equals(topKey, "rule-providers:", StringComparison.OrdinalIgnoreCase) ||
                                         (seenTun && (string.Equals(topKey, "proxies:", StringComparison.OrdinalIgnoreCase) ||
                                                      string.Equals(topKey, "proxy-groups:", StringComparison.OrdinalIgnoreCase))))
                                {
                                    break;
                                }
                                else if (trimmed.StartsWith("external-controller:", StringComparison.OrdinalIgnoreCase))
                                {
                                    string v = StripYamlComment(trimmed.Substring("external-controller:".Length)).Trim().Trim('\'', '"');
                                    if (!string.IsNullOrEmpty(v))
                                    {
                                        parsedController = v;
                                    }
                                }
                                else if (trimmed.StartsWith("external-controller-pipe:", StringComparison.OrdinalIgnoreCase))
                                {
                                    string v = StripYamlComment(trimmed.Substring("external-controller-pipe:".Length)).Trim().Trim('\'', '"');
                                    if (!string.IsNullOrEmpty(v))
                                    {
                                        parsedPipe = v;
                                    }
                                }
                                else if (trimmed.StartsWith("secret:", StringComparison.OrdinalIgnoreCase))
                                {
                                    string v = StripYamlComment(trimmed.Substring("secret:".Length)).Trim().Trim('\'', '"');
                                    if (!string.IsNullOrEmpty(v))
                                    {
                                        parsedSecret = v;
                                    }
                                }
                                else if (trimmed.StartsWith("mixed-port:", StringComparison.OrdinalIgnoreCase))
                                {
                                    ushort p;
                                    if (TryParseYamlPort(trimmed.Substring("mixed-port:".Length), out p))
                                    {
                                        parsedMixedPort = p;
                                    }
                                }
                                else if (trimmed.StartsWith("port:", StringComparison.OrdinalIgnoreCase))
                                {
                                    ushort p;
                                    if (TryParseYamlPort(trimmed.Substring("port:".Length), out p))
                                    {
                                        parsedHttpPort = p;
                                    }
                                }
                                else if (trimmed.StartsWith("socks-port:", StringComparison.OrdinalIgnoreCase))
                                {
                                    ushort p;
                                    if (TryParseYamlPort(trimmed.Substring("socks-port:".Length), out p))
                                    {
                                        parsedSocksPort = p;
                                    }
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
                                    parsedAutoRoute = b;
                                }
                            }
                            else if (trimmed.StartsWith("device:", StringComparison.OrdinalIgnoreCase))
                            {
                                string dev = StripYamlComment(trimmed.Substring("device:".Length)).Trim().Trim('\'', '"');
                                if (!string.IsNullOrEmpty(dev))
                                {
                                    parsedDevice = dev;
                                }
                            }
                        }

                        if (anyLine)
                        {
                            autoRouteVal = parsedAutoRoute;
                            deviceVal = parsedDevice;
                            controllerVal = parsedController;
                            pipeVal = parsedPipe;
                            secretVal = parsedSecret;
                            mixedPortVal = parsedMixedPort;
                            httpPortVal = parsedHttpPort;
                            socksPortVal = parsedSocksPort;
                            return true;
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

            return false;
        }

        private static bool TryParseYamlPort(string rawValue, out ushort port)
        {
            port = 0;
            if (string.IsNullOrEmpty(rawValue))
            {
                return false;
            }
            string v = StripYamlComment(rawValue).Trim().Trim('\'', '"');
            int parsed;
            if (int.TryParse(v, out parsed) && parsed > 0 && parsed <= 65535)
            {
                port = (ushort)parsed;
                return true;
            }
            return false;
        }

        private bool ReadBaseClashYamlSafe(bool force)
        {
            bool exists;
            long writeTicks;
            long length;
            GetFileStat(_baseClashYamlPath, out exists, out writeTicks, out length);

            if (!force && _baseClashStatValid &&
                exists == _baseClashLastExists &&
                writeTicks == _baseClashLastWriteTicks &&
                length == _baseClashLastLength)
            {
                return false;
            }

            if (!exists)
            {
                _baseClashStatValid = true;
                _baseClashLastExists = false;
                _baseClashLastWriteTicks = 0;
                _baseClashLastLength = 0;
                bool changed = (_baseExternalController != null || _baseExternalPipe != null || _baseSecret != null ||
                                _baseMixedPort != 0 || _baseHttpPort != 0 || _baseSocksPort != 0);
                _baseExternalController = null;
                _baseExternalPipe = null;
                _baseSecret = null;
                _baseMixedPort = 0;
                _baseHttpPort = 0;
                _baseSocksPort = 0;
                return changed;
            }

            string content = ReadAllTextRetry(_baseClashYamlPath);
            if (string.IsNullOrEmpty(content))
            {
                return false;
            }

            GetFileStat(_baseClashYamlPath, out exists, out writeTicks, out length);
            _baseClashStatValid = true;
            _baseClashLastExists = exists;
            _baseClashLastWriteTicks = writeTicks;
            _baseClashLastLength = length;

            string controllerVal = null;
            string pipeVal = null;
            string secretVal = null;
            ushort mixedPortVal = 0;
            ushort httpPortVal = 0;
            ushort socksPortVal = 0;

            using (StringReader sr = new StringReader(content))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(line) || CountLeadingSpaces(line) != 0)
                    {
                        continue;
                    }
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith("#"))
                    {
                        continue;
                    }
                    if (trimmed.StartsWith("external-controller:", StringComparison.OrdinalIgnoreCase))
                    {
                        string v = StripYamlComment(trimmed.Substring("external-controller:".Length)).Trim().Trim('\'', '"');
                        if (!string.IsNullOrEmpty(v))
                        {
                            controllerVal = v;
                        }
                    }
                    else if (trimmed.StartsWith("external-controller-pipe:", StringComparison.OrdinalIgnoreCase))
                    {
                        string v = StripYamlComment(trimmed.Substring("external-controller-pipe:".Length)).Trim().Trim('\'', '"');
                        if (!string.IsNullOrEmpty(v))
                        {
                            pipeVal = v;
                        }
                    }
                    else if (trimmed.StartsWith("secret:", StringComparison.OrdinalIgnoreCase))
                    {
                        string v = StripYamlComment(trimmed.Substring("secret:".Length)).Trim().Trim('\'', '"');
                        if (!string.IsNullOrEmpty(v))
                        {
                            secretVal = v;
                        }
                    }
                    else if (trimmed.StartsWith("mixed-port:", StringComparison.OrdinalIgnoreCase))
                    {
                        ushort p;
                        if (TryParseYamlPort(trimmed.Substring("mixed-port:".Length), out p))
                        {
                            mixedPortVal = p;
                        }
                    }
                    else if (trimmed.StartsWith("port:", StringComparison.OrdinalIgnoreCase))
                    {
                        ushort p;
                        if (TryParseYamlPort(trimmed.Substring("port:".Length), out p))
                        {
                            httpPortVal = p;
                        }
                    }
                    else if (trimmed.StartsWith("socks-port:", StringComparison.OrdinalIgnoreCase))
                    {
                        ushort p;
                        if (TryParseYamlPort(trimmed.Substring("socks-port:".Length), out p))
                        {
                            socksPortVal = p;
                        }
                    }
                }
            }

            bool valueChanged = !string.Equals(_baseExternalController, controllerVal, StringComparison.Ordinal) ||
                                !string.Equals(_baseExternalPipe, pipeVal, StringComparison.Ordinal) ||
                                !string.Equals(_baseSecret, secretVal, StringComparison.Ordinal) ||
                                _baseMixedPort != mixedPortVal ||
                                _baseHttpPort != httpPortVal ||
                                _baseSocksPort != socksPortVal;
            _baseExternalController = controllerVal;
            _baseExternalPipe = pipeVal;
            _baseSecret = secretVal;
            _baseMixedPort = mixedPortVal;
            _baseHttpPort = httpPortVal;
            _baseSocksPort = socksPortVal;
            return valueChanged;
        }

        private void SyncMihomoConnectionConfig()
        {
            string pipe = !string.IsNullOrEmpty(_clashExternalPipe) ? _clashExternalPipe : _baseExternalPipe;
            string secret = !string.IsNullOrEmpty(_clashSecret) ? _clashSecret : _baseSecret;
            _mihomoClient.UpdateConnectionConfig(pipe, _clashExternalController, _baseExternalController, secret);

            _clashLocalProxyPorts.Clear();
            AddUniquePort(_clashLocalProxyPorts, _clashMixedPort != 0 ? _clashMixedPort : _baseMixedPort);
            AddUniquePort(_clashLocalProxyPorts, _clashHttpPort != 0 ? _clashHttpPort : _baseHttpPort);
            AddUniquePort(_clashLocalProxyPorts, _clashSocksPort != 0 ? _clashSocksPort : _baseSocksPort);
            _clashLocalProxyPorts.Sort();
        }

        private static void AddUniquePort(List<ushort> ports, ushort port)
        {
            if (port == 0)
            {
                return;
            }
            for (int i = 0; i < ports.Count; i++)
            {
                if (ports[i] == port)
                {
                    return;
                }
            }
            ports.Add(port);
        }

        private bool ReadNodeGuardConfigSafe(bool force)
        {
            bool exists;
            long writeTicks;
            long length;
            GetFileStat(_nodeConfigPath, out exists, out writeTicks, out length);

            if (!force && _nodeConfigStatValid &&
                exists == _nodeConfigLastExists &&
                writeTicks == _nodeConfigLastWriteTicks &&
                length == _nodeConfigLastLength)
            {
                return false;
            }

            NodeGuardConfig loaded;
            if (!NodeGuardConfigStore.TryLoad(_nodeConfigPath, out loaded))
            {
                return false;
            }

            GetFileStat(_nodeConfigPath, out exists, out writeTicks, out length);
            _nodeConfigStatValid = true;
            _nodeConfigLastExists = exists;
            _nodeConfigLastWriteTicks = writeTicks;
            _nodeConfigLastLength = length;

            _nodeConfig = loaded;
            _mihomoClient.InvalidateRulesCache();

            if (!force)
            {
                AppLogger.ConfigureDirectoryQuiet(loaded.LogDirectory);
                AppLogger.Info("CONFIG", "检测到外部配置文件热更新 | " + FormatConfigSummary(loaded));
            }

            Action<NodeGuardConfig> cfgHandler = NodeConfigChanged;
            if (!force && cfgHandler != null)
            {
                cfgHandler(loaded);
            }
            return true;
        }

        private void RefreshNodeConfigStatAfterSave()
        {
            bool exists;
            long writeTicks;
            long length;
            GetFileStat(_nodeConfigPath, out exists, out writeTicks, out length);
            _nodeConfigStatValid = true;
            _nodeConfigLastExists = exists;
            _nodeConfigLastWriteTicks = writeTicks;
            _nodeConfigLastLength = length;
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

            // Always close WFP DYNAMIC session immediately so BFE clears all kernel filters on exit
            _wfp.Dispose();

            if (watchdogExited)
            {
                _mihomoClient.Dispose();
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
        private const int TASK_CREATE_OR_UPDATE = 6;
        private const int TASK_LOGON_INTERACTIVE_TOKEN = 3;
        private const int HRESULT_FILE_NOT_FOUND = unchecked((int)0x80070002);

        public static bool IsAutoStartEnabled()
        {
            string xml;
            if (!TryGetTaskXml(out xml) || string.IsNullOrEmpty(xml))
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

        public static bool SetAutoStart(bool enable)
        {
            object service = null;
            object rootFolder = null;
            object registeredTask = null;

            try
            {
                if (!TryConnectRootFolder(out service, out rootFolder))
                {
                    return false;
                }

                if (enable)
                {
                    string exePath = Application.ExecutablePath;
                    string workDir = Path.GetDirectoryName(exePath) ?? string.Empty;
                    string userId = WindowsIdentity.GetCurrent().Name;
                    string xml = BuildTaskXml(userId, exePath, workDir);

                    registeredTask = rootFolder.GetType().InvokeMember(
                        "RegisterTask",
                        BindingFlags.InvokeMethod,
                        null,
                        rootFolder,
                        new object[]
                        {
                            TaskName,
                            xml,
                            TASK_CREATE_OR_UPDATE,
                            Type.Missing,
                            Type.Missing,
                            TASK_LOGON_INTERACTIVE_TOKEN,
                            Type.Missing
                        });
                    return registeredTask != null;
                }
                else
                {
                    try
                    {
                        rootFolder.GetType().InvokeMember(
                            "DeleteTask",
                            BindingFlags.InvokeMethod,
                            null,
                            rootFolder,
                            new object[] { TaskName, 0 });
                        return true;
                    }
                    catch (Exception ex)
                    {
                        return IsNotFoundException(ex);
                    }
                }
            }
            catch
            {
                return false;
            }
            finally
            {
                ReleaseComQuietly(registeredTask);
                ReleaseComQuietly(rootFolder);
                ReleaseComQuietly(service);
            }
        }

        private static bool TryGetTaskXml(out string xml)
        {
            xml = null;
            object service = null;
            object rootFolder = null;
            object task = null;

            try
            {
                if (!TryConnectRootFolder(out service, out rootFolder))
                {
                    return false;
                }

                task = rootFolder.GetType().InvokeMember(
                    "GetTask",
                    BindingFlags.InvokeMethod,
                    null,
                    rootFolder,
                    new object[] { TaskName });
                if (task == null)
                {
                    return false;
                }

                xml = task.GetType().InvokeMember(
                    "Xml",
                    BindingFlags.GetProperty,
                    null,
                    task,
                    null) as string;
                return !string.IsNullOrEmpty(xml);
            }
            catch
            {
                return false;
            }
            finally
            {
                ReleaseComQuietly(task);
                ReleaseComQuietly(rootFolder);
                ReleaseComQuietly(service);
            }
        }

        private static bool TryConnectRootFolder(out object service, out object rootFolder)
        {
            service = null;
            rootFolder = null;
            Type serviceType = Type.GetTypeFromProgID("Schedule.Service");
            if (serviceType == null)
            {
                return false;
            }

            service = Activator.CreateInstance(serviceType);
            if (service == null)
            {
                return false;
            }

            serviceType.InvokeMember(
                "Connect",
                BindingFlags.InvokeMethod,
                null,
                service,
                new object[] { Type.Missing, Type.Missing, Type.Missing, Type.Missing });

            rootFolder = serviceType.InvokeMember(
                "GetFolder",
                BindingFlags.InvokeMethod,
                null,
                service,
                new object[] { "\\" });
            return rootFolder != null;
        }

        private static bool IsNotFoundException(Exception ex)
        {
            Exception cur = ex;
            while (cur != null)
            {
                if (cur is FileNotFoundException)
                {
                    return true;
                }
                COMException comEx = cur as COMException;
                if (comEx != null && comEx.ErrorCode == HRESULT_FILE_NOT_FOUND)
                {
                    return true;
                }
                cur = cur.InnerException;
            }
            return false;
        }

        private static void ReleaseComQuietly(object comObj)
        {
            if (comObj != null && Marshal.IsComObject(comObj))
            {
                try
                {
                    Marshal.FinalReleaseComObject(comObj);
                }
                catch
                {
                }
            }
        }

        private static string BuildTaskXml(string userId, string exePath, string workDir)
        {
            return string.Format(
@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo>
    <Description>Monitor Clash Verge TUN mode and node rules for Antigravity, ChatGPT and Claude Desktop.</Description>
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

        public static void DrawGitHubMark(Graphics g, float x, float y, float size, Color color)
        {
            if (g == null || size <= 0f)
            {
                return;
            }

            GraphicsState state = g.Save();
            try
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TranslateTransform(x, y);
                float scale = size / 16f;
                g.ScaleTransform(scale, scale);

                using (GraphicsPath path = CreateGitHubMarkPath())
                using (SolidBrush brush = new SolidBrush(color))
                {
                    g.FillPath(brush, path);
                }
            }
            finally
            {
                g.Restore(state);
            }
        }

        private static GraphicsPath CreateGitHubMarkPath()
        {
            // Official 16x16 GitHub Octocat mark contour
            GraphicsPath path = new GraphicsPath();
            path.AddArc(0f, 0f, 16f, 16f, -90f, 161.43f);
            path.AddBezier(10.55f, 15.59f, 10.15f, 15.67f, 10.00f, 15.42f, 10.00f, 15.21f);
            path.AddBezier(10.00f, 15.21f, 10.00f, 14.94f, 10.01f, 14.08f, 10.01f, 13.01f);
            path.AddBezier(10.01f, 13.01f, 10.01f, 12.26f, 9.76f, 11.78f, 9.47f, 11.53f);
            path.AddBezier(9.47f, 11.53f, 11.25f, 11.33f, 13.12f, 10.65f, 13.12f, 7.58f);
            path.AddBezier(13.12f, 7.58f, 13.12f, 6.70f, 12.81f, 5.99f, 12.30f, 5.43f);
            path.AddBezier(12.30f, 5.43f, 12.38f, 5.23f, 12.66f, 4.41f, 12.22f, 3.31f);
            path.AddBezier(12.22f, 3.31f, 12.22f, 3.31f, 11.55f, 3.09f, 10.02f, 4.13f);
            path.AddBezier(10.02f, 4.13f, 9.38f, 3.95f, 8.70f, 3.86f, 8.02f, 3.86f);
            path.AddBezier(8.02f, 3.86f, 7.34f, 3.86f, 6.66f, 3.95f, 6.02f, 4.13f);
            path.AddBezier(6.02f, 4.13f, 4.49f, 3.10f, 3.82f, 3.31f, 3.82f, 3.31f);
            path.AddBezier(3.82f, 3.31f, 3.38f, 4.41f, 3.66f, 5.23f, 3.74f, 5.43f);
            path.AddBezier(3.74f, 5.43f, 3.23f, 5.99f, 2.92f, 6.71f, 2.92f, 7.58f);
            path.AddBezier(2.92f, 7.58f, 2.92f, 10.64f, 4.78f, 11.33f, 6.56f, 11.53f);
            path.AddBezier(6.56f, 11.53f, 6.33f, 11.73f, 6.12f, 12.08f, 6.05f, 12.60f);
            path.AddBezier(6.05f, 12.60f, 5.59f, 12.81f, 4.44f, 13.15f, 3.72f, 11.94f);
            path.AddBezier(3.72f, 11.94f, 3.57f, 11.70f, 3.12f, 11.11f, 2.49f, 11.12f);
            path.AddBezier(2.49f, 11.12f, 1.82f, 11.13f, 2.22f, 11.50f, 2.50f, 11.65f);
            path.AddBezier(2.50f, 11.65f, 2.84f, 11.84f, 3.23f, 12.55f, 3.32f, 12.78f);
            path.AddBezier(3.32f, 12.78f, 3.48f, 13.23f, 4.00f, 14.09f, 6.01f, 13.72f);
            path.AddBezier(6.01f, 13.72f, 6.01f, 14.39f, 6.02f, 15.02f, 6.02f, 15.21f);
            path.AddBezier(6.02f, 15.21f, 6.02f, 15.42f, 5.87f, 15.66f, 5.47f, 15.59f);
            path.AddArc(0f, 0f, 16f, 16f, 108.57f, 161.43f);
            path.CloseFigure();
            return path;
        }
    }

    internal sealed class GitHubIconButton : Control
    {
        private bool _hovered;
        private bool _pressed;

        public GitHubIconButton()
        {
            SetStyle(
                ControlStyles.AllPaintingInWmPaint |
                ControlStyles.OptimizedDoubleBuffer |
                ControlStyles.ResizeRedraw |
                ControlStyles.UserPaint |
                ControlStyles.Selectable |
                ControlStyles.SupportsTransparentBackColor,
                true);
            BackColor = Color.Transparent;
            Cursor = Cursors.Hand;
            TabStop = true;
            AccessibleName = "GitHub";
            Size = new Size(28, 26);
        }

        protected override void OnMouseEnter(EventArgs e)
        {
            base.OnMouseEnter(e);
            _hovered = true;
            Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            _hovered = false;
            _pressed = false;
            Invalidate();
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button == MouseButtons.Left)
            {
                _pressed = true;
                Focus();
                Invalidate();
            }
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            if (_pressed)
            {
                _pressed = false;
                Invalidate();
            }
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (e.KeyCode == Keys.Space || e.KeyCode == Keys.Enter)
            {
                e.Handled = true;
                OnClick(EventArgs.Empty);
            }
        }

        protected override void OnGotFocus(EventArgs e)
        {
            base.OnGotFocus(e);
            Invalidate();
        }

        protected override void OnLostFocus(EventArgs e)
        {
            base.OnLostFocus(e);
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            if (_pressed || _hovered)
            {
                Color bg = _pressed
                    ? Color.FromArgb(203, 213, 225)
                    : Color.FromArgb(226, 232, 240);
                using (GraphicsPath pill = CreateRoundedRectPath(1f, 1f, Width - 3f, Height - 3f, 5f))
                using (SolidBrush brush = new SolidBrush(bg))
                {
                    g.FillPath(brush, pill);
                }
            }

            if (Focused)
            {
                using (GraphicsPath focusRect = CreateRoundedRectPath(1f, 1f, Width - 3f, Height - 3f, 5f))
                using (Pen pen = new Pen(Color.FromArgb(148, 163, 184), 1f))
                {
                    g.DrawPath(pen, focusRect);
                }
            }

            float iconSize = Math.Max(15f, Math.Min(Width, Height) * 0.68f);
            float ix = (Width - iconSize) * 0.5f;
            float iy = (Height - iconSize) * 0.5f;
            Color iconColor = (_hovered || _pressed)
                ? Color.FromArgb(15, 23, 42)
                : Color.FromArgb(51, 65, 85);
            TrayIconFactory.DrawGitHubMark(g, ix, iy, iconSize, iconColor);
        }

        private static GraphicsPath CreateRoundedRectPath(float x, float y, float w, float h, float r)
        {
            GraphicsPath gp = new GraphicsPath();
            float d = r * 2f;
            if (w <= d || h <= d)
            {
                gp.AddRectangle(new RectangleF(x, y, Math.Max(1f, w), Math.Max(1f, h)));
                return gp;
            }
            gp.AddArc(x, y, d, d, 180f, 90f);
            gp.AddArc(x + w - d, y, d, d, 270f, 90f);
            gp.AddArc(x + w - d, y + h - d, d, d, 0f, 90f);
            gp.AddArc(x, y + h - d, d, d, 90f, 90f);
            gp.CloseFigure();
            return gp;
        }
    }

    internal sealed class UpdateCheckResult
    {
        public bool Success;
        public bool HasUpdate;
        public Version CurrentVersion;
        public Version LatestVersion;
        public string LatestTag;
        public string ReleasePageUrl;
        public string DownloadUrl;
        public string ChecksumUrl;
        public bool ChecksumAssetPresent;
        public long ExpectedSize;
        public string ReleaseNotes;
        public string ErrorMessage;
        public bool UsedRedirectFallback;
    }

    internal static class AppUpdater
    {
        public const string RepoOwner = "wdnmd123-zzz";
        public const string RepoName = "TunGuard";
        public const string RepoUrl = "https://github.com/wdnmd123-zzz/TunGuard";
        public const string ReleasesUrl = "https://github.com/wdnmd123-zzz/TunGuard/releases";

        private const string LatestReleaseApiUrl = "https://api.github.com/repos/wdnmd123-zzz/TunGuard/releases/latest";
        private const string LatestReleaseWebUrl = "https://github.com/wdnmd123-zzz/TunGuard/releases/latest";
        private const string ReleaseAssetExeName = "TunGuard.exe";
        private const string ReleaseAssetChecksumName = "SHA256SUMS.txt";
        private const int ApiTimeoutMs = 10000;
        private const int DownloadTimeoutMs = 20000;
        private const long MinValidExeBytes = 16 * 1024;
        private const long MaxValidExeBytes = 64 * 1024 * 1024;
        private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(10);

        private static readonly object CacheLock = new object();
        private static UpdateCheckResult _cachedResult;
        private static DateTime _cachedAtUtc = DateTime.MinValue;
        private static int _tlsInitialized;

        public static Version GetCurrentVersion()
        {
            try
            {
                Version v = Assembly.GetExecutingAssembly().GetName().Version;
                if (v != null)
                {
                    return new Version(
                        Math.Max(0, v.Major),
                        Math.Max(0, v.Minor),
                        Math.Max(0, v.Build));
                }
            }
            catch
            {
            }
            return new Version(1, 0, 0);
        }

        public static string GetCurrentVersionText()
        {
            Version v = GetCurrentVersion();
            return string.Format("v{0}.{1}.{2}", v.Major, v.Minor, v.Build);
        }

        public static string GetCurrentExecutablePath()
        {
            try
            {
                string path = Application.ExecutablePath;
                if (!string.IsNullOrWhiteSpace(path))
                {
                    return Path.GetFullPath(path);
                }
            }
            catch
            {
            }
            return Path.GetFullPath(Assembly.GetExecutingAssembly().Location);
        }

        public static bool TryParseVersionTag(string rawTag, out Version version)
        {
            version = null;
            if (string.IsNullOrWhiteSpace(rawTag))
            {
                return false;
            }

            string s = rawTag.Trim();
            while (s.Length > 0 && (s[0] == 'v' || s[0] == 'V'))
            {
                s = s.Substring(1);
            }

            int suffixIdx = s.IndexOfAny(new char[] { '-', '+' });
            if (suffixIdx > 0)
            {
                s = s.Substring(0, suffixIdx);
            }

            string[] parts = s.Split('.');
            if (parts.Length < 2 || parts.Length > 4)
            {
                return false;
            }

            int major;
            int minor;
            int patch = 0;
            if (!int.TryParse(parts[0], out major) || major < 0)
            {
                return false;
            }
            if (!int.TryParse(parts[1], out minor) || minor < 0)
            {
                return false;
            }
            if (parts.Length >= 3)
            {
                if (!int.TryParse(parts[2], out patch) || patch < 0)
                {
                    return false;
                }
            }

            version = new Version(major, minor, patch);
            return true;
        }

        public static UpdateCheckResult CheckForUpdates(bool forceRefresh)
        {
            if (!forceRefresh)
            {
                lock (CacheLock)
                {
                    if (_cachedResult != null &&
                        _cachedResult.Success &&
                        (DateTime.UtcNow - _cachedAtUtc) < CacheTtl)
                    {
                        return _cachedResult;
                    }
                }
            }

            EnsureTlsEnabled();
            Version current = GetCurrentVersion();
            string apiError;
            bool shouldFallback;
            UpdateCheckResult result;

            if (TryCheckViaGitHubApi(current, out result, out apiError, out shouldFallback))
            {
                StoreCache(result);
                AppLogger.Info("UPDATER", string.Format(
                    "更新检测完成: 当前 {0}，最新 {1} ({2})",
                    GetCurrentVersionText(),
                    result.LatestTag,
                    result.HasUpdate ? "有新版本" : "已是最新"));
                return result;
            }

            if (shouldFallback)
            {
                string fallbackError;
                if (TryCheckViaLatestRedirect(current, out result, out fallbackError))
                {
                    StoreCache(result);
                    AppLogger.Info("UPDATER", string.Format(
                        "更新检测完成 (直连回退): 当前 {0}，最新 {1} ({2})",
                        GetCurrentVersionText(),
                        result.LatestTag,
                        result.HasUpdate ? "有新版本" : "已是最新"));
                    return result;
                }
                if (!string.IsNullOrEmpty(fallbackError))
                {
                    apiError = apiError + "；回退检测失败: " + fallbackError;
                }
            }

            AppLogger.Warn("UPDATER", "检查更新失败: " + apiError);
            return new UpdateCheckResult
            {
                Success = false,
                HasUpdate = false,
                CurrentVersion = current,
                ReleasePageUrl = ReleasesUrl,
                ErrorMessage = apiError
            };
        }

        public static bool DownloadAndVerifyUpdate(
            UpdateCheckResult info,
            Func<bool> isCancelled,
            Action<int, long, long, string> onProgress,
            out string stagedExePath,
            out string error)
        {
            stagedExePath = null;
            error = null;

            if (info == null || string.IsNullOrWhiteSpace(info.DownloadUrl))
            {
                error = "未找到可用的更新包下载地址";
                return false;
            }

            EnsureTlsEnabled();
            string currentExePath = GetCurrentExecutablePath();
            string appDir = Path.GetDirectoryName(currentExePath);
            if (string.IsNullOrEmpty(appDir) || !Directory.Exists(appDir))
            {
                error = "无法定位当前程序目录";
                return false;
            }

            string tempPath = currentExePath + ".new." + Process.GetCurrentProcess().Id;
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }

                // Pre-check directory write permission before downloading
                using (FileStream probe = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    probe.Flush();
                }
            }
            catch (Exception ex)
            {
                TryDeleteFileQuiet(tempPath);
                error = "无法写入程序目录（可能需要以管理员权限运行）: " + ex.Message;
                return false;
            }

            bool downloadOk = false;
            try
            {
                ReportProgressSafe(onProgress, 0, 0, info.ExpectedSize, "正在连接 GitHub 下载更新...");
                HttpWebRequest req = CreateWebRequest(info.DownloadUrl, DownloadTimeoutMs, true);
                req.Accept = "application/octet-stream, */*";

                long downloadedBytes = 0;
                long totalBytes = info.ExpectedSize;
                long lastReportTicks = 0;
                long reportIntervalTicks = TimeSpan.FromMilliseconds(80).Ticks;

                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    if (resp.ContentLength > 0)
                    {
                        totalBytes = resp.ContentLength;
                    }

                    using (Stream respStream = resp.GetResponseStream())
                    using (FileStream fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 16384))
                    {
                        if (respStream == null)
                        {
                            error = "下载响应流为空";
                            return false;
                        }

                        byte[] buffer = new byte[16384];
                        int read;
                        while ((read = respStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            if (isCancelled != null && isCancelled())
                            {
                                error = "已取消更新";
                                return false;
                            }

                            downloadedBytes += read;
                            if (downloadedBytes > MaxValidExeBytes)
                            {
                                error = "下载文件体积异常，已中止更新";
                                return false;
                            }

                            fs.Write(buffer, 0, read);

                            long nowTicks = DateTime.UtcNow.Ticks;
                            if (nowTicks - lastReportTicks >= reportIntervalTicks)
                            {
                                lastReportTicks = nowTicks;
                                int pct = totalBytes > 0
                                    ? (int)Math.Min(99L, (downloadedBytes * 100L) / totalBytes)
                                    : -1;
                                ReportProgressSafe(onProgress, pct, downloadedBytes, totalBytes, null);
                            }
                        }
                        fs.Flush();
                    }
                }

                if (isCancelled != null && isCancelled())
                {
                    error = "已取消更新";
                    return false;
                }

                ReportProgressSafe(onProgress, 100, downloadedBytes, totalBytes > 0 ? totalBytes : downloadedBytes, "正在校验文件完整性...");

                if (downloadedBytes < MinValidExeBytes)
                {
                    error = "下载的文件过小或无效 (" + downloadedBytes + " 字节)";
                    return false;
                }

                if (info.ExpectedSize > 0 && downloadedBytes != info.ExpectedSize)
                {
                    error = string.Format("文件大小不匹配 (预期 {0} 字节，实际 {1} 字节)", info.ExpectedSize, downloadedBytes);
                    return false;
                }

                if (!HasValidPeHeader(tempPath))
                {
                    error = "下载的文件不是有效的 Windows 可执行程序";
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(info.ChecksumUrl))
                {
                    ReportProgressSafe(onProgress, 100, downloadedBytes, totalBytes, "正在校验 SHA-256...");
                    string expectedHash;
                    bool checksumNotFound;
                    string checksumErr;
                    if (TryFetchExpectedExeSha256(info.ChecksumUrl, out expectedHash, out checksumNotFound, out checksumErr))
                    {
                        string actualHash = ComputeFileSha256Hex(tempPath);
                        if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                        {
                            error = "SHA-256 校验失败，文件可能已损坏，已取消更新";
                            AppLogger.Error("UPDATER", string.Format("SHA-256 校验不匹配: 预期={0}, 实际={1}", expectedHash, actualHash));
                            return false;
                        }
                        AppLogger.Info("UPDATER", "更新文件 SHA-256 校验通过: " + actualHash);
                    }
                    else if (checksumNotFound && !info.ChecksumAssetPresent)
                    {
                        AppLogger.Warn("UPDATER", "该 Release 未提供 SHA256SUMS.txt，已通过 PE 头与体积校验");
                    }
                    else
                    {
                        error = "SHA-256 校验文件获取失败: " + checksumErr;
                        return false;
                    }
                }

                stagedExePath = tempPath;
                downloadOk = true;
                return true;
            }
            catch (Exception ex)
            {
                if (isCancelled != null && isCancelled())
                {
                    error = "已取消更新";
                }
                else
                {
                    error = FormatNetworkError(ex);
                }
                return false;
            }
            finally
            {
                if (!downloadOk)
                {
                    TryDeleteFileQuiet(tempPath);
                }
            }
        }

        public static bool SwapExecutableInPlace(string stagedExePath, out string currentExePath, out string error)
        {
            currentExePath = GetCurrentExecutablePath();
            error = null;

            if (string.IsNullOrWhiteSpace(stagedExePath) || !File.Exists(stagedExePath))
            {
                error = "未找到已下载的更新文件";
                return false;
            }

            string backupPath = currentExePath + ".old";
            if (File.Exists(backupPath))
            {
                try
                {
                    File.Delete(backupPath);
                }
                catch
                {
                    backupPath = currentExePath + ".old." + Process.GetCurrentProcess().Id;
                    TryDeleteFileQuiet(backupPath);
                }
            }

            bool movedCurrent = false;
            Exception moveEx = null;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    File.Move(currentExePath, backupPath);
                    movedCurrent = true;
                    break;
                }
                catch (Exception ex)
                {
                    moveEx = ex;
                    Thread.Sleep(120);
                }
            }

            if (!movedCurrent)
            {
                TryDeleteFileQuiet(stagedExePath);
                error = "无法替换当前程序文件: " + (moveEx != null ? moveEx.Message : "文件被占用");
                return false;
            }

            try
            {
                File.Move(stagedExePath, currentExePath);
                return true;
            }
            catch (Exception ex)
            {
                // Roll back so the user is never left without TunGuard.exe
                try
                {
                    if (!File.Exists(currentExePath) && File.Exists(backupPath))
                    {
                        File.Move(backupPath, currentExePath);
                    }
                }
                catch
                {
                }
                TryDeleteFileQuiet(stagedExePath);
                error = "写入新版本文件失败（已回滚旧版本）: " + ex.Message;
                return false;
            }
        }

        public static void LaunchRestartedProcess(string exePath)
        {
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            {
                return;
            }

            string workDir = Path.GetDirectoryName(exePath);
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    WorkingDirectory = !string.IsNullOrEmpty(workDir) ? workDir : AppDomain.CurrentDomain.BaseDirectory,
                    UseShellExecute = true
                };
                Process.Start(psi);
            }
            catch
            {
                try
                {
                    ProcessStartInfo fallback = new ProcessStartInfo
                    {
                        FileName = exePath,
                        WorkingDirectory = !string.IsNullOrEmpty(workDir) ? workDir : AppDomain.CurrentDomain.BaseDirectory,
                        UseShellExecute = false
                    };
                    Process.Start(fallback);
                }
                catch
                {
                }
            }
        }

        public static void CleanupStaleUpdateFilesAsync()
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    string exePath = GetCurrentExecutablePath();
                    string dir = Path.GetDirectoryName(exePath);
                    string exeName = Path.GetFileName(exePath);
                    if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(exeName) || !Directory.Exists(dir))
                    {
                        return;
                    }

                    Thread.Sleep(1500);
                    bool anyRemaining = DeleteMatchingFiles(dir, exeName + ".old*") | DeleteMatchingFiles(dir, exeName + ".new*");
                    if (anyRemaining)
                    {
                        Thread.Sleep(3000);
                        DeleteMatchingFiles(dir, exeName + ".old*");
                        DeleteMatchingFiles(dir, exeName + ".new*");
                    }
                }
                catch
                {
                }
            });
        }

        public static void OpenUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                return;
            }
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("APP", "无法打开浏览器链接 (" + url + "): " + ex.Message);
            }
        }

        public static string FormatReleaseNotesPreview(string rawBody, int maxLines, int maxChars)
        {
            if (string.IsNullOrWhiteSpace(rawBody))
            {
                return string.Empty;
            }

            string normalized = rawBody.Replace("\r\n", "\n").Replace('\r', '\n');
            string[] lines = normalized.Split('\n');
            StringBuilder sb = new StringBuilder(256);
            int added = 0;

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();
                if (line.Length == 0)
                {
                    continue;
                }
                if (line.StartsWith("### 校验信息", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("## 校验信息", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("**Full Changelog**", StringComparison.OrdinalIgnoreCase) ||
                    line == "---")
                {
                    break;
                }
                if (line.StartsWith("## TunGuard", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("### 变更内容", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("Windows x64 独立可执行文件", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                line = line.Replace("`", string.Empty);
                while (line.StartsWith("#"))
                {
                    line = line.Substring(1).TrimStart();
                }
                if (line.Length == 0)
                {
                    continue;
                }

                if (added >= maxLines || sb.Length + line.Length + 2 > maxChars)
                {
                    sb.AppendLine("...");
                    break;
                }

                sb.AppendLine(line);
                added++;
            }

            return sb.ToString().Trim();
        }

        public static string FormatBytesShort(long bytes)
        {
            if (bytes < 1024)
            {
                return bytes + " B";
            }
            if (bytes < 1024 * 1024)
            {
                return string.Format("{0:F0} KB", bytes / 1024.0);
            }
            return string.Format("{0:F2} MB", bytes / (1024.0 * 1024.0));
        }

        internal static bool TryParseSha256SumsForFile(string content, string targetFileName, out string sha256Hex)
        {
            sha256Hex = null;
            if (string.IsNullOrWhiteSpace(content) || string.IsNullOrWhiteSpace(targetFileName))
            {
                return false;
            }

            string[] lines = content.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();
                if (line.Length < 66)
                {
                    continue;
                }

                int wsIdx = line.IndexOfAny(new char[] { ' ', '\t' });
                if (wsIdx != 64)
                {
                    continue;
                }

                string hashPart = line.Substring(0, 64);
                string filePart = line.Substring(wsIdx).Trim().TrimStart('*').Trim();
                if (string.Equals(filePart, targetFileName, StringComparison.OrdinalIgnoreCase) &&
                    IsHexString(hashPart))
                {
                    sha256Hex = hashPart.ToLowerInvariant();
                    return true;
                }
            }
            return false;
        }

        private static bool TryCheckViaGitHubApi(
            Version current,
            out UpdateCheckResult result,
            out string error,
            out bool shouldFallback)
        {
            result = null;
            error = null;
            shouldFallback = false;

            try
            {
                HttpWebRequest req = CreateWebRequest(LatestReleaseApiUrl, ApiTimeoutMs, true);
                req.Accept = "application/vnd.github+json";

                string json;
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (Stream s = resp.GetResponseStream())
                using (StreamReader sr = new StreamReader(s, Encoding.UTF8))
                {
                    json = sr.ReadToEnd();
                }

                JavaScriptSerializer serializer = new JavaScriptSerializer();
                serializer.MaxJsonLength = 2 * 1024 * 1024;
                Dictionary<string, object> obj = serializer.DeserializeObject(json) as Dictionary<string, object>;
                if (obj == null)
                {
                    error = "GitHub 返回数据格式无效";
                    shouldFallback = true;
                    return false;
                }

                string tagName = GetDictString(obj, "tag_name");
                Version remoteVersion;
                if (!TryParseVersionTag(tagName, out remoteVersion))
                {
                    error = "无法解析最新版本号 (" + (tagName ?? "空") + ")";
                    shouldFallback = true;
                    return false;
                }

                string htmlUrl = GetDictString(obj, "html_url");
                if (string.IsNullOrWhiteSpace(htmlUrl))
                {
                    htmlUrl = RepoUrl + "/releases/tag/" + Uri.EscapeDataString(tagName);
                }

                string body = GetDictString(obj, "body") ?? string.Empty;
                string exeUrl = null;
                long exeSize = 0;
                string checksumUrl = null;
                bool checksumAssetPresent = false;

                object assetsVal;
                if (TryGetDictValue(obj, "assets", out assetsVal) && assetsVal != null)
                {
                    System.Collections.IEnumerable assetList = assetsVal as System.Collections.IEnumerable;
                    if (assetList != null)
                    {
                        foreach (object item in assetList)
                        {
                            Dictionary<string, object> asset = item as Dictionary<string, object>;
                            if (asset == null)
                            {
                                continue;
                            }
                            string name = GetDictString(asset, "name");
                            string dlUrl = GetDictString(asset, "browser_download_url");
                            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(dlUrl))
                            {
                                continue;
                            }

                            if (string.Equals(name, ReleaseAssetExeName, StringComparison.OrdinalIgnoreCase))
                            {
                                exeUrl = dlUrl;
                                exeSize = GetDictLong(asset, "size");
                            }
                            else if (string.Equals(name, ReleaseAssetChecksumName, StringComparison.OrdinalIgnoreCase))
                            {
                                checksumUrl = dlUrl;
                                checksumAssetPresent = true;
                            }
                        }
                    }
                }

                if (string.IsNullOrWhiteSpace(exeUrl))
                {
                    exeUrl = BuildDeterministicAssetUrl(tagName, ReleaseAssetExeName);
                }

                result = new UpdateCheckResult
                {
                    Success = true,
                    HasUpdate = remoteVersion > current,
                    CurrentVersion = current,
                    LatestVersion = remoteVersion,
                    LatestTag = tagName.Trim(),
                    ReleasePageUrl = htmlUrl,
                    DownloadUrl = exeUrl,
                    ChecksumUrl = checksumUrl,
                    ChecksumAssetPresent = checksumAssetPresent,
                    ExpectedSize = exeSize,
                    ReleaseNotes = body,
                    UsedRedirectFallback = false
                };
                return true;
            }
            catch (WebException wex)
            {
                HttpWebResponse httpResp = wex.Response as HttpWebResponse;
                if (httpResp != null)
                {
                    int code = (int)httpResp.StatusCode;
                    if (code == 403 || code == 429 || code >= 500)
                    {
                        shouldFallback = true;
                        error = "GitHub API 请求受限 (HTTP " + code + ")";
                        return false;
                    }
                    if (code == 404)
                    {
                        error = "仓库暂未发布任何 Release";
                        return false;
                    }
                    error = "GitHub API 返回 HTTP " + code;
                    return false;
                }
                error = FormatNetworkError(wex);
                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                shouldFallback = true;
                return false;
            }
        }

        private static bool TryCheckViaLatestRedirect(
            Version current,
            out UpdateCheckResult result,
            out string error)
        {
            result = null;
            error = null;

            try
            {
                HttpWebRequest req = CreateWebRequest(LatestReleaseWebUrl, ApiTimeoutMs, false);
                req.Method = "HEAD";

                string location = null;
                try
                {
                    using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                    {
                        location = resp.Headers["Location"];
                    }
                }
                catch (WebException wex)
                {
                    HttpWebResponse httpResp = wex.Response as HttpWebResponse;
                    if (httpResp != null)
                    {
                        location = httpResp.Headers["Location"];
                    }
                    else
                    {
                        error = FormatNetworkError(wex);
                        return false;
                    }
                }

                if (string.IsNullOrWhiteSpace(location))
                {
                    error = "未获取到 Release 重定向地址";
                    return false;
                }

                const string marker = "/releases/tag/";
                int idx = location.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (idx < 0)
                {
                    error = "仓库暂未发布可用版本";
                    return false;
                }

                string tag = location.Substring(idx + marker.Length);
                int qIdx = tag.IndexOfAny(new char[] { '?', '#', '/' });
                if (qIdx >= 0)
                {
                    tag = tag.Substring(0, qIdx);
                }
                tag = Uri.UnescapeDataString(tag).Trim();

                Version remoteVersion;
                if (!TryParseVersionTag(tag, out remoteVersion))
                {
                    error = "无法解析版本号: " + tag;
                    return false;
                }

                result = new UpdateCheckResult
                {
                    Success = true,
                    HasUpdate = remoteVersion > current,
                    CurrentVersion = current,
                    LatestVersion = remoteVersion,
                    LatestTag = tag,
                    ReleasePageUrl = RepoUrl + "/releases/tag/" + Uri.EscapeDataString(tag),
                    DownloadUrl = BuildDeterministicAssetUrl(tag, ReleaseAssetExeName),
                    ChecksumUrl = BuildDeterministicAssetUrl(tag, ReleaseAssetChecksumName),
                    ChecksumAssetPresent = false,
                    ExpectedSize = 0,
                    ReleaseNotes = string.Empty,
                    UsedRedirectFallback = true
                };
                return true;
            }
            catch (Exception ex)
            {
                error = FormatNetworkError(ex);
                return false;
            }
        }

        private static bool TryFetchExpectedExeSha256(
            string checksumUrl,
            out string expectedHash,
            out bool notFound,
            out string error)
        {
            expectedHash = null;
            notFound = false;
            error = null;

            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    HttpWebRequest req = CreateWebRequest(checksumUrl, ApiTimeoutMs, true);
                    using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                    using (Stream s = resp.GetResponseStream())
                    using (StreamReader sr = new StreamReader(s, Encoding.UTF8))
                    {
                        string content = sr.ReadToEnd();
                        if (TryParseSha256SumsForFile(content, ReleaseAssetExeName, out expectedHash))
                        {
                            return true;
                        }
                        error = "SHA256SUMS.txt 中未找到 " + ReleaseAssetExeName + " 的校验项";
                        return false;
                    }
                }
                catch (WebException wex)
                {
                    HttpWebResponse httpResp = wex.Response as HttpWebResponse;
                    if (httpResp != null && (int)httpResp.StatusCode == 404)
                    {
                        notFound = true;
                        error = "未找到校验文件 (HTTP 404)";
                        return false;
                    }
                    error = FormatNetworkError(wex);
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                }
            }
            return false;
        }

        private static string ComputeFileSha256Hex(string filePath)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] hash = sha.ComputeHash(fs);
                StringBuilder sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++)
                {
                    sb.Append(hash[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        private static bool HasValidPeHeader(string filePath)
        {
            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (fs.Length < 64)
                    {
                        return false;
                    }
                    int b0 = fs.ReadByte();
                    int b1 = fs.ReadByte();
                    return b0 == 'M' && b1 == 'Z';
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool IsHexString(string s)
        {
            if (string.IsNullOrEmpty(s))
            {
                return false;
            }
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!ok)
                {
                    return false;
                }
            }
            return true;
        }

        private static string BuildDeterministicAssetUrl(string tag, string assetName)
        {
            return RepoUrl + "/releases/download/" + Uri.EscapeDataString(tag) + "/" + Uri.EscapeDataString(assetName);
        }

        private static HttpWebRequest CreateWebRequest(string url, int timeoutMs, bool allowAutoRedirect)
        {
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET";
            req.UserAgent = "TunGuard/" + GetCurrentVersionText();
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.AllowAutoRedirect = allowAutoRedirect;
            req.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            return req;
        }

        private static void EnsureTlsEnabled()
        {
            if (Interlocked.CompareExchange(ref _tlsInitialized, 1, 0) != 0)
            {
                return;
            }
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            }
            catch
            {
            }
            try
            {
                // TLS 1.3 (12288) if supported by the host OS / .NET Framework patch level
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)12288;
            }
            catch
            {
            }
        }

        private static void StoreCache(UpdateCheckResult result)
        {
            if (result == null || !result.Success)
            {
                return;
            }
            lock (CacheLock)
            {
                _cachedResult = result;
                _cachedAtUtc = DateTime.UtcNow;
            }
        }

        private static bool DeleteMatchingFiles(string dir, string pattern)
        {
            bool remaining = false;
            try
            {
                string[] files = Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly);
                for (int i = 0; i < files.Length; i++)
                {
                    try
                    {
                        File.Delete(files[i]);
                    }
                    catch
                    {
                        remaining = true;
                    }
                }
            }
            catch
            {
            }
            return remaining;
        }

        private static void TryDeleteFileQuiet(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return;
            }
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
            }
        }

        private static void ReportProgressSafe(Action<int, long, long, string> onProgress, int percent, long bytesRead, long totalBytes, string phase)
        {
            if (onProgress == null)
            {
                return;
            }
            try
            {
                onProgress(percent, bytesRead, totalBytes, phase);
            }
            catch
            {
            }
        }

        private static string FormatNetworkError(Exception ex)
        {
            WebException wex = ex as WebException;
            if (wex != null)
            {
                HttpWebResponse resp = wex.Response as HttpWebResponse;
                if (resp != null)
                {
                    return "HTTP " + (int)resp.StatusCode + " " + resp.StatusDescription;
                }
                if (wex.Status == WebExceptionStatus.Timeout)
                {
                    return "连接 GitHub 超时";
                }
                if (wex.Status == WebExceptionStatus.NameResolutionFailure)
                {
                    return "无法解析 GitHub 域名";
                }
                if (wex.Status == WebExceptionStatus.ConnectFailure)
                {
                    return "无法连接到 GitHub";
                }
            }
            return ex != null ? ex.Message : "网络错误";
        }

        private static bool TryGetDictValue(Dictionary<string, object> dict, string key, out object value)
        {
            if (dict.TryGetValue(key, out value))
            {
                return true;
            }
            foreach (KeyValuePair<string, object> kv in dict)
            {
                if (string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase))
                {
                    value = kv.Value;
                    return true;
                }
            }
            value = null;
            return false;
        }

        private static string GetDictString(Dictionary<string, object> dict, string key)
        {
            object val;
            if (TryGetDictValue(dict, key, out val) && val != null)
            {
                return val.ToString();
            }
            return null;
        }

        private static long GetDictLong(Dictionary<string, object> dict, string key)
        {
            object val;
            if (!TryGetDictValue(dict, key, out val) || val == null)
            {
                return 0;
            }
            try
            {
                return Convert.ToInt64(val);
            }
            catch
            {
                return 0;
            }
        }
    }

    internal struct GuardAlertPayload
    {
        public string Title;
        public string AppNames;
        public string Reason;
        public string ActiveChain;
        public string AllowedNodesText;
        public string ActionText;
        public string HintText;
        public bool IsSevere;
        public bool IsKillEvent;
        public int KilledDelta;
        public double FirstPassMs;
    }

    internal sealed class GuardAlertForm : Form
    {
        private const int AutoCloseSeconds = 10;
        private const int CS_DROPSHADOW = 0x00020000;
        private const int WS_EX_TOPMOST = 0x00000008;
        private const int WS_EX_TOOLWINDOW = 0x00000080;
        private const uint SWP_NOSIZE = 0x0001;
        private const uint SWP_NOMOVE = 0x0002;
        private const uint SWP_NOACTIVATE = 0x0010;
        private const int WM_NCLBUTTONDOWN = 0xA1;
        private const int HTCAPTION = 0x2;
        private static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetWindowPos(
            IntPtr hWnd,
            IntPtr hWndInsertAfter,
            int x,
            int y,
            int cx,
            int cy,
            uint uFlags);

        [DllImport("user32.dll")]
        private static extern bool ReleaseCapture();

        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        private readonly Action _onOpenSettings;
        private readonly Action _onOpenLogs;
        private readonly Font _titleFont;
        private readonly Font _boldLabelFont;
        private readonly Font _hintFont;
        private readonly Font _closeXFont;
        private readonly System.Windows.Forms.Timer _countdownTimer;

        private readonly Panel _badgePanel;
        private readonly Label _lblTitle;
        private readonly Button _btnCloseX;
        private readonly Label _lblReasonVal;
        private readonly Label _lblChainCaption;
        private readonly Label _lblChainVal;
        private readonly Label _lblAllowedCaption;
        private readonly Label _lblAllowedVal;
        private readonly Label _lblActionVal;
        private readonly Label _lblHint;
        private readonly Button _btnSettings;
        private readonly Button _btnLogs;
        private readonly Button _btnAck;

        private Color _accentColor = Color.FromArgb(220, 38, 38);
        private int _remainingSeconds = AutoCloseSeconds;
        private int _burstKilledTotal;
        private bool _positionedOnce;
        private bool _dismissedByUser;

        public bool DismissedByUser
        {
            get { return _dismissedByUser; }
        }

        protected override bool ShowWithoutActivation
        {
            get { return true; }
        }

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                cp.ClassStyle |= CS_DROPSHADOW;
                cp.ExStyle |= WS_EX_TOPMOST | WS_EX_TOOLWINDOW;
                return cp;
            }
        }

        public GuardAlertForm(Action onOpenSettings, Action onOpenLogs)
        {
            _onOpenSettings = onOpenSettings;
            _onOpenLogs = onOpenLogs;

            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            ShowInTaskbar = false;
            TopMost = true;
            DoubleBuffered = true;
            BackColor = Color.White;
            Font = new Font("Microsoft YaHei UI", 9.2f);
            AutoScaleMode = AutoScaleMode.Font;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(1, 6, 1, 1);

            _titleFont = new Font("Microsoft YaHei UI", 10.8f, FontStyle.Bold);
            _boldLabelFont = new Font(Font, FontStyle.Bold);
            _hintFont = new Font("Microsoft YaHei UI", 8.6f);
            _closeXFont = new Font("Microsoft YaHei UI", 11f);

            TableLayoutPanel root = new TableLayoutPanel
            {
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(16, 12, 16, 14),
                BackColor = Color.White,
                Margin = new Padding(0)
            };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // header
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // detail card
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // hint
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // buttons

            // Header row (draggable)
            TableLayoutPanel header = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 3,
                RowCount = 1,
                Margin = new Padding(0, 0, 0, 10),
                BackColor = Color.White
            };
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            _badgePanel = new Panel
            {
                Size = new Size(28, 28),
                Margin = new Padding(0, 1, 10, 0),
                BackColor = Color.Transparent
            };
            _badgePanel.Paint += OnBadgePaint;

            _lblTitle = new Label
            {
                AutoSize = true,
                MaximumSize = new Size(370, 0),
                Font = _titleFont,
                ForeColor = Color.FromArgb(15, 23, 42),
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 3, 8, 0)
            };

            _btnCloseX = new Button
            {
                Text = "×",
                FlatStyle = FlatStyle.Flat,
                Size = new Size(28, 26),
                Font = _closeXFont,
                ForeColor = Color.FromArgb(100, 116, 139),
                BackColor = Color.White,
                TabStop = false,
                Cursor = Cursors.Hand,
                Margin = new Padding(0)
            };
            _btnCloseX.FlatAppearance.BorderSize = 0;
            _btnCloseX.FlatAppearance.MouseOverBackColor = Color.FromArgb(241, 245, 249);
            _btnCloseX.Click += (s, e) => DismissByUser();

            header.Controls.Add(_badgePanel, 0, 0);
            header.Controls.Add(_lblTitle, 1, 0);
            header.Controls.Add(_btnCloseX, 2, 0);
            AttachDragHandler(header);
            AttachDragHandler(_badgePanel);
            AttachDragHandler(_lblTitle);
            root.Controls.Add(header, 0, 0);

            // Details card
            TableLayoutPanel card = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 2,
                RowCount = 4,
                BackColor = Color.FromArgb(248, 250, 252),
                Padding = new Padding(12, 10, 12, 10),
                Margin = new Padding(0, 0, 0, 10)
            };
            card.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            card.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            card.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            card.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            card.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            card.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            Label lblReasonCap = CreateCaptionLabel("拦截原因:");
            _lblReasonVal = CreateValueLabel(Color.FromArgb(185, 28, 28), true);

            _lblChainCaption = CreateCaptionLabel("当前出口:");
            _lblChainVal = CreateValueLabel(Color.FromArgb(30, 41, 59), false);

            _lblAllowedCaption = CreateCaptionLabel("允许节点:");
            _lblAllowedVal = CreateValueLabel(Color.FromArgb(21, 128, 61), false);

            Label lblActionCap = CreateCaptionLabel("执行动作:");
            _lblActionVal = CreateValueLabel(Color.FromArgb(51, 65, 85), false);

            card.Controls.Add(lblReasonCap, 0, 0);
            card.Controls.Add(_lblReasonVal, 1, 0);
            card.Controls.Add(_lblChainCaption, 0, 1);
            card.Controls.Add(_lblChainVal, 1, 1);
            card.Controls.Add(_lblAllowedCaption, 0, 2);
            card.Controls.Add(_lblAllowedVal, 1, 2);
            card.Controls.Add(lblActionCap, 0, 3);
            card.Controls.Add(_lblActionVal, 1, 3);
            root.Controls.Add(card, 0, 1);

            // Hint row
            _lblHint = new Label
            {
                AutoSize = true,
                MaximumSize = new Size(440, 0),
                Font = _hintFont,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(2, 0, 2, 12)
            };
            root.Controls.Add(_lblHint, 0, 2);

            // Footer buttons
            TableLayoutPanel footer = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            FlowLayoutPanel leftBtns = new FlowLayoutPanel
            {
                AutoSize = true,
                WrapContents = false,
                Margin = new Padding(0)
            };

            _btnSettings = new Button
            {
                Text = "打开控制面板",
                AutoSize = true,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(241, 245, 249),
                ForeColor = Color.FromArgb(30, 41, 59),
                Padding = new Padding(8, 3, 8, 3),
                Cursor = Cursors.Hand,
                Margin = new Padding(0, 0, 8, 0)
            };
            _btnSettings.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
            _btnSettings.Click += (s, e) =>
            {
                Action cb = _onOpenSettings;
                DismissByUser();
                if (cb != null)
                {
                    cb();
                }
            };

            _btnLogs = new Button
            {
                Text = "查看日志",
                AutoSize = true,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(241, 245, 249),
                ForeColor = Color.FromArgb(30, 41, 59),
                Padding = new Padding(8, 3, 8, 3),
                Cursor = Cursors.Hand,
                Margin = new Padding(0)
            };
            _btnLogs.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
            _btnLogs.Click += (s, e) =>
            {
                Action cb = _onOpenLogs;
                DismissByUser();
                if (cb != null)
                {
                    cb();
                }
            };

            leftBtns.Controls.Add(_btnSettings);
            leftBtns.Controls.Add(_btnLogs);

            _btnAck = new Button
            {
                Text = "知道了 (10s)",
                AutoSize = true,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(220, 38, 38),
                ForeColor = Color.White,
                Padding = new Padding(12, 3, 12, 3),
                Cursor = Cursors.Hand,
                Margin = new Padding(12, 0, 0, 0)
            };
            _btnAck.FlatAppearance.BorderSize = 0;
            _btnAck.Click += (s, e) => DismissByUser();

            footer.Controls.Add(leftBtns, 0, 0);
            footer.Controls.Add(_btnAck, 1, 0);
            root.Controls.Add(footer, 0, 3);

            Controls.Add(root);

            KeyPreview = true;
            KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Escape)
                {
                    DismissByUser();
                }
            };

            _countdownTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            _countdownTimer.Tick += OnCountdownTick;
        }

        private Label CreateCaptionLabel(string text)
        {
            return new Label
            {
                Text = text,
                AutoSize = true,
                Font = _boldLabelFont,
                ForeColor = Color.FromArgb(71, 85, 105),
                Margin = new Padding(0, 2, 10, 4)
            };
        }

        private Label CreateValueLabel(Color foreColor, bool bold)
        {
            return new Label
            {
                AutoSize = true,
                MaximumSize = new Size(345, 0),
                Font = bold ? _boldLabelFont : Font,
                ForeColor = foreColor,
                Margin = new Padding(0, 2, 0, 4)
            };
        }

        private void AttachDragHandler(Control control)
        {
            control.MouseDown += (s, e) =>
            {
                if (e.Button == MouseButtons.Left)
                {
                    ReleaseCapture();
                    SendMessage(Handle, WM_NCLBUTTONDOWN, new IntPtr(HTCAPTION), IntPtr.Zero);
                }
            };
        }

        private void OnBadgePaint(object sender, PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (SolidBrush brush = new SolidBrush(_accentColor))
            {
                e.Graphics.FillEllipse(brush, 1, 1, 25, 25);
            }
            using (Pen whitePen = new Pen(Color.White, 2.6f))
            {
                whitePen.StartCap = LineCap.Round;
                whitePen.EndCap = LineCap.Round;
                e.Graphics.DrawLine(whitePen, 13.5f, 7.5f, 13.5f, 15.5f);
            }
            using (SolidBrush whiteBrush = new SolidBrush(Color.White))
            {
                e.Graphics.FillEllipse(whiteBrush, 12.1f, 18.2f, 2.9f, 2.9f);
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            using (SolidBrush topBar = new SolidBrush(_accentColor))
            {
                e.Graphics.FillRectangle(topBar, 0, 0, Width, 5);
            }
            using (Pen borderPen = new Pen(Color.FromArgb(203, 213, 225), 1f))
            {
                e.Graphics.DrawRectangle(borderPen, 0, 0, Width - 1, Height - 1);
            }
        }

        public void ShowOrUpdate(GuardAlertPayload payload, bool accumulateBurst)
        {
            _dismissedByUser = false;
            _accentColor = payload.IsSevere
                ? Color.FromArgb(220, 38, 38)
                : Color.FromArgb(217, 119, 6);
            _btnAck.BackColor = _accentColor;
            _lblReasonVal.ForeColor = payload.IsSevere
                ? Color.FromArgb(185, 28, 28)
                : Color.FromArgb(180, 83, 9);

            if (payload.IsKillEvent)
            {
                _burstKilledTotal = accumulateBurst ? (_burstKilledTotal + payload.KilledDelta) : payload.KilledDelta;
            }
            else
            {
                _burstKilledTotal = 0;
            }

            _lblTitle.Text = payload.Title ?? "TunGuard 拦截提示";
            _lblReasonVal.Text = string.IsNullOrEmpty(payload.Reason) ? "当前状态不满足放行条件" : payload.Reason;

            bool hasChain = !string.IsNullOrEmpty(payload.ActiveChain);
            _lblChainCaption.Visible = hasChain;
            _lblChainVal.Visible = hasChain;
            _lblChainVal.Text = hasChain ? payload.ActiveChain : string.Empty;

            bool hasAllowed = !string.IsNullOrEmpty(payload.AllowedNodesText);
            _lblAllowedCaption.Visible = hasAllowed;
            _lblAllowedVal.Visible = hasAllowed;
            _lblAllowedVal.Text = hasAllowed ? payload.AllowedNodesText : string.Empty;

            if (payload.IsKillEvent && _burstKilledTotal > 0)
            {
                string apps = string.IsNullOrEmpty(payload.AppNames) ? "受控应用" : payload.AppNames;
                _lblActionVal.Text = string.Format(
                    "已终止 {0} 共 {1} 个进程（首轮耗时 {2:F2} ms）",
                    apps,
                    _burstKilledTotal,
                    payload.FirstPassMs);
            }
            else
            {
                _lblActionVal.Text = payload.ActionText ?? string.Empty;
            }

            _lblHint.Text = payload.HintText ?? string.Empty;

            _remainingSeconds = AutoCloseSeconds;
            UpdateAckButtonText();
            _countdownTimer.Stop();
            _countdownTimer.Start();

            PerformLayout();
            _badgePanel.Invalidate();
            Invalidate();

            if (!Visible)
            {
                PositionOnActiveScreen();
                Show();
            }
            else if (!_positionedOnce)
            {
                PositionOnActiveScreen();
            }

            EnsureTopMostNoActivate();
        }

        private void PositionOnActiveScreen()
        {
            Rectangle area = Screen.FromPoint(Cursor.Position).WorkingArea;
            int x = area.Left + (area.Width - Width) / 2;
            int y = area.Top + Math.Max(48, Math.Min(140, area.Height / 6));
            if (x < area.Left + 12) x = area.Left + 12;
            if (x + Width > area.Right - 12) x = Math.Max(area.Left + 12, area.Right - Width - 12);
            if (y + Height > area.Bottom - 12) y = Math.Max(area.Top + 12, area.Bottom - Height - 12);
            Location = new Point(x, y);
            _positionedOnce = true;
        }

        private void EnsureTopMostNoActivate()
        {
            if (IsHandleCreated && !IsDisposed)
            {
                SetWindowPos(Handle, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            }
        }

        private void OnCountdownTick(object sender, EventArgs e)
        {
            if (IsDisposed || !Visible)
            {
                _countdownTimer.Stop();
                return;
            }
            // Pause auto-close while cursor is hovering over the popup
            if (Bounds.Contains(Cursor.Position))
            {
                return;
            }
            _remainingSeconds--;
            if (_remainingSeconds <= 0)
            {
                _countdownTimer.Stop();
                Close();
                return;
            }
            UpdateAckButtonText();
        }

        private void UpdateAckButtonText()
        {
            _btnAck.Text = string.Format("知道了 ({0}s)", _remainingSeconds);
        }

        private void DismissByUser()
        {
            _dismissedByUser = true;
            _countdownTimer.Stop();
            Close();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_countdownTimer != null)
                {
                    _countdownTimer.Stop();
                    _countdownTimer.Dispose();
                }
                if (_titleFont != null) _titleFont.Dispose();
                if (_boldLabelFont != null) _boldLabelFont.Dispose();
                if (_hintFont != null) _hintFont.Dispose();
                if (_closeXFont != null) _closeXFont.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    internal delegate bool LogDirectoryChangeHandler(
        string newConfiguredDir,
        bool migrateExisting,
        out int migratedCount,
        out string effectiveDir,
        out string error);

    internal sealed class LogViewerForm : Form
    {
        private const int MaxDisplayedLines = 2000;
        private const int MaxLiveLinesBeforeReload = 2500;

        private sealed class LogFileItem
        {
            public string FullPath;
            public string DisplayText;
            public bool IsToday;

            public override string ToString()
            {
                return DisplayText;
            }
        }

        private readonly LogDirectoryChangeHandler _onChangeLogDir;
        private readonly Font _boldFont;
        private readonly Font _monoFont;
        private readonly System.Windows.Forms.Timer _searchDebounceTimer;

        private readonly TextBox _txtLogDir;
        private readonly Label _lblDirBadge;
        private readonly Button _btnChangeDir;
        private readonly Button _btnResetDir;
        private readonly Button _btnOpenDir;

        private readonly ComboBox _cmbFiles;
        private readonly ComboBox _cmbLevel;
        private readonly TextBox _txtSearch;
        private readonly CheckBox _chkAutoScroll;
        private readonly Button _btnRefresh;
        private readonly Button _btnCopy;
        private readonly Button _btnClear;

        private readonly RichTextBox _rtbLog;
        private readonly Label _lblStatus;
        private readonly Button _btnClose;

        private string _activeFilePath = string.Empty;
        private bool _viewingTodayFile;
        private bool _suppressUiEvents;
        private int _displayedLines;
        private int _totalFileLines;
        private long _currentFileBytes;

        public LogViewerForm(LogDirectoryChangeHandler onChangeLogDir, Icon windowIcon)
        {
            _onChangeLogDir = onChangeLogDir;

            Text = "运行日志 - TunGuard";
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9f);
            _boldFont = new Font(Font, FontStyle.Bold);
            _monoFont = CreateMonoFont();
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(920, 600);
            MinimumSize = new Size(740, 460);
            if (windowIcon != null)
            {
                Icon = windowIcon;
            }

            _searchDebounceTimer = new System.Windows.Forms.Timer { Interval = 100 };
            _searchDebounceTimer.Tick += (s, e) =>
            {
                _searchDebounceTimer.Stop();
                LoadSelectedFileContent();
            };

            TableLayoutPanel root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(12)
            };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 0: Log directory bar
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 1: Filter toolbar
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f)); // 2: Log viewer
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 3: Footer status bar

            // Row 0: Log directory bar
            TableLayoutPanel dirPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 6,
                RowCount = 1,
                BackColor = Color.FromArgb(245, 247, 250),
                Padding = new Padding(10, 7, 10, 7),
                Margin = new Padding(0, 0, 0, 8)
            };
            dirPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            dirPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            dirPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            dirPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            dirPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            dirPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            Label lblDir = new Label
            {
                Text = "日志存放目录:",
                AutoSize = true,
                Font = _boldFont,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 4, 8, 2)
            };

            _txtLogDir = new TextBox
            {
                ReadOnly = true,
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                Margin = new Padding(0, 2, 6, 2)
            };

            _lblDirBadge = new Label
            {
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(0, 4, 8, 2)
            };

            _btnChangeDir = new Button
            {
                Text = "修改目录...",
                AutoSize = true,
                Margin = new Padding(0, 0, 6, 0)
            };
            _btnChangeDir.Click += OnChangeDirClick;

            _btnResetDir = new Button
            {
                Text = "恢复默认",
                AutoSize = true,
                Margin = new Padding(0, 0, 6, 0)
            };
            _btnResetDir.Click += OnResetDirClick;

            _btnOpenDir = new Button
            {
                Text = "打开目录",
                AutoSize = true,
                Margin = new Padding(0)
            };
            _btnOpenDir.Click += OnOpenDirClick;

            dirPanel.Controls.Add(lblDir, 0, 0);
            dirPanel.Controls.Add(_txtLogDir, 1, 0);
            dirPanel.Controls.Add(_lblDirBadge, 2, 0);
            dirPanel.Controls.Add(_btnChangeDir, 3, 0);
            dirPanel.Controls.Add(_btnResetDir, 4, 0);
            dirPanel.Controls.Add(_btnOpenDir, 5, 0);
            root.Controls.Add(dirPanel, 0, 0);

            // Row 1: Filter & actions toolbar
            TableLayoutPanel filterPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 10,
                RowCount = 1,
                Margin = new Padding(0, 0, 0, 8)
            };
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); // 0: file label
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 210f)); // 1: file combo
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); // 2: level label
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 88f)); // 3: level combo
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); // 4: search label
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f)); // 5: search box
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); // 6: auto scroll
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); // 7: refresh
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); // 8: copy
            filterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); // 9: clear

            Label lblFile = new Label
            {
                Text = "文件:",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 4, 2)
            };

            _cmbFiles = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 10, 2)
            };
            _cmbFiles.SelectedIndexChanged += (s, e) =>
            {
                if (!_suppressUiEvents)
                {
                    LoadSelectedFileContent();
                }
            };

            Label lblLevel = new Label
            {
                Text = "级别:",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 4, 2)
            };

            _cmbLevel = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 10, 2)
            };
            _cmbLevel.Items.AddRange(new object[] { "全部", "INFO", "WARN", "ERROR" });
            _cmbLevel.SelectedIndex = 0;
            _cmbLevel.SelectedIndexChanged += (s, e) =>
            {
                if (!_suppressUiEvents)
                {
                    LoadSelectedFileContent();
                }
            };

            Label lblSearch = new Label
            {
                Text = "搜索:",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 4, 2)
            };

            _txtSearch = new TextBox
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 10, 2)
            };
            _txtSearch.TextChanged += (s, e) =>
            {
                _searchDebounceTimer.Stop();
                _searchDebounceTimer.Start();
            };

            _chkAutoScroll = new CheckBox
            {
                Text = "实时滚动",
                AutoSize = true,
                Checked = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 4, 8, 2)
            };

            _btnRefresh = new Button
            {
                Text = "刷新",
                AutoSize = true,
                Margin = new Padding(0, 0, 6, 0)
            };
            _btnRefresh.Click += (s, e) => RefreshAll();

            _btnCopy = new Button
            {
                Text = "复制",
                AutoSize = true,
                Margin = new Padding(0, 0, 6, 0)
            };
            _btnCopy.Click += OnCopyClick;

            _btnClear = new Button
            {
                Text = "清空",
                AutoSize = true,
                Margin = new Padding(0)
            };
            _btnClear.Click += OnClearClick;

            filterPanel.Controls.Add(lblFile, 0, 0);
            filterPanel.Controls.Add(_cmbFiles, 1, 0);
            filterPanel.Controls.Add(lblLevel, 2, 0);
            filterPanel.Controls.Add(_cmbLevel, 3, 0);
            filterPanel.Controls.Add(lblSearch, 4, 0);
            filterPanel.Controls.Add(_txtSearch, 5, 0);
            filterPanel.Controls.Add(_chkAutoScroll, 6, 0);
            filterPanel.Controls.Add(_btnRefresh, 7, 0);
            filterPanel.Controls.Add(_btnCopy, 8, 0);
            filterPanel.Controls.Add(_btnClear, 9, 0);
            root.Controls.Add(filterPanel, 0, 1);

            // Row 2: RichTextBox log content
            _rtbLog = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                WordWrap = false,
                DetectUrls = false,
                ScrollBars = RichTextBoxScrollBars.Both,
                BorderStyle = BorderStyle.FixedSingle,
                BackColor = Color.FromArgb(24, 28, 36),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = _monoFont,
                HideSelection = false,
                Margin = new Padding(0, 0, 0, 8)
            };
            root.Controls.Add(_rtbLog, 0, 2);

            // Row 3: Bottom status & close button
            TableLayoutPanel footer = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            _lblStatus = new Label
            {
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(0, 5, 8, 0)
            };

            _btnClose = new Button
            {
                Text = "关闭",
                AutoSize = true,
                Padding = new Padding(14, 3, 14, 3),
                DialogResult = DialogResult.Cancel,
                Margin = new Padding(0)
            };
            _btnClose.Click += (s, e) => Close();

            footer.Controls.Add(_lblStatus, 0, 0);
            footer.Controls.Add(_btnClose, 1, 0);
            root.Controls.Add(footer, 0, 3);

            Controls.Add(root);
            CancelButton = _btnClose;

            Load += (s, e) =>
            {
                AppLogger.EntryLogged += OnLiveLogEntry;
                RefreshAll();
            };
            FormClosed += (s, e) =>
            {
                AppLogger.EntryLogged -= OnLiveLogEntry;
            };
        }

        private static Font CreateMonoFont()
        {
            try
            {
                return new Font("Consolas", 9.5f);
            }
            catch
            {
                return new Font("Microsoft YaHei UI", 9f);
            }
        }

        public void SyncLogDirectoryChanged()
        {
            if (IsDisposed)
            {
                return;
            }
            RefreshAll();
        }

        private void RefreshAll()
        {
            AppLogger.Flush(500);
            UpdateDirectoryBar();
            PopulateFileList();
            LoadSelectedFileContent();
        }

        private void UpdateDirectoryBar()
        {
            string effective = AppLogger.EffectiveLogDirectory;
            bool isDefault = AppLogger.IsUsingDefaultDirectory;
            _txtLogDir.Text = effective;
            _lblDirBadge.Text = isDefault ? "(默认)" : "(自定义)";
            _btnResetDir.Enabled = !isDefault;
        }

        private void PopulateFileList()
        {
            string dir = AppLogger.EffectiveLogDirectory;
            string todayPath = AppLogger.GetCurrentLogFilePath();
            string prevSelected = _activeFilePath;

            List<string> files = AppLogger.ListLogFiles(dir);
            bool hasTodayInList = false;
            for (int i = 0; i < files.Count; i++)
            {
                if (string.Equals(files[i], todayPath, StringComparison.OrdinalIgnoreCase))
                {
                    hasTodayInList = true;
                    break;
                }
            }
            if (!hasTodayInList)
            {
                files.Insert(0, todayPath);
            }

            _suppressUiEvents = true;
            _cmbFiles.BeginUpdate();
            try
            {
                _cmbFiles.Items.Clear();
                int restoreIdx = 0;
                for (int i = 0; i < files.Count; i++)
                {
                    string path = files[i];
                    bool isToday = string.Equals(path, todayPath, StringComparison.OrdinalIgnoreCase);
                    string name = Path.GetFileName(path);
                    string label = isToday ? (name + " [今天]") : name;
                    _cmbFiles.Items.Add(new LogFileItem
                    {
                        FullPath = path,
                        DisplayText = label,
                        IsToday = isToday
                    });
                    if (!string.IsNullOrEmpty(prevSelected) &&
                        string.Equals(path, prevSelected, StringComparison.OrdinalIgnoreCase))
                    {
                        restoreIdx = i;
                    }
                }
                if (_cmbFiles.Items.Count > 0)
                {
                    _cmbFiles.SelectedIndex = restoreIdx;
                }
            }
            finally
            {
                _cmbFiles.EndUpdate();
                _suppressUiEvents = false;
            }
        }

        private void LoadSelectedFileContent()
        {
            LogFileItem item = _cmbFiles.SelectedItem as LogFileItem;
            if (item == null)
            {
                _activeFilePath = string.Empty;
                _viewingTodayFile = false;
                _rtbLog.Clear();
                _lblStatus.Text = "暂无日志文件";
                return;
            }

            _activeFilePath = item.FullPath;
            _viewingTodayFile = item.IsToday;

            int totalLines;
            long fileBytes;
            string[] lines = AppLogger.ReadLogFileLinesSafe(_activeFilePath, MaxDisplayedLines, out totalLines, out fileBytes);
            _totalFileLines = totalLines;
            _currentFileBytes = fileBytes;

            string levelFilter = _cmbLevel.SelectedItem != null ? _cmbLevel.SelectedItem.ToString() : "全部";
            string search = _txtSearch.Text != null ? _txtSearch.Text.Trim() : string.Empty;

            List<string> matched = new List<string>(lines.Length);
            for (int i = 0; i < lines.Length; i++)
            {
                if (LineMatchesFilter(lines[i], levelFilter, search))
                {
                    matched.Add(lines[i]);
                }
            }
            _displayedLines = matched.Count;

            if (matched.Count == 0)
            {
                _rtbLog.Clear();
                _rtbLog.ForeColor = Color.FromArgb(148, 163, 184);
                _rtbLog.Text = File.Exists(_activeFilePath)
                    ? "（当前筛选条件下无匹配日志记录）"
                    : "（今日日志文件尚未生成记录）";
            }
            else
            {
                _rtbLog.Rtf = BuildColoredRtf(matched);
                if (_chkAutoScroll.Checked)
                {
                    _rtbLog.SelectionStart = _rtbLog.TextLength;
                    _rtbLog.ScrollToCaret();
                }
            }

            UpdateStatusLabel();
        }

        private void OnLiveLogEntry(LogEntry entry)
        {
            if (IsDisposed || !IsHandleCreated)
            {
                return;
            }
            try
            {
                BeginInvoke((Action)(() => AppendLiveEntryOnUi(entry)));
            }
            catch
            {
            }
        }

        private void AppendLiveEntryOnUi(LogEntry entry)
        {
            if (IsDisposed || !_viewingTodayFile)
            {
                return;
            }
            string expectedToday = AppLogger.GetLogFilePathForDate(AppLogger.EffectiveLogDirectory, entry.Timestamp);
            if (!string.Equals(expectedToday, _activeFilePath, StringComparison.OrdinalIgnoreCase))
            {
                RefreshAll();
                return;
            }

            string levelFilter = _cmbLevel.SelectedItem != null ? _cmbLevel.SelectedItem.ToString() : "全部";
            string search = _txtSearch.Text != null ? _txtSearch.Text.Trim() : string.Empty;
            _totalFileLines++;

            if (!LineMatchesFilter(entry.FormattedLine, levelFilter, search))
            {
                UpdateStatusLabel();
                return;
            }

            if (_displayedLines == 0)
            {
                _rtbLog.Clear();
            }

            if (_displayedLines >= MaxLiveLinesBeforeReload)
            {
                LoadSelectedFileContent();
                return;
            }

            bool shouldScroll = _chkAutoScroll.Checked;
            int savedStart = _rtbLog.SelectionStart;
            int savedLen = _rtbLog.SelectionLength;

            _rtbLog.SelectionStart = _rtbLog.TextLength;
            _rtbLog.SelectionLength = 0;
            _rtbLog.SelectionColor = GetColorForLevel(entry.Level);
            _rtbLog.AppendText(entry.FormattedLine + "\n");
            _displayedLines++;

            if (shouldScroll)
            {
                _rtbLog.SelectionStart = _rtbLog.TextLength;
                _rtbLog.ScrollToCaret();
            }
            else
            {
                _rtbLog.Select(savedStart, savedLen);
            }

            UpdateStatusLabel();
        }

        private void UpdateStatusLabel()
        {
            string fileName = !string.IsNullOrEmpty(_activeFilePath) ? Path.GetFileName(_activeFilePath) : "无";
            string sizeText = FormatFileSize(_currentFileBytes);
            string truncateNote = _totalFileLines > MaxDisplayedLines
                ? string.Format(" (仅加载最新 {0} 行)", MaxDisplayedLines)
                : string.Empty;
            string liveTag = _viewingTodayFile ? " | 实时跟踪中" : " | 历史日志";
            string writeErr = AppLogger.LastWriteError;
            string errTag = !string.IsNullOrEmpty(writeErr) ? (" | 写入异常: " + writeErr) : string.Empty;

            _lblStatus.Text = string.Format(
                "当前文件: {0} | 显示 {1} / 共 {2} 行{3} | 大小 {4}{5}{6}",
                fileName,
                _displayedLines,
                _totalFileLines,
                truncateNote,
                sizeText,
                liveTag,
                errTag);
        }

        private static bool LineMatchesFilter(string line, string levelFilter, string search)
        {
            if (string.IsNullOrEmpty(line))
            {
                return false;
            }
            if (string.Equals(levelFilter, "INFO", StringComparison.OrdinalIgnoreCase))
            {
                if (line.IndexOf("[INFO", StringComparison.OrdinalIgnoreCase) < 0) return false;
            }
            else if (string.Equals(levelFilter, "WARN", StringComparison.OrdinalIgnoreCase))
            {
                if (line.IndexOf("[WARN", StringComparison.OrdinalIgnoreCase) < 0) return false;
            }
            else if (string.Equals(levelFilter, "ERROR", StringComparison.OrdinalIgnoreCase))
            {
                if (line.IndexOf("[ERROR", StringComparison.OrdinalIgnoreCase) < 0) return false;
            }

            if (!string.IsNullOrEmpty(search) &&
                line.IndexOf(search, StringComparison.OrdinalIgnoreCase) < 0)
            {
                return false;
            }
            return true;
        }

        private static Color GetColorForLevel(LogLevel level)
        {
            if (level == LogLevel.Error) return Color.FromArgb(248, 113, 113);
            if (level == LogLevel.Warn) return Color.FromArgb(251, 191, 36);
            return Color.FromArgb(226, 232, 240);
        }

        private static string BuildColoredRtf(List<string> lines)
        {
            StringBuilder sb = new StringBuilder(lines.Count * 120 + 256);
            sb.Append(@"{\rtf1\ansi\deff0{\fonttbl{\f0\fnil Consolas;}{\f1\fnil Microsoft YaHei UI;}}");
            sb.Append(@"{\colortbl;\red226\green232\blue240;\red251\green191\blue36;\red248\green113\blue113;}");
            sb.Append(@"\viewkind4\uc1\f0\fs19 ");

            for (int i = 0; i < lines.Count; i++)
            {
                string line = lines[i];
                if (line.IndexOf("[ERROR]", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    sb.Append(@"\cf3 ");
                }
                else if (line.IndexOf("[WARN", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    sb.Append(@"\cf2 ");
                }
                else
                {
                    sb.Append(@"\cf1 ");
                }

                for (int j = 0; j < line.Length; j++)
                {
                    char c = line[j];
                    if (c == '\\')
                    {
                        sb.Append(@"\\");
                    }
                    else if (c == '{')
                    {
                        sb.Append(@"\{");
                    }
                    else if (c == '}')
                    {
                        sb.Append(@"\}");
                    }
                    else if (c >= 0x20 && c <= 0x7E)
                    {
                        sb.Append(c);
                    }
                    else
                    {
                        sb.Append(@"\u").Append(unchecked((short)c)).Append('?');
                    }
                }
                sb.Append(@"\par");
                sb.AppendLine();
            }

            sb.Append('}');
            return sb.ToString();
        }

        private void OnChangeDirClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "请选择 TunGuard 日志文件的存放目录";
                dlg.ShowNewFolderButton = true;
                string cur = AppLogger.EffectiveLogDirectory;
                if (Directory.Exists(cur))
                {
                    dlg.SelectedPath = cur;
                }
                if (dlg.ShowDialog(this) != DialogResult.OK || string.IsNullOrWhiteSpace(dlg.SelectedPath))
                {
                    return;
                }
                ApplyDirectoryChange(dlg.SelectedPath);
            }
        }

        private void OnResetDirClick(object sender, EventArgs e)
        {
            ApplyDirectoryChange(string.Empty);
        }

        private void ApplyDirectoryChange(string newConfiguredDir)
        {
            string targetNormalized;
            string checkErr;
            if (!AppLogger.TryValidateWritableDirectory(newConfiguredDir, out targetNormalized, out checkErr))
            {
                MessageBox.Show(
                    this,
                    "无法使用所选日志目录（可能无写入权限或路径无效）：\n" + checkErr,
                    "目录不可用",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            string currentDir = AppLogger.EffectiveLogDirectory;
            if (AppLogger.PathsEqual(currentDir, targetNormalized))
            {
                int unusedMig;
                string unusedEff;
                string unusedErr;
                if (_onChangeLogDir != null)
                {
                    _onChangeLogDir(newConfiguredDir, false, out unusedMig, out unusedEff, out unusedErr);
                }
                UpdateDirectoryBar();
                return;
            }

            bool migrate = false;
            int existingCount = AppLogger.CountLogFiles(currentDir);
            if (existingCount > 0)
            {
                DialogResult ans = MessageBox.Show(
                    this,
                    string.Format(
                        "原日志目录中共有 {0} 个历史日志文件：\n{1}\n\n是否将这些历史日志文件一并迁移到新目录？\n{2}\n\n· 选择「是」：迁移历史日志并继续记录\n· 选择「否」：仅将后续新日志写入新目录",
                        existingCount,
                        currentDir,
                        targetNormalized),
                    "迁移历史日志",
                    MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Question);
                if (ans == DialogResult.Cancel)
                {
                    return;
                }
                migrate = (ans == DialogResult.Yes);
            }

            int migratedCount;
            string effectiveDir;
            string error;
            bool ok = _onChangeLogDir != null
                ? _onChangeLogDir(newConfiguredDir, migrate, out migratedCount, out effectiveDir, out error)
                : AppLogger.SetLogDirectory(newConfiguredDir, migrate, out migratedCount, out effectiveDir, out error);

            if (!ok)
            {
                MessageBox.Show(
                    this,
                    "修改日志存放目录失败：\n" + (error ?? "未知错误"),
                    "修改失败",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            _activeFilePath = AppLogger.GetCurrentLogFilePath();
            RefreshAll();

            string msg = "日志存放目录已更新为：\n" + effectiveDir;
            if (migratedCount > 0)
            {
                msg += string.Format("\n\n已迁移 {0} 个历史日志文件。", migratedCount);
            }
            MessageBox.Show(this, msg, "修改成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void OnOpenDirClick(object sender, EventArgs e)
        {
            string dir = AppLogger.EffectiveLogDirectory;
            try
            {
                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                Process.Start("explorer.exe", "\"" + dir + "\"");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "打开日志目录失败：\n" + ex.Message, "打开失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnCopyClick(object sender, EventArgs e)
        {
            try
            {
                string text = _rtbLog.SelectionLength > 0 ? _rtbLog.SelectedText : _rtbLog.Text;
                if (!string.IsNullOrEmpty(text))
                {
                    Clipboard.SetText(text);
                }
            }
            catch
            {
            }
        }

        private void OnClearClick(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(_activeFilePath) || !File.Exists(_activeFilePath))
            {
                return;
            }
            DialogResult confirm = MessageBox.Show(
                this,
                "确定要清空当前日志文件吗？\n" + _activeFilePath,
                "确认清空日志",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (confirm != DialogResult.Yes)
            {
                return;
            }
            string err;
            if (!AppLogger.TryClearLogFile(_activeFilePath, out err))
            {
                MessageBox.Show(this, "清空日志文件失败：\n" + err, "清空失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            RefreshAll();
        }

        private static string FormatFileSize(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("F1") + " KB";
            return (bytes / (1024.0 * 1024.0)).ToString("F2") + " MB";
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                AppLogger.EntryLogged -= OnLiveLogEntry;
                if (_searchDebounceTimer != null)
                {
                    _searchDebounceTimer.Stop();
                    _searchDebounceTimer.Dispose();
                }
                if (_boldFont != null) _boldFont.Dispose();
                if (_monoFont != null) _monoFont.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    internal sealed class CustomAppPathsForm : Form
    {
        private sealed class AppOption
        {
            public string Key;
            public string Label;

            public override string ToString()
            {
                return Label;
            }
        }

        private sealed class CustomEntryItem
        {
            public string RawPath;
            public string DisplayText;

            public override string ToString()
            {
                return DisplayText;
            }
        }

        private readonly Dictionary<string, List<string>> _workingPaths;
        private readonly Func<bool, AppPathDiagnostics> _diagnosticsProvider;
        private readonly Font _boldFont;
        private readonly ComboBox _cmbApp;
        private readonly Button _btnRescan;
        private readonly Label _lblCustomHeader;
        private readonly ListBox _lstCustom;
        private readonly Button _btnAddExe;
        private readonly Button _btnAddDir;
        private readonly Button _btnRemove;
        private readonly Label _lblDiscoveredHeader;
        private readonly ListBox _lstDiscovered;
        private AppPathDiagnostics _diagnostics;

        public Dictionary<string, List<string>> ResultCustomPaths { get; private set; }

        public CustomAppPathsForm(
            Dictionary<string, List<string>> initialCustomPaths,
            Func<bool, AppPathDiagnostics> diagnosticsProvider,
            Icon windowIcon)
        {
            _diagnosticsProvider = diagnosticsProvider;
            _workingPaths = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            NodeGuardConfig.CopyNormalizedAppPathMap(initialCustomPaths, _workingPaths);

            Text = "受控应用路径管理 - TunGuard";
            StartPosition = FormStartPosition.CenterParent;
            Font = new Font("Microsoft YaHei UI", 9f);
            _boldFont = new Font(Font, FontStyle.Bold);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(740, 540);
            MinimumSize = new Size(620, 440);
            MaximizeBox = true;
            MinimizeBox = false;
            if (windowIcon != null)
            {
                Icon = windowIcon;
            }

            TableLayoutPanel root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                Padding = new Padding(14)
            };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));     // 0: app selector + rescan
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 52f)); // 1: custom paths panel
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 48f)); // 2: auto-discovered panel
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));     // 3: tip
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));     // 4: footer

            // Row 0: App selector & Rescan
            TableLayoutPanel topBar = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 3,
                RowCount = 1,
                Margin = new Padding(0, 0, 0, 10),
                BackColor = Color.FromArgb(245, 247, 250),
                Padding = new Padding(10, 7, 10, 7)
            };
            topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            topBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            topBar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            Label lblApp = new Label
            {
                Text = "受控应用:",
                AutoSize = true,
                Font = _boldFont,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 10, 2)
            };

            _cmbApp = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 12, 2)
            };
            _cmbApp.Items.Add(new AppOption { Key = "claude", Label = "Claude 桌面端 (Claude Code)" });
            _cmbApp.Items.Add(new AppOption { Key = "chatgpt", Label = "ChatGPT 桌面端 (Codex)" });
            _cmbApp.Items.Add(new AppOption { Key = "antigravity", Label = "Antigravity" });
            _cmbApp.SelectedIndex = 0;
            _cmbApp.SelectedIndexChanged += (s, e) => RefreshListsForCurrentApp();

            _btnRescan = new Button
            {
                Text = "立即重新扫描本机",
                AutoSize = true,
                Margin = new Padding(0, 1, 0, 1)
            };
            _btnRescan.Click += OnRescanClick;

            topBar.Controls.Add(lblApp, 0, 0);
            topBar.Controls.Add(_cmbApp, 1, 0);
            topBar.Controls.Add(_btnRescan, 2, 0);
            root.Controls.Add(topBar, 0, 0);

            // Row 1: Custom paths panel
            TableLayoutPanel customPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(8),
                BackColor = Color.FromArgb(250, 251, 252),
                Margin = new Padding(0, 0, 0, 10)
            };
            customPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            customPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            customPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            customPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            _lblCustomHeader = new Label
            {
                Text = "自定义目录 / 程序 (.exe) — 同时生效于进程拦截与 WFP 内核断网 (0)",
                AutoSize = true,
                Font = _boldFont,
                Margin = new Padding(0, 0, 0, 6)
            };

            _lstCustom = new ListBox
            {
                Dock = DockStyle.Fill,
                SelectionMode = SelectionMode.MultiExtended,
                IntegralHeight = false,
                HorizontalScrollbar = true,
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 0, 0, 6)
            };
            _lstCustom.SelectedIndexChanged += (s, e) => _btnRemove.Enabled = _lstCustom.SelectedItems.Count > 0;

            FlowLayoutPanel customBtns = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                WrapContents = true,
                Margin = new Padding(0)
            };

            _btnAddDir = new Button
            {
                Text = "+ 添加目录...",
                AutoSize = true,
                Margin = new Padding(0, 0, 8, 0)
            };
            _btnAddDir.Click += OnAddDirectoryClick;

            _btnAddExe = new Button
            {
                Text = "+ 添加程序 (.exe)...",
                AutoSize = true,
                Margin = new Padding(0, 0, 8, 0)
            };
            _btnAddExe.Click += OnAddExeClick;

            _btnRemove = new Button
            {
                Text = "移除选中",
                AutoSize = true,
                Enabled = false,
                Margin = new Padding(0)
            };
            _btnRemove.Click += OnRemoveSelectedClick;

            customBtns.Controls.Add(_btnAddDir);
            customBtns.Controls.Add(_btnAddExe);
            customBtns.Controls.Add(_btnRemove);

            customPanel.Controls.Add(_lblCustomHeader, 0, 0);
            customPanel.Controls.Add(_lstCustom, 0, 1);
            customPanel.Controls.Add(customBtns, 0, 2);
            root.Controls.Add(customPanel, 0, 1);

            // Row 2: Auto-discovered targets panel (read-only)
            TableLayoutPanel discoveredPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
                Padding = new Padding(8),
                BackColor = Color.FromArgb(250, 251, 252),
                Margin = new Padding(0, 0, 0, 8)
            };
            discoveredPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            discoveredPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            discoveredPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

            _lblDiscoveredHeader = new Label
            {
                Text = "当前已生效的本机保护目标（只读）",
                AutoSize = true,
                Font = _boldFont,
                ForeColor = Color.FromArgb(21, 128, 61),
                Margin = new Padding(0, 0, 0, 6)
            };

            _lstDiscovered = new ListBox
            {
                Dock = DockStyle.Fill,
                IntegralHeight = false,
                HorizontalScrollbar = true,
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0)
            };

            discoveredPanel.Controls.Add(_lblDiscoveredHeader, 0, 0);
            discoveredPanel.Controls.Add(_lstDiscovered, 0, 1);
            root.Controls.Add(discoveredPanel, 0, 2);

            // Row 3: Hint
            Label lblHint = new Label
            {
                Text = "提示：若使用绿色/便携版、自定义安装目录，或未来软件更新改名/新增子进程，添加其安装目录即可自动覆盖全部 .exe；修改后请点击控制面板的「保存并生效」。",
                AutoSize = true,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(0, 0, 0, 10)
            };
            root.Controls.Add(lblHint, 0, 3);

            // Row 4: Footer buttons
            FlowLayoutPanel footer = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                FlowDirection = FlowDirection.RightToLeft,
                WrapContents = false,
                Margin = new Padding(0)
            };

            Button btnCancel = new Button
            {
                Text = "取消",
                AutoSize = true,
                Padding = new Padding(14, 3, 14, 3),
                DialogResult = DialogResult.Cancel,
                Margin = new Padding(8, 0, 0, 0)
            };

            Button btnOk = new Button
            {
                Text = "确定",
                AutoSize = true,
                Padding = new Padding(14, 3, 14, 3),
                Margin = new Padding(0)
            };
            btnOk.Click += (s, e) =>
            {
                ResultCustomPaths = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                NodeGuardConfig.CopyNormalizedAppPathMap(_workingPaths, ResultCustomPaths);
                DialogResult = DialogResult.OK;
                Close();
            };

            footer.Controls.Add(btnCancel);
            footer.Controls.Add(btnOk);
            root.Controls.Add(footer, 0, 4);

            Controls.Add(root);
            AcceptButton = btnOk;
            CancelButton = btnCancel;

            Load += (s, e) =>
            {
                LoadDiagnostics(false);
                RefreshListsForCurrentApp();
            };
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _boldFont != null)
            {
                _boldFont.Dispose();
            }
            base.Dispose(disposing);
        }

        private string CurrentAppKey
        {
            get
            {
                AppOption opt = _cmbApp.SelectedItem as AppOption;
                return opt != null ? opt.Key : "claude";
            }
        }

        private void LoadDiagnostics(bool rescan)
        {
            if (_diagnosticsProvider != null)
            {
                try
                {
                    _diagnostics = _diagnosticsProvider(rescan);
                }
                catch
                {
                    _diagnostics = new AppPathDiagnostics();
                }
            }
            if (_diagnostics == null)
            {
                _diagnostics = new AppPathDiagnostics();
            }
        }

        private void OnRescanClick(object sender, EventArgs e)
        {
            _btnRescan.Enabled = false;
            try
            {
                LoadDiagnostics(true);
                RefreshListsForCurrentApp();
            }
            finally
            {
                _btnRescan.Enabled = true;
            }
        }

        private void OnAddDirectoryClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "请选择受控应用的安装目录或便携版根目录（将自动覆盖该目录及子目录下的 .exe）";
                dlg.ShowNewFolderButton = false;
                if (dlg.ShowDialog(this) != DialogResult.OK || string.IsNullOrWhiteSpace(dlg.SelectedPath))
                {
                    return;
                }
                string reason;
                if (!GuardedAppPathResolver.IsSafeCustomDirectory(dlg.SelectedPath, out reason))
                {
                    MessageBox.Show(this, reason, "目录不可用", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                AddCustomEntryForCurrentApp(dlg.SelectedPath);
            }
        }

        private void OnAddExeClick(object sender, EventArgs e)
        {
            using (OpenFileDialog dlg = new OpenFileDialog())
            {
                dlg.Title = "请选择要保护的可执行程序 (.exe)";
                dlg.Filter = "可执行文件 (*.exe)|*.exe";
                dlg.Multiselect = true;
                dlg.CheckFileExists = true;
                if (dlg.ShowDialog(this) != DialogResult.OK || dlg.FileNames == null || dlg.FileNames.Length == 0)
                {
                    return;
                }
                for (int i = 0; i < dlg.FileNames.Length; i++)
                {
                    AddCustomEntryForCurrentApp(dlg.FileNames[i]);
                }
            }
        }

        private void AddCustomEntryForCurrentApp(string rawPath)
        {
            string norm = NodeGuardConfig.NormalizeConfiguredPathEntry(rawPath);
            if (string.IsNullOrEmpty(norm))
            {
                return;
            }
            string key = CurrentAppKey;
            List<string> list;
            if (!_workingPaths.TryGetValue(key, out list) || list == null)
            {
                list = new List<string>();
                _workingPaths[key] = list;
            }
            for (int i = 0; i < list.Count; i++)
            {
                if (string.Equals(list[i], norm, StringComparison.OrdinalIgnoreCase))
                {
                    RefreshListsForCurrentApp();
                    return;
                }
            }
            list.Add(norm);
            list.Sort(StringComparer.OrdinalIgnoreCase);
            RefreshListsForCurrentApp();
        }

        private void OnRemoveSelectedClick(object sender, EventArgs e)
        {
            if (_lstCustom.SelectedItems.Count == 0)
            {
                return;
            }
            string key = CurrentAppKey;
            List<string> list;
            if (!_workingPaths.TryGetValue(key, out list) || list == null)
            {
                return;
            }
            HashSet<string> toRemove = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < _lstCustom.SelectedItems.Count; i++)
            {
                CustomEntryItem item = _lstCustom.SelectedItems[i] as CustomEntryItem;
                if (item != null && !string.IsNullOrEmpty(item.RawPath))
                {
                    toRemove.Add(item.RawPath);
                }
            }
            for (int i = list.Count - 1; i >= 0; i--)
            {
                if (toRemove.Contains(list[i]))
                {
                    list.RemoveAt(i);
                }
            }
            if (list.Count == 0)
            {
                _workingPaths.Remove(key);
            }
            RefreshListsForCurrentApp();
        }

        private void RefreshListsForCurrentApp()
        {
            string key = CurrentAppKey;
            List<string> customList;
            _workingPaths.TryGetValue(key, out customList);
            int customCount = customList != null ? customList.Count : 0;

            _lstCustom.BeginUpdate();
            _lstCustom.Items.Clear();
            if (customList != null)
            {
                for (int i = 0; i < customList.Count; i++)
                {
                    string p = customList[i];
                    bool isExe = p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
                    bool exists = isExe ? File.Exists(p) : Directory.Exists(p);
                    string tag = isExe
                        ? (exists ? "[程序] " : "[程序 · 本机不存在] ")
                        : (exists ? "[目录] " : "[目录 · 本机不存在] ");
                    _lstCustom.Items.Add(new CustomEntryItem { RawPath = p, DisplayText = tag + p });
                }
            }
            _lstCustom.EndUpdate();
            _lblCustomHeader.Text = string.Format("自定义目录 / 程序 (.exe) — 同时生效于进程拦截与 WFP 内核断网 ({0})", customCount);
            _btnRemove.Enabled = false;

            List<string> exes = null;
            List<string> pkgs = null;
            if (_diagnostics != null)
            {
                if (string.Equals(key, "antigravity", StringComparison.OrdinalIgnoreCase))
                {
                    exes = _diagnostics.AntigravityExes;
                }
                else if (string.Equals(key, "chatgpt", StringComparison.OrdinalIgnoreCase))
                {
                    exes = _diagnostics.ChatGptExes;
                    pkgs = _diagnostics.ChatGptPackages;
                }
                else
                {
                    exes = _diagnostics.ClaudeExes;
                    pkgs = _diagnostics.ClaudePackages;
                }
            }

            int exeCount = exes != null ? exes.Count : 0;
            int pkgCount = pkgs != null ? pkgs.Count : 0;
            _lstDiscovered.BeginUpdate();
            _lstDiscovered.Items.Clear();
            if (pkgs != null)
            {
                for (int i = 0; i < pkgs.Count; i++)
                {
                    _lstDiscovered.Items.Add("[MSIX 包] " + pkgs[i]);
                }
            }
            if (exes != null)
            {
                for (int i = 0; i < exes.Count; i++)
                {
                    _lstDiscovered.Items.Add("[程序] " + exes[i]);
                }
            }
            if (_lstDiscovered.Items.Count == 0)
            {
                _lstDiscovered.Items.Add("(暂未在常见路径发现该应用；绿色版请在上方添加目录，或运行一次后自动热发现)");
            }
            _lstDiscovered.EndUpdate();
            _lblDiscoveredHeader.Text = string.Format("当前已生效的本机保护目标（只读：{0} 个程序{1}）", exeCount, pkgCount > 0 ? (" + " + pkgCount + " 个 MSIX 包") : string.Empty);
        }
    }

    internal sealed class NodeSettingsForm : Form
    {
        private const string AutoGroupLabel = "(自动跟踪默认出口组)";

        private sealed class ProfileFilterItem
        {
            public string ProfileUid; // null => all profiles
            public string DisplayText;

            public override string ToString()
            {
                return DisplayText;
            }
        }

        private sealed class TransferNodeItem
        {
            public string NodeName;
            public string DisplayText;

            public override string ToString()
            {
                return DisplayText;
            }
        }

        public delegate bool ApplyUpdateCallback(string stagedExePath, string targetVersionTag, out string error);

        private readonly string _configPath;
        private readonly Func<ClashCatalogData> _catalogProvider;
        private readonly Func<TunStatus> _statusProvider;
        private readonly Func<bool, AppPathDiagnostics> _pathDiagnosticsProvider;
        private readonly Action _onOpenLogViewer;
        private readonly ApplyUpdateCallback _onApplyUpdate;
        private readonly Dictionary<string, List<string>> _preservedDiscoveredPaths;
        private Dictionary<string, List<string>> _draftCustomAppPaths;

        private readonly ToolTip _toolTip;
        private readonly Font _boldHeaderFont;
        private readonly System.Windows.Forms.Timer _searchDebounceTimer;
        private readonly CheckBox _chkGuardAntigravity;
        private readonly CheckBox _chkGuardChatGPT;
        private readonly CheckBox _chkGuardClaude;
        private readonly Button _btnAutoDetectApps;
        private readonly Button _btnManagePaths;
        private readonly Label _lblAppDetectStatus;
        private readonly CheckBox _chkWfpEnabled;
        private readonly CheckBox _chkWfpKillOnBlock;
        private readonly CheckBox _chkWfpBlockNonTunDns;
        private readonly CheckBox _chkPopupOnBlock;
        private readonly Label _lblWfpStatus;
        private readonly TextBox _txtLogDir;
        private readonly Button _btnChangeLogDir;
        private readonly Button _btnResetLogDir;
        private readonly Button _btnViewLogs;
        private readonly CheckBox _chkEnabled;
        private readonly Label _lblClashStatus;
        private readonly Button _btnRefresh;
        private readonly ComboBox _cmbProxyGroup;
        private readonly RadioButton _rbExact;
        private readonly RadioButton _rbContains;

        // Left pane (Available subscription nodes)
        private readonly Label _lblAvailableHeader;
        private readonly ComboBox _cmbProfileFilter;
        private readonly TextBox _txtLeftSearch;
        private readonly ListBox _lstAvailable;

        // Center transfer buttons
        private readonly Button _btnMoveRight;
        private readonly Button _btnMoveAllRight;
        private readonly Button _btnMoveLeft;
        private readonly Button _btnMoveAllLeft;

        // Right pane (Allowed nodes / keywords)
        private readonly Label _lblAllowedHeader;
        private readonly Button _btnAddCurrent;
        private readonly TextBox _txtRightSearch;
        private readonly ListBox _lstAllowed;
        private readonly TextBox _txtCustomNode;
        private readonly Button _btnAddCustom;

        private readonly Label _lblPreview;
        private readonly GitHubIconButton _btnGitHub;
        private readonly Label _lblVersion;
        private readonly Button _btnCheckUpdate;
        private readonly Button _btnOneClickUpdate;
        private readonly Label _lblUpdateStatus;
        private readonly Button _btnSave;
        private readonly Button _btnCancel;

        private readonly HashSet<string> _selectedSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> _selectedOrder = new List<string>();
        private readonly Dictionary<string, SubscriptionNodeInfo> _nodeInfoByName = new Dictionary<string, SubscriptionNodeInfo>(StringComparer.OrdinalIgnoreCase);

        private ClashCatalogData _catalog;
        private ClashSnapshot _lastSnapshot;
        private AppPathDiagnostics _lastAppDiagnostics;
        private UpdateCheckResult _latestUpdate;
        private string _lastActiveLeafNode = string.Empty;
        private int _refreshing;
        private int _detectingApps;
        private int _checkingUpdate;
        private int _updating;
        private int _cancelUpdate;
        private bool _suppressFilterEvents;
        private bool _suppressAppToggleEvents;
        private bool _suppressNodeToggleEvents;
        private string _draftLogDirectory = string.Empty;

        public NodeGuardConfig ResultConfig { get; private set; }

        public NodeSettingsForm(
            NodeGuardConfig initialConfig,
            string configPath,
            Func<ClashCatalogData> catalogProvider,
            Func<TunStatus> statusProvider,
            Func<bool, AppPathDiagnostics> pathDiagnosticsProvider,
            Action onOpenLogViewer,
            ApplyUpdateCallback onApplyUpdate,
            Icon windowIcon)
        {
            _configPath = configPath;
            _catalogProvider = catalogProvider;
            _statusProvider = statusProvider;
            _pathDiagnosticsProvider = pathDiagnosticsProvider;
            _onOpenLogViewer = onOpenLogViewer;
            _onApplyUpdate = onApplyUpdate;
            _toolTip = new ToolTip();
            _searchDebounceTimer = new System.Windows.Forms.Timer { Interval = 80 };
            _searchDebounceTimer.Tick += (s, e) =>
            {
                _searchDebounceTimer.Stop();
                RebuildTransferLists();
            };

            NodeGuardConfig cfg = (initialConfig != null ? initialConfig : new NodeGuardConfig()).CloneNormalized();
            _preservedDiscoveredPaths = cfg.DiscoveredAppPaths ?? new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            _draftCustomAppPaths = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            NodeGuardConfig.CopyNormalizedAppPathMap(cfg.CustomAppPaths, _draftCustomAppPaths);
            _draftLogDirectory = cfg.LogDirectory ?? string.Empty;
            for (int i = 0; i < cfg.AllowedNodes.Count; i++)
            {
                AddSelectionInternal(cfg.AllowedNodes[i]);
            }

            Text = "控制面板 - TunGuard";
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9f);
            _boldHeaderFont = new Font(Font, FontStyle.Bold);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(860, 760);
            MinimumSize = new Size(740, 640);
            MaximizeBox = true;
            MinimizeBox = false;
            if (windowIcon != null)
            {
                Icon = windowIcon;
            }

            TableLayoutPanel root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 9,
                Padding = new Padding(14)
            };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 0: Guarded target apps
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 1: WFP kernel kill switch panel
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 2: Popup & logging settings panel
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 3: Enable node guard switch
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 4: Live Clash status banner
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 5: Proxy group & match mode
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f)); // 6: Transfer box
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 7: Live preview
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // 8: Footer buttons

            // Row 0: Guarded target apps selector + auto-detection status
            TableLayoutPanel targetAppsPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 3,
                RowCount = 2,
                Margin = new Padding(0, 0, 0, 8),
                BackColor = Color.FromArgb(245, 247, 250),
                Padding = new Padding(10, 7, 10, 7)
            };
            targetAppsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            targetAppsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            targetAppsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            targetAppsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            targetAppsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            Label lblTargetApps = new Label
            {
                Text = "受控应用:",
                AutoSize = true,
                Font = _boldHeaderFont,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 3, 12, 3)
            };

            FlowLayoutPanel targetAppsFlow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                WrapContents = true,
                Margin = new Padding(0)
            };

            _chkGuardAntigravity = new CheckBox
            {
                Text = "Antigravity",
                AutoSize = true,
                Checked = cfg.GuardAntigravity,
                Margin = new Padding(0, 2, 18, 2)
            };
            _toolTip.SetToolTip(_chkGuardAntigravity, "拦截 Antigravity.exe 及 Antigravity 目录下的 language_server*.exe");
            _chkGuardAntigravity.CheckedChanged += OnTargetAppCheckedChanged;

            _chkGuardChatGPT = new CheckBox
            {
                Text = "ChatGPT 桌面端",
                AutoSize = true,
                Checked = cfg.GuardChatGPT,
                Margin = new Padding(0, 2, 18, 2)
            };
            _toolTip.SetToolTip(_chkGuardChatGPT, "拦截 Windows ChatGPT 桌面端（ChatGPT.exe 及 OpenAI MSIX/桌面应用组件）");
            _chkGuardChatGPT.CheckedChanged += OnTargetAppCheckedChanged;

            _chkGuardClaude = new CheckBox
            {
                Text = "Claude 桌面端 (Claude Code)",
                AutoSize = true,
                Checked = cfg.GuardClaude,
                Margin = new Padding(0, 2, 0, 2)
            };
            _toolTip.SetToolTip(_chkGuardClaude, "拦截 Claude / Claude Code 桌面端（Claude.exe 及 MSIX 包组件，不影响 VS Code 插件或命令行 CLI）");
            _chkGuardClaude.CheckedChanged += OnTargetAppCheckedChanged;

            FlowLayoutPanel targetAppsButtons = new FlowLayoutPanel
            {
                AutoSize = true,
                WrapContents = false,
                Anchor = AnchorStyles.Right,
                Margin = new Padding(8, 0, 0, 0)
            };

            _btnAutoDetectApps = new Button
            {
                Text = "自动检测",
                AutoSize = true,
                Margin = new Padding(0, 0, 6, 0)
            };
            _toolTip.SetToolTip(_btnAutoDetectApps, "立即扫描本机安装目录、MSIX 商店包、注册表、桌面/开始菜单快捷方式及运行中进程，自动检测三个受控软件并同步 WFP");
            _btnAutoDetectApps.Click += (s, e) => DetectAppsAsync(true);

            _btnManagePaths = new Button
            {
                Text = "路径管理...",
                AutoSize = true,
                Margin = new Padding(0)
            };
            _toolTip.SetToolTip(_btnManagePaths, "查看本机已自动发现的受控程序与 MSIX 包，或手动添加绿色版目录、自定义 .exe（应对软件更新改名或换电脑）");
            _btnManagePaths.Click += OnManagePathsClick;

            targetAppsButtons.Controls.Add(_btnAutoDetectApps);
            targetAppsButtons.Controls.Add(_btnManagePaths);

            _lblAppDetectStatus = new Label
            {
                Text = "自动检测: 正在检测 Antigravity / ChatGPT / Claude...",
                AutoSize = true,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(0, 4, 0, 0)
            };

            targetAppsFlow.Controls.Add(_chkGuardAntigravity);
            targetAppsFlow.Controls.Add(_chkGuardChatGPT);
            targetAppsFlow.Controls.Add(_chkGuardClaude);

            targetAppsPanel.Controls.Add(lblTargetApps, 0, 0);
            targetAppsPanel.Controls.Add(targetAppsFlow, 1, 0);
            targetAppsPanel.Controls.Add(targetAppsButtons, 2, 0);
            targetAppsPanel.Controls.Add(_lblAppDetectStatus, 0, 1);
            targetAppsPanel.SetColumnSpan(_lblAppDetectStatus, 3);
            root.Controls.Add(targetAppsPanel, 0, 0);
            UpdateManagePathsButtonText();

            // Row 1: WFP kernel kill switch settings
            TableLayoutPanel wfpPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 2,
                RowCount = 2,
                Margin = new Padding(0, 0, 0, 8),
                BackColor = Color.FromArgb(245, 247, 250),
                Padding = new Padding(10, 7, 10, 7)
            };
            wfpPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            wfpPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            wfpPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            wfpPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            Label lblWfpHeader = new Label
            {
                Text = "内核断网:",
                AutoSize = true,
                Font = _boldHeaderFont,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 3, 12, 3)
            };

            FlowLayoutPanel wfpFlow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                WrapContents = true,
                Margin = new Padding(0)
            };

            _chkWfpEnabled = new CheckBox
            {
                Text = "启用 WFP 内核断网保护 (零漏包)",
                AutoSize = true,
                Checked = cfg.WfpEnabled,
                Margin = new Padding(0, 2, 16, 2)
            };
            _toolTip.SetToolTip(_chkWfpEnabled, "通过 Windows Filtering Platform 在内核层常驻规则：仅允许受控应用走 TUN 与 Loopback，TUN 掉线瞬间零窗口丢包；使用 DYNAMIC 动态会话，退出自动清理绝不锁死网络（需管理员权限）。");
            _chkWfpEnabled.CheckedChanged += OnWfpOptionChanged;

            _chkWfpKillOnBlock = new CheckBox
            {
                Text = "拦截时同时终止进程",
                AutoSize = true,
                Checked = cfg.WfpKillOnBlock,
                Enabled = cfg.WfpEnabled,
                Margin = new Padding(0, 2, 16, 2)
            };
            _toolTip.SetToolTip(_chkWfpKillOnBlock, "勾选：WFP 内核断网 + 终止进程双重兜底；取消勾选：仅由 WFP 内核断网挂起（保留编辑内容不杀进程，WFP 降级时自动回退强杀）。");
            _chkWfpKillOnBlock.CheckedChanged += OnWfpOptionChanged;

            _chkWfpBlockNonTunDns = new CheckBox
            {
                Text = "全局防 DNS 泄漏 (53 端口)",
                AutoSize = true,
                Checked = cfg.WfpBlockNonTunDns,
                Enabled = cfg.WfpEnabled,
                Margin = new Padding(0, 2, 0, 2)
            };
            _toolTip.SetToolTip(_chkWfpBlockNonTunDns, "阻断系统 dnscache 等所有进程经非 TUN 网卡发出的 UDP/TCP 53 端口 DNS 查询（自动放行 Loopback、TUN 与 Mihomo 内核；仅在 Clash TUN 开启 DNS 劫持时建议启用）。");
            _chkWfpBlockNonTunDns.CheckedChanged += OnWfpOptionChanged;

            wfpFlow.Controls.Add(_chkWfpEnabled);
            wfpFlow.Controls.Add(_chkWfpKillOnBlock);
            wfpFlow.Controls.Add(_chkWfpBlockNonTunDns);

            _lblWfpStatus = new Label
            {
                Text = "内核状态: 正在读取...",
                AutoSize = true,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(0, 4, 0, 0)
            };

            wfpPanel.Controls.Add(lblWfpHeader, 0, 0);
            wfpPanel.Controls.Add(wfpFlow, 1, 0);
            wfpPanel.Controls.Add(_lblWfpStatus, 0, 1);
            wfpPanel.SetColumnSpan(_lblWfpStatus, 2);
            root.Controls.Add(wfpPanel, 0, 1);

            // Row 2: On-screen alert popup & logging directory settings
            TableLayoutPanel alertLogPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 5,
                RowCount = 2,
                Margin = new Padding(0, 0, 0, 8),
                BackColor = Color.FromArgb(245, 247, 250),
                Padding = new Padding(10, 7, 10, 7)
            };
            alertLogPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            alertLogPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            alertLogPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            alertLogPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            alertLogPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            alertLogPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            alertLogPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            Label lblAlertHeader = new Label
            {
                Text = "弹窗提示:",
                AutoSize = true,
                Font = _boldHeaderFont,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 3, 12, 4)
            };

            _chkPopupOnBlock = new CheckBox
            {
                Text = "未匹配节点或 TUN 关闭时打开受控软件，在屏幕弹出置顶提示",
                AutoSize = true,
                Checked = cfg.PopupOnBlock,
                Margin = new Padding(0, 2, 0, 4)
            };
            _toolTip.SetToolTip(_chkPopupOnBlock, "在节点不匹配或 TUN 关闭状态下打开受控应用（或运行中被拦截）时，在屏幕上方弹出醒目的置顶提示卡片，不再仅依赖易被系统屏蔽的托盘气泡。");

            Label lblLogDirHeader = new Label
            {
                Text = "日志目录:",
                AutoSize = true,
                Font = _boldHeaderFont,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 12, 2)
            };

            _txtLogDir = new TextBox
            {
                ReadOnly = true,
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                Margin = new Padding(0, 2, 6, 2)
            };

            _btnChangeLogDir = new Button
            {
                Text = "修改目录...",
                AutoSize = true,
                Margin = new Padding(0, 1, 6, 1)
            };
            _btnChangeLogDir.Click += OnBrowseLogDirClick;

            _btnResetLogDir = new Button
            {
                Text = "恢复默认",
                AutoSize = true,
                Margin = new Padding(0, 1, 6, 1)
            };
            _btnResetLogDir.Click += (s, e) =>
            {
                _draftLogDirectory = string.Empty;
                UpdateLogDirectoryDisplay();
            };

            _btnViewLogs = new Button
            {
                Text = "查看日志...",
                AutoSize = true,
                Margin = new Padding(0, 1, 0, 1)
            };
            _btnViewLogs.Click += (s, e) =>
            {
                if (_onOpenLogViewer != null)
                {
                    _onOpenLogViewer();
                }
            };

            alertLogPanel.Controls.Add(lblAlertHeader, 0, 0);
            alertLogPanel.Controls.Add(_chkPopupOnBlock, 1, 0);
            alertLogPanel.SetColumnSpan(_chkPopupOnBlock, 4);
            alertLogPanel.Controls.Add(lblLogDirHeader, 0, 1);
            alertLogPanel.Controls.Add(_txtLogDir, 1, 1);
            alertLogPanel.Controls.Add(_btnChangeLogDir, 2, 1);
            alertLogPanel.Controls.Add(_btnResetLogDir, 3, 1);
            alertLogPanel.Controls.Add(_btnViewLogs, 4, 1);
            root.Controls.Add(alertLogPanel, 0, 2);
            UpdateLogDirectoryDisplay();

            // Row 3: Enable node guard checkbox (disabled & unchecked until at least 1 allowed node is selected)
            bool hasInitialAllowedNodes = _selectedOrder.Count > 0;
            _chkEnabled = new CheckBox
            {
                Text = "启用 Clash 节点守护（当 Clash 未使用右侧允许节点时，同样立即触发内核断网/拦截）",
                AutoSize = true,
                Enabled = hasInitialAllowedNodes,
                Checked = hasInitialAllowedNodes && cfg.Enabled,
                Margin = new Padding(0, 0, 0, 8)
            };
            _toolTip.SetToolTip(_chkEnabled, "需先在下方右侧「已允许的节点 / 关键词」中选入至少 1 项；选入后将自动勾选，也可手动取消勾选");
            _chkEnabled.CheckedChanged += OnRuleInputChanged;
            root.Controls.Add(_chkEnabled, 0, 3);

            // Row 3: Live Clash status bar
            TableLayoutPanel statusPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0, 0, 0, 8),
                BackColor = Color.FromArgb(245, 247, 250),
                Padding = new Padding(10, 6, 8, 6)
            };
            statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            _lblClashStatus = new Label
            {
                Text = "正在读取本机 Clash 订阅与实时节点...",
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                Margin = new Padding(0, 4, 8, 4)
            };
            _btnRefresh = new Button
            {
                Text = "刷新订阅与节点",
                AutoSize = true,
                Margin = new Padding(0)
            };
            _btnRefresh.Click += (s, e) => RefreshCatalogAsync();

            statusPanel.Controls.Add(_lblClashStatus, 0, 0);
            statusPanel.Controls.Add(_btnRefresh, 1, 0);
            root.Controls.Add(statusPanel, 0, 4);

            // Row 4: Proxy group & match mode
            TableLayoutPanel rulePanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 4,
                RowCount = 2,
                Margin = new Padding(0, 0, 0, 10)
            };
            rulePanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            rulePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
            rulePanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            rulePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));

            Label lblGroup = new Label
            {
                Text = "监控代理组:",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 8, 2)
            };
            _cmbProxyGroup = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDown,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 16, 2)
            };
            _cmbProxyGroup.Items.Add(AutoGroupLabel);
            _cmbProxyGroup.Text = string.IsNullOrEmpty(cfg.ProxyGroup) ? AutoGroupLabel : cfg.ProxyGroup;
            _cmbProxyGroup.TextChanged += OnRuleInputChanged;
            _cmbProxyGroup.SelectedIndexChanged += OnRuleInputChanged;

            Label lblMatch = new Label
            {
                Text = "匹配方式:",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 8, 2)
            };
            FlowLayoutPanel matchFlow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                WrapContents = true,
                Margin = new Padding(0, 2, 0, 2)
            };
            bool isContains = string.Equals(cfg.MatchMode, "contains", StringComparison.OrdinalIgnoreCase);
            _rbExact = new RadioButton
            {
                Text = "精确匹配节点名",
                AutoSize = true,
                Checked = !isContains,
                Margin = new Padding(0, 2, 14, 0)
            };
            _rbContains = new RadioButton
            {
                Text = "关键词包含（如 美国 / IEPL）",
                AutoSize = true,
                Checked = isContains,
                Margin = new Padding(0, 2, 0, 0)
            };
            _rbExact.CheckedChanged += OnRuleInputChanged;
            _rbContains.CheckedChanged += OnRuleInputChanged;
            matchFlow.Controls.Add(_rbExact);
            matchFlow.Controls.Add(_rbContains);

            Label lblGroupHint = new Label
            {
                Text = "默认自动跟踪：Rule 模式看 MATCH 主组，Global 模式看 GLOBAL，Direct 模式直接拦截。",
                AutoSize = true,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(0, 2, 0, 0)
            };

            rulePanel.Controls.Add(lblGroup, 0, 0);
            rulePanel.Controls.Add(_cmbProxyGroup, 1, 0);
            rulePanel.Controls.Add(lblMatch, 2, 0);
            rulePanel.Controls.Add(matchFlow, 3, 0);
            rulePanel.Controls.Add(lblGroupHint, 0, 1);
            rulePanel.SetColumnSpan(lblGroupHint, 4);
            root.Controls.Add(rulePanel, 0, 5);

            // Row 4: Transfer Box (Left pane | Transfer buttons | Right pane)
            TableLayoutPanel transfer = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1,
                Margin = new Padding(0, 0, 0, 10)
            };
            transfer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
            transfer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            transfer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
            transfer.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

            // --- Left Pane ---
            TableLayoutPanel leftPane = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 5,
                Padding = new Padding(8),
                CellBorderStyle = TableLayoutPanelCellBorderStyle.None,
                BackColor = Color.FromArgb(250, 251, 252),
                Margin = new Padding(0)
            };
            leftPane.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            leftPane.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            leftPane.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // header
            leftPane.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // profile filter
            leftPane.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // search
            leftPane.RowStyles.Add(new RowStyle(SizeType.Percent, 100f)); // list
            leftPane.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // hint

            _lblAvailableHeader = new Label
            {
                Text = "可选订阅节点 (0)",
                AutoSize = true,
                Font = _boldHeaderFont,
                Margin = new Padding(0, 0, 0, 6)
            };
            Label lblProfile = new Label
            {
                Text = "订阅:",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 6, 4)
            };
            _cmbProfileFilter = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 0, 4)
            };
            _cmbProfileFilter.SelectedIndexChanged += (s, e) =>
            {
                if (!_suppressFilterEvents)
                {
                    RebuildTransferLists();
                }
            };

            Label lblLeftSearch = new Label
            {
                Text = "搜索:",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 6, 6)
            };
            _txtLeftSearch = new TextBox
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 0, 6)
            };
            _txtLeftSearch.TextChanged += OnSearchTextChanged;

            _lstAvailable = new ListBox
            {
                Dock = DockStyle.Fill,
                SelectionMode = SelectionMode.MultiExtended,
                IntegralHeight = false,
                HorizontalScrollbar = true,
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 0, 0, 6)
            };
            _lstAvailable.SelectedIndexChanged += (s, e) => UpdateTransferButtonStates();
            _lstAvailable.DoubleClick += (s, e) => MoveSelectedRight();

            Label lblLeftHint = new Label
            {
                Text = "支持 Ctrl/Shift 多选，双击节点可直接移入右侧",
                AutoSize = true,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(0, 2, 0, 0)
            };

            leftPane.Controls.Add(_lblAvailableHeader, 0, 0);
            leftPane.SetColumnSpan(_lblAvailableHeader, 2);
            leftPane.Controls.Add(lblProfile, 0, 1);
            leftPane.Controls.Add(_cmbProfileFilter, 1, 1);
            leftPane.Controls.Add(lblLeftSearch, 0, 2);
            leftPane.Controls.Add(_txtLeftSearch, 1, 2);
            leftPane.Controls.Add(_lstAvailable, 0, 3);
            leftPane.SetColumnSpan(_lstAvailable, 2);
            leftPane.Controls.Add(lblLeftHint, 0, 4);
            leftPane.SetColumnSpan(lblLeftHint, 2);

            // --- Center Transfer Buttons ---
            TableLayoutPanel midPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 1,
                RowCount = 6,
                Margin = new Padding(10, 0, 10, 0)
            };
            midPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            midPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50f));
            midPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            midPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            midPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            midPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            midPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50f));

            _btnMoveRight = CreateTransferButton(">", "将左侧选中节点移入允许列表");
            _btnMoveRight.Click += (s, e) => MoveSelectedRight();

            _btnMoveAllRight = CreateTransferButton(">>", "将左侧当前可见节点全部移入允许列表");
            _btnMoveAllRight.Click += (s, e) => MoveAllVisibleRight();

            _btnMoveLeft = CreateTransferButton("<", "将右侧选中节点移出允许列表");
            _btnMoveLeft.Click += (s, e) => MoveSelectedLeft();

            _btnMoveAllLeft = CreateTransferButton("<<", "清空右侧所有允许节点");
            _btnMoveAllLeft.Click += (s, e) => MoveAllLeft();

            midPanel.Controls.Add(_btnMoveRight, 0, 1);
            midPanel.Controls.Add(_btnMoveAllRight, 0, 2);
            midPanel.Controls.Add(_btnMoveLeft, 0, 3);
            midPanel.Controls.Add(_btnMoveAllLeft, 0, 4);

            // --- Right Pane ---
            TableLayoutPanel rightPane = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 5,
                Padding = new Padding(8),
                BackColor = Color.FromArgb(250, 251, 252),
                Margin = new Padding(0)
            };
            rightPane.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            rightPane.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            rightPane.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            rightPane.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // header
            rightPane.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // quick add current
            rightPane.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // search
            rightPane.RowStyles.Add(new RowStyle(SizeType.Percent, 100f)); // list
            rightPane.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // custom add

            _lblAllowedHeader = new Label
            {
                Text = "已允许的节点 / 关键词 (0)",
                AutoSize = true,
                Font = _boldHeaderFont,
                ForeColor = Color.FromArgb(21, 128, 61),
                Margin = new Padding(0, 0, 0, 6)
            };

            _btnAddCurrent = new Button
            {
                Text = "+ 一键移入当前正在使用的节点",
                Dock = DockStyle.Fill,
                Enabled = false,
                Margin = new Padding(0, 1, 0, 4)
            };
            _btnAddCurrent.Click += OnAddCurrentClick;

            Label lblRightSearch = new Label
            {
                Text = "搜索:",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 6, 6)
            };
            _txtRightSearch = new TextBox
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 0, 6)
            };
            _txtRightSearch.TextChanged += OnSearchTextChanged;

            _lstAllowed = new ListBox
            {
                Dock = DockStyle.Fill,
                SelectionMode = SelectionMode.MultiExtended,
                IntegralHeight = false,
                HorizontalScrollbar = true,
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 0, 0, 6)
            };
            _lstAllowed.SelectedIndexChanged += (s, e) => UpdateTransferButtonStates();
            _lstAllowed.DoubleClick += (s, e) => MoveSelectedLeft();

            Label lblCustom = new Label
            {
                Text = "关键词/自定义:",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 5, 6, 0)
            };
            _txtCustomNode = new TextBox
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 2, 6, 0)
            };
            _txtCustomNode.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter)
                {
                    e.SuppressKeyPress = true;
                    AddCustomNodeFromInput();
                }
            };
            _btnAddCustom = new Button
            {
                Text = "+ 添加",
                AutoSize = true,
                Margin = new Padding(0)
            };
            _btnAddCustom.Click += (s, e) => AddCustomNodeFromInput();

            rightPane.Controls.Add(_lblAllowedHeader, 0, 0);
            rightPane.SetColumnSpan(_lblAllowedHeader, 3);
            rightPane.Controls.Add(_btnAddCurrent, 0, 1);
            rightPane.SetColumnSpan(_btnAddCurrent, 3);
            rightPane.Controls.Add(lblRightSearch, 0, 2);
            rightPane.Controls.Add(_txtRightSearch, 1, 2);
            rightPane.SetColumnSpan(_txtRightSearch, 2);
            rightPane.Controls.Add(_lstAllowed, 0, 3);
            rightPane.SetColumnSpan(_lstAllowed, 3);
            rightPane.Controls.Add(lblCustom, 0, 4);
            rightPane.Controls.Add(_txtCustomNode, 1, 4);
            rightPane.Controls.Add(_btnAddCustom, 2, 4);

            transfer.Controls.Add(leftPane, 0, 0);
            transfer.Controls.Add(midPanel, 1, 0);
            transfer.Controls.Add(rightPane, 2, 0);
            root.Controls.Add(transfer, 0, 6);

            // Row 7: Live preview
            _lblPreview = new Label
            {
                Text = "预览: 正在检测...",
                AutoSize = true,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 0, 10)
            };
            root.Controls.Add(_lblPreview, 0, 7);

            // Row 8: Footer (left: GitHub icon, version & update actions; right: Save / Cancel)
            TableLayoutPanel footerPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                ColumnCount = 6,
                RowCount = 1,
                Margin = new Padding(0)
            };
            footerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));     // 0: GitHub icon
            footerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));     // 1: Version label
            footerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));     // 2: Check update button
            footerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));     // 3: One-click update button
            footerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));// 4: Update status text
            footerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));     // 5: Save / Cancel buttons
            footerPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            _btnGitHub = new GitHubIconButton
            {
                Anchor = AnchorStyles.Left,
                Margin = new Padding(0, 1, 4, 1)
            };
            _toolTip.SetToolTip(_btnGitHub, "访问 GitHub 项目主页\n" + AppUpdater.RepoUrl);
            _btnGitHub.Click += (s, e) => AppUpdater.OpenUrl(AppUpdater.RepoUrl);

            _lblVersion = new Label
            {
                Text = AppUpdater.GetCurrentVersionText(),
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(0, 0, 8, 0)
            };
            _toolTip.SetToolTip(_lblVersion, "当前版本: " + AppUpdater.GetCurrentVersionText());

            _btnCheckUpdate = new Button
            {
                Text = "检查更新",
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Padding = new Padding(8, 2, 8, 2),
                Margin = new Padding(0, 0, 6, 0)
            };
            _toolTip.SetToolTip(_btnCheckUpdate, "从 GitHub Releases 检查最新版本");
            _btnCheckUpdate.Click += (s, e) => CheckForUpdatesAsync(true);

            _btnOneClickUpdate = new Button
            {
                Text = "一键更新",
                AutoSize = true,
                Visible = false,
                Anchor = AnchorStyles.Left,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(22, 163, 74),
                ForeColor = Color.White,
                Cursor = Cursors.Hand,
                Padding = new Padding(10, 2, 10, 2),
                Margin = new Padding(0, 0, 8, 0)
            };
            _btnOneClickUpdate.FlatAppearance.BorderSize = 0;
            _btnOneClickUpdate.FlatAppearance.MouseOverBackColor = Color.FromArgb(21, 128, 61);
            _btnOneClickUpdate.FlatAppearance.MouseDownBackColor = Color.FromArgb(22, 101, 52);
            _btnOneClickUpdate.Click += OnOneClickUpdateClick;

            _lblUpdateStatus = new Label
            {
                Text = string.Empty,
                Dock = DockStyle.Fill,
                AutoEllipsis = true,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = Color.FromArgb(100, 116, 139),
                Margin = new Padding(0, 0, 10, 0)
            };

            FlowLayoutPanel footerRight = new FlowLayoutPanel
            {
                AutoSize = true,
                FlowDirection = FlowDirection.RightToLeft,
                WrapContents = false,
                Anchor = AnchorStyles.Right,
                Margin = new Padding(0)
            };

            _btnCancel = new Button
            {
                Text = "取消",
                AutoSize = true,
                Padding = new Padding(14, 3, 14, 3),
                DialogResult = DialogResult.Cancel,
                Margin = new Padding(8, 0, 0, 0)
            };

            _btnSave = new Button
            {
                Text = "保存并生效",
                AutoSize = true,
                Padding = new Padding(14, 3, 14, 3),
                Margin = new Padding(0)
            };
            _btnSave.Click += OnSaveClick;

            footerRight.Controls.Add(_btnCancel);
            footerRight.Controls.Add(_btnSave);

            footerPanel.Controls.Add(_btnGitHub, 0, 0);
            footerPanel.Controls.Add(_lblVersion, 1, 0);
            footerPanel.Controls.Add(_btnCheckUpdate, 2, 0);
            footerPanel.Controls.Add(_btnOneClickUpdate, 3, 0);
            footerPanel.Controls.Add(_lblUpdateStatus, 4, 0);
            footerPanel.Controls.Add(footerRight, 5, 0);
            root.Controls.Add(footerPanel, 0, 8);

            Controls.Add(root);
            CancelButton = _btnCancel;

            Load += (s, e) =>
            {
                if (_statusProvider != null)
                {
                    UpdateWfpStatus(_statusProvider());
                }
                RebuildTransferLists();
                UpdatePreview();
                DetectAppsAsync(true);
                RefreshCatalogAsync();
                CheckForUpdatesAsync(false);
            };
        }

        private Button CreateTransferButton(string text, string tooltip)
        {
            Button btn = new Button
            {
                Text = text,
                Width = 56,
                Height = 30,
                Margin = new Padding(0, 4, 0, 4),
                Enabled = false
            };
            _toolTip.SetToolTip(btn, tooltip);
            return btn;
        }

        private void OnSearchTextChanged(object sender, EventArgs e)
        {
            _searchDebounceTimer.Stop();
            _searchDebounceTimer.Start();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_searchDebounceTimer != null)
                {
                    _searchDebounceTimer.Stop();
                    _searchDebounceTimer.Dispose();
                }
                if (_toolTip != null)
                {
                    _toolTip.Dispose();
                }
                if (_boldHeaderFont != null)
                {
                    _boldHeaderFont.Dispose();
                }
            }
            base.Dispose(disposing);
        }

        private void AddSelectionInternal(string nodeName)
        {
            if (string.IsNullOrWhiteSpace(nodeName))
            {
                return;
            }
            string trimmed = nodeName.Trim();
            if (_selectedSet.Add(trimmed))
            {
                _selectedOrder.Add(trimmed);
            }
        }

        private void RemoveSelectionInternal(string nodeName)
        {
            if (string.IsNullOrWhiteSpace(nodeName))
            {
                return;
            }
            string trimmed = nodeName.Trim();
            if (_selectedSet.Remove(trimmed))
            {
                for (int i = _selectedOrder.Count - 1; i >= 0; i--)
                {
                    if (string.Equals(_selectedOrder[i], trimmed, StringComparison.OrdinalIgnoreCase))
                    {
                        _selectedOrder.RemoveAt(i);
                    }
                }
            }
        }

        private void ClearSelectionInternal()
        {
            _selectedSet.Clear();
            _selectedOrder.Clear();
        }

        public void SyncGuardedApps(NodeGuardConfig config)
        {
            if (IsDisposed || config == null)
            {
                return;
            }
            _suppressAppToggleEvents = true;
            try
            {
                _chkGuardAntigravity.Checked = config.GuardAntigravity;
                _chkGuardChatGPT.Checked = config.GuardChatGPT;
                _chkGuardClaude.Checked = config.GuardClaude;
            }
            finally
            {
                _suppressAppToggleEvents = false;
            }
            UpdateAppDetectStatusDisplay();
            UpdatePreview();
        }

        public void SyncLogDirectory(string configuredDir)
        {
            if (IsDisposed)
            {
                return;
            }
            _draftLogDirectory = configuredDir != null ? configuredDir.Trim() : string.Empty;
            UpdateLogDirectoryDisplay();
        }

        private void UpdateLogDirectoryDisplay()
        {
            string effective = AppLogger.ResolveEffectiveDirectory(_draftLogDirectory);
            bool isDefault = string.IsNullOrWhiteSpace(_draftLogDirectory) ||
                             AppLogger.PathsEqual(effective, AppLogger.DefaultLogDirectory);
            _txtLogDir.Text = isDefault ? (effective + "  (默认)") : effective;
            _btnResetLogDir.Enabled = !isDefault;
        }

        private void OnBrowseLogDirClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "请选择 TunGuard 日志文件的存放目录";
                dlg.ShowNewFolderButton = true;
                string current = AppLogger.ResolveEffectiveDirectory(_draftLogDirectory);
                if (Directory.Exists(current))
                {
                    dlg.SelectedPath = current;
                }
                if (dlg.ShowDialog(this) != DialogResult.OK || string.IsNullOrWhiteSpace(dlg.SelectedPath))
                {
                    return;
                }
                string normalized;
                string err;
                if (!AppLogger.TryValidateWritableDirectory(dlg.SelectedPath, out normalized, out err))
                {
                    MessageBox.Show(
                        this,
                        "所选日志目录不可写或无效：\n" + err,
                        "目录不可用",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }
                _draftLogDirectory = AppLogger.PathsEqual(normalized, AppLogger.DefaultLogDirectory)
                    ? string.Empty
                    : normalized;
                UpdateLogDirectoryDisplay();
            }
        }

        public void UpdateWfpStatus(TunStatus status)
        {
            if (IsDisposed)
            {
                return;
            }

            if (status.WfpDegraded)
            {
                _lblWfpStatus.ForeColor = Color.FromArgb(180, 83, 9);
                _lblWfpStatus.Text = "内核状态: " + status.WfpStatusText + " — 当前自动回退为进程终止模式，请以管理员权限运行以启用 WFP";
            }
            else if (status.WfpActive)
            {
                _lblWfpStatus.ForeColor = status.WfpBlockingNow
                    ? Color.FromArgb(185, 28, 28)
                    : Color.FromArgb(21, 128, 61);
                string luidHint = status.AdapterLuid != 0
                    ? (" | TUN LUID: 0x" + status.AdapterLuid.ToString("X"))
                    : string.Empty;
                _lblWfpStatus.Text = "内核状态: " + status.WfpStatusText + luidHint + " | 已放行 Loopback，退出自动清理";
            }
            else if (status.WfpEnabled)
            {
                _lblWfpStatus.ForeColor = Color.FromArgb(100, 116, 139);
                _lblWfpStatus.Text = "内核状态: " + (string.IsNullOrEmpty(status.WfpStatusText) ? "等待激活" : status.WfpStatusText);
            }
            else
            {
                _lblWfpStatus.ForeColor = Color.FromArgb(100, 116, 139);
                _lblWfpStatus.Text = "内核状态: 未启用（仅使用应用层进程终止保护）";
            }
        }

        private void OnWfpOptionChanged(object sender, EventArgs e)
        {
            bool wfpOn = _chkWfpEnabled.Checked;
            _chkWfpKillOnBlock.Enabled = wfpOn;
            _chkWfpBlockNonTunDns.Enabled = wfpOn;
            UpdatePreview();
        }

        private void OnTargetAppCheckedChanged(object sender, EventArgs e)
        {
            if (_suppressAppToggleEvents)
            {
                return;
            }
            UpdateAppDetectStatusDisplay();
            UpdatePreview();
        }

        private void DetectAppsAsync(bool rescan)
        {
            if (_pathDiagnosticsProvider == null)
            {
                return;
            }
            if (Interlocked.CompareExchange(ref _detectingApps, 1, 0) != 0)
            {
                return;
            }

            _btnAutoDetectApps.Enabled = false;
            _btnAutoDetectApps.Text = "检测中...";
            _lblAppDetectStatus.ForeColor = Color.FromArgb(100, 116, 139);
            _lblAppDetectStatus.Text = "自动检测: 正在扫描 Antigravity / ChatGPT / Claude（安装目录、MSIX、注册表、快捷方式与进程）...";

            ThreadPool.QueueUserWorkItem(_ =>
            {
                AppPathDiagnostics diag = null;
                try
                {
                    diag = _pathDiagnosticsProvider(rescan);
                }
                catch
                {
                    diag = new AppPathDiagnostics { ScannedAt = DateTime.Now };
                }
                finally
                {
                    Interlocked.Exchange(ref _detectingApps, 0);
                }

                if (IsDisposed)
                {
                    return;
                }
                try
                {
                    BeginInvoke((Action)(() =>
                    {
                        if (IsDisposed)
                        {
                            return;
                        }
                        _btnAutoDetectApps.Enabled = true;
                        _btnAutoDetectApps.Text = "自动检测";
                        _lastAppDiagnostics = diag ?? new AppPathDiagnostics { ScannedAt = DateTime.Now };
                        UpdateAppDetectStatusDisplay();
                        if (_statusProvider != null)
                        {
                            UpdateWfpStatus(_statusProvider());
                        }
                    }));
                }
                catch
                {
                }
            });
        }

        private void UpdateAppDetectStatusDisplay()
        {
            if (IsDisposed)
            {
                return;
            }
            if (_lastAppDiagnostics == null)
            {
                return;
            }

            AppPathDiagnostics diag = _lastAppDiagnostics;
            int antiCustom = CountExistingDraftCustomEntries("antigravity");
            int chatCustom = CountExistingDraftCustomEntries("chatgpt");
            int claudeCustom = CountExistingDraftCustomEntries("claude");

            bool antiFound = diag.AntigravityExes.Count > 0 || antiCustom > 0;
            bool chatFound = diag.ChatGptExes.Count > 0 || diag.ChatGptPackages.Count > 0 || chatCustom > 0;
            bool claudeFound = diag.ClaudeExes.Count > 0 || diag.ClaudePackages.Count > 0 || claudeCustom > 0;

            string antiText = FormatSingleAppDetectSummary("Antigravity", diag.AntigravityExes.Count, 0, antiCustom, (diag.RunningApps & GuardedAppFlags.Antigravity) != 0);
            string chatText = FormatSingleAppDetectSummary("ChatGPT", diag.ChatGptExes.Count, diag.ChatGptPackages.Count, chatCustom, (diag.RunningApps & GuardedAppFlags.ChatGPT) != 0);
            string claudeText = FormatSingleAppDetectSummary("Claude", diag.ClaudeExes.Count, diag.ClaudePackages.Count, claudeCustom, (diag.RunningApps & GuardedAppFlags.Claude) != 0);

            bool missingChecked =
                (_chkGuardAntigravity.Checked && !antiFound) ||
                (_chkGuardChatGPT.Checked && !chatFound) ||
                (_chkGuardClaude.Checked && !claudeFound);

            string summary = "自动检测: " + antiText + "  |  " + chatText + "  |  " + claudeText;
            if (missingChecked)
            {
                _lblAppDetectStatus.ForeColor = Color.FromArgb(180, 83, 9);
                _lblAppDetectStatus.Text = summary + "（有已勾选应用未发现，可点「路径管理...」手动添加）";
            }
            else if (antiFound || chatFound || claudeFound)
            {
                _lblAppDetectStatus.ForeColor = Color.FromArgb(21, 128, 61);
                _lblAppDetectStatus.Text = summary;
            }
            else
            {
                _lblAppDetectStatus.ForeColor = Color.FromArgb(100, 116, 139);
                _lblAppDetectStatus.Text = summary;
            }

            _toolTip.SetToolTip(_lblAppDetectStatus, BuildAppDetectTooltip(diag));
        }

        private int CountExistingDraftCustomEntries(string key)
        {
            if (_draftCustomAppPaths == null)
            {
                return 0;
            }
            List<string> list;
            if (!_draftCustomAppPaths.TryGetValue(key, out list) || list == null)
            {
                return 0;
            }
            int count = 0;
            for (int i = 0; i < list.Count; i++)
            {
                string p = list[i];
                if (string.IsNullOrEmpty(p)) continue;
                bool exists = p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? File.Exists(p)
                    : Directory.Exists(p);
                if (exists)
                {
                    count++;
                }
            }
            return count;
        }

        private static string FormatSingleAppDetectSummary(string name, int exeCount, int pkgCount, int customCount, bool running)
        {
            if (exeCount == 0 && pkgCount == 0 && customCount == 0)
            {
                return name + " ✗ 未发现";
            }

            List<string> parts = new List<string>(3);
            if (exeCount > 0) parts.Add(exeCount + "程序");
            if (pkgCount > 0) parts.Add(pkgCount + "MSIX");
            if (exeCount == 0 && pkgCount == 0 && customCount > 0) parts.Add(customCount + "自定义");
            string detail = string.Join("+", parts.ToArray());
            if (running)
            {
                detail += "·运行中";
            }
            return string.Format("{0} ✓ ({1})", name, detail);
        }

        private static string BuildAppDetectTooltip(AppPathDiagnostics diag)
        {
            StringBuilder sb = new StringBuilder(512);
            string timeText = diag.ScannedAt != DateTime.MinValue ? diag.ScannedAt.ToString("HH:mm:ss") : "刚刚";
            sb.AppendFormat("最近自动检测时间: {0}\n", timeText);
            AppendAppTooltipSection(sb, "Antigravity", diag.AntigravityExes, null, (diag.RunningApps & GuardedAppFlags.Antigravity) != 0);
            AppendAppTooltipSection(sb, "ChatGPT 桌面端", diag.ChatGptExes, diag.ChatGptPackages, (diag.RunningApps & GuardedAppFlags.ChatGPT) != 0);
            AppendAppTooltipSection(sb, "Claude 桌面端", diag.ClaudeExes, diag.ClaudePackages, (diag.RunningApps & GuardedAppFlags.Claude) != 0);
            return sb.ToString().TrimEnd();
        }

        private static void AppendAppTooltipSection(StringBuilder sb, string title, List<string> exes, List<string> pkgs, bool running)
        {
            sb.Append("\n[").Append(title).Append(running ? " · 运行中]" : "]").Append('\n');
            int shown = 0;
            if (pkgs != null)
            {
                for (int i = 0; i < pkgs.Count; i++)
                {
                    sb.Append("  MSIX: ").Append(pkgs[i]).Append('\n');
                    shown++;
                }
            }
            if (exes != null)
            {
                int limit = Math.Min(exes.Count, 5);
                for (int i = 0; i < limit; i++)
                {
                    sb.Append("  ").Append(exes[i]).Append('\n');
                    shown++;
                }
                if (exes.Count > limit)
                {
                    sb.AppendFormat("  ... 其余 {0} 个程序（点击「路径管理...」查看全部）\n", exes.Count - limit);
                }
            }
            if (shown == 0)
            {
                sb.Append("  (未检测到，可点击「路径管理...」手动添加目录或 .exe)\n");
            }
        }

        private void UpdateManagePathsButtonText()
        {
            int count = 0;
            if (_draftCustomAppPaths != null)
            {
                foreach (KeyValuePair<string, List<string>> kv in _draftCustomAppPaths)
                {
                    if (kv.Value != null)
                    {
                        count += kv.Value.Count;
                    }
                }
            }
            _btnManagePaths.Text = count > 0
                ? string.Format("路径管理 ({0})...", count)
                : "路径管理...";
        }

        private void OnManagePathsClick(object sender, EventArgs e)
        {
            using (CustomAppPathsForm dlg = new CustomAppPathsForm(_draftCustomAppPaths, _pathDiagnosticsProvider, Icon))
            {
                if (dlg.ShowDialog(this) == DialogResult.OK && dlg.ResultCustomPaths != null)
                {
                    _draftCustomAppPaths = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                    NodeGuardConfig.CopyNormalizedAppPathMap(dlg.ResultCustomPaths, _draftCustomAppPaths);
                    UpdateManagePathsButtonText();
                    UpdatePreview();
                }
            }
            DetectAppsAsync(false);
        }

        public NodeGuardConfig BuildDraftConfig()
        {
            NodeGuardConfig draft = new NodeGuardConfig();
            draft.Enabled = _selectedOrder.Count > 0 && _chkEnabled.Checked;
            draft.GuardAntigravity = _chkGuardAntigravity.Checked;
            draft.GuardChatGPT = _chkGuardChatGPT.Checked;
            draft.GuardClaude = _chkGuardClaude.Checked;
            draft.WfpEnabled = _chkWfpEnabled.Checked;
            draft.WfpKillOnBlock = _chkWfpKillOnBlock.Checked;
            draft.WfpBlockNonTunDns = _chkWfpBlockNonTunDns.Checked;
            draft.PopupOnBlock = _chkPopupOnBlock.Checked;
            draft.LogDirectory = _draftLogDirectory ?? string.Empty;
            NodeGuardConfig.CopyNormalizedAppPathMap(_draftCustomAppPaths, draft.CustomAppPaths);
            if (_preservedDiscoveredPaths != null)
            {
                foreach (KeyValuePair<string, List<string>> kv in _preservedDiscoveredPaths)
                {
                    if (kv.Value != null)
                    {
                        draft.DiscoveredAppPaths[kv.Key] = new List<string>(kv.Value);
                    }
                }
            }

            string rawGroup = _cmbProxyGroup.Text != null ? _cmbProxyGroup.Text.Trim() : string.Empty;
            draft.ProxyGroup = string.Equals(rawGroup, AutoGroupLabel, StringComparison.Ordinal)
                ? string.Empty
                : rawGroup;
            draft.MatchMode = _rbContains.Checked ? "contains" : "exact";

            for (int i = 0; i < _selectedOrder.Count; i++)
            {
                draft.AllowedNodes.Add(_selectedOrder[i]);
            }
            return draft.CloneNormalized();
        }

        private void OnRuleInputChanged(object sender, EventArgs e)
        {
            if (_suppressNodeToggleEvents)
            {
                return;
            }
            if (_lastSnapshot != null && _lastSnapshot.Connected)
            {
                string prevActive = _lastActiveLeafNode;
                RecomputeActiveLeafFromSnapshot();
                if (!string.Equals(prevActive, _lastActiveLeafNode, StringComparison.OrdinalIgnoreCase))
                {
                    RebuildTransferLists();
                }
            }
            UpdatePreview();
        }

        private void MoveSelectedRight()
        {
            if (_lstAvailable.SelectedItems.Count == 0)
            {
                return;
            }
            List<string> toAdd = new List<string>(_lstAvailable.SelectedItems.Count);
            for (int i = 0; i < _lstAvailable.SelectedItems.Count; i++)
            {
                TransferNodeItem item = _lstAvailable.SelectedItems[i] as TransferNodeItem;
                if (item != null && !string.IsNullOrEmpty(item.NodeName))
                {
                    toAdd.Add(item.NodeName);
                }
            }
            for (int i = 0; i < toAdd.Count; i++)
            {
                AddSelectionInternal(toAdd[i]);
            }
            RebuildTransferLists();
            UpdatePreview();
        }

        private void MoveAllVisibleRight()
        {
            if (_lstAvailable.Items.Count == 0)
            {
                return;
            }
            for (int i = 0; i < _lstAvailable.Items.Count; i++)
            {
                TransferNodeItem item = _lstAvailable.Items[i] as TransferNodeItem;
                if (item != null && !string.IsNullOrEmpty(item.NodeName))
                {
                    AddSelectionInternal(item.NodeName);
                }
            }
            RebuildTransferLists();
            UpdatePreview();
        }

        private void MoveSelectedLeft()
        {
            if (_lstAllowed.SelectedItems.Count == 0)
            {
                return;
            }
            List<string> toRemove = new List<string>(_lstAllowed.SelectedItems.Count);
            for (int i = 0; i < _lstAllowed.SelectedItems.Count; i++)
            {
                TransferNodeItem item = _lstAllowed.SelectedItems[i] as TransferNodeItem;
                if (item != null && !string.IsNullOrEmpty(item.NodeName))
                {
                    toRemove.Add(item.NodeName);
                }
            }
            for (int i = 0; i < toRemove.Count; i++)
            {
                RemoveSelectionInternal(toRemove[i]);
            }
            RebuildTransferLists();
            UpdatePreview();
        }

        private void MoveAllLeft()
        {
            if (_selectedOrder.Count == 0)
            {
                return;
            }
            ClearSelectionInternal();
            RebuildTransferLists();
            UpdatePreview();
        }

        private void OnAddCurrentClick(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(_lastActiveLeafNode))
            {
                return;
            }
            AddSelectionInternal(_lastActiveLeafNode);
            RebuildTransferLists();
            UpdatePreview();
        }

        private void AddCustomNodeFromInput()
        {
            string raw = _txtCustomNode.Text != null ? _txtCustomNode.Text.Trim() : string.Empty;
            if (raw.Length == 0)
            {
                return;
            }
            AddSelectionInternal(raw);
            _txtCustomNode.Clear();
            RebuildTransferLists();
            UpdatePreview();
        }

        private void RebuildTransferLists()
        {
            ProfileFilterItem selectedProfile = _cmbProfileFilter.SelectedItem as ProfileFilterItem;
            string profileUid = selectedProfile != null ? selectedProfile.ProfileUid : null;
            string leftFilter = _txtLeftSearch.Text != null ? _txtLeftSearch.Text.Trim() : string.Empty;
            string rightFilter = _txtRightSearch.Text != null ? _txtRightSearch.Text.Trim() : string.Empty;

            // Source candidates for left pane based on profile filter
            List<SubscriptionNodeInfo> sourceNodes = new List<SubscriptionNodeInfo>();
            if (_catalog != null)
            {
                if (string.IsNullOrEmpty(profileUid))
                {
                    sourceNodes.AddRange(_catalog.AllUniqueNodes);
                }
                else
                {
                    for (int i = 0; i < _catalog.Profiles.Count; i++)
                    {
                        if (string.Equals(_catalog.Profiles[i].Uid, profileUid, StringComparison.Ordinal))
                        {
                            sourceNodes.AddRange(_catalog.Profiles[i].Nodes);
                            break;
                        }
                    }
                }
            }

            // Build left items (exclude already selected nodes; active Clash node pinned first)
            List<TransferNodeItem> leftItems = new List<TransferNodeItem>(sourceNodes.Count);
            TransferNodeItem activeLeftItem = null;
            bool showProfileTag = string.IsNullOrEmpty(profileUid);

            for (int i = 0; i < sourceNodes.Count; i++)
            {
                SubscriptionNodeInfo node = sourceNodes[i];
                if (node == null || string.IsNullOrEmpty(node.Name))
                {
                    continue;
                }
                if (_selectedSet.Contains(node.Name))
                {
                    continue;
                }

                if (leftFilter.Length > 0 &&
                    node.Name.IndexOf(leftFilter, StringComparison.OrdinalIgnoreCase) < 0 &&
                    (node.Type == null || node.Type.IndexOf(leftFilter, StringComparison.OrdinalIgnoreCase) < 0) &&
                    (node.ProfileName == null || node.ProfileName.IndexOf(leftFilter, StringComparison.OrdinalIgnoreCase) < 0))
                {
                    continue;
                }

                bool isActive = !string.IsNullOrEmpty(_lastActiveLeafNode) &&
                                string.Equals(node.Name, _lastActiveLeafNode, StringComparison.OrdinalIgnoreCase);
                string meta = BuildNodeMetaLabel(node.Type, showProfileTag ? node.ProfileName : null);
                string display = isActive
                    ? ("[当前使用] " + node.Name + meta)
                    : (node.Name + meta);

                TransferNodeItem item = new TransferNodeItem
                {
                    NodeName = node.Name,
                    DisplayText = display
                };
                if (isActive && activeLeftItem == null)
                {
                    activeLeftItem = item;
                }
                else
                {
                    leftItems.Add(item);
                }
            }
            if (activeLeftItem != null)
            {
                leftItems.Insert(0, activeLeftItem);
            }

            // Build right items (preserve order, tag active / subscription / custom)
            List<TransferNodeItem> rightItems = new List<TransferNodeItem>(_selectedOrder.Count);
            for (int i = 0; i < _selectedOrder.Count; i++)
            {
                string name = _selectedOrder[i];
                SubscriptionNodeInfo known;
                _nodeInfoByName.TryGetValue(name, out known);

                if (rightFilter.Length > 0 &&
                    name.IndexOf(rightFilter, StringComparison.OrdinalIgnoreCase) < 0 &&
                    (known == null || known.ProfileName == null || known.ProfileName.IndexOf(rightFilter, StringComparison.OrdinalIgnoreCase) < 0))
                {
                    continue;
                }

                bool isActive = !string.IsNullOrEmpty(_lastActiveLeafNode) &&
                                string.Equals(name, _lastActiveLeafNode, StringComparison.OrdinalIgnoreCase);
                string display;
                if (isActive)
                {
                    string meta = known != null ? BuildNodeMetaLabel(known.Type, known.ProfileName) : string.Empty;
                    display = "[当前使用] " + name + meta;
                }
                else if (known != null)
                {
                    display = name + BuildNodeMetaLabel(known.Type, known.ProfileName);
                }
                else
                {
                    display = "[自定义/关键词] " + name;
                }

                rightItems.Add(new TransferNodeItem
                {
                    NodeName = name,
                    DisplayText = display
                });
            }

            _lstAvailable.BeginUpdate();
            _lstAvailable.Items.Clear();
            for (int i = 0; i < leftItems.Count; i++)
            {
                _lstAvailable.Items.Add(leftItems[i]);
            }
            _lstAvailable.EndUpdate();

            _lstAllowed.BeginUpdate();
            _lstAllowed.Items.Clear();
            for (int i = 0; i < rightItems.Count; i++)
            {
                _lstAllowed.Items.Add(rightItems[i]);
            }
            _lstAllowed.EndUpdate();

            _lblAvailableHeader.Text = string.Format("可选订阅节点 ({0})", leftItems.Count);
            _lblAllowedHeader.Text = string.Format("已允许的节点 / 关键词 ({0})", _selectedOrder.Count);
            UpdateTransferButtonStates();
            UpdateNodeGuardEnableState();
        }

        private void UpdateNodeGuardEnableState()
        {
            bool hasNodes = _selectedOrder.Count > 0;
            bool wasEnabled = _chkEnabled.Enabled;

            _suppressNodeToggleEvents = true;
            try
            {
                if (!hasNodes)
                {
                    _chkEnabled.Checked = false;
                    _chkEnabled.Enabled = false;
                }
                else
                {
                    _chkEnabled.Enabled = true;
                    if (!wasEnabled)
                    {
                        _chkEnabled.Checked = true;
                    }
                }
            }
            finally
            {
                _suppressNodeToggleEvents = false;
            }
        }

        private static string BuildNodeMetaLabel(string type, string profileName)
        {
            bool hasType = !string.IsNullOrEmpty(type);
            bool hasProf = !string.IsNullOrEmpty(profileName);
            if (hasType && hasProf)
            {
                return string.Format("  ({0} · {1})", type, profileName);
            }
            if (hasProf)
            {
                return string.Format("  ({0})", profileName);
            }
            if (hasType)
            {
                return string.Format("  ({0})", type);
            }
            return string.Empty;
        }

        private void UpdateTransferButtonStates()
        {
            _btnMoveRight.Enabled = _lstAvailable.SelectedItems.Count > 0;
            _btnMoveAllRight.Enabled = _lstAvailable.Items.Count > 0;
            _btnMoveLeft.Enabled = _lstAllowed.SelectedItems.Count > 0;
            _btnMoveAllLeft.Enabled = _selectedOrder.Count > 0;
        }

        private void RefreshCatalogAsync()
        {
            if (Interlocked.CompareExchange(ref _refreshing, 1, 0) != 0)
            {
                return;
            }

            _btnRefresh.Enabled = false;
            _lblClashStatus.Text = "正在读取本机 Clash 订阅与实时节点...";

            ThreadPool.QueueUserWorkItem(_ =>
            {
                ClashCatalogData data = null;
                try
                {
                    if (_catalogProvider != null)
                    {
                        data = _catalogProvider();
                    }
                }
                catch
                {
                    data = new ClashCatalogData
                    {
                        LiveSnapshot = new ClashSnapshot { Connected = false, Error = "读取 Clash 订阅与状态失败" }
                    };
                }
                finally
                {
                    Interlocked.Exchange(ref _refreshing, 0);
                }

                if (IsDisposed)
                {
                    return;
                }
                try
                {
                    BeginInvoke((Action)(() => ApplyCatalogToUi(data)));
                }
                catch
                {
                }
            });
        }

        private void RecomputeActiveLeafFromSnapshot()
        {
            int profCount = _catalog != null ? _catalog.Profiles.Count : 0;
            int totalNodes = _catalog != null ? _catalog.AllUniqueNodes.Count : 0;
            string catalogSuffix = string.Format(" | 已扫描 {0} 个订阅共 {1} 个节点", profCount, totalNodes);

            if (_lastSnapshot == null || !_lastSnapshot.Connected)
            {
                _lastActiveLeafNode = string.Empty;
                _btnAddCurrent.Enabled = false;
                string err = (_lastSnapshot != null && !string.IsNullOrEmpty(_lastSnapshot.Error))
                    ? _lastSnapshot.Error
                    : "未连接 Clash 实时接口";
                _lblClashStatus.Text = "Clash 状态: " + err + catalogSuffix;
                return;
            }

            NodeGuardConfig probe = BuildDraftConfig();
            probe.Enabled = true;
            if (probe.AllowedNodes.Count == 0)
            {
                probe.AllowedNodes.Add("__probe__");
            }
            NodeEvaluationResult probeEval = NodeGuardEvaluator.Evaluate(probe, _lastSnapshot);
            _lastActiveLeafNode = probeEval.ActiveNode ?? string.Empty;
            bool canAddActive = !string.IsNullOrEmpty(_lastActiveLeafNode) &&
                                !NodeGuardEvaluator.IsBuiltinNode(_lastActiveLeafNode);
            _btnAddCurrent.Enabled = canAddActive;
            _btnAddCurrent.Text = canAddActive
                ? ("+ 一键移入当前节点: " + _lastActiveLeafNode)
                : "+ 一键移入当前正在使用的节点";

            string chainDisplay = !string.IsNullOrEmpty(probeEval.ResolutionChain)
                ? probeEval.ResolutionChain
                : (string.IsNullOrEmpty(_lastActiveLeafNode) ? "无" : _lastActiveLeafNode);
            _lblClashStatus.Text = string.Format("Clash 实时: 模式 {0} | 出口 {1}{2}", _lastSnapshot.Mode, chainDisplay, catalogSuffix);
        }

        public void ApplyCatalogToUi(ClashCatalogData catalog)
        {
            if (IsDisposed)
            {
                return;
            }

            _btnRefresh.Enabled = true;
            _catalog = catalog ?? new ClashCatalogData();
            _lastSnapshot = _catalog.LiveSnapshot;

            _nodeInfoByName.Clear();
            for (int i = 0; i < _catalog.AllUniqueNodes.Count; i++)
            {
                SubscriptionNodeInfo n = _catalog.AllUniqueNodes[i];
                if (n != null && !string.IsNullOrEmpty(n.Name) && !_nodeInfoByName.ContainsKey(n.Name))
                {
                    _nodeInfoByName[n.Name] = n;
                }
            }

            // Populate subscription filter dropdown (preserving user's previous selection if still present)
            ProfileFilterItem prevProfile = _cmbProfileFilter.SelectedItem as ProfileFilterItem;
            string prevProfileUid = prevProfile != null ? prevProfile.ProfileUid : null;

            _suppressFilterEvents = true;
            _cmbProfileFilter.BeginUpdate();
            try
            {
                _cmbProfileFilter.Items.Clear();
                _cmbProfileFilter.Items.Add(new ProfileFilterItem
                {
                    ProfileUid = null,
                    DisplayText = string.Format("全部订阅 ({0} 个订阅 · {1} 节点)", _catalog.Profiles.Count, _catalog.AllUniqueNodes.Count)
                });

                int restoreIdx = 0;
                for (int i = 0; i < _catalog.Profiles.Count; i++)
                {
                    SubscriptionProfileInfo prof = _catalog.Profiles[i];
                    string label = prof.IsCurrent
                        ? string.Format("{0} [当前] ({1})", prof.Name, prof.Nodes.Count)
                        : string.Format("{0} ({1})", prof.Name, prof.Nodes.Count);
                    _cmbProfileFilter.Items.Add(new ProfileFilterItem
                    {
                        ProfileUid = prof.Uid,
                        DisplayText = label
                    });
                    if (!string.IsNullOrEmpty(prevProfileUid) &&
                        string.Equals(prof.Uid, prevProfileUid, StringComparison.Ordinal))
                    {
                        restoreIdx = i + 1;
                    }
                }
                _cmbProfileFilter.SelectedIndex = restoreIdx;
            }
            finally
            {
                _cmbProfileFilter.EndUpdate();
                _suppressFilterEvents = false;
            }

            // Populate live proxy groups dropdown
            if (_lastSnapshot != null && _lastSnapshot.Connected && _lastSnapshot.Proxies != null)
            {
                string currentGroupText = _cmbProxyGroup.Text;
                List<string> groups = new List<string>();
                foreach (KeyValuePair<string, ClashProxyEntry> kv in _lastSnapshot.Proxies)
                {
                    ClashProxyEntry entry = kv.Value;
                    if (entry != null && entry.IsGroup &&
                        !string.Equals(entry.Name, "GLOBAL", StringComparison.OrdinalIgnoreCase))
                    {
                        groups.Add(entry.Name);
                    }
                }
                groups.Sort(StringComparer.OrdinalIgnoreCase);

                _cmbProxyGroup.BeginUpdate();
                _cmbProxyGroup.Items.Clear();
                _cmbProxyGroup.Items.Add(AutoGroupLabel);
                for (int i = 0; i < groups.Count; i++)
                {
                    _cmbProxyGroup.Items.Add(groups[i]);
                }
                _cmbProxyGroup.Text = string.IsNullOrEmpty(currentGroupText) ? AutoGroupLabel : currentGroupText;
                _cmbProxyGroup.EndUpdate();
            }

            RecomputeActiveLeafFromSnapshot();
            RebuildTransferLists();
            UpdatePreview();
        }

        private void UpdatePreview()
        {
            NodeGuardConfig draft = BuildDraftConfig();
            GuardedAppFlags apps = draft.GetGuardedAppFlags();
            if (apps == GuardedAppFlags.None)
            {
                _lblPreview.ForeColor = Color.FromArgb(180, 83, 9);
                _lblPreview.Text = draft.WfpEnabled && draft.WfpBlockNonTunDns
                    ? "预览: 未勾选受控应用（仅全局 53 端口防 DNS 泄漏生效）"
                    : "预览: 未勾选任何受控应用（TUN 断开或节点不匹配时不会拦截或终止任何进程）";
                return;
            }

            string appsText = GuardedAppHelper.FormatNames(apps);
            string actionDesc = draft.WfpEnabled
                ? (draft.WfpKillOnBlock ? "WFP 内核断网 + 终止进程" : "仅 WFP 内核断网（保留进程）")
                : "仅终止进程";

            if (!draft.Enabled)
            {
                _lblPreview.ForeColor = Color.FromArgb(100, 116, 139);
                _lblPreview.Text = "预览: 节点守护未启用（仅监控 TUN；动作: " + actionDesc + "；受控应用: " + appsText + "）";
                return;
            }

            if (draft.AllowedNodes.Count == 0)
            {
                _lblPreview.ForeColor = Color.FromArgb(185, 28, 28);
                _lblPreview.Text = "预览: 请至少将 1 个允许节点移入右侧列表";
                return;
            }

            if (_lastSnapshot == null)
            {
                _lblPreview.ForeColor = Color.FromArgb(100, 116, 139);
                _lblPreview.Text = "预览: 正在读取 Clash 实时状态...";
                return;
            }

            NodeEvaluationResult eval = NodeGuardEvaluator.Evaluate(draft, _lastSnapshot);
            if (eval.IsAllowed)
            {
                _lblPreview.ForeColor = Color.FromArgb(21, 128, 61);
                _lblPreview.Text = "预览: 当前命中 — " + eval.ResolutionChain + "（保存后正常放行；策略: " + actionDesc + "）";
            }
            else
            {
                _lblPreview.ForeColor = Color.FromArgb(185, 28, 28);
                _lblPreview.Text = "预览: 当前未命中 — " + eval.Reason + "（保存后将立即执行「" + actionDesc + "」: " + appsText + "！）";
            }
        }

        private void OnSaveClick(object sender, EventArgs e)
        {
            NodeGuardConfig draft = BuildDraftConfig();
            if (draft.Enabled && draft.AllowedNodes.Count == 0)
            {
                MessageBox.Show(
                    this,
                    "启用节点守护时，请至少将 1 个允许节点移入右侧列表或手动添加关键词。",
                    "配置不完整",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            GuardedAppFlags apps = draft.GetGuardedAppFlags();
            if (draft.Enabled && apps != GuardedAppFlags.None && _lastSnapshot != null)
            {
                NodeEvaluationResult eval = NodeGuardEvaluator.Evaluate(draft, _lastSnapshot);
                if (!eval.IsAllowed)
                {
                    string actionSummary = (draft.WfpEnabled && !draft.WfpKillOnBlock)
                        ? ("立即通过 WFP 内核阻断 " + GuardedAppHelper.FormatNames(apps) + " 联网（若 WFP 降级则终止进程）")
                        : ("立即触发拦截并终止 " + GuardedAppHelper.FormatNames(apps));
                    DialogResult confirm = MessageBox.Show(
                        this,
                        "当前 Clash 状态未满足右侧允许节点规则：\n" + eval.Reason + "\n\n保存后将" + actionSummary + "。\n是否确认保存？",
                        "确认保存并触发拦截",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning,
                        MessageBoxDefaultButton.Button2);
                    if (confirm != DialogResult.Yes)
                    {
                        return;
                    }
                }
            }

            string currentEffectiveLogDir = AppLogger.EffectiveLogDirectory;
            string targetEffectiveLogDir;
            string logDirErr;
            if (!AppLogger.TryValidateWritableDirectory(draft.LogDirectory, out targetEffectiveLogDir, out logDirErr))
            {
                MessageBox.Show(
                    this,
                    "日志存放目录不可用：\n" + logDirErr,
                    "配置无效",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }
            draft.LogDirectory = AppLogger.PathsEqual(targetEffectiveLogDir, AppLogger.DefaultLogDirectory)
                ? string.Empty
                : targetEffectiveLogDir;

            bool logDirChanged = !AppLogger.PathsEqual(currentEffectiveLogDir, targetEffectiveLogDir);
            bool migrateLogs = false;
            if (logDirChanged)
            {
                int oldCount = AppLogger.CountLogFiles(currentEffectiveLogDir);
                if (oldCount > 0)
                {
                    DialogResult ans = MessageBox.Show(
                        this,
                        string.Format(
                            "日志目录即将从：\n{0}\n修改为：\n{1}\n\n原目录中有 {2} 个历史日志文件，是否一并迁移到新目录？",
                            currentEffectiveLogDir,
                            targetEffectiveLogDir,
                            oldCount),
                        "迁移历史日志",
                        MessageBoxButtons.YesNoCancel,
                        MessageBoxIcon.Question);
                    if (ans == DialogResult.Cancel)
                    {
                        return;
                    }
                    migrateLogs = (ans == DialogResult.Yes);
                }
            }

            try
            {
                NodeGuardConfigStore.Save(_configPath, draft);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    this,
                    "保存设置失败:\n" + ex.Message,
                    "保存失败",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            if (logDirChanged)
            {
                int unusedMigrated;
                string unusedEff;
                string switchErr;
                AppLogger.SetLogDirectory(draft.LogDirectory, migrateLogs, out unusedMigrated, out unusedEff, out switchErr);
            }

            ResultConfig = draft;
            DialogResult = DialogResult.OK;
            Close();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            Volatile.Write(ref _cancelUpdate, 1);
            base.OnFormClosing(e);
        }

        private void CheckForUpdatesAsync(bool manual)
        {
            if (Volatile.Read(ref _updating) != 0)
            {
                return;
            }
            if (Interlocked.CompareExchange(ref _checkingUpdate, 1, 0) != 0)
            {
                return;
            }

            _btnCheckUpdate.Enabled = false;
            if (manual)
            {
                _btnCheckUpdate.Text = "检查中...";
                _lblUpdateStatus.ForeColor = Color.FromArgb(100, 116, 139);
                _lblUpdateStatus.Text = "正在检查更新...";
                _toolTip.SetToolTip(_lblUpdateStatus, "正在连接 GitHub Releases 检测最新版本");
            }

            ThreadPool.QueueUserWorkItem(_ =>
            {
                UpdateCheckResult result;
                try
                {
                    result = AppUpdater.CheckForUpdates(manual);
                }
                catch (Exception ex)
                {
                    result = new UpdateCheckResult
                    {
                        Success = false,
                        HasUpdate = false,
                        CurrentVersion = AppUpdater.GetCurrentVersion(),
                        ReleasePageUrl = AppUpdater.ReleasesUrl,
                        ErrorMessage = ex.Message
                    };
                }
                finally
                {
                    Interlocked.Exchange(ref _checkingUpdate, 0);
                }

                if (IsDisposed)
                {
                    return;
                }
                try
                {
                    BeginInvoke((Action)(() => ApplyUpdateCheckResult(result, manual)));
                }
                catch
                {
                }
            });
        }

        private void ApplyUpdateCheckResult(UpdateCheckResult result, bool manual)
        {
            if (IsDisposed)
            {
                return;
            }

            bool isUpdating = Volatile.Read(ref _updating) != 0;
            _btnCheckUpdate.Enabled = !isUpdating;
            _btnCheckUpdate.Text = "检查更新";

            if (result == null)
            {
                return;
            }

            if (!result.Success)
            {
                if (manual)
                {
                    string err = string.IsNullOrEmpty(result.ErrorMessage) ? "网络请求失败" : result.ErrorMessage;
                    _lblUpdateStatus.ForeColor = Color.FromArgb(180, 83, 9);
                    _lblUpdateStatus.Text = "检查失败: " + err;
                    _toolTip.SetToolTip(_lblUpdateStatus, "检查更新失败:\n" + err);
                }
                return;
            }

            _latestUpdate = result;

            if (result.HasUpdate)
            {
                string tag = !string.IsNullOrEmpty(result.LatestTag)
                    ? result.LatestTag
                    : string.Format("v{0}.{1}.{2}", result.LatestVersion.Major, result.LatestVersion.Minor, result.LatestVersion.Build);
                SetOneClickUpdateButtonReady(tag);

                string notes = AppUpdater.FormatReleaseNotesPreview(result.ReleaseNotes, 6, 320);
                string tip = "发现新版本 " + tag + "（当前 " + AppUpdater.GetCurrentVersionText() + "），点击一键下载校验并重启更新";
                if (!string.IsNullOrEmpty(notes))
                {
                    tip += "\n\n变更摘要:\n" + notes;
                }
                _toolTip.SetToolTip(_btnOneClickUpdate, tip);

                if (!isUpdating)
                {
                    _lblUpdateStatus.ForeColor = Color.FromArgb(21, 128, 61);
                    _lblUpdateStatus.Text = result.ExpectedSize > 0
                        ? ("发现新版本 (" + AppUpdater.FormatBytesShort(result.ExpectedSize) + ")")
                        : "发现新版本";
                    _toolTip.SetToolTip(_lblUpdateStatus, tip);
                }
            }
            else
            {
                if (!isUpdating)
                {
                    _btnOneClickUpdate.Visible = false;
                    _lblUpdateStatus.ForeColor = manual
                        ? Color.FromArgb(21, 128, 61)
                        : Color.FromArgb(100, 116, 139);
                    _lblUpdateStatus.Text = manual ? "已是最新版本" : "已是最新";
                    string latestLabel = !string.IsNullOrEmpty(result.LatestTag) ? result.LatestTag : AppUpdater.GetCurrentVersionText();
                    _toolTip.SetToolTip(_lblUpdateStatus, "当前版本 " + AppUpdater.GetCurrentVersionText() + " 已是最新（GitHub 最新: " + latestLabel + "）");
                }
            }
        }

        private void SetOneClickUpdateButtonReady(string tag)
        {
            _btnOneClickUpdate.Text = "一键更新 " + tag;
            _btnOneClickUpdate.BackColor = Color.FromArgb(22, 163, 74);
            _btnOneClickUpdate.FlatAppearance.MouseOverBackColor = Color.FromArgb(21, 128, 61);
            _btnOneClickUpdate.FlatAppearance.MouseDownBackColor = Color.FromArgb(22, 101, 52);
            _btnOneClickUpdate.Enabled = true;
            _btnOneClickUpdate.Visible = true;
        }

        private void SetOneClickUpdateButtonCancellingMode()
        {
            _btnOneClickUpdate.Text = "取消更新";
            _btnOneClickUpdate.BackColor = Color.FromArgb(100, 116, 139);
            _btnOneClickUpdate.FlatAppearance.MouseOverBackColor = Color.FromArgb(71, 85, 105);
            _btnOneClickUpdate.FlatAppearance.MouseDownBackColor = Color.FromArgb(51, 65, 85);
            _btnOneClickUpdate.Enabled = true;
            _btnOneClickUpdate.Visible = true;
        }

        private void OnOneClickUpdateClick(object sender, EventArgs e)
        {
            if (Volatile.Read(ref _updating) != 0)
            {
                Volatile.Write(ref _cancelUpdate, 1);
                _btnOneClickUpdate.Enabled = false;
                _lblUpdateStatus.ForeColor = Color.FromArgb(100, 116, 139);
                _lblUpdateStatus.Text = "正在取消更新...";
                return;
            }

            UpdateCheckResult info = _latestUpdate;
            if (info == null || !info.HasUpdate)
            {
                return;
            }

            string targetTag = !string.IsNullOrEmpty(info.LatestTag)
                ? info.LatestTag
                : string.Format("v{0}.{1}.{2}", info.LatestVersion.Major, info.LatestVersion.Minor, info.LatestVersion.Build);

            StringBuilder msg = new StringBuilder(384);
            msg.AppendFormat("发现新版本：{0}  →  {1}\n", AppUpdater.GetCurrentVersionText(), targetTag);
            if (info.ExpectedSize > 0)
            {
                msg.AppendFormat("更新包大小：约 {0}\n", AppUpdater.FormatBytesShort(info.ExpectedSize));
            }
            string notes = AppUpdater.FormatReleaseNotesPreview(info.ReleaseNotes, 8, 420);
            if (!string.IsNullOrEmpty(notes))
            {
                msg.AppendLine();
                msg.AppendLine("主要变更：");
                msg.AppendLine(notes);
            }
            msg.AppendLine();
            msg.Append("点击「是」将自动下载新版本、校验 SHA-256、替换当前程序并重启 TunGuard（重启期间防护将短暂中断约 1~2 秒）。");

            DialogResult ans = MessageBox.Show(
                this,
                msg.ToString(),
                "一键更新 TunGuard",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Information,
                MessageBoxDefaultButton.Button1);
            if (ans != DialogResult.Yes)
            {
                return;
            }

            StartDownloadAndApplyUpdate(info, targetTag);
        }

        private void StartDownloadAndApplyUpdate(UpdateCheckResult info, string targetTag)
        {
            if (Interlocked.CompareExchange(ref _updating, 1, 0) != 0)
            {
                return;
            }
            Volatile.Write(ref _cancelUpdate, 0);

            _btnCheckUpdate.Enabled = false;
            _btnSave.Enabled = false;
            SetOneClickUpdateButtonCancellingMode();
            _lblUpdateStatus.ForeColor = Color.FromArgb(37, 99, 235);
            _lblUpdateStatus.Text = "正在连接 GitHub 下载 " + targetTag + "...";
            _toolTip.SetToolTip(_lblUpdateStatus, "正在下载 " + targetTag);

            ThreadPool.QueueUserWorkItem(_ =>
            {
                string stagedPath;
                string err;
                bool ok = AppUpdater.DownloadAndVerifyUpdate(
                    info,
                    () => Volatile.Read(ref _cancelUpdate) != 0 || IsDisposed,
                    (pct, readBytes, totalBytes, phase) =>
                    {
                        if (IsDisposed)
                        {
                            return;
                        }
                        try
                        {
                            BeginInvoke((Action)(() =>
                            {
                                if (IsDisposed || Volatile.Read(ref _updating) == 0)
                                {
                                    return;
                                }
                                if (!string.IsNullOrEmpty(phase))
                                {
                                    _lblUpdateStatus.Text = phase;
                                }
                                else if (pct >= 0 && totalBytes > 0)
                                {
                                    _lblUpdateStatus.Text = string.Format(
                                        "下载中 {0}% ({1} / {2})",
                                        pct,
                                        AppUpdater.FormatBytesShort(readBytes),
                                        AppUpdater.FormatBytesShort(totalBytes));
                                }
                                else
                                {
                                    _lblUpdateStatus.Text = "下载中 (" + AppUpdater.FormatBytesShort(readBytes) + ")...";
                                }
                            }));
                        }
                        catch
                        {
                        }
                    },
                    out stagedPath,
                    out err);

                bool wasCancelled = Volatile.Read(ref _cancelUpdate) != 0;
                if (IsDisposed)
                {
                    Interlocked.Exchange(ref _updating, 0);
                    return;
                }

                try
                {
                    BeginInvoke((Action)(() =>
                    {
                        if (IsDisposed)
                        {
                            Interlocked.Exchange(ref _updating, 0);
                            return;
                        }

                        if (!ok)
                        {
                            Interlocked.Exchange(ref _updating, 0);
                            _btnCheckUpdate.Enabled = true;
                            _btnSave.Enabled = true;
                            SetOneClickUpdateButtonReady(targetTag);

                            if (wasCancelled)
                            {
                                _lblUpdateStatus.ForeColor = Color.FromArgb(100, 116, 139);
                                _lblUpdateStatus.Text = "已取消更新";
                                _toolTip.SetToolTip(_lblUpdateStatus, "已取消下载更新");
                                return;
                            }

                            string failMsg = !string.IsNullOrEmpty(err) ? err : "下载或校验失败";
                            _lblUpdateStatus.ForeColor = Color.FromArgb(185, 28, 28);
                            _lblUpdateStatus.Text = "更新失败: " + failMsg;
                            _toolTip.SetToolTip(_lblUpdateStatus, "更新失败:\n" + failMsg);

                            DialogResult openWeb = MessageBox.Show(
                                this,
                                "自动更新失败：\n" + failMsg + "\n\n是否打开 GitHub Releases 页面手动下载最新版本？",
                                "更新失败",
                                MessageBoxButtons.YesNo,
                                MessageBoxIcon.Warning,
                                MessageBoxDefaultButton.Button2);
                            if (openWeb == DialogResult.Yes)
                            {
                                AppUpdater.OpenUrl(!string.IsNullOrEmpty(info.ReleasePageUrl) ? info.ReleasePageUrl : AppUpdater.ReleasesUrl);
                            }
                            return;
                        }

                        _btnOneClickUpdate.Enabled = false;
                        _btnOneClickUpdate.Text = "正在重启...";
                        _btnCancel.Enabled = false;
                        _lblUpdateStatus.ForeColor = Color.FromArgb(21, 128, 61);
                        _lblUpdateStatus.Text = "校验通过，正在替换并重启...";

                        string swapErr = null;
                        bool applied = _onApplyUpdate != null && _onApplyUpdate(stagedPath, targetTag, out swapErr);
                        if (applied)
                        {
                            // ExitCleanly has closed this form and scheduled process restart
                            return;
                        }

                        Interlocked.Exchange(ref _updating, 0);
                        if (IsDisposed)
                        {
                            return;
                        }

                        _btnCheckUpdate.Enabled = true;
                        _btnSave.Enabled = true;
                        _btnCancel.Enabled = true;
                        SetOneClickUpdateButtonReady(targetTag);
                        string applyErr = !string.IsNullOrEmpty(swapErr) ? swapErr : "替换程序文件失败";
                        _lblUpdateStatus.ForeColor = Color.FromArgb(185, 28, 28);
                        _lblUpdateStatus.Text = "替换失败: " + applyErr;
                        _toolTip.SetToolTip(_lblUpdateStatus, "替换程序文件失败:\n" + applyErr);

                        DialogResult openRelease = MessageBox.Show(
                            this,
                            "替换程序文件失败：\n" + applyErr + "\n\n是否打开 GitHub Releases 页面手动下载覆盖？",
                            "更新失败",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Error,
                            MessageBoxDefaultButton.Button2);
                        if (openRelease == DialogResult.Yes)
                        {
                            AppUpdater.OpenUrl(!string.IsNullOrEmpty(info.ReleasePageUrl) ? info.ReleasePageUrl : AppUpdater.ReleasesUrl);
                        }
                    }));
                }
                catch
                {
                    Interlocked.Exchange(ref _updating, 0);
                }
            });
        }
    }

    internal sealed class TrayApplication : ApplicationContext
    {
        private static readonly long AccessDeniedNotifyCooldownTicks = TimeSpan.FromSeconds(10).Ticks;
        private static readonly long AlertDismissCooldownTicks = TimeSpan.FromMilliseconds(1500).Ticks;

        private readonly SynchronizationContext _uiSync;
        private readonly TunMonitor _monitor;
        private readonly ContextMenuStrip _menu;
        private readonly NotifyIcon _trayIcon;
        private readonly ToolStripMenuItem _statusItem;
        private readonly ToolStripMenuItem _wfpStatusItem;
        private readonly ToolStripMenuItem _guardedAppsSummaryItem;
        private readonly ToolStripMenuItem _nodeRuleItem;
        private readonly ToolStripMenuItem _lastKillItem;
        private readonly ToolStripMenuItem _nodeSettingsItem;
        private readonly ToolStripMenuItem _logViewerItem;
        private readonly ToolStripMenuItem _guardedAppsMenu;
        private readonly ToolStripMenuItem _guardAntigravityItem;
        private readonly ToolStripMenuItem _guardChatGPTItem;
        private readonly ToolStripMenuItem _guardClaudeItem;
        private readonly ToolStripMenuItem _toggleMonitorItem;
        private readonly ToolStripMenuItem _autoStartItem;

        private readonly Icon _iconSafe;
        private readonly Icon _iconAlert;
        private readonly Icon _iconPaused;
        private readonly Font _boldMenuFont;

        private readonly EventWaitHandle _pingEvent;
        private readonly ManualResetEvent _pingStop = new ManualResetEvent(false);
        private readonly Thread _pingThread;

        private NodeSettingsForm _settingsForm;
        private LogViewerForm _logViewerForm;
        private GuardAlertForm _alertForm;
        private int _totalKills;
        private int _autoStartRefreshing;
        private int _autoStartToggling;
        private long _lastAccessDeniedNotifyTicks;
        private long _lastAlertDismissedTicks;
        private GuardedAppFlags _lastAlertDismissedApps;
        private GuardedAppFlags _currentAlertApps;
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
            _wfpStatusItem = new ToolStripMenuItem("内核断网: 正在初始化...") { Enabled = false };
            _guardedAppsSummaryItem = new ToolStripMenuItem("受控应用: Antigravity、ChatGPT、Claude") { Enabled = false };
            _nodeRuleItem = new ToolStripMenuItem("节点守护: 未启用") { Enabled = false };
            _lastKillItem = new ToolStripMenuItem("拦截记录: 暂无") { Enabled = false };

            _nodeSettingsItem = new ToolStripMenuItem("打开控制面板...");
            _boldMenuFont = new Font(_nodeSettingsItem.Font, FontStyle.Bold);
            _nodeSettingsItem.Font = _boldMenuFont;
            _nodeSettingsItem.Click += OnNodeSettingsClick;

            _logViewerItem = new ToolStripMenuItem("查看日志...");
            _logViewerItem.Click += OnLogViewerClick;

            _guardAntigravityItem = new ToolStripMenuItem("Antigravity") { Checked = true };
            _guardAntigravityItem.Click += (s, e) => OnToggleGuardedAppClick(GuardedAppFlags.Antigravity);

            _guardChatGPTItem = new ToolStripMenuItem("ChatGPT 桌面端") { Checked = true };
            _guardChatGPTItem.Click += (s, e) => OnToggleGuardedAppClick(GuardedAppFlags.ChatGPT);

            _guardClaudeItem = new ToolStripMenuItem("Claude 桌面端 (Claude Code)") { Checked = true };
            _guardClaudeItem.Click += (s, e) => OnToggleGuardedAppClick(GuardedAppFlags.Claude);

            _guardedAppsMenu = new ToolStripMenuItem("受控应用");
            _guardedAppsMenu.DropDownItems.Add(_guardAntigravityItem);
            _guardedAppsMenu.DropDownItems.Add(_guardChatGPTItem);
            _guardedAppsMenu.DropDownItems.Add(_guardClaudeItem);

            _toggleMonitorItem = new ToolStripMenuItem("启用实时监控") { Checked = true };
            _toggleMonitorItem.Click += OnToggleMonitorClick;

            _autoStartItem = new ToolStripMenuItem("开机自动启动") { Checked = false };
            _autoStartItem.Click += OnToggleAutoStartClick;

            ToolStripMenuItem exitItem = new ToolStripMenuItem("退出");
            exitItem.Click += OnExitClick;

            _menu = new ContextMenuStrip();
            _menu.Items.Add(_statusItem);
            _menu.Items.Add(_wfpStatusItem);
            _menu.Items.Add(_guardedAppsSummaryItem);
            _menu.Items.Add(_nodeRuleItem);
            _menu.Items.Add(_lastKillItem);
            _menu.Items.Add(new ToolStripSeparator());
            _menu.Items.Add(_nodeSettingsItem);
            _menu.Items.Add(_logViewerItem);
            _menu.Items.Add(_guardedAppsMenu);
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
            _monitor.ProcessesKilled += OnProcessesKilled;
            _monitor.WfpBlocked += OnWfpBlocked;
            _monitor.GuardedAppLaunchedWhileBlocked += OnGuardedAppLaunchedWhileBlocked;
            _monitor.AccessDenied += OnAccessDenied;
            _monitor.NodeConfigChanged += OnNodeConfigChanged;
            _monitor.Start();

            UpdateTrayUi(_monitor.CurrentStatus);
            _trayIcon.Visible = true;

            // Listen for duplicate-launch ping so clicking the desktop shortcut shows status
            _pingEvent = CreatePingEvent(pingEventName);
            _pingThread = new Thread(PingListenerLoop) { IsBackground = true, Name = "PingListener" };
            _pingThread.Start();

            SystemEvents.SessionEnding += OnSessionEnding;
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
                AppLogger.Info("APP", "收到重复启动唤醒信号，弹出托盘状态气泡");
                PostToUi(() => ShowStatusBalloon("Clash TUN 守护已在后台运行"));
            }
        }

        private void OnMonitorStatusChanged(TunStatus status)
        {
            PostToUi(() => UpdateTrayUi(status));
        }

        private void OnNodeConfigChanged(NodeGuardConfig config)
        {
            PostToUi(() =>
            {
                if (!_disposed && config != null)
                {
                    SyncGuardedAppsUi(config);
                    _nodeRuleItem.Text = config.GetSummaryText();
                    if (_settingsForm != null && !_settingsForm.IsDisposed)
                    {
                        _settingsForm.SyncGuardedApps(config);
                        _settingsForm.SyncLogDirectory(config.LogDirectory);
                    }
                    if (_logViewerForm != null && !_logViewerForm.IsDisposed)
                    {
                        _logViewerForm.SyncLogDirectoryChanged();
                    }
                    UpdateTrayUi(_monitor.CurrentStatus);
                }
            });
        }

        private void SyncGuardedAppsUi(NodeGuardConfig config)
        {
            NodeGuardConfig cfg = config ?? new NodeGuardConfig();
            _guardedAppsSummaryItem.Text = cfg.GetGuardedAppsSummaryText();
            _guardAntigravityItem.Checked = cfg.GuardAntigravity;
            _guardChatGPTItem.Checked = cfg.GuardChatGPT;
            _guardClaudeItem.Checked = cfg.GuardClaude;
        }

        private void OnToggleGuardedAppClick(GuardedAppFlags appFlag)
        {
            if (_disposed)
            {
                return;
            }
            NodeGuardConfig current = _monitor.CurrentNodeConfig ?? new NodeGuardConfig();
            NodeGuardConfig next = current.CloneNormalized();
            if (appFlag == GuardedAppFlags.Antigravity)
            {
                next.GuardAntigravity = !next.GuardAntigravity;
            }
            else if (appFlag == GuardedAppFlags.ChatGPT)
            {
                next.GuardChatGPT = !next.GuardChatGPT;
            }
            else if (appFlag == GuardedAppFlags.Claude)
            {
                next.GuardClaude = !next.GuardClaude;
            }

            try
            {
                NodeGuardConfigStore.Save(_monitor.NodeConfigPath, next);
            }
            catch (Exception ex)
            {
                AppLogger.Error("CONFIG", "通过托盘切换受控应用保存失败: " + ex.Message);
                _trayIcon.ShowBalloonTip(3000, "保存受控应用设置失败", ex.Message, ToolTipIcon.Error);
                return;
            }

            _monitor.ApplyNodeGuardConfig(next);
            SyncGuardedAppsUi(next);
            if (_settingsForm != null && !_settingsForm.IsDisposed)
            {
                _settingsForm.SyncGuardedApps(next);
            }
            UpdateTrayUi(_monitor.CurrentStatus);
        }

        private void OnProcessesKilled(KillResult result, string trigger, TunStatus status)
        {
            int count = Interlocked.Increment(ref _totalKills);
            string timeText = DateTime.Now.ToString("HH:mm:ss");
            bool isNodeTrigger = status.IsTunActive && status.NodeGuardEnabled && !status.IsNodeAllowed;
            string killedNames = result.KilledApps != GuardedAppFlags.None
                ? GuardedAppHelper.FormatNames(result.KilledApps)
                : "受控应用";
            string killedShortNames = result.KilledApps != GuardedAppFlags.None
                ? GuardedAppHelper.FormatShortNames(result.KilledApps)
                : "受控应用";
            string balloonTitle = isNodeTrigger
                ? ("Clash 节点不匹配 — 已终止 " + killedNames)
                : ("TUN 已关闭 — 已终止 " + killedNames);
            string detailReason = isNodeTrigger ? status.NodeReason : status.Reason;
            NodeGuardConfig cfg = _monitor.CurrentNodeConfig;

            GuardAlertPayload alert = new GuardAlertPayload
            {
                Title = isNodeTrigger
                    ? ("未匹配允许节点 — 已拦截 " + killedNames)
                    : ("TUN 未开启 — 已拦截 " + killedNames),
                AppNames = killedNames,
                Reason = detailReason,
                ActiveChain = isNodeTrigger
                    ? (!string.IsNullOrEmpty(status.ActiveNodeChain) ? status.ActiveNodeChain : status.ActiveNodeName)
                    : string.Empty,
                AllowedNodesText = isNodeTrigger ? FormatAllowedNodesSummary(cfg) : string.Empty,
                ActionText = string.Format("已终止 {0} 共 {1} 个进程（首轮耗时 {2:F2} ms）", killedNames, result.KilledCount, result.FirstPassMs),
                HintText = isNodeTrigger
                    ? "请在 Clash Verge 中切换到允许的节点后，再重新打开该软件。"
                    : "请在 Clash Verge 中开启 TUN 模式后，再重新打开该软件。",
                IsSevere = true,
                IsKillEvent = true,
                KilledDelta = result.KilledCount,
                FirstPassMs = result.FirstPassMs
            };

            PostToUi(() =>
            {
                _lastKillItem.Text = string.Format("上次拦截: {0} ({1}, {2}进程, {3:F2}ms)", timeText, killedShortNames, result.KilledCount, result.FirstPassMs);
                _trayIcon.ShowBalloonTip(
                    2500,
                    balloonTitle,
                    string.Format("触发源: {0}\n原因: {1}\n已终止 {2} 共 {3} 个进程，首轮耗时 {4:F2} ms (累计拦截 {5} 次)", trigger, detailReason, killedNames, result.KilledCount, result.FirstPassMs, count),
                    ToolTipIcon.Warning);
                ShowGuardAlertPopup(alert, result.KilledApps);
            });
        }

        private void OnWfpBlocked(GuardedAppFlags runningApps, string trigger, TunStatus status)
        {
            string timeText = DateTime.Now.ToString("HH:mm:ss");
            bool isNodeTrigger = status.IsTunActive && status.NodeGuardEnabled && !status.IsNodeAllowed;
            NodeGuardConfig cfg = _monitor.CurrentNodeConfig;
            string appNames = runningApps != GuardedAppFlags.None
                ? GuardedAppHelper.FormatNames(runningApps)
                : (cfg != null ? GuardedAppHelper.FormatNames(cfg.GetGuardedAppFlags()) : "受控应用");
            string title = isNodeTrigger
                ? "Clash 节点不匹配 — WFP 已断网"
                : "TUN 已关闭 — WFP 已断网";
            string detailReason = isNodeTrigger ? status.NodeReason : status.Reason;

            GuardAlertPayload alert = new GuardAlertPayload
            {
                Title = isNodeTrigger
                    ? ("未匹配允许节点 — 已阻断 " + appNames + " 联网")
                    : ("TUN 未开启 — 已阻断 " + appNames + " 联网"),
                AppNames = appNames,
                Reason = detailReason,
                ActiveChain = isNodeTrigger
                    ? (!string.IsNullOrEmpty(status.ActiveNodeChain) ? status.ActiveNodeChain : status.ActiveNodeName)
                    : string.Empty,
                AllowedNodesText = isNodeTrigger ? FormatAllowedNodesSummary(cfg) : string.Empty,
                ActionText = string.Format("已通过 WFP 内核阻断 {0} 出站联网（进程已保留，不丢失内容）", appNames),
                HintText = isNodeTrigger
                    ? "请在 Clash Verge 切换至允许节点，合规后将自动恢复联网。"
                    : "请在 Clash Verge 开启 TUN 模式，恢复后将自动恢复联网。",
                IsSevere = true,
                IsKillEvent = false
            };

            PostToUi(() =>
            {
                _lastKillItem.Text = string.Format("上次拦截: {0} (WFP 内核断网，未终止进程)", timeText);
                _trayIcon.ShowBalloonTip(
                    2500,
                    title,
                    string.Format("触发源: {0}\n原因: {1}\n已通过 WFP 内核阻断 {2} 联网（进程保留，恢复合规后自动恢复联网）", trigger, detailReason, appNames),
                    ToolTipIcon.Warning);
                if (runningApps != GuardedAppFlags.None)
                {
                    ShowGuardAlertPopup(alert, runningApps);
                }
            });
        }

        private void OnGuardedAppLaunchedWhileBlocked(GuardedAppFlags launchedApps, TunStatus status)
        {
            string timeText = DateTime.Now.ToString("HH:mm:ss");
            bool isNodeTrigger = status.IsTunActive && status.NodeGuardEnabled && !status.IsNodeAllowed;
            NodeGuardConfig cfg = _monitor.CurrentNodeConfig;
            string appNames = GuardedAppHelper.FormatNames(launchedApps);
            string appShortNames = GuardedAppHelper.FormatShortNames(launchedApps);
            string detailReason = isNodeTrigger ? status.NodeReason : status.Reason;
            string balloonTitle = isNodeTrigger
                ? ("未匹配允许节点 — 已阻断 " + appNames)
                : ("TUN 未开启 — 已阻断 " + appNames);

            GuardAlertPayload alert = new GuardAlertPayload
            {
                Title = isNodeTrigger
                    ? ("未匹配允许节点 — 已阻断 " + appNames + " 联网")
                    : ("TUN 未开启 — 已阻断 " + appNames + " 联网"),
                AppNames = appNames,
                Reason = detailReason,
                ActiveChain = isNodeTrigger
                    ? (!string.IsNullOrEmpty(status.ActiveNodeChain) ? status.ActiveNodeChain : status.ActiveNodeName)
                    : string.Empty,
                AllowedNodesText = isNodeTrigger ? FormatAllowedNodesSummary(cfg) : string.Empty,
                ActionText = string.Format("检测到您打开了 {0}，当前已由 WFP 内核阻断出站联网（进程已保留）", appNames),
                HintText = isNodeTrigger
                    ? "请在 Clash Verge 切换至允许节点后即可恢复联网使用。"
                    : "请在 Clash Verge 开启 TUN 模式后即可恢复联网使用。",
                IsSevere = true,
                IsKillEvent = false
            };

            PostToUi(() =>
            {
                _lastKillItem.Text = string.Format("上次拦截: {0} (启动 {1}，WFP 断网)", timeText, appShortNames);
                _trayIcon.ShowBalloonTip(
                    2500,
                    balloonTitle,
                    string.Format("原因: {0}\n检测到启动 {1}，已由 WFP 内核阻断出站联网。", detailReason, appNames),
                    ToolTipIcon.Warning);
                ShowGuardAlertPopup(alert, launchedApps);
            });
        }

        private void OnAccessDenied(int deniedCount, GuardedAppFlags deniedApps, string trigger)
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
            string appNames = deniedApps != GuardedAppFlags.None
                ? GuardedAppHelper.FormatNames(deniedApps)
                : "受控应用";
            GuardAlertPayload alert = new GuardAlertPayload
            {
                Title = "权限不足 — 无法终止 " + appNames,
                AppNames = appNames,
                Reason = string.Format("触发源: {0}，检测到 {1} 个 {2} 进程但无权终止", trigger, deniedCount, appNames),
                ActiveChain = string.Empty,
                AllowedNodesText = string.Empty,
                ActionText = "当前未具备足够权限终止目标高权限进程",
                HintText = "请关闭后以管理员身份运行 TunGuard，或开启开机自启计划任务。",
                IsSevere = false,
                IsKillEvent = false
            };

            PostToUi(() =>
            {
                _lastKillItem.Text = string.Format("权限不足: {0} ({1}进程无法终止)", timeText, deniedCount);
                _trayIcon.ShowBalloonTip(
                    3000,
                    "权限不足 — 无法终止 " + appNames,
                    string.Format("触发源: {0}\n检测到 {1} 个 {2} 进程但无权终止，请以管理员身份运行 TunGuard。", trigger, deniedCount, appNames),
                    ToolTipIcon.Error);
                ShowGuardAlertPopup(alert, deniedApps);
            });
        }

        private static string FormatAllowedNodesSummary(NodeGuardConfig cfg)
        {
            if (cfg == null || !cfg.Enabled)
            {
                return string.Empty;
            }
            if (cfg.AllowedNodes == null || cfg.AllowedNodes.Count == 0)
            {
                return "未配置任何允许节点";
            }
            string modeLabel = string.Equals(cfg.MatchMode, "contains", StringComparison.OrdinalIgnoreCase)
                ? "关键词"
                : "精确";
            int showCount = Math.Min(cfg.AllowedNodes.Count, 3);
            List<string> preview = new List<string>(showCount);
            for (int i = 0; i < showCount; i++)
            {
                preview.Add(cfg.AllowedNodes[i]);
            }
            string joined = string.Join("、", preview.ToArray());
            if (cfg.AllowedNodes.Count > showCount)
            {
                return string.Format("{0} 等 {1} 项 ({2}匹配)", joined, cfg.AllowedNodes.Count, modeLabel);
            }
            return string.Format("{0} ({1}匹配)", joined, modeLabel);
        }

        private void ShowGuardAlertPopup(GuardAlertPayload payload, GuardedAppFlags affectedApps)
        {
            if (_disposed)
            {
                return;
            }
            NodeGuardConfig cfg = _monitor.CurrentNodeConfig;
            if (cfg != null && !cfg.PopupOnBlock)
            {
                return;
            }

            if (_alertForm != null && !_alertForm.IsDisposed)
            {
                _currentAlertApps |= affectedApps;
                _alertForm.ShowOrUpdate(payload, true);
                return;
            }

            long nowTicks = DateTime.UtcNow.Ticks;
            if (nowTicks - _lastAlertDismissedTicks < AlertDismissCooldownTicks &&
                affectedApps != GuardedAppFlags.None &&
                (affectedApps & _lastAlertDismissedApps) == affectedApps)
            {
                return;
            }

            GuardAlertForm form = new GuardAlertForm(
                () => OpenNodeSettingsWindow(),
                () => OpenLogViewerWindow());
            _alertForm = form;
            _currentAlertApps = affectedApps;
            form.FormClosed += (s, args) =>
            {
                if (ReferenceEquals(_alertForm, form))
                {
                    if (form.DismissedByUser)
                    {
                        _lastAlertDismissedTicks = DateTime.UtcNow.Ticks;
                        _lastAlertDismissedApps = _currentAlertApps;
                    }
                    _alertForm = null;
                    _currentAlertApps = GuardedAppFlags.None;
                }
                form.Dispose();
            };
            form.ShowOrUpdate(payload, false);
        }

        private void CloseGuardAlertPopupIfOpen()
        {
            if (_alertForm != null && !_alertForm.IsDisposed)
            {
                try
                {
                    _alertForm.Close();
                }
                catch
                {
                }
            }
        }

        private static string TruncateNotifyText(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return string.Empty;
            }
            return text.Length > 63 ? text.Substring(0, 63) : text;
        }

        private void UpdateTrayUi(TunStatus status)
        {
            if (_disposed)
            {
                return;
            }

            NodeGuardConfig cfg = _monitor.CurrentNodeConfig;
            SyncGuardedAppsUi(cfg);
            _nodeRuleItem.Text = cfg != null ? cfg.GetSummaryText() : "节点守护: 未启用";
            _wfpStatusItem.Text = "内核断网: " + (string.IsNullOrEmpty(status.WfpStatusText) ? "未启用" : status.WfpStatusText);
            if (_settingsForm != null && !_settingsForm.IsDisposed)
            {
                _settingsForm.UpdateWfpStatus(status);
            }
            bool hasTargets = cfg == null || cfg.GetGuardedAppFlags() != GuardedAppFlags.None;
            bool wfpOnlyMode = status.WfpActive && cfg != null && cfg.WfpEnabled && !cfg.WfpKillOnBlock;

            if (!_monitor.MonitoringEnabled)
            {
                CloseGuardAlertPopupIfOpen();
                string detail = !status.IsTunActive
                    ? status.Reason
                    : (status.NodeGuardEnabled ? status.NodeReason : status.Reason);
                _trayIcon.Icon = _iconPaused;
                _trayIcon.Text = "Clash TUN 守护 | 已暂停监控";
                _statusItem.Text = "状态: 已暂停 (" + detail + ")";
                return;
            }

            if (status.IsGuardSafe)
            {
                CloseGuardAlertPopupIfOpen();
                _trayIcon.Icon = _iconSafe;
                string wfpTag = status.WfpActive ? " [WFP]" : string.Empty;
                if (status.NodeGuardEnabled)
                {
                    string node = !string.IsNullOrEmpty(status.ActiveNodeName) ? status.ActiveNodeName : "未知";
                    _trayIcon.Text = TruncateNotifyText("Clash TUN 守护" + wfpTag + " | 正常 | 节点: " + node);
                    _statusItem.Text = "状态: 正常 | TUN(" + status.AdapterAlias + ") | 节点: " + node;
                }
                else
                {
                    _trayIcon.Text = TruncateNotifyText("Clash TUN 守护" + wfpTag + " | TUN: 已开启 (" + status.AdapterAlias + ")");
                    _statusItem.Text = "状态: TUN 已开启 (" + status.AdapterAlias + ")";
                }
            }
            else if (!status.IsTunActive)
            {
                _trayIcon.Icon = _iconAlert;
                string alertTag = !hasTargets
                    ? "(未勾选受控应用)"
                    : (wfpOnlyMode ? "(WFP 已断网)" : "(禁止启动)");
                _trayIcon.Text = TruncateNotifyText("Clash TUN 守护 | TUN: 已关闭 " + alertTag);
                _statusItem.Text = "状态: TUN 已关闭 (" + status.Reason + ")";
            }
            else
            {
                _trayIcon.Icon = _iconAlert;
                string alertTag = !hasTargets
                    ? "(未勾选受控应用)"
                    : (wfpOnlyMode ? "(WFP 已断网)" : "(禁止启动)");
                _trayIcon.Text = TruncateNotifyText("Clash TUN 守护 | 节点不匹配 " + alertTag);
                _statusItem.Text = "状态: 已拦截 (" + status.NodeReason + ")";
            }
        }

        private void OnNodeSettingsClick(object sender, EventArgs e)
        {
            OpenNodeSettingsWindow();
        }

        private void OpenNodeSettingsWindow()
        {
            if (_disposed)
            {
                return;
            }
            if (_settingsForm != null && !_settingsForm.IsDisposed)
            {
                if (_settingsForm.WindowState == FormWindowState.Minimized)
                {
                    _settingsForm.WindowState = FormWindowState.Normal;
                }
                _settingsForm.Activate();
                _settingsForm.BringToFront();
                return;
            }

            NodeSettingsForm form = new NodeSettingsForm(
                _monitor.CurrentNodeConfig,
                _monitor.NodeConfigPath,
                () => _monitor.QueryClashCatalog(),
                () => _monitor.CurrentStatus,
                rescan => _monitor.GetAppPathDiagnostics(rescan),
                () => OpenLogViewerWindow(),
                ApplyUpdateAndRestart,
                _iconSafe);
            _settingsForm = form;
            form.FormClosed += (s, args) =>
            {
                if (ReferenceEquals(_settingsForm, form))
                {
                    _settingsForm = null;
                }
                if (!_disposed && form.DialogResult == DialogResult.OK && form.ResultConfig != null)
                {
                    _monitor.ApplyNodeGuardConfig(form.ResultConfig);
                    if (_logViewerForm != null && !_logViewerForm.IsDisposed)
                    {
                        _logViewerForm.SyncLogDirectoryChanged();
                    }
                    UpdateTrayUi(_monitor.CurrentStatus);
                }
                form.Dispose();
            };
            form.Show();
            form.Activate();
        }

        private bool ApplyUpdateAndRestart(string stagedExePath, string targetVersionTag, out string error)
        {
            error = null;
            if (_disposed)
            {
                error = "应用正在退出";
                return false;
            }

            string currentExePath;
            if (!AppUpdater.SwapExecutableInPlace(stagedExePath, out currentExePath, out error))
            {
                AppLogger.Error("UPDATER", "替换程序文件失败: " + error);
                return false;
            }

            AppLogger.Info("UPDATER", string.Format(
                "已完成版本替换 ({0} -> {1})，即将重启 TunGuard",
                AppUpdater.GetCurrentVersionText(),
                string.IsNullOrEmpty(targetVersionTag) ? "最新版本" : targetVersionTag));
            Program.PendingRestartExePath = currentExePath;
            ExitCleanly();
            return true;
        }

        private void OnLogViewerClick(object sender, EventArgs e)
        {
            OpenLogViewerWindow();
        }

        private void OpenLogViewerWindow()
        {
            if (_disposed)
            {
                return;
            }
            if (_logViewerForm != null && !_logViewerForm.IsDisposed)
            {
                if (_logViewerForm.WindowState == FormWindowState.Minimized)
                {
                    _logViewerForm.WindowState = FormWindowState.Normal;
                }
                _logViewerForm.Activate();
                _logViewerForm.BringToFront();
                return;
            }

            LogViewerForm form = new LogViewerForm(HandleLogDirectoryChangeFromViewer, _iconSafe);
            _logViewerForm = form;
            form.FormClosed += (s, args) =>
            {
                if (ReferenceEquals(_logViewerForm, form))
                {
                    _logViewerForm = null;
                }
                form.Dispose();
            };
            form.Show();
            form.Activate();
        }

        private bool HandleLogDirectoryChangeFromViewer(
            string newConfiguredDir,
            bool migrateExisting,
            out int migratedCount,
            out string effectiveDir,
            out string error)
        {
            if (!AppLogger.SetLogDirectory(newConfiguredDir, migrateExisting, out migratedCount, out effectiveDir, out error))
            {
                return false;
            }

            NodeGuardConfig current = _monitor.CurrentNodeConfig ?? new NodeGuardConfig();
            NodeGuardConfig next = current.CloneNormalized();
            next.LogDirectory = AppLogger.IsUsingDefaultDirectory ? string.Empty : effectiveDir;

            try
            {
                NodeGuardConfigStore.Save(_monitor.NodeConfigPath, next);
            }
            catch (Exception ex)
            {
                error = "目录已切换，但写入配置文件失败: " + ex.Message;
                AppLogger.Error("CONFIG", error);
                return false;
            }

            _monitor.ApplyNodeGuardConfig(next);
            if (_settingsForm != null && !_settingsForm.IsDisposed)
            {
                _settingsForm.SyncLogDirectory(next.LogDirectory);
            }
            return true;
        }

        private void OnTrayDoubleClick(object sender, EventArgs e)
        {
            OnNodeSettingsClick(sender, e);
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
            NodeGuardConfig cfg = _monitor.CurrentNodeConfig ?? new NodeGuardConfig();
            string mode = _monitor.MonitoringEnabled ? "实时监控中" : "已暂停监控";
            string tunLine = s.IsTunActive ? ("TUN: 已开启 (" + s.AdapterAlias + ")") : ("TUN: 已关闭 (" + s.Reason + ")");
            string wfpLine = "内核断网: " + (string.IsNullOrEmpty(s.WfpStatusText) ? "未启用" : s.WfpStatusText);
            string body = mode + "\n" + cfg.GetGuardedAppsSummaryText() + "\n" + tunLine + "\n" + wfpLine;
            if (s.NodeGuardEnabled)
            {
                string nodeDetail = !string.IsNullOrEmpty(s.ActiveNodeChain)
                    ? (s.NodeReason + " [" + s.ActiveNodeChain + "]")
                    : s.NodeReason;
                body += "\n节点: " + nodeDetail;
            }
            _trayIcon.ShowBalloonTip(2500, title, body, s.IsGuardSafe ? ToolTipIcon.Info : ToolTipIcon.Warning);
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
                    if (ok)
                    {
                        AppLogger.Info("STARTUP", target ? "已开启开机自动启动计划任务" : "已关闭开机自动启动计划任务");
                    }
                    else
                    {
                        AppLogger.Error("STARTUP", (target ? "开启" : "关闭") + "开机自动启动失败（可能缺少管理员权限）");
                    }
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
            AppLogger.Info("APP", "收到系统关机/注销事件，正在退出 TunGuard");
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
            AppLogger.Info("APP", "用户点击退出 TunGuard");
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

                    if (_alertForm != null && !_alertForm.IsDisposed)
                    {
                        try
                        {
                            _alertForm.Close();
                            _alertForm.Dispose();
                        }
                        catch
                        {
                        }
                        _alertForm = null;
                    }

                    if (_logViewerForm != null && !_logViewerForm.IsDisposed)
                    {
                        try
                        {
                            _logViewerForm.Close();
                            _logViewerForm.Dispose();
                        }
                        catch
                        {
                        }
                        _logViewerForm = null;
                    }

                    if (_settingsForm != null && !_settingsForm.IsDisposed)
                    {
                        try
                        {
                            _settingsForm.Close();
                            _settingsForm.Dispose();
                        }
                        catch
                        {
                        }
                        _settingsForm = null;
                    }

                    AppLogger.Info("APP", "TunGuard 资源已清理完毕，退出运行");
                    AppLogger.Shutdown();

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
                    if (_boldMenuFont != null)
                    {
                        _boldMenuFont.Dispose();
                    }

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
