using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Background;
using Windows.Data.Json;
using Windows.Foundation;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage;

namespace Xelite.Core
{
    /// <summary>Creates the VPN profile and connects/disconnects it.</summary>
    public static class VpnService
    {
        public const string ProfileName = "Xelite";

        private const int E_HANDLE = unchecked((int)0x80070006);

        /// <summary>
        /// Runs one VpnManagementAgent call on a fresh agent. A long-lived agent
        /// fails with E_HANDLE ("the handle is invalid") once the system VPN
        /// service restarts, so one retry is made with a new agent. Errors are
        /// logged and labelled with the step that failed.
        /// </summary>
        private static async Task<T> Call<T>(string step, Func<VpnManagementAgent, IAsyncOperation<T>> op, bool log = true)
        {
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    return await op(new VpnManagementAgent());
                }
                catch (Exception e) when (attempt == 0 && e.HResult == E_HANDLE)
                {
                    if (log)
                    {
                        AppLog(step + ": invalid handle, retrying");
                    }
                    await Task.Delay(500);
                }
                catch (Exception e)
                {
                    if (log)
                    {
                        AppLog(step + " failed: 0x" + e.HResult.ToString("X8") + " " + e.Message);
                    }
                    throw new InvalidOperationException(step + " failed (0x" + e.HResult.ToString("X8") + "): " + e.Message, e);
                }
            }
        }

        public static string DataDir => ApplicationData.Current.LocalFolder.Path;
        public static string XrayLogPath => Path.Combine(DataDir, "xray.log");
        public static string PluginLogPath => Path.Combine(DataDir, "vpn.log");
        public static string AppLogPath => Path.Combine(DataDir, "app.log");

        public static void AppLog(string message)
        {
            try
            {
                File.AppendAllText(AppLogPath, DateTime.Now.ToString("HH:mm:ss ") + message + Environment.NewLine);
            }
            catch (Exception)
            {
            }
        }

        public static async Task<VpnManagementConnectionStatus> GetStatusAsync()
        {
            var profile = await FindProfileAsync(log: false);
            if (profile == null)
            {
                return VpnManagementConnectionStatus.Disconnected;
            }
            try
            {
                return profile.ConnectionStatus;
            }
            catch (Exception)
            {
                // Throws E_HANDLE on Windows 10 Mobile; use the state the plug-in reports.
                return StatusFromPlugin();
            }
        }

        public static string StatePath => Path.Combine(DataDir, "vpn.state");
        public static string StatsPath => Path.Combine(DataDir, "core.stats");

        /// <summary>Counters written by xelite-core every second ("key=value ..."), empty if none.</summary>
        public static Dictionary<string, long> ReadStats()
        {
            var result = new Dictionary<string, long>();
            var text = ReadTail(StatsPath, 2000);
            var firstLine = text.Split('\n')[0];
            foreach (var part in firstLine.Split(' '))
            {
                var kv = part.Split('=');
                long v;
                if (kv.Length == 2 && long.TryParse(kv[1], out v))
                {
                    result[kv[0]] = v;
                }
            }
            return result;
        }

        /// <summary>Public IP and country as seen by a web service, through whatever route Windows picks.</summary>
        public static async Task<string> CheckPublicIpAsync()
        {
            var filter = new Windows.Web.Http.Filters.HttpBaseProtocolFilter();
            filter.CacheControl.ReadBehavior = Windows.Web.Http.Filters.HttpCacheReadBehavior.MostRecent;
            filter.CacheControl.WriteBehavior = Windows.Web.Http.Filters.HttpCacheWriteBehavior.NoCache;
            using (var client = new Windows.Web.Http.HttpClient(filter))
            {
                var get = client.GetStringAsync(new Uri("http://ip-api.com/json/?fields=query,country,isp")).AsTask();
                if (await Task.WhenAny(get, Task.Delay(8000)) != get)
                {
                    throw new TimeoutException("no answer in 8 seconds");
                }
                var json = JsonObject.Parse(await get);
                return json.GetNamedString("query", "?") + " · " + json.GetNamedString("country", "") + " · " + json.GetNamedString("isp", "");
            }
        }

        private static string ReadState()
        {
            try
            {
                return File.Exists(StatePath) ? File.ReadAllText(StatePath).Trim() : "";
            }
            catch (Exception)
            {
                return "";
            }
        }

        private static VpnManagementConnectionStatus StatusFromPlugin()
        {
            var state = ReadState();
            if (state == "connected")
            {
                return VpnManagementConnectionStatus.Connected;
            }
            if (state == "connecting" && DateTime.Now - File.GetLastWriteTime(StatePath) < TimeSpan.FromSeconds(30))
            {
                return VpnManagementConnectionStatus.Connecting;
            }
            return VpnManagementConnectionStatus.Disconnected;
        }

        /// <summary>Most servers an "auto" entry balances between (each one is probed every minute).</summary>
        public const int MaxBalancedServers = 32;

        /// <summary>Connects to one server, or to several behind Xray's balancer.</summary>
        public static async Task ConnectAsync(IList<ProxyLink> servers)
        {
            var settings = AppSettings.Current;

            // Resolve every server up front so its IP can be excluded from the tunnel.
            var candidates = servers.Take(MaxBalancedServers).ToList();
            var resolved = await Task.WhenAll(candidates.Select(TryResolveAsync));
            var links = new List<ProxyLink>();
            var ips = new List<string>();
            for (var i = 0; i < candidates.Count; i++)
            {
                if (resolved[i] != null)
                {
                    links.Add(candidates[i]);
                    ips.Add(resolved[i]);
                }
            }
            if (links.Count == 0)
            {
                throw new InvalidOperationException("Cannot resolve " + candidates.First().Address);
            }
            AppLog("connect: " + links.Count + " server(s), first " + links[0].Name + " (" + ips[0] + ")");
            LastServers = links.Select((l, i) => new KeyValuePair<ProxyLink, string>(l, ips[i])).ToList();

            File.WriteAllText(Path.Combine(DataDir, "config.json"),
                ConfigBuilder.Build(links, ips, settings, XrayLogPath));

            var exclude = new JsonArray();
            foreach (var ip in ips.Distinct())
            {
                if (new HostName(ip).Type == HostNameType.Ipv4)
                {
                    // Keep Xray's own connections to the servers outside the tunnel.
                    exclude.Add(JsonValue.CreateStringValue(ip + "/32"));
                }
            }
            if (settings.BypassLan)
            {
                foreach (var cidr in ConfigBuilder.PrivateRanges)
                {
                    exclude.Add(JsonValue.CreateStringValue(cidr));
                }
            }
            var dns = new JsonArray();
            foreach (var d in settings.DnsServers.Select(s => s.Trim()).Where(s => s.Length > 0))
            {
                dns.Add(JsonValue.CreateStringValue(d));
            }
            var vpn = new JsonObject
            {
                ["mtu"] = JsonValue.CreateNumberValue(settings.Mtu),
                ["port"] = JsonValue.CreateNumberValue(0),
                ["bypassLan"] = JsonValue.CreateBooleanValue(settings.BypassLan),
                ["ipv6"] = JsonValue.CreateBooleanValue(settings.AllowIpv6),
                ["dns"] = dns,
                ["exclude"] = exclude,
            };
            File.WriteAllText(Path.Combine(DataDir, "vpn.json"), vpn.Stringify());
            TrimLog(XrayLogPath);
            TrimLog(PluginLogPath);
            TrimLog(AppLogPath);

            await EnsureBackgroundAccessAsync();
            var profile = await EnsureProfileAsync();
            var pluginLogSize = FileSize(PluginLogPath);
            AppLog("ConnectProfileAsync(" + profile.ProfileName + ", " + profile.VpnPluginPackageFamilyName + ")");
            try
            {
                File.Delete(StatePath);
                File.Delete(StatsPath);
            }
            catch (Exception)
            {
            }
            var status = await Call("connect VPN profile", a => a.ConnectProfileAsync(profile));
            AppLog("ConnectProfileAsync -> " + status + ", plug-in state '" + ReadState() + "'");
            if (status != VpnManagementErrorStatus.Ok && FileSize(PluginLogPath) == pluginLogSize)
            {
                // Right after a disconnect Windows is still tearing the old tunnel down and
                // refuses without starting the plug-in; a second try a moment later works.
                await Task.Delay(3000);
                AppLog("retrying ConnectProfileAsync");
                status = await Call("connect VPN profile", a => a.ConnectProfileAsync(profile));
                AppLog("ConnectProfileAsync -> " + status + ", plug-in state '" + ReadState() + "'");
            }
            if (status != VpnManagementErrorStatus.Ok)
            {
                var pluginRan = FileSize(PluginLogPath) > pluginLogSize;
                var lastLine = LastLine(PluginLogPath);
                if (pluginRan && lastLine.Length > 0)
                {
                    throw new InvalidOperationException("Connect failed: " + status + "\n" + lastLine);
                }
                throw new InvalidOperationException("Connect failed: " + status + "\nThe VPN plug-in did not start. Try ⋯ → reset VPN profile, then connect again.");
            }

            // "Ok" only means the request was accepted; wait for the plug-in's own result.
            for (var i = 0; i < 60; i++)
            {
                var state = ReadState();
                if (state == "connected")
                {
                    AppLog("plug-in connected");
                    return;
                }
                if (state.StartsWith("error"))
                {
                    AppLog("plug-in " + state);
                    throw new InvalidOperationException("Connect failed: " + state.Substring(5).TrimStart(':', ' '));
                }
                await Task.Delay(250);
            }
            var started = FileSize(PluginLogPath) > pluginLogSize;
            AppLog("no plug-in result after 15 s, plug-in log " + (started ? "written" : "empty"));
            if (!started)
            {
                throw new InvalidOperationException("Windows accepted the connection, but the VPN plug-in did not start. " +
                                                    "Try connecting from Settings → Network & wireless → VPN → Xelite and tell me the message shown there.");
            }
        }

        public static async Task DisconnectAsync()
        {
            var profile = await FindProfileAsync();
            if (profile != null)
            {
                await Call("disconnect VPN profile", a => a.DisconnectProfileAsync(profile));
            }
        }

        /// <summary>Servers of the current/last connection with their resolved IPs.</summary>
        public static IReadOnlyList<KeyValuePair<ProxyLink, string>> LastServers { get; private set; } =
            new List<KeyValuePair<ProxyLink, string>>();

        /// <summary>TCP connect latency in ms, or -1 on failure.</summary>
        public static Task<int> PingAsync(ProxyLink link, int timeoutMs = 3000)
        {
            return PingAsync(link.Address, link.Port, timeoutMs);
        }

        /// <summary>
        /// TCP connect latency to host:port in ms, or -1. Use the resolved IP while
        /// connected: server IPs bypass the tunnel, DNS names would not.
        /// </summary>
        public static async Task<int> PingAsync(string host, int port, int timeoutMs = 3000)
        {
            using (var socket = new StreamSocket())
            {
                var sw = Stopwatch.StartNew();
                var connect = socket.ConnectAsync(new HostName(host), port.ToString()).AsTask();
                var done = await Task.WhenAny(connect, Task.Delay(timeoutMs));
                if (done != connect || connect.IsFaulted)
                {
                    return -1;
                }
                return (int)sw.ElapsedMilliseconds;
            }
        }

        private static async Task<string> TryResolveAsync(ProxyLink link)
        {
            try
            {
                var resolve = ResolveAsync(link.Address);
                return await Task.WhenAny(resolve, Task.Delay(5000)) == resolve ? await resolve : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static async Task<string> ResolveAsync(string host)
        {
            if (ConfigBuilder.IsIp(host))
            {
                return host;
            }
            var pairs = await DatagramSocket.GetEndpointPairsAsync(new HostName(host), "0");
            var names = pairs.Select(p => p.RemoteHostName).ToList();
            var best = names.FirstOrDefault(h => h.Type == HostNameType.Ipv4) ?? names.FirstOrDefault();
            if (best == null)
            {
                throw new InvalidOperationException("Cannot resolve " + host);
            }
            return best.CanonicalName;
        }

        /// <summary>
        /// Background tasks on Windows 10 Mobile only run after the app has asked
        /// for background access. The VPN plug-in is a background task too.
        /// </summary>
        public static async Task<BackgroundAccessStatus> EnsureBackgroundAccessAsync()
        {
            BackgroundAccessStatus access;
            try
            {
                access = await BackgroundExecutionManager.RequestAccessAsync();
            }
            catch (Exception e)
            {
                AppLog("RequestAccessAsync failed: 0x" + e.HResult.ToString("X8") + " " + e.Message);
                return BackgroundAccessStatus.Unspecified;
            }
            AppLog("background access: " + access);
            if (access == BackgroundAccessStatus.Denied || access == BackgroundAccessStatus.DeniedByUser ||
                access == BackgroundAccessStatus.DeniedBySystemPolicy)
            {
                throw new InvalidOperationException("Windows does not let Xelite run in the background (" + access + "), " +
                                                    "which the VPN needs. Turn on Xelite in Settings → Privacy → Background apps, " +
                                                    "turn off Battery saver, then connect again.");
            }
            return access;
        }

        /// <summary>Deletes the Xelite VPN profile; the next connect creates it again.</summary>
        public static async Task ResetProfileAsync()
        {
            var profile = await FindProfileAsync();
            if (profile == null)
            {
                AppLog("reset: no profile");
                return;
            }
            try
            {
                await Call("disconnect VPN profile", a => a.DisconnectProfileAsync(profile));
            }
            catch (InvalidOperationException)
            {
                // not connected; delete anyway
            }
            var status = await Call("delete VPN profile", a => a.DeleteProfileAsync(profile));
            AppLog("reset: DeleteProfileAsync -> " + status);
            if (status != VpnManagementErrorStatus.Ok)
            {
                throw new InvalidOperationException("Cannot delete the VPN profile: " + status +
                                                    ". Remove \"" + ProfileName + "\" in Settings → Network & wireless → VPN.");
            }
        }

        private static long FileSize(string path)
        {
            try
            {
                return File.Exists(path) ? new FileInfo(path).Length : 0;
            }
            catch (IOException)
            {
                return 0;
            }
        }

        private static string LastLine(string path)
        {
            var lines = ReadTail(path, 2000).Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            return lines.Length > 0 ? lines[lines.Length - 1] : "";
        }

        /// <param name="log">False for the once-a-second status poll, to keep app.log readable.</param>
        private static async Task<VpnPlugInProfile> FindProfileAsync(bool log = true)
        {
            var profiles = await Call("list VPN profiles", a => a.GetProfilesAsync(), log);
            return profiles.OfType<VpnPlugInProfile>().FirstOrDefault(p => p.ProfileName == ProfileName);
        }

        private static async Task<VpnPlugInProfile> EnsureProfileAsync()
        {
            var profile = await FindProfileAsync();
            if (profile != null)
            {
                return profile;
            }
            profile = new VpnPlugInProfile
            {
                ProfileName = ProfileName,
                VpnPluginPackageFamilyName = Package.Current.Id.FamilyName,
                AlwaysOn = false,
                RememberCredentials = false,
                RequireVpnClientAppUI = true,
            };
            profile.ServerUris.Add(new Uri("https://127.0.0.1"));
            var status = await Call("create VPN profile", a => a.AddProfileFromObjectAsync(profile));
            AppLog("AddProfileFromObjectAsync(" + profile.VpnPluginPackageFamilyName + ") -> " + status);
            if (status != VpnManagementErrorStatus.Ok)
            {
                throw new InvalidOperationException("Cannot create VPN profile: " + status);
            }
            return await FindProfileAsync() ?? profile;
        }

        public static string ReadLogs()
        {
            var tempPluginLog = Path.Combine(ApplicationData.Current.TemporaryFolder.Path, "vpn.log");
            return "--- app ---" + Environment.NewLine + ReadTail(AppLogPath, 3000) + Environment.NewLine +
                   "--- vpn plug-in ---" + Environment.NewLine + ReadTail(PluginLogPath, 4000) + ReadTail(tempPluginLog, 2000) + Environment.NewLine +
                   "--- traffic ---" + Environment.NewLine + ReadTail(StatsPath, 1000) + Environment.NewLine +
                   "--- xray ---" + Environment.NewLine + ReadTail(XrayLogPath, 12000);
        }

        public static void ClearLogs()
        {
            foreach (var path in new[] { XrayLogPath, PluginLogPath, AppLogPath })
            {
                try
                {
                    File.Delete(path);
                }
                catch (IOException)
                {
                }
            }
        }

        private static string ReadTail(string path, int chars)
        {
            try
            {
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var reader = new StreamReader(stream))
                {
                    var text = reader.ReadToEnd();
                    return text.Length > chars ? text.Substring(text.Length - chars) : text;
                }
            }
            catch (Exception)
            {
                return "";
            }
        }

        private static void TrimLog(string path)
        {
            try
            {
                if (File.Exists(path) && new FileInfo(path).Length > 1 << 20)
                {
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
            }
        }
    }
}
