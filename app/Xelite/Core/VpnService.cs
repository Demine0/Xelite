using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.Data.Json;
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

        private static readonly VpnManagementAgent Agent = new VpnManagementAgent();

        public static string DataDir => ApplicationData.Current.LocalFolder.Path;
        public static string XrayLogPath => Path.Combine(DataDir, "xray.log");
        public static string PluginLogPath => Path.Combine(DataDir, "vpn.log");

        public static async Task<VpnManagementConnectionStatus> GetStatusAsync()
        {
            var profile = await FindProfileAsync();
            return profile?.ConnectionStatus ?? VpnManagementConnectionStatus.Disconnected;
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
                ["dns"] = dns,
                ["exclude"] = exclude,
            };
            File.WriteAllText(Path.Combine(DataDir, "vpn.json"), vpn.Stringify());
            TrimLog(XrayLogPath);
            TrimLog(PluginLogPath);

            var profile = await EnsureProfileAsync();
            var status = await Agent.ConnectProfileAsync(profile);
            if (status != VpnManagementErrorStatus.Ok)
            {
                throw new InvalidOperationException("Connect failed: " + status);
            }
        }

        public static async Task DisconnectAsync()
        {
            var profile = await FindProfileAsync();
            if (profile != null)
            {
                await Agent.DisconnectProfileAsync(profile);
            }
        }

        /// <summary>TCP connect latency in ms, or -1 on failure.</summary>
        public static async Task<int> PingAsync(ProxyLink link, int timeoutMs = 3000)
        {
            using (var socket = new StreamSocket())
            {
                var sw = Stopwatch.StartNew();
                var connect = socket.ConnectAsync(new HostName(link.Address), link.Port.ToString()).AsTask();
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

        private static async Task<VpnPlugInProfile> FindProfileAsync()
        {
            var profiles = await Agent.GetProfilesAsync();
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
                RequireVpnClientAppUI = false,
            };
            profile.ServerUris.Add(new Uri("https://127.0.0.1"));
            var status = await Agent.AddProfileFromObjectAsync(profile);
            if (status != VpnManagementErrorStatus.Ok)
            {
                throw new InvalidOperationException("Cannot create VPN profile: " + status);
            }
            return await FindProfileAsync() ?? profile;
        }

        public static string ReadLogs()
        {
            return ReadTail(PluginLogPath, 4000) + Environment.NewLine + "--- xray ---" + Environment.NewLine + ReadTail(XrayLogPath, 12000);
        }

        public static void ClearLogs()
        {
            foreach (var path in new[] { XrayLogPath, PluginLogPath })
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
            catch (IOException)
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
