using Windows.Storage;

namespace Xelite.Core
{
    /// <summary>User preferences, persisted in LocalSettings.</summary>
    public sealed class AppSettings
    {
        private static readonly ApplicationDataContainer Values = ApplicationData.Current.LocalSettings;

        public static AppSettings Current { get; } = new AppSettings();

        public string[] DnsServers
        {
            get { return Get("dns", "1.1.1.1,8.8.8.8").Split(','); }
            set { Values.Values["dns"] = string.Join(",", value); }
        }

        public bool BypassLan
        {
            get { return Get("bypassLan", true); }
            set { Values.Values["bypassLan"] = value; }
        }

        public bool BlockQuic
        {
            get { return Get("blockQuic", false); }
            set { Values.Values["blockQuic"] = value; }
        }

        /// <summary>"leastPing" or "leastLoad", used by a subscription's "auto" entry.</summary>
        public string BalancerStrategy
        {
            get { return Get("balancer", "leastPing"); }
            set { Values.Values["balancer"] = value; }
        }

        /// <summary>
        /// How the VPN's routes cover the internet: "halves" (0.0.0.0/1 + 128.0.0.0/1),
        /// "defaultHalves" (0.0.0.0/0 plus the halves) or "blocks" (eight /3 routes).
        /// </summary>
        public string RouteMode
        {
            get { return Get("routeMode", "halves"); }
            set { Values.Values["routeMode"] = value; }
        }

        /// <summary>Proxy IPv6 traffic instead of rejecting it (the server must have IPv6).</summary>
        public bool AllowIpv6
        {
            get { return Get("ipv6", false); }
            set { Values.Values["ipv6"] = value; }
        }

        /// <summary>
        /// Carry the server connection on the VPN's own transport so server replies wake
        /// the plug-in (needed on Windows 10 Mobile, see ServerTunnel). Off: relay only.
        /// </summary>
        public bool PlatformTransport
        {
            get { return Get("platformTransport", true); }
            set { Values.Values["platformTransport"] = value; }
        }

        /// <summary>Answer apps' DNS with Xray's DNS over HTTPS through the proxy instead of UDP.</summary>
        public bool XrayDns
        {
            get { return Get("xrayDns", true); }
            set { Values.Values["xrayDns"] = value; }
        }

        /// <summary>Seconds between HTTP/2 pings that keep the single server connection open.</summary>
        public int KeepAliveSeconds
        {
            get { return Get("keepAlive", 4); }
            set { Values.Values["keepAlive"] = value; }
        }

        /// <summary>
        /// Streams per Xray mux connection. A page opens dozens of connections; past this
        /// limit Xray opens another server connection, which can't ride the VPN transport.
        /// </summary>
        public int MuxConcurrency
        {
            get { return Get("muxConcurrency", 128); }
            set { Values.Values["muxConcurrency"] = value; }
        }

        /// <summary>Write upload straight to the server socket instead of the VPN platform's send buffers.</summary>
        public bool DirectUpload
        {
            get { return Get("directUpload", true); }
            set { Values.Values["directUpload"] = value; }
        }

        public bool UpdateOnStart
        {
            get { return Get("updateOnStart", true); }
            set { Values.Values["updateOnStart"] = value; }
        }

        public int Mtu
        {
            get { return Get("mtu", 1500); }
            set { Values.Values["mtu"] = value; }
        }

        public string LogLevel
        {
            get { return Get("logLevel", "warning"); }
            set { Values.Values["logLevel"] = value; }
        }

        /// <summary>
        /// Sent when downloading subscriptions. Panels (Marzban, Remnawave, 3x-ui)
        /// return a plain base64 link list for v2rayN-style clients.
        /// </summary>
        public string UserAgent
        {
            get { return Get("userAgent", "v2rayN/7.10.0"); }
            set { Values.Values["userAgent"] = value; }
        }

        /// <summary>Send x-hwid and device headers with subscription requests.</summary>
        public bool SendHwid
        {
            get { return Get("sendHwid", true); }
            set { Values.Values["sendHwid"] = value; }
        }

        /// <summary>User-entered HWID that replaces the device's own; empty to use the device's.</summary>
        public string CustomHwid
        {
            get { return Get("customHwid", ""); }
            set { Values.Values["customHwid"] = value; }
        }

        /// <summary>Random seed used when the system ID is unavailable.</summary>
        public string GeneratedHwidSeed
        {
            get { return Get("hwidSeed", ""); }
            set { Values.Values["hwidSeed"] = value; }
        }

        /// <summary>Raw link of the selected server, or "auto:&lt;subscription id&gt;".</summary>
        public string SelectedLink
        {
            get { return Get("selected", ""); }
            set { Values.Values["selected"] = value; }
        }

        private static T Get<T>(string key, T fallback)
        {
            object v;
            return Values.Values.TryGetValue(key, out v) && v is T ? (T)v : fallback;
        }
    }
}
