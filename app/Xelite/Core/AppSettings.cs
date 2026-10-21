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
