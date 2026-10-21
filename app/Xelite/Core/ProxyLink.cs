using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Windows.Data.Json;

namespace Xelite.Core
{
    /// <summary>
    /// A parsed share link (vless://, vmess://, trojan://, ss://, hysteria2://).
    /// Transport options are normalised to the v2rayN/Xray URL parameter names
    /// (type, security, sni, fp, alpn, pbk, sid, spx, path, host, ...).
    /// </summary>
    public sealed class ProxyLink
    {
        public string Protocol { get; private set; }
        public string Name { get; private set; }
        public string Address { get; private set; }
        public int Port { get; private set; }

        /// <summary>UUID for vless/vmess, password for trojan/ss/hysteria2.</summary>
        public string Secret { get; private set; }

        /// <summary>Cipher for shadowsocks.</summary>
        public string Method { get; private set; }

        public Dictionary<string, string> Params { get; private set; }

        public string Raw { get; private set; }

        /// <summary>
        /// Ready-made Xray outbound, for servers that came from a JSON subscription
        /// (what Remnawave/Marzban serve to Happ and Incy). Null for share links.
        /// </summary>
        public JsonObject Outbound { get; private set; }

        /// <summary>Pseudo-scheme used to store JSON outbounds as a single line.</summary>
        public const string JsonScheme = "xray-json";

        private static readonly string[] ProxyProtocols = { "vless", "vmess", "trojan", "shadowsocks", "hysteria" };

        /// <summary>
        /// Extracts the proxy outbound of a full Xray client config and encodes it
        /// as an "xray-json://" line, or returns null when there is none.
        /// </summary>
        public static string FromXrayConfig(JsonObject config)
        {
            var outbounds = config.GetNamedArray("outbounds", new JsonArray())
                .Where(v => v.ValueType == JsonValueType.Object)
                .Select(v => v.GetObject())
                .Where(o => ProxyProtocols.Contains(o.GetNamedString("protocol", "")))
                .ToList();
            var outbound = outbounds.FirstOrDefault(o => o.GetNamedString("tag", "") == "proxy") ?? outbounds.FirstOrDefault();
            if (outbound == null)
            {
                return null;
            }
            return FromOutbound(outbound, config.GetNamedString("remarks", ""));
        }

        /// <summary>Encodes an Xray outbound as an "xray-json://" line.</summary>
        public static string FromOutbound(JsonObject outbound, string name)
        {
            var bytes = Encoding.UTF8.GetBytes(outbound.Stringify());
            var line = JsonScheme + "://" + Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return string.IsNullOrEmpty(name) ? line : line + "#" + Uri.EscapeDataString(name);
        }

        private static ProxyLink ParseJsonOutbound(string body)
        {
            var p = new ProxyLink();
            body = SplitFragment(body, p);
            p.Outbound = JsonObject.Parse(Base64.DecodeToString(body));
            p.Protocol = p.Outbound.GetNamedString("protocol");
            if (p.Protocol == "hysteria")
            {
                p.Protocol = "hysteria2";
            }
            var server = ServerObject(p.Outbound);
            p.Address = server.GetNamedString("address");
            p.Port = (int)server.GetNamedNumber("port");

            // Fill Params so the server list can show transport/security.
            var stream = p.Outbound.GetNamedObject("streamSettings", new JsonObject());
            p.Params["type"] = stream.GetNamedString("network", "tcp");
            p.Params["security"] = stream.GetNamedString("security", "none");
            return p;
        }

        /// <summary>The object holding "address"/"port" in an outbound's settings.</summary>
        internal static JsonObject ServerObject(JsonObject outbound)
        {
            var settings = outbound.GetNamedObject("settings");
            foreach (var key in new[] { "vnext", "servers" })
            {
                var arr = settings.GetNamedArray(key, null);
                if (arr != null && arr.Count > 0)
                {
                    return arr.GetObjectAt(0);
                }
            }
            return settings;
        }

        private ProxyLink()
        {
            Params = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public string Param(string key, string fallback = "")
        {
            string v;
            return Params.TryGetValue(key, out v) && !string.IsNullOrEmpty(v) ? v : fallback;
        }

        public static bool TryParse(string link, out ProxyLink result)
        {
            result = null;
            try
            {
                result = Parse(link);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static ProxyLink Parse(string link)
        {
            link = link.Trim();
            var sep = link.IndexOf("://", StringComparison.Ordinal);
            if (sep <= 0)
            {
                throw new FormatException("not a share link");
            }
            var scheme = link.Substring(0, sep).ToLowerInvariant();
            var body = link.Substring(sep + 3);
            ProxyLink p;
            switch (scheme)
            {
                case "vless":
                case "trojan":
                    p = ParseStandard(scheme, body);
                    break;
                case "hysteria2":
                case "hy2":
                    p = ParseStandard("hysteria2", body);
                    break;
                case "vmess":
                    p = ParseVmess(body);
                    break;
                case "ss":
                    p = ParseShadowsocks(body);
                    break;
                case JsonScheme:
                    p = ParseJsonOutbound(body);
                    break;
                default:
                    throw new FormatException("unsupported protocol " + scheme);
            }
            p.Raw = link;
            if (string.IsNullOrEmpty(p.Name))
            {
                p.Name = p.Address + ":" + p.Port;
            }
            return p;
        }

        // scheme://secret@host:port?query#name
        private static ProxyLink ParseStandard(string protocol, string body)
        {
            var p = new ProxyLink { Protocol = protocol };
            body = SplitFragment(body, p);
            var q = body.IndexOf('?');
            if (q >= 0)
            {
                ParseQuery(body.Substring(q + 1), p.Params);
                body = body.Substring(0, q);
            }
            body = body.TrimEnd('/');
            var at = body.LastIndexOf('@');
            if (at < 0)
            {
                throw new FormatException("missing user info");
            }
            p.Secret = Uri.UnescapeDataString(body.Substring(0, at));
            SetHostPort(p, body.Substring(at + 1));
            return p;
        }

        private static ProxyLink ParseVmess(string body)
        {
            var p = new ProxyLink { Protocol = "vmess" };
            var json = JsonObject.Parse(Base64.DecodeToString(body));
            p.Name = Str(json, "ps");
            p.Address = Str(json, "add");
            p.Port = int.Parse(Str(json, "port"));
            p.Secret = Str(json, "id");
            p.Method = Str(json, "scy");
            var net = Str(json, "net");
            p.Params["type"] = net == "h2" ? "xhttp" : net;
            p.Params["headerType"] = Str(json, "type");
            p.Params["host"] = Str(json, "host");
            p.Params["path"] = Str(json, "path");
            p.Params["security"] = Str(json, "tls");
            p.Params["sni"] = Str(json, "sni");
            p.Params["alpn"] = Str(json, "alpn");
            p.Params["fp"] = Str(json, "fp");
            p.Params["aid"] = Str(json, "aid");
            if (net == "grpc")
            {
                p.Params["serviceName"] = Str(json, "path");
                p.Params["mode"] = Str(json, "type");
            }
            if (net == "xhttp")
            {
                p.Params["mode"] = Str(json, "type");
            }
            return p;
        }

        // SIP002: ss://base64(method:password)@host:port#name
        // legacy: ss://base64(method:password@host:port)#name
        private static ProxyLink ParseShadowsocks(string body)
        {
            var p = new ProxyLink { Protocol = "shadowsocks" };
            body = SplitFragment(body, p);
            var q = body.IndexOf('?');
            if (q >= 0)
            {
                ParseQuery(body.Substring(q + 1), p.Params);
                body = body.Substring(0, q);
            }
            body = body.TrimEnd('/');
            var at = body.LastIndexOf('@');
            string userInfo;
            if (at < 0)
            {
                var decoded = Base64.DecodeToString(body);
                at = decoded.LastIndexOf('@');
                userInfo = decoded.Substring(0, at);
                SetHostPort(p, decoded.Substring(at + 1));
            }
            else
            {
                userInfo = Uri.UnescapeDataString(body.Substring(0, at));
                if (userInfo.IndexOf(':') < 0)
                {
                    userInfo = Base64.DecodeToString(userInfo);
                }
                SetHostPort(p, body.Substring(at + 1));
            }
            var colon = userInfo.IndexOf(':');
            p.Method = userInfo.Substring(0, colon);
            p.Secret = userInfo.Substring(colon + 1);
            return p;
        }

        private static string SplitFragment(string body, ProxyLink p)
        {
            var hash = body.IndexOf('#');
            if (hash < 0)
            {
                return body;
            }
            p.Name = Uri.UnescapeDataString(body.Substring(hash + 1).Replace('+', ' ')).Trim();
            return body.Substring(0, hash);
        }

        private static void SetHostPort(ProxyLink p, string hostPort)
        {
            string host, port;
            if (hostPort.StartsWith("["))
            {
                var end = hostPort.IndexOf(']');
                host = hostPort.Substring(1, end - 1);
                port = hostPort.Substring(end + 2);
            }
            else
            {
                var colon = hostPort.LastIndexOf(':');
                host = hostPort.Substring(0, colon);
                port = hostPort.Substring(colon + 1);
            }
            // hysteria2 port hopping "443,20000-30000": dial the first port
            var comma = port.IndexOfAny(new[] { ',', '-' });
            if (comma > 0)
            {
                p.Params["mport"] = port;
                port = port.Substring(0, comma);
            }
            p.Address = host;
            p.Port = int.Parse(port);
            if (p.Port <= 0 || p.Port > 65535)
            {
                throw new FormatException("bad port");
            }
        }

        private static void ParseQuery(string query, Dictionary<string, string> into)
        {
            foreach (var pair in query.Split('&'))
            {
                if (pair.Length == 0)
                {
                    continue;
                }
                var eq = pair.IndexOf('=');
                var key = eq < 0 ? pair : pair.Substring(0, eq);
                var value = eq < 0 ? "" : pair.Substring(eq + 1);
                // '+' is kept literally: keys and VLESS encryption strings may contain it
                into[Uri.UnescapeDataString(key)] = Uri.UnescapeDataString(value);
            }
        }

        private static string Str(JsonObject obj, string name)
        {
            IJsonValue v;
            if (!obj.TryGetValue(name, out v))
            {
                return "";
            }
            switch (v.ValueType)
            {
                case JsonValueType.String:
                    return v.GetString();
                case JsonValueType.Number:
                    return ((long)v.GetNumber()).ToString();
                default:
                    return "";
            }
        }
    }

    public static class Base64
    {
        /// <summary>Decodes standard or URL-safe base64 with or without padding.</summary>
        public static byte[] Decode(string s)
        {
            s = s.Trim().Replace('-', '+').Replace('_', '/').Replace("\r", "").Replace("\n", "").Replace(" ", "");
            switch (s.Length % 4)
            {
                case 2:
                    s += "==";
                    break;
                case 3:
                    s += "=";
                    break;
            }
            return Convert.FromBase64String(s);
        }

        public static string DecodeToString(string s)
        {
            var bytes = Decode(s);
            return Encoding.UTF8.GetString(bytes, 0, bytes.Length);
        }

        public static bool TryDecodeToString(string s, out string result)
        {
            try
            {
                result = DecodeToString(s);
                return true;
            }
            catch (FormatException)
            {
                result = null;
                return false;
            }
        }
    }
}
