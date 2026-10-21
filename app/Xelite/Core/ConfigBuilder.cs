using System;
using System.Collections.Generic;
using Windows.Data.Json;

namespace Xelite.Core
{
    /// <summary>Turns a <see cref="ProxyLink"/> into a complete Xray JSON config.</summary>
    public static class ConfigBuilder
    {
        public static readonly string[] PrivateRanges =
        {
            "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
            "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
        };

        public const string ProbeUrl = "https://www.gstatic.com/generate_204";

        /// <summary>
        /// Builds the config for one server, or for several servers behind an
        /// automatic balancer ("auto" entry of a subscription).
        /// </summary>
        /// <param name="links">Servers; with more than one, a balancer picks between them.</param>
        /// <param name="dialAddresses">Pre-resolved server IPs (keeps Xray from resolving through the tunnel).</param>
        public static string Build(IList<ProxyLink> links, IList<string> dialAddresses, AppSettings settings, string logPath)
        {
            var config = new JsonObject
            {
                ["log"] = new JsonObject
                {
                    ["loglevel"] = Str(settings.LogLevel),
                    ["error"] = Str(logPath),
                    ["access"] = Str("none"),
                },
                ["dns"] = new JsonObject { ["servers"] = StrArray(settings.DnsServers) },
            };

            var balanced = links.Count > 1;
            var outbounds = new JsonArray();
            for (var i = 0; i < links.Count; i++)
            {
                var outbound = BuildOutbound(links[i], dialAddresses[i]);
                outbound["tag"] = Str(balanced ? "proxy-" + i : "proxy");
                outbounds.Add(outbound);
            }
            outbounds.Add(new JsonObject { ["tag"] = Str("direct"), ["protocol"] = Str("freedom") });
            outbounds.Add(new JsonObject { ["tag"] = Str("block"), ["protocol"] = Str("blackhole") });
            config["outbounds"] = outbounds;

            var rules = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = Str("field"),
                    ["ip"] = StrArray(PrivateRanges),
                    ["outboundTag"] = Str("direct"),
                },
            };
            if (settings.BlockQuic)
            {
                // Browsers fall back to TCP, which most proxies carry much better than UDP.
                rules.Add(new JsonObject
                {
                    ["type"] = Str("field"),
                    ["network"] = Str("udp"),
                    ["port"] = Str("443"),
                    ["outboundTag"] = Str("block"),
                });
            }
            var routing = new JsonObject { ["domainStrategy"] = Str("AsIs") };
            if (balanced)
            {
                AddBalancer(config, routing, rules, settings.BalancerStrategy);
            }
            routing["rules"] = rules;
            config["routing"] = routing;
            return config.Stringify();
        }

        /// <summary>
        /// leastPing: "observatory" probes every server and the fastest one wins.
        /// leastLoad: "burstObservatory" samples each server several times and
        /// picks among the stable, low-latency ones (less flapping under load).
        /// </summary>
        private static void AddBalancer(JsonObject config, JsonObject routing, JsonArray rules, string strategy)
        {
            var selector = StrArray(new[] { "proxy-" });
            JsonObject strategyObj;
            if (strategy == "leastLoad")
            {
                config["burstObservatory"] = new JsonObject
                {
                    ["subjectSelector"] = StrArray(new[] { "proxy-" }),
                    ["pingConfig"] = new JsonObject
                    {
                        ["destination"] = Str(ProbeUrl),
                        ["interval"] = Str("1m"),
                        ["sampling"] = JsonValue.CreateNumberValue(3),
                        ["timeout"] = Str("5s"),
                        ["connectivity"] = Str(""),
                    },
                };
                strategyObj = new JsonObject
                {
                    ["type"] = Str("leastLoad"),
                    ["settings"] = new JsonObject
                    {
                        ["expected"] = JsonValue.CreateNumberValue(2),
                        ["maxRTT"] = Str("1s"),
                        ["tolerance"] = JsonValue.CreateNumberValue(0.1),
                    },
                };
            }
            else
            {
                config["observatory"] = new JsonObject
                {
                    ["subjectSelector"] = StrArray(new[] { "proxy-" }),
                    ["probeURL"] = Str(ProbeUrl),
                    ["probeInterval"] = Str("1m"),
                    ["enableConcurrency"] = JsonValue.CreateBooleanValue(true),
                };
                strategyObj = new JsonObject { ["type"] = Str("leastPing") };
            }
            routing["balancers"] = new JsonArray
            {
                new JsonObject
                {
                    ["tag"] = Str("auto"),
                    ["selector"] = selector,
                    ["strategy"] = strategyObj,
                    ["fallbackTag"] = Str("proxy-0"),
                },
            };
            // Last rule: everything else goes through the balancer.
            rules.Add(new JsonObject
            {
                ["type"] = Str("field"),
                ["network"] = Str("tcp,udp"),
                ["balancerTag"] = Str("auto"),
            });
        }

        public static JsonObject BuildOutbound(ProxyLink link, string dialAddress)
        {
            if (link.Outbound != null)
            {
                return FromJsonOutbound(link, dialAddress);
            }
            var outbound = new JsonObject { ["tag"] = Str("proxy") };
            var address = Str(dialAddress ?? link.Address);
            var port = JsonValue.CreateNumberValue(link.Port);

            switch (link.Protocol)
            {
                case "vless":
                    {
                        var user = new JsonObject
                        {
                            ["id"] = Str(link.Secret),
                            ["encryption"] = Str(link.Param("encryption", "none")),
                        };
                        if (link.Param("flow") != "")
                        {
                            user["flow"] = Str(link.Param("flow"));
                        }
                        outbound["protocol"] = Str("vless");
                        outbound["settings"] = Vnext(address, port, user);
                        break;
                    }
                case "vmess":
                    {
                        int aid;
                        int.TryParse(link.Param("aid", "0"), out aid);
                        var user = new JsonObject
                        {
                            ["id"] = Str(link.Secret),
                            ["alterId"] = JsonValue.CreateNumberValue(aid),
                            ["security"] = Str(string.IsNullOrEmpty(link.Method) ? "auto" : link.Method),
                        };
                        outbound["protocol"] = Str("vmess");
                        outbound["settings"] = Vnext(address, port, user);
                        break;
                    }
                case "trojan":
                    outbound["protocol"] = Str("trojan");
                    outbound["settings"] = Servers(new JsonObject
                    {
                        ["address"] = address,
                        ["port"] = port,
                        ["password"] = Str(link.Secret),
                    });
                    break;
                case "shadowsocks":
                    outbound["protocol"] = Str("shadowsocks");
                    outbound["settings"] = Servers(new JsonObject
                    {
                        ["address"] = address,
                        ["port"] = port,
                        ["method"] = Str(link.Method),
                        ["password"] = Str(link.Secret),
                    });
                    break;
                case "hysteria2":
                    outbound["protocol"] = Str("hysteria");
                    outbound["settings"] = new JsonObject
                    {
                        ["version"] = JsonValue.CreateNumberValue(2),
                        ["address"] = address,
                        ["port"] = port,
                    };
                    outbound["streamSettings"] = HysteriaStream(link);
                    return outbound;
                default:
                    throw new NotSupportedException(link.Protocol);
            }

            outbound["streamSettings"] = Stream(link);
            return outbound;
        }

        /// <summary>Copies a JSON-subscription outbound, pointing it at the resolved IP.</summary>
        private static JsonObject FromJsonOutbound(ProxyLink link, string dialAddress)
        {
            var outbound = JsonObject.Parse(link.Outbound.Stringify());
            if (dialAddress != null)
            {
                ProxyLink.ServerObject(outbound)["address"] = Str(dialAddress);
            }
            var stream = outbound.GetNamedObject("streamSettings", null);
            if (stream != null)
            {
                // Chains to other outbounds of the original config (fragment etc.) are not kept.
                var sockopt = stream.GetNamedObject("sockopt", null);
                if (sockopt != null)
                {
                    sockopt.Remove("dialerProxy");
                }
                foreach (var key in new[] { "tlsSettings", "realitySettings" })
                {
                    var tls = stream.GetNamedObject(key, null);
                    if (tls == null)
                    {
                        continue;
                    }
                    // Xray v26 refuses to start when this removed option is present.
                    tls.Remove("allowInsecure");
                    if (!IsIp(link.Address) && tls.GetNamedString("serverName", "") == "")
                    {
                        tls["serverName"] = Str(link.Address);
                    }
                }
                // The dial address is now an IP, so HTTP-based transports need an explicit Host.
                foreach (var key in new[] { "wsSettings", "httpupgradeSettings", "xhttpSettings", "splithttpSettings" })
                {
                    var transport = stream.GetNamedObject(key, null);
                    if (transport != null && !IsIp(link.Address) && transport.GetNamedString("host", "") == "")
                    {
                        transport["host"] = Str(link.Address);
                    }
                }
            }
            return outbound;
        }

        private static JsonObject Stream(ProxyLink link)
        {
            var network = link.Param("type", "tcp").ToLowerInvariant();
            if (network == "http" || network == "h2" || network == "splithttp")
            {
                network = "xhttp";
            }
            var stream = new JsonObject { ["network"] = Str(network) };
            // The dial address is an IP, so default Host/SNI to the original domain.
            var host = link.Param("host", IsIp(link.Address) ? "" : link.Address);
            var path = link.Param("path", "/");

            switch (network)
            {
                case "tcp":
                case "raw":
                    if (link.Param("headerType") == "http")
                    {
                        var headers = new JsonObject();
                        if (host != "")
                        {
                            headers["Host"] = StrArray(host.Split(','));
                        }
                        stream["tcpSettings"] = new JsonObject
                        {
                            ["header"] = new JsonObject
                            {
                                ["type"] = Str("http"),
                                ["request"] = new JsonObject
                                {
                                    ["path"] = StrArray(path.Split(',')),
                                    ["headers"] = headers,
                                },
                            },
                        };
                    }
                    break;
                case "ws":
                    stream["wsSettings"] = new JsonObject { ["path"] = Str(path), ["host"] = Str(host) };
                    break;
                case "httpupgrade":
                    stream["httpupgradeSettings"] = new JsonObject { ["path"] = Str(path), ["host"] = Str(host) };
                    break;
                case "grpc":
                    {
                        var grpc = new JsonObject
                        {
                            ["serviceName"] = Str(link.Param("serviceName", "")),
                            ["multiMode"] = JsonValue.CreateBooleanValue(link.Param("mode") == "multi"),
                        };
                        if (link.Param("authority") != "")
                        {
                            grpc["authority"] = Str(link.Param("authority"));
                        }
                        stream["grpcSettings"] = grpc;
                        break;
                    }
                case "xhttp":
                    {
                        var xhttp = new JsonObject
                        {
                            ["path"] = Str(path),
                            ["host"] = Str(host),
                            ["mode"] = Str(link.Param("mode", "auto")),
                        };
                        JsonObject extra;
                        if (link.Param("extra") != "" && JsonObject.TryParse(link.Param("extra"), out extra))
                        {
                            xhttp["extra"] = extra;
                        }
                        stream["xhttpSettings"] = xhttp;
                        break;
                    }
            }

            var security = link.Param("security", "none").ToLowerInvariant();
            if (link.Protocol == "trojan" && !link.Params.ContainsKey("security"))
            {
                security = "tls";
            }
            var sni = link.Param("sni", link.Param("peer", host));
            switch (security)
            {
                case "tls":
                    stream["security"] = Str("tls");
                    stream["tlsSettings"] = Tls(link, sni);
                    break;
                case "reality":
                    stream["security"] = Str("reality");
                    stream["realitySettings"] = new JsonObject
                    {
                        ["serverName"] = Str(sni),
                        ["fingerprint"] = Str(link.Param("fp", "chrome")),
                        ["publicKey"] = Str(link.Param("pbk")),
                        ["shortId"] = Str(link.Param("sid")),
                        ["spiderX"] = Str(link.Param("spx")),
                        ["mldsa65Verify"] = Str(link.Param("pqv")),
                    };
                    break;
                default:
                    stream["security"] = Str("none");
                    break;
            }
            return stream;
        }

        private static JsonObject HysteriaStream(ProxyLink link)
        {
            var sni = link.Param("sni", IsIp(link.Address) ? "" : link.Address);
            var tls = Tls(link, sni);
            if (link.Param("alpn") == "")
            {
                tls["alpn"] = StrArray(new[] { "h3" });
            }
            var stream = new JsonObject
            {
                ["network"] = Str("hysteria"),
                ["hysteriaSettings"] = new JsonObject
                {
                    ["version"] = JsonValue.CreateNumberValue(2),
                    ["auth"] = Str(link.Secret),
                },
                ["security"] = Str("tls"),
                ["tlsSettings"] = tls,
            };
            if (link.Param("obfs") == "salamander")
            {
                stream["finalmask"] = new JsonObject
                {
                    ["udp"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["type"] = Str("salamander"),
                            ["settings"] = new JsonObject { ["password"] = Str(link.Param("obfs-password")) },
                        },
                    },
                };
            }
            return stream;
        }

        private static JsonObject Tls(ProxyLink link, string sni)
        {
            var tls = new JsonObject
            {
                ["serverName"] = Str(sni),
                ["fingerprint"] = Str(link.Param("fp", "chrome")),
            };
            if (link.Param("alpn") != "")
            {
                tls["alpn"] = StrArray(link.Param("alpn").Split(','));
            }
            // Xray v26 rejects "allowInsecure"; certificate pinning replaces it.
            var pin = link.Param("pcs", link.Param("pinSHA256"));
            if (pin != "")
            {
                tls["pinnedPeerCertSha256"] = Str(pin.Replace(":", ""));
            }
            if (link.Param("ech") != "")
            {
                tls["echConfigList"] = Str(link.Param("ech"));
            }
            return tls;
        }

        private static JsonObject Vnext(IJsonValue address, IJsonValue port, JsonObject user)
        {
            return new JsonObject
            {
                ["vnext"] = new JsonArray
                {
                    new JsonObject { ["address"] = address, ["port"] = port, ["users"] = new JsonArray { user } },
                },
            };
        }

        private static JsonObject Servers(JsonObject server)
        {
            return new JsonObject { ["servers"] = new JsonArray { server } };
        }

        public static bool IsIp(string host)
        {
            Windows.Networking.HostName h;
            try
            {
                h = new Windows.Networking.HostName(host);
            }
            catch (ArgumentException)
            {
                return false;
            }
            return h.Type == Windows.Networking.HostNameType.Ipv4 || h.Type == Windows.Networking.HostNameType.Ipv6;
        }

        /// <summary>Indented JSON, for the config editor.</summary>
        public static string Pretty(IJsonValue value, string indent = "")
        {
            var inner = indent + "  ";
            switch (value.ValueType)
            {
                case JsonValueType.Object:
                    {
                        var obj = value.GetObject();
                        if (obj.Count == 0)
                        {
                            return "{}";
                        }
                        var parts = new List<string>();
                        foreach (var kv in obj)
                        {
                            parts.Add(inner + JsonValue.CreateStringValue(kv.Key).Stringify() + ": " + Pretty(kv.Value, inner));
                        }
                        return "{\n" + string.Join(",\n", parts) + "\n" + indent + "}";
                    }
                case JsonValueType.Array:
                    {
                        var arr = value.GetArray();
                        if (arr.Count == 0)
                        {
                            return "[]";
                        }
                        var parts = new List<string>();
                        foreach (var v in arr)
                        {
                            parts.Add(inner + Pretty(v, inner));
                        }
                        return "[\n" + string.Join(",\n", parts) + "\n" + indent + "]";
                    }
                default:
                    return value.Stringify();
            }
        }

        private static JsonValue Str(string s)
        {
            return JsonValue.CreateStringValue(s ?? "");
        }

        private static JsonArray StrArray(System.Collections.Generic.IEnumerable<string> items)
        {
            var arr = new JsonArray();
            foreach (var s in items)
            {
                var t = s.Trim();
                if (t.Length > 0)
                {
                    arr.Add(Str(t));
                }
            }
            return arr;
        }
    }
}
