using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Windows.Data.Json;
using Windows.Storage;
using Windows.Web.Http;

namespace Xelite.Core
{
    public sealed class Subscription
    {
        public const string ManualId = "manual";

        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = "";
        public string Url { get; set; } = "";
        public DateTimeOffset? Updated { get; set; }

        // From the "subscription-userinfo" response header, in bytes / unix seconds.
        public long Upload { get; set; }
        public long Download { get; set; }
        public long Total { get; set; }
        public long Expire { get; set; }

        public List<string> Links { get; set; } = new List<string>();

        public bool IsManual => Id == ManualId;

        public string Summary
        {
            get
            {
                if (IsManual)
                {
                    return Links.Count + " servers added manually";
                }
                var parts = new List<string> { Links.Count + " servers" };
                if (Total > 0)
                {
                    parts.Add(FormatBytes(Upload + Download) + " / " + FormatBytes(Total));
                }
                else if (Upload + Download > 0)
                {
                    parts.Add(FormatBytes(Upload + Download) + " used");
                }
                if (Expire > 0)
                {
                    parts.Add("until " + DateTimeOffset.FromUnixTimeSeconds(Expire).ToLocalTime().ToString("d"));
                }
                if (Updated.HasValue)
                {
                    parts.Add("updated " + Updated.Value.ToLocalTime().ToString("g"));
                }
                return string.Join(" · ", parts);
            }
        }

        /// <summary>Downloads the subscription and replaces <see cref="Links"/>.</summary>
        public async Task UpdateAsync()
        {
            // The WinRT HTTP stack caches GETs; always fetch a fresh server list.
            var filter = new Windows.Web.Http.Filters.HttpBaseProtocolFilter();
            filter.CacheControl.ReadBehavior = Windows.Web.Http.Filters.HttpCacheReadBehavior.MostRecent;
            filter.CacheControl.WriteBehavior = Windows.Web.Http.Filters.HttpCacheWriteBehavior.NoCache;
            using (var client = new HttpClient(filter))
            {
                client.DefaultRequestHeaders.UserAgent.TryParseAdd(AppSettings.Current.UserAgent);
                using (var response = await client.GetAsync(new Uri(Url)))
                {
                    response.EnsureSuccessStatusCode();
                    var body = await response.Content.ReadAsStringAsync();

                    string header;
                    if (response.Headers.TryGetValue("subscription-userinfo", out header))
                    {
                        ParseUserInfo(header);
                    }
                    if (response.Headers.TryGetValue("profile-title", out header) && string.IsNullOrEmpty(Name))
                    {
                        Name = DecodeTitle(header);
                    }
                    if (string.IsNullOrEmpty(Name))
                    {
                        Name = new Uri(Url).Host;
                    }

                    var links = ExtractLinks(body);
                    if (links.Count == 0)
                    {
                        throw new InvalidOperationException("The subscription contains no supported servers.");
                    }
                    Links = links;
                    Updated = DateTimeOffset.UtcNow;
                }
            }
        }

        /// <summary>
        /// Accepts a base64 blob, plain text with one link per line, or Xray JSON
        /// (one config or an array of configs, as served to Happ / Incy / v2rayNG).
        /// </summary>
        public static List<string> ExtractLinks(string body)
        {
            body = body.Trim();
            var result = new List<string>();
            if (body.StartsWith("[") || body.StartsWith("{"))
            {
                JsonValue json;
                if (JsonValue.TryParse(body, out json))
                {
                    var configs = json.ValueType == JsonValueType.Array
                        ? json.GetArray().Where(v => v.ValueType == JsonValueType.Object).Select(v => v.GetObject())
                        : new[] { json.GetObject() };
                    foreach (var config in configs)
                    {
                        var line = ProxyLink.FromXrayConfig(config);
                        ProxyLink link;
                        if (line != null && ProxyLink.TryParse(line, out link))
                        {
                            result.Add(line);
                        }
                    }
                    return result;
                }
            }

            string decoded;
            if (body.IndexOf("://", StringComparison.Ordinal) < 0 && Base64.TryDecodeToString(body, out decoded))
            {
                body = decoded;
            }
            foreach (var line in body.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                ProxyLink link;
                if (ProxyLink.TryParse(line, out link))
                {
                    result.Add(line.Trim());
                }
            }
            return result;
        }

        /// <summary>
        /// Unwraps import links of other clients, e.g. "happ://add/https://…",
        /// "incy://import/https://…" or "v2rayng://install-config?url=https%3A…".
        /// Returns null if no subscription URL is inside.
        /// </summary>
        public static string UnwrapImportLink(string text)
        {
            text = text.Trim();
            if (text.StartsWith("http://") || text.StartsWith("https://"))
            {
                return text;
            }
            var idx = text.IndexOf("http", StringComparison.OrdinalIgnoreCase);
            if (idx <= 0 || text.IndexOf("://", StringComparison.Ordinal) > idx)
            {
                return null;
            }
            var inner = text.Substring(idx);
            if (inner.StartsWith("http%3A", StringComparison.OrdinalIgnoreCase) || inner.StartsWith("https%3A", StringComparison.OrdinalIgnoreCase))
            {
                inner = Uri.UnescapeDataString(inner);
            }
            var end = inner.IndexOfAny(new[] { ' ', '\r', '\n' });
            if (end > 0)
            {
                inner = inner.Substring(0, end);
            }
            Uri uri;
            return Uri.TryCreate(inner, UriKind.Absolute, out uri) && (uri.Scheme == "http" || uri.Scheme == "https") ? inner : null;
        }

        private void ParseUserInfo(string header)
        {
            foreach (var part in header.Split(';'))
            {
                var kv = part.Split('=');
                long value;
                if (kv.Length != 2 || !long.TryParse(kv[1].Trim(), out value))
                {
                    continue;
                }
                switch (kv[0].Trim().ToLowerInvariant())
                {
                    case "upload":
                        Upload = value;
                        break;
                    case "download":
                        Download = value;
                        break;
                    case "total":
                        Total = value;
                        break;
                    case "expire":
                        Expire = value;
                        break;
                }
            }
        }

        private static string DecodeTitle(string title)
        {
            string decoded;
            if (title.StartsWith("base64:") && Base64.TryDecodeToString(title.Substring(7), out decoded))
            {
                return decoded;
            }
            return title;
        }

        public static string FormatBytes(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double v = bytes;
            var i = 0;
            while (v >= 1024 && i < units.Length - 1)
            {
                v /= 1024;
                i++;
            }
            return v.ToString(i == 0 ? "0" : "0.##") + " " + units[i];
        }

        public JsonObject ToJson()
        {
            var links = new JsonArray();
            foreach (var l in Links)
            {
                links.Add(JsonValue.CreateStringValue(l));
            }
            return new JsonObject
            {
                ["id"] = JsonValue.CreateStringValue(Id),
                ["name"] = JsonValue.CreateStringValue(Name),
                ["url"] = JsonValue.CreateStringValue(Url),
                ["updated"] = JsonValue.CreateNumberValue(Updated.HasValue ? Updated.Value.ToUnixTimeSeconds() : 0),
                ["upload"] = JsonValue.CreateNumberValue(Upload),
                ["download"] = JsonValue.CreateNumberValue(Download),
                ["total"] = JsonValue.CreateNumberValue(Total),
                ["expire"] = JsonValue.CreateNumberValue(Expire),
                ["links"] = links,
            };
        }

        public static Subscription FromJson(JsonObject o)
        {
            var updated = (long)o.GetNamedNumber("updated", 0);
            return new Subscription
            {
                Id = o.GetNamedString("id"),
                Name = o.GetNamedString("name", ""),
                Url = o.GetNamedString("url", ""),
                Updated = updated > 0 ? DateTimeOffset.FromUnixTimeSeconds(updated) : (DateTimeOffset?)null,
                Upload = (long)o.GetNamedNumber("upload", 0),
                Download = (long)o.GetNamedNumber("download", 0),
                Total = (long)o.GetNamedNumber("total", 0),
                Expire = (long)o.GetNamedNumber("expire", 0),
                Links = o.GetNamedArray("links", new JsonArray()).Select(v => v.GetString()).ToList(),
            };
        }
    }

    /// <summary>Loads and saves subscriptions to LocalFolder\data.json.</summary>
    public static class SubscriptionStore
    {
        private const string FileName = "data.json";

        public static async Task<List<Subscription>> LoadAsync()
        {
            var list = new List<Subscription>();
            var item = await ApplicationData.Current.LocalFolder.TryGetItemAsync(FileName) as StorageFile;
            if (item != null)
            {
                JsonObject root;
                if (JsonObject.TryParse(await FileIO.ReadTextAsync(item), out root))
                {
                    foreach (var v in root.GetNamedArray("subscriptions", new JsonArray()))
                    {
                        list.Add(Subscription.FromJson(v.GetObject()));
                    }
                }
            }
            if (!list.Any(s => s.IsManual))
            {
                list.Add(new Subscription { Id = Subscription.ManualId, Name = "Manual" });
            }
            return list;
        }

        public static async Task SaveAsync(IEnumerable<Subscription> subscriptions)
        {
            var arr = new JsonArray();
            foreach (var s in subscriptions)
            {
                arr.Add(s.ToJson());
            }
            var root = new JsonObject { ["subscriptions"] = arr };
            var file = await ApplicationData.Current.LocalFolder.CreateFileAsync(FileName, CreationCollisionOption.ReplaceExisting);
            await FileIO.WriteTextAsync(file, root.Stringify(), Windows.Storage.Streams.UnicodeEncoding.Utf8);
        }
    }
}
