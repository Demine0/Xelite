using System;
using System.Text;
using System.Text.RegularExpressions;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Security.ExchangeActiveSyncProvisioning;
using Windows.System.Profile;
using Windows.Web.Http;

namespace Xelite.Core
{
    /// <summary>
    /// Device identity sent with subscription requests, for panels with a device
    /// limit (Remnawave "HWID Device Limit", also used by Happ and Incy):
    /// x-hwid, x-device-os, x-ver-os, x-device-model.
    /// </summary>
    public static class DeviceInfo
    {
        /// <summary>What Remnawave accepts; anything else is ignored by the panel.</summary>
        private static readonly Regex HwidFormat = new Regex("^[a-zA-Z0-9=-]{10,64}$");

        private static string _systemHwid;

        /// <summary>The HWID in use: the custom one from settings, or the device's own.</summary>
        public static string Hwid
        {
            get
            {
                var custom = AppSettings.Current.CustomHwid;
                return IsValidHwid(custom) ? custom : SystemHwid;
            }
        }

        /// <summary>
        /// Stable per device and survives reinstalling the app, so a reinstall does
        /// not use up another device slot. Formatted as an uppercase UUID, like Incy.
        /// </summary>
        public static string SystemHwid
        {
            get
            {
                if (_systemHwid == null)
                {
                    _systemHwid = ComputeSystemHwid();
                }
                return _systemHwid;
            }
        }

        public static string Os => "Windows";

        public static string OsVersion
        {
            get
            {
                // DeviceFamilyVersion is a packed 64-bit "major.minor.build.revision".
                ulong v;
                if (!ulong.TryParse(AnalyticsInfo.VersionInfo.DeviceFamilyVersion, out v))
                {
                    return "10.0";
                }
                return string.Format("{0}.{1}.{2}.{3}", v >> 48, (v >> 32) & 0xFFFF, (v >> 16) & 0xFFFF, v & 0xFFFF);
            }
        }

        public static string Model
        {
            get
            {
                try
                {
                    var info = new EasClientDeviceInformation();
                    var maker = (info.SystemManufacturer ?? "").Trim();
                    var product = (info.SystemProductName ?? "").Trim();
                    var model = product.StartsWith(maker, StringComparison.OrdinalIgnoreCase) ? product : (maker + " " + product).Trim();
                    return model.Length > 0 ? model : "Windows Phone";
                }
                catch (Exception)
                {
                    return "Windows Phone";
                }
            }
        }

        public static bool IsValidHwid(string hwid)
        {
            return !string.IsNullOrEmpty(hwid) && HwidFormat.IsMatch(hwid);
        }

        /// <summary>Adds the device headers to a subscription request.</summary>
        public static void AddHeaders(HttpRequestMessage request)
        {
            request.Headers.Add("x-hwid", Hwid);
            request.Headers.Add("x-device-os", Os);
            request.Headers.Add("x-ver-os", OsVersion);
            request.Headers.Add("x-device-model", Ascii(Model));
        }

        private static string ComputeSystemHwid()
        {
            byte[] seed = null;
            try
            {
                // Same value for all apps of this publisher on this device, kept across reinstalls.
                var id = SystemIdentification.GetSystemIdForPublisher();
                if (id != null && id.Source != SystemIdentificationSource.None && id.Id != null && id.Id.Length > 0)
                {
                    CryptographicBuffer.CopyToByteArray(id.Id, out seed);
                }
            }
            catch (Exception)
            {
                // not available on this device
            }
            if (seed == null)
            {
                // Fallback: random, kept until the app is uninstalled.
                var stored = AppSettings.Current.GeneratedHwidSeed;
                if (string.IsNullOrEmpty(stored))
                {
                    stored = Guid.NewGuid().ToString("N");
                    AppSettings.Current.GeneratedHwidSeed = stored;
                }
                seed = Encoding.UTF8.GetBytes(stored);
            }

            // Hash with an app-specific salt so the raw system ID is never sent.
            var salted = new byte[seed.Length + 7];
            Encoding.UTF8.GetBytes("xelite:").CopyTo(salted, 0);
            seed.CopyTo(salted, 7);
            var sha = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            byte[] hash;
            CryptographicBuffer.CopyToByteArray(sha.HashData(CryptographicBuffer.CreateFromByteArray(salted)), out hash);
            var bytes = new byte[16];
            Array.Copy(hash, bytes, 16);
            return new Guid(bytes).ToString("D").ToUpperInvariant();
        }

        /// <summary>HTTP header values must be ASCII.</summary>
        private static string Ascii(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                sb.Append(c >= 0x20 && c < 0x7F ? c : '_');
            }
            return sb.ToString();
        }
    }
}
