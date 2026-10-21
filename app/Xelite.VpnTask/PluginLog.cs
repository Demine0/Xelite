using System;
using System.IO;
using Windows.Networking.Vpn;
using Windows.Storage;

namespace Xelite.VpnTask
{
    /// <summary>Writes LocalFolder\vpn.log, shown by the app's "show log".</summary>
    internal static class PluginLog
    {
        public static void Write(string message, VpnChannel channel = null)
        {
            var line = DateTime.Now.ToString("HH:mm:ss ") + message + Environment.NewLine;
            try
            {
                File.AppendAllText(Path.Combine(ApplicationData.Current.LocalFolder.Path, "vpn.log"), line);
            }
            catch (Exception)
            {
                try
                {
                    // LocalFolder unavailable in this host: leave a trace in TemporaryFolder.
                    File.AppendAllText(Path.Combine(ApplicationData.Current.TemporaryFolder.Path, "vpn.log"), line);
                }
                catch (Exception)
                {
                }
            }
            if (channel != null)
            {
                try
                {
                    channel.LogDiagnosticMessage(message);
                }
                catch (Exception)
                {
                }
            }
        }

        /// <summary>
        /// Writes LocalFolder\vpn.state ("connecting", "connected", "error: ...",
        /// "disconnected"). The app reads it because VpnPlugInProfile.ConnectionStatus
        /// throws E_HANDLE on Windows 10 Mobile.
        /// </summary>
        public static void SetState(string state)
        {
            try
            {
                File.WriteAllText(Path.Combine(ApplicationData.Current.LocalFolder.Path, "vpn.state"), state);
            }
            catch (Exception)
            {
            }
        }

        public static string Describe(Exception e)
        {
            var inner = e is AggregateException && e.InnerException != null ? e.InnerException : e;
            return inner.GetType().Name + " 0x" + inner.HResult.ToString("X8") + ": " + inner.Message;
        }
    }
}
