using Windows.ApplicationModel.Background;
using Windows.Networking.Vpn;

namespace Xelite.VpnTask
{
    /// <summary>
    /// Entry point the VPN platform activates for every plug-in event
    /// (connect, disconnect, encapsulate, decapsulate).
    /// </summary>
    public sealed class VpnBackgroundTask : IBackgroundTask
    {
        private static readonly object Gate = new object();
        private static IVpnPlugIn _plugin;

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            lock (Gate)
            {
                if (_plugin == null)
                {
                    _plugin = new XrayVpnPlugin();
                }
            }
            VpnChannel.ProcessEventAsync(_plugin, taskInstance.TriggerDetails);
        }
    }
}
