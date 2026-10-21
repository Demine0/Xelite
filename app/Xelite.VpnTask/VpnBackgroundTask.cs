using System;
using Windows.ApplicationModel.Background;
using Windows.Networking.Vpn;

namespace Xelite.VpnTask
{
    /// <summary>
    /// Entry point the VPN platform activates for every plug-in event
    /// (connect, disconnect, encapsulate, decapsulate).
    /// </summary>
    /// <remarks>
    /// Each activation is completed as soon as its event is handled. The plug-in is
    /// kept awake by the platform itself: server replies arrive on the main transport
    /// and xelite-core's packets and doorbells on the optional one, and each of them
    /// raises a Decapsulate event. Holding deferrals instead got the activation killed
    /// by the platform's ~90 s watchdog, taking the tunnel down with it.
    /// </remarks>
    public sealed class VpnBackgroundTask : IBackgroundTask
    {
        private static readonly object Gate = new object();
        private static XrayVpnPlugin _plugin;

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            var deferral = taskInstance.GetDeferral();
            taskInstance.Canceled += (sender, reason) => PluginLog.Write("plug-in task canceled: " + reason);
            try
            {
                lock (Gate)
                {
                    if (_plugin == null)
                    {
                        PluginLog.Write("plug-in activated");
                        _plugin = new XrayVpnPlugin();
                    }
                }
                VpnChannel.ProcessEventAsync(_plugin, taskInstance.TriggerDetails);
            }
            catch (Exception e)
            {
                PluginLog.Write("plug-in task failed: " + PluginLog.Describe(e));
            }
            finally
            {
                deferral.Complete();
            }
        }
    }
}
