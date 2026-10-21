using System;
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
            try
            {
                // The app's "test VPN plug-in" starts this task with an ApplicationTrigger
                // to check that Windows can run it at all.
                if (taskInstance.TriggerDetails is ApplicationTriggerDetails)
                {
                    PluginLog.Write("self-test: background task started OK");
                    return;
                }
                lock (Gate)
                {
                    if (_plugin == null)
                    {
                        PluginLog.Write("plug-in activated (" + (taskInstance.TriggerDetails?.GetType().Name ?? "no trigger") + ")");
                        _plugin = new XrayVpnPlugin();
                    }
                }
                VpnChannel.ProcessEventAsync(_plugin, taskInstance.TriggerDetails);
            }
            catch (Exception e)
            {
                PluginLog.Write("plug-in task failed: " + PluginLog.Describe(e));
                throw;
            }
        }
    }
}
