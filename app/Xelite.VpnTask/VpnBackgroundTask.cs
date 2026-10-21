using System;
using System.Collections.Generic;
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
        private static XrayVpnPlugin _plugin;

        // Deferrals kept while the tunnel is up. A completed task lets Windows
        // suspend the host process between events, which freezes the packet
        // sender, the relay and xelite-core; holding them keeps it running.
        private static readonly List<BackgroundTaskDeferral> Held = new List<BackgroundTaskDeferral>();

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            // Keeps the host process alive until ProcessEventAsync has handled the event.
            var deferral = taskInstance.GetDeferral();
            taskInstance.Canceled += (sender, reason) => PluginLog.Write("plug-in task canceled: " + reason);
            var keep = false;
            try
            {
                lock (Gate)
                {
                    if (_plugin == null)
                    {
                        PluginLog.Write("plug-in activated (" + (taskInstance.TriggerDetails?.GetType().Name ?? "no trigger") + ")");
                        _plugin = new XrayVpnPlugin();
                    }
                }
                VpnChannel.ProcessEventAsync(_plugin, taskInstance.TriggerDetails);
                keep = _plugin.IsConnected;
            }
            catch (Exception e)
            {
                PluginLog.Write("plug-in task failed: " + PluginLog.Describe(e));
            }
            finally
            {
                lock (Gate)
                {
                    if (keep)
                    {
                        Held.Add(deferral);
                    }
                    else
                    {
                        deferral.Complete();
                        foreach (var held in Held)
                        {
                            held.Complete();
                        }
                        Held.Clear();
                    }
                }
            }
        }
    }
}
