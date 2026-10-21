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
        private static XrayVpnPlugin _plugin;

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            // Keeps the host process alive until ProcessEventAsync has handled the event.
            var deferral = taskInstance.GetDeferral();
            taskInstance.Canceled += (sender, reason) => PluginLog.Write("plug-in task canceled: " + reason);
            try
            {
                lock (Gate)
                {
                    if (_plugin == null)
                    {
                        PluginLog.Write("plug-in activated (" + (taskInstance.TriggerDetails?.GetType().Name ?? "no trigger") +
                                        "), host command line: " +
                                        System.Runtime.InteropServices.Marshal.PtrToStringUni(NativeMethods.GetCommandLineW()));
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
                // Always complete: the platform kills activations that run too long
                // (about 90 s) or ignore a cancel, and the tunnel goes down with them.
                deferral.Complete();
            }
        }
    }
}
