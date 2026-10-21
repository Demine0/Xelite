using System;
using System.Threading;
using System.Threading.Tasks;
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
        /// <summary>
        /// How long the newest activation is kept open after its event. Between
        /// activations Windows freezes the host, and with it the relay and
        /// xelite-core, so replies from the server sit unread. Holding one activation
        /// keeps the tunnel awake while traffic flows; it is released well before the
        /// platform's ~90 s limit, at once on a cancel, and when the next event arrives.
        /// </summary>
        private const int HoldMilliseconds = 20000;

        private static readonly object Gate = new object();
        private static XrayVpnPlugin _plugin;
        private static Held _held;

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            // Keeps the host process alive until ProcessEventAsync has handled the event.
            var held = new Held(taskInstance.GetDeferral());
            taskInstance.Canceled += (sender, reason) =>
            {
                PluginLog.Write("plug-in task canceled: " + reason);
                held.Complete();
            };
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
                Held previous;
                lock (Gate)
                {
                    previous = _held;
                    _held = _plugin != null && _plugin.IsConnected ? held : null;
                }
                previous?.Complete();
                if (_held == held)
                {
                    held.CompleteAfter(HoldMilliseconds);
                }
                else
                {
                    held.Complete();
                }
            }
        }

        /// <summary>A deferral that is completed exactly once.</summary>
        private sealed class Held
        {
            private BackgroundTaskDeferral _deferral;

            public Held(BackgroundTaskDeferral deferral)
            {
                _deferral = deferral;
            }

            public void Complete()
            {
                Interlocked.Exchange(ref _deferral, null)?.Complete();
            }

            public void CompleteAfter(int milliseconds)
            {
                Task.Delay(milliseconds).ContinueWith(t => Complete());
            }
        }
    }
}
