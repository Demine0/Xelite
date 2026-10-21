using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.ApplicationModel;
using Windows.Data.Json;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using System.Threading;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Streams;

namespace Xelite.VpnTask
{
    /// <summary>
    /// VPN plug-in that hands every IP packet to xelite-core over loopback UDP.
    ///
    /// The outer "transport" of the VPN channel is a DatagramSocket connected to
    /// xelite-core. Encapsulate passes captured packets through unchanged, so the
    /// platform sends each one as a datagram to the core; datagrams coming back
    /// from the core are IP packets that Decapsulate injects into the interface.
    /// </summary>
    internal sealed class XrayVpnPlugin : IVpnPlugIn
    {
        private const string TunAddress = "198.18.0.1";
        private const string TunAddress6 = "fd66:7865::1";

        private DatagramSocket _socket;
        private CoreProcess _core;
        private RelayServer _relay;
        private CancellationTokenSource _heartbeat;

        /// <summary>True between a successful Connect and Disconnect.</summary>
        public bool IsConnected { get; private set; }

        // Packets to xelite-core go through this socket, not the VPN transport:
        // Windows binds the transport to the physical interface, where datagrams
        // to 127.0.0.1 never arrive. Replies come back on the transport.
        private DatagramSocket _side;
        private BlockingCollection<IBuffer> _sendQueue;
        private readonly AutoResetEvent _controlReply = new AutoResetEvent(false);
        private string _controlExpected;
        private string _lastHeartbeat = "none yet";
        private DateTime _lastHeartbeatAt = DateTime.MinValue;

        // Traffic counters, logged at 1, 10, 100 and then every 1000 packets each way.
        private static bool ShouldLog(long n)
        {
            return n == 1 || n == 10 || n == 100 || n % 1000 == 0;
        }
        private long _sent;
        private long _received;

        public void Connect(VpnChannel channel)
        {
            Log(channel, "connect requested");
            _sent = 0;
            _received = 0;
            PluginLog.SetState("connecting");
            try
            {
                var dataDir = ApplicationData.Current.LocalFolder.Path;
                var settings = JsonObject.Parse(File.ReadAllText(Path.Combine(dataDir, "vpn.json")));
                var mtu = (int)settings.GetNamedNumber("mtu", 1500);
                var port = (int)settings.GetNamedNumber("port", 0);
                if (port == 0)
                {
                    port = new Random().Next(20000, 40000);
                }

                // xelite-core may not open internet sockets itself; it dials through this relay.
                _relay = new RelayServer();
                _relay.StartAsync().Wait();
                Log(channel, "relay listening on 127.0.0.1:" + _relay.Port);

                Log(channel, "starting xelite-core on 127.0.0.1:" + port);
                _core = new CoreProcess(Path.Combine(Package.Current.InstalledLocation.Path, "xelite-core.exe"), dataDir);
                var allowIpv6 = settings.GetNamedBoolean("ipv6", false);
                _core.StartAsync(Path.Combine(dataDir, "config.json"), port, mtu, allowIpv6, _relay.Port).Wait();
                Log(channel, "xelite-core ready, started " + _core.StartMode);
                OpenSideSocket(port);
                if (!Control("XELITE-PING", "XELITE-PONG"))
                {
                    throw new InvalidOperationException(
                        "Windows blocks loopback traffic between Xelite's VPN plug-in and its engine (127.0.0.1:" + port +
                        "), so no traffic can pass. This is the UWP network isolation sandbox.");
                }
                Log(channel, "loopback test: OK");

                _socket = new DatagramSocket();
                channel.AssociateTransport(_socket, null);
                _socket.ConnectAsync(new HostName("127.0.0.1"), port.ToString()).AsTask().Wait();
                var transportPort = _socket.Information.LocalPort;
                var ack = Control("XELITE-RT" + transportPort, "XELITE-RT" + transportPort);
                Log(channel, "transport associated (local port " + transportPort + ", reply-to " +
                             (ack ? "acknowledged" : "NOT acknowledged") + "), starting tunnel");

                var routes = new VpnRouteAssignment { ExcludeLocalSubnets = settings.GetNamedBoolean("bypassLan", true) };
                // Two /1 routes instead of 0.0.0.0/0: they are more specific than the
                // system default route, so they always win (same trick as OpenVPN's def1).
                routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("0.0.0.0"), 1));
                routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("128.0.0.0"), 1));
                // Capture IPv6 too, or it leaks past the VPN over the Wi-Fi's own IPv6 route.
                // xelite-core rejects it (unless enabled) so apps fall back to IPv4.
                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("::"), 1));
                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("8000::"), 1));
                foreach (var cidr in Strings(settings, "exclude"))
                {
                    routes.Ipv4ExclusionRoutes.Add(ParseRoute(cidr));
                }

                var dnsServers = new List<HostName>();
                foreach (var dns in Strings(settings, "dns"))
                {
                    dnsServers.Add(new HostName(dns));
                }
                var domains = new VpnDomainNameAssignment();
                domains.DomainNameList.Add(new VpnDomainNameInfo(".", VpnDomainNameType.Suffix, dnsServers, new List<HostName>()));

                Log(channel, "routes: include 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1 (ipv6 " + (allowIpv6 ? "proxied" : "rejected") + "); exclude " + string.Join(", ", Strings(settings, "exclude")) +
                             "; dns " + string.Join(", ", Strings(settings, "dns")) + "; mtu " + mtu);
                channel.StartExistingTransports(
                    new List<HostName> { new HostName(TunAddress) },
                    new List<HostName> { new HostName(TunAddress6) },
                    null,
                    routes,
                    domains,
                    (uint)mtu,
                    (uint)mtu + 64,
                    false);
                Log(channel, "connected");
                PluginLog.SetState("connected");
                IsConnected = true;
                StartHeartbeat();
            }
            catch (Exception e)
            {
                var inner = e is AggregateException ? e.InnerException ?? e : e;
                Log(channel, "connect failed: " + PluginLog.Describe(inner));
                Cleanup();
                PluginLog.SetState("error: " + inner.Message);
                channel.TerminateConnection(inner.Message);
            }
        }

        public void Disconnect(VpnChannel channel)
        {
            Log(channel, "disconnect requested");
            PluginLog.SetState("disconnected");
            IsConnected = false;
            try
            {
                channel.Stop();
            }
            catch (Exception)
            {
                // already stopped
            }
            Cleanup();
        }

        public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
        {
            // Loopback transport: nothing to keep alive.
            keepAlivePacket = null;
        }

        public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapulatedPackets)
        {
            var queue = _sendQueue;
            while (packets.Size > 0)
            {
                // Copy the packet and send it to xelite-core ourselves (see _side);
                // nothing goes out through the transport.
                var src = packets.RemoveAtBegin().Buffer;
                var copy = new Windows.Storage.Streams.Buffer(src.Length);
                src.CopyTo(0, copy, 0, src.Length);
                copy.Length = src.Length;
                if (queue == null || !queue.TryAdd(copy))
                {
                    continue; // queue full or closing: drop, TCP retransmits
                }
                var n = ++_sent;
                if (ShouldLog(n))
                {
                    Log(channel, "to xelite-core: " + n + " packets");
                }
            }
        }

        public void Decapsulate(VpnChannel channel, VpnPacketBuffer encapBuffer, VpnPacketBufferList decapsulatedPackets, VpnPacketBufferList controlPacketsToSend)
        {
            var src = encapBuffer.Buffer;
            if (src.Length < 20)
            {
                return;
            }
            var packet = channel.GetVpnReceivePacketBuffer();
            if (packet.Buffer.Capacity < src.Length)
            {
                return;
            }
            src.CopyTo(0, packet.Buffer, 0, src.Length);
            packet.Buffer.Length = src.Length;
            decapsulatedPackets.Append(packet);
            var n = ++_received;
            if (ShouldLog(n))
            {
                Log(channel, "from xelite-core: " + n + " packets");
            }
        }

        private void OpenSideSocket(int port)
        {
            _side = new DatagramSocket();
            _side.MessageReceived += (sock, e) =>
            {
                try
                {
                    var reader = e.GetDataReader();
                    var text = reader.ReadString(reader.UnconsumedBufferLength);
                    if (text.StartsWith("XELITE-HB "))
                    {
                        _lastHeartbeat = text.Substring(10);
                        _lastHeartbeatAt = DateTime.UtcNow;
                        return;
                    }
                    var expected = _controlExpected;
                    if (expected != null && text == expected)
                    {
                        _controlReply.Set();
                    }
                }
                catch (Exception)
                {
                }
            };
            _side.ConnectAsync(new HostName("127.0.0.1"), port.ToString()).AsTask().Wait();

            _sendQueue = new BlockingCollection<IBuffer>(4096);
            var queue = _sendQueue;
            var output = _side.OutputStream;
            // Long-running task (UWP has no System.Threading.Thread) sending packets one by one.
            Task.Factory.StartNew(() =>
            {
                try
                {
                    foreach (var packet in queue.GetConsumingEnumerable())
                    {
                        output.WriteAsync(packet).AsTask().Wait();
                    }
                }
                catch (Exception e)
                {
                    PluginLog.Write("sender stopped: " + PluginLog.Describe(e));
                }
            }, TaskCreationOptions.LongRunning);
        }

        /// <summary>
        /// Sends a control datagram to xelite-core over the side socket and waits
        /// for the expected answer (XELITE-PING to XELITE-PONG, XELITE-RT port echoed).
        /// </summary>
        private bool Control(string message, string expected)
        {
            _controlExpected = expected;
            _controlReply.Reset();
            var ok = false;
            try
            {
                for (var i = 0; i < 3 && !ok; i++)
                {
                    var writer = new DataWriter();
                    writer.WriteString(message);
                    _sendQueue.Add(writer.DetachBuffer());
                    ok = _controlReply.WaitOne(700);
                }
            }
            catch (Exception e)
            {
                PluginLog.Write("control " + message + " error: " + PluginLog.Describe(e));
            }
            _controlExpected = null;
            PluginLog.Write("control " + message + ": " + (ok ? "answered" : "no answer"));
            return ok;
        }

        /// <summary>
        /// Logs every 5 s while connected. Gaps in these lines mean the host process
        /// was frozen; the counters show whether packets keep flowing.
        /// </summary>
        private void StartHeartbeat()
        {
            _heartbeat?.Cancel();
            var cts = new CancellationTokenSource();
            _heartbeat = cts;
            Task.Run(async () =>
            {
                try
                {
                    while (!cts.IsCancellationRequested)
                    {
                        await Task.Delay(5000, cts.Token);
                        var cpu = _core?.CpuMilliseconds() ?? -1;
                        PluginLog.Write("alive: to core " + _sent + ", from core " + _received +
                                        ", send queue " + (_sendQueue?.Count ?? -1) +
                                        ", xelite-core cpu " + (cpu == -1 ? "EXITED" : cpu + " ms") +
                                        ", core heartbeat " + (_lastHeartbeatAt == DateTime.MinValue
                                            ? "never"
                                            : (int)(DateTime.UtcNow - _lastHeartbeatAt).TotalSeconds + " s ago: " + _lastHeartbeat));
                    }
                }
                catch (OperationCanceledException)
                {
                }
            });
        }

        private void Cleanup()
        {
            IsConnected = false;
            _heartbeat?.Cancel();
            _heartbeat = null;
            if (_sendQueue != null)
            {
                _sendQueue.CompleteAdding();
                _sendQueue = null;
            }
            if (_side != null)
            {
                _side.Dispose();
                _side = null;
            }
            if (_socket != null)
            {
                _socket.Dispose();
                _socket = null;
            }
            if (_core != null)
            {
                _core.Stop();
                _core = null;
            }
            if (_relay != null)
            {
                _relay.Dispose();
                _relay = null;
            }
        }

        private static IEnumerable<string> Strings(JsonObject obj, string name)
        {
            var arr = obj.GetNamedArray(name, new JsonArray());
            foreach (var v in arr)
            {
                if (v.ValueType == JsonValueType.String)
                {
                    yield return v.GetString();
                }
            }
        }

        private static VpnRoute ParseRoute(string cidr)
        {
            var parts = cidr.Split('/');
            var prefix = parts.Length > 1 ? byte.Parse(parts[1]) : (byte)32;
            return new VpnRoute(new HostName(parts[0]), prefix);
        }

        private static void Log(VpnChannel channel, string message)
        {
            PluginLog.Write(message, channel);
        }
    }
}
