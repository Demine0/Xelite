using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.ApplicationModel;
using Windows.Data.Json;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage;

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

        private DatagramSocket _socket;
        private CoreProcess _core;

        // Traffic counters, logged at the first packet each way and then every LogEvery packets.
        private const long LogEvery = 2000;
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

                Log(channel, "starting xelite-core on 127.0.0.1:" + port);
                _core = new CoreProcess(Path.Combine(Package.Current.InstalledLocation.Path, "xelite-core.exe"), dataDir);
                _core.StartAsync(Path.Combine(dataDir, "config.json"), port, mtu).Wait();
                Log(channel, "xelite-core ready");

                _socket = new DatagramSocket();
                channel.AssociateTransport(_socket, null);
                _socket.ConnectAsync(new HostName("127.0.0.1"), port.ToString()).AsTask().Wait();
                Log(channel, "transport associated, starting tunnel");

                var routes = new VpnRouteAssignment { ExcludeLocalSubnets = settings.GetNamedBoolean("bypassLan", true) };
                routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("0.0.0.0"), 0));
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

                channel.StartExistingTransports(
                    new List<HostName> { new HostName(TunAddress) },
                    null,
                    null,
                    routes,
                    domains,
                    (uint)mtu,
                    (uint)mtu + 64,
                    false);
                Log(channel, "connected");
                PluginLog.SetState("connected");
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
            while (packets.Size > 0)
            {
                encapulatedPackets.Append(packets.RemoveAtBegin());
                var n = ++_sent;
                if (n == 1 || n % LogEvery == 0)
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
            if (n == 1 || n % LogEvery == 0)
            {
                Log(channel, "from xelite-core: " + n + " packets");
            }
        }

        private void Cleanup()
        {
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
