using System;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace Xelite.VpnTask
{
    /// <summary>
    /// Opens xelite-core's outbound connections with WinRT sockets.
    ///
    /// A process started by the VPN plug-in may not open its own sockets to the
    /// internet on Windows 10 Mobile (Xray's connect fails with WSAEACCES), but
    /// the plug-in's WinRT sockets may. xelite-core therefore connects here over
    /// loopback and sends one line, "TCP 1.2.3.4:443" or "UDP 1.2.3.4:443"; the
    /// relay answers "OK" or "ERR message" and then pipes the bytes. UDP payloads
    /// are framed as a 2-byte big-endian length plus the datagram.
    /// </summary>
    internal sealed class RelayServer : IDisposable
    {
        private const int ConnectTimeoutMs = 10000;
        private const int MaxLoggedErrors = 20;

        private StreamSocketListener _listener;
        private int _errorsLogged;
        private long _opened;

        public int Port { get; private set; }

        public async Task StartAsync()
        {
            _listener = new StreamSocketListener();
            _listener.Control.NoDelay = true;
            _listener.ConnectionReceived += (sender, e) => { var unused = HandleAsync(e.Socket); };
            await _listener.BindEndpointAsync(new HostName("127.0.0.1"), "");
            Port = int.Parse(_listener.Information.LocalPort);
        }

        public void Dispose()
        {
            _listener?.Dispose();
            _listener = null;
        }

        private async Task HandleAsync(StreamSocket local)
        {
            string request = null;
            var fromCore = local.InputStream.AsStreamForRead(0);
            var toCore = local.OutputStream.AsStreamForWrite(0);
            try
            {
                request = await ReadLineAsync(fromCore);
                var space = request.IndexOf(' ');
                var colon = request.LastIndexOf(':');
                if (space < 0 || colon < space)
                {
                    throw new FormatException("bad request '" + request + "'");
                }
                var network = request.Substring(0, space);
                var host = request.Substring(space + 1, colon - space - 1).Trim('[', ']');
                var port = request.Substring(colon + 1);

                if (network == "TCP")
                {
                    await RelayTcpAsync(local, fromCore, toCore, host, port);
                }
                else if (network == "UDP")
                {
                    await RelayUdpAsync(fromCore, toCore, host, port);
                }
                else
                {
                    throw new FormatException("unknown network '" + network + "'");
                }
            }
            catch (Exception e)
            {
                if (Interlocked.Increment(ref _errorsLogged) <= MaxLoggedErrors)
                {
                    PluginLog.Write("relay " + (request ?? "?") + ": " + PluginLog.Describe(e));
                }
                try
                {
                    await WriteLineAsync(toCore, "ERR " + e.Message.Replace('\r', ' ').Replace('\n', ' '));
                }
                catch (Exception)
                {
                    // core already gone
                }
            }
            finally
            {
                local.Dispose();
            }
        }

        private async Task RelayTcpAsync(StreamSocket local, Stream fromCore, Stream toCore, string host, string port)
        {
            using (var remote = new StreamSocket())
            {
                remote.Control.NoDelay = true;
                var connect = remote.ConnectAsync(new HostName(host), port).AsTask();
                if (await Task.WhenAny(connect, Task.Delay(ConnectTimeoutMs)) != connect)
                {
                    throw new TimeoutException("connect to " + host + ":" + port + " timed out");
                }
                await connect;
                await WriteLineAsync(toCore, "OK");
                LogFirst("TCP " + host + ":" + port);

                // Raw WinRT streams with Partial reads: a read returns as soon as any bytes
                // arrive. Through the .NET stream adapters small writes (DNS answers, short
                // HTTP/2 frames) could sit waiting for a full buffer, so most requests hung.
                var up = PumpAsync(local.InputStream, remote.OutputStream);
                var down = PumpAsync(remote.InputStream, local.OutputStream);
                // Either side closing ends the relay; disposing both sockets stops the other pump.
                await Task.WhenAny(up, down);
            }
        }

        private async Task RelayUdpAsync(Stream fromCore, Stream toCore, string host, string port)
        {
            using (var remote = new DatagramSocket())
            {
                var writeLock = new SemaphoreSlim(1, 1);
                remote.MessageReceived += async (s, e) =>
                {
                    try
                    {
                        var reader = e.GetDataReader();
                        var length = reader.UnconsumedBufferLength;
                        var frame = new byte[2 + length];
                        frame[0] = (byte)(length >> 8);
                        frame[1] = (byte)length;
                        var payload = new byte[length];
                        reader.ReadBytes(payload);
                        System.Buffer.BlockCopy(payload, 0, frame, 2, (int)length);
                        await writeLock.WaitAsync();
                        try
                        {
                            await toCore.WriteAsync(frame, 0, frame.Length);
                            await toCore.FlushAsync();
                        }
                        finally
                        {
                            writeLock.Release();
                        }
                    }
                    catch (Exception)
                    {
                        // ICMP unreachable or core gone; the read loop below ends the relay
                    }
                };
                await remote.ConnectAsync(new HostName(host), port);
                await WriteLineAsync(toCore, "OK");
                LogFirst("UDP " + host + ":" + port);

                var header = new byte[2];
                while (true)
                {
                    if (!await ReadExactlyAsync(fromCore, header, 2))
                    {
                        return;
                    }
                    var length = (header[0] << 8) | header[1];
                    var payload = new byte[length];
                    if (!await ReadExactlyAsync(fromCore, payload, length))
                    {
                        return;
                    }
                    await remote.OutputStream.WriteAsync(payload.AsBuffer());
                }
            }
        }

        private void LogFirst(string what)
        {
            var n = Interlocked.Increment(ref _opened);
            if (n <= 3 || n % 100 == 0)
            {
                PluginLog.Write("relay opened #" + n + ": " + what);
            }
        }

        private static async Task PumpAsync(IInputStream from, IOutputStream to)
        {
            var buffer = new Windows.Storage.Streams.Buffer(16384);
            try
            {
                while (true)
                {
                    var read = await from.ReadAsync(buffer, buffer.Capacity, InputStreamOptions.Partial);
                    if (read.Length == 0)
                    {
                        break;
                    }
                    await to.WriteAsync(read);
                }
            }
            catch (Exception)
            {
                // connection closed or reset
            }
        }

        private static async Task<bool> ReadExactlyAsync(Stream from, byte[] buffer, int count)
        {
            var read = 0;
            while (read < count)
            {
                var n = await from.ReadAsync(buffer, read, count - read);
                if (n <= 0)
                {
                    return false;
                }
                read += n;
            }
            return true;
        }

        private static async Task<string> ReadLineAsync(Stream from)
        {
            var bytes = new byte[512];
            var one = new byte[1];
            var length = 0;
            while (length < bytes.Length)
            {
                if (await from.ReadAsync(one, 0, 1) <= 0)
                {
                    throw new EndOfStreamException("core closed the relay connection");
                }
                if (one[0] == (byte)'\n')
                {
                    return Encoding.UTF8.GetString(bytes, 0, length).Trim();
                }
                bytes[length++] = one[0];
            }
            throw new FormatException("request line too long");
        }

        private static async Task WriteLineAsync(Stream to, string line)
        {
            var bytes = Encoding.UTF8.GetBytes(line + "\n");
            await to.WriteAsync(bytes, 0, bytes.Length);
            await to.FlushAsync();
        }
    }
}
