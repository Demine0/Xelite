using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;

namespace Xelite.VpnTask
{
    /// <summary>
    /// The connection to the proxy server, owned by the VPN platform as the main
    /// transport.
    ///
    /// Windows runs the plug-in (and xelite-core with it) only during VPN events
    /// and freezes it in between. A socket of our own would receive the server's
    /// replies while frozen and nothing would wake us; data arriving on the main
    /// transport makes the platform call Decapsulate, so the tunnel keeps moving.
    ///
    /// Xray's single connection to the server (XHTTP's one HTTP/2 connection, or Xray
    /// mux) is bridged onto it: the plug-in opens the TCP connection itself in Connect,
    /// and when xelite-core's relay asks for that address it is attached here.
    /// Server bytes arrive in Decapsulate and are written to the relay connection;
    /// Xray's bytes are read from it, queued, and sent as buffers with
    /// TransportAffinity 0 in the next Encapsulate/Decapsulate, which a doorbell
    /// datagram on the optional transport provokes.
    /// </summary>
    internal sealed class ServerTunnel : IDisposable
    {
        private const int MaxBuffersPerDrain = 256;

        private readonly object _gate = new object();
        private readonly Queue<byte[]> _upload = new Queue<byte[]>();
        private int _uploadOffset;
        private StreamSocket _relay;
        private DataWriterQueue _toCore;
        private Action _ringDoorbell;
        private Action<string> _onClosed;
        private int _closed;

        public ServerTunnel(string address, int port)
        {
            Address = address;
            Port = port;
            Socket = new StreamSocket();
            Socket.Control.NoDelay = true;
        }

        public string Address { get; }
        public int Port { get; }

        /// <summary>The platform's main transport.</summary>
        public StreamSocket Socket { get; }

        public string Target => Address + ":" + Port;

        public long BytesDown;
        public long BytesUp;
        public long PoolFailures;

        /// <summary>
        /// Write Xray's upload straight to the server socket. The platform only reads it
        /// (we give it nothing to send), so we are its only writer. Going through
        /// GetVpnSendPacketBuffer drained the platform's small buffer pool, which it also
        /// needs to hand app packets to Encapsulate: Windows stopped delivering them.
        /// </summary>
        public bool DirectWrite = true;
        private DataWriterQueue _toServer;

        public Task ConnectAsync()
        {
            return Socket.ConnectAsync(new HostName(Address), Port.ToString()).AsTask();
        }

        /// <summary>
        /// Attaches xelite-core's relay connection for this server. Only one: Xray
        /// keeps a single multiplexed connection; a second one is relayed normally.
        /// </summary>
        public bool TryAttach(StreamSocket relay, Action ringDoorbell, Action<string> onClosed)
        {
            lock (_gate)
            {
                if (_relay != null || _closed != 0)
                {
                    return false;
                }
                _relay = relay;
                _toCore = new DataWriterQueue(relay.OutputStream, e => Close("writing to xelite-core failed: " + e.Message));
                _toServer = new DataWriterQueue(Socket.OutputStream, e =>
                {
                    // The platform refused direct writes: fall back to its send buffers.
                    PluginLog.Write("direct write to the server transport failed (" + PluginLog.Describe(e) + "); using platform buffers");
                    DirectWrite = false;
                    _ringDoorbell?.Invoke();
                });
                _ringDoorbell = ringDoorbell;
                _onClosed = onClosed;
            }
            Task.Run(ReadUploadAsync);
            return true;
        }

        public bool IsAttached
        {
            get { lock (_gate) { return _relay != null; } }
        }

        /// <summary>Server bytes from Decapsulate, for Xray.</summary>
        public void Deliver(IBuffer bytes)
        {
            var copy = new byte[bytes.Length];
            bytes.CopyTo(0, copy, 0, (int)bytes.Length);
            Interlocked.Add(ref BytesDown, copy.Length);
            DataWriterQueue toCore;
            lock (_gate)
            {
                toCore = _toCore;
            }
            toCore?.Enqueue(copy);
        }

        /// <summary>Moves queued upload bytes into send buffers on the main transport.</summary>
        public void Drain(VpnChannel channel, VpnPacketBufferList into)
        {
            var more = false;
            lock (_gate)
            {
                for (var n = 0; n < MaxBuffersPerDrain && _upload.Count > 0; n++)
                {
                    VpnPacketBuffer packet;
                    try
                    {
                        packet = channel.GetVpnSendPacketBuffer();
                    }
                    catch (Exception)
                    {
                        Interlocked.Increment(ref PoolFailures);
                        more = true; // pool exhausted; the next event continues
                        break;
                    }
                    var buffer = packet.Buffer;
                    var chunk = _upload.Peek();
                    var count = (int)Math.Min(buffer.Capacity, (uint)(chunk.Length - _uploadOffset));
                    chunk.CopyTo(_uploadOffset, buffer, 0, count);
                    buffer.Length = (uint)count;
                    packet.TransportAffinity = 0; // main transport: the server connection
                    into.Append(packet);
                    Interlocked.Add(ref BytesUp, count);
                    _uploadOffset += count;
                    if (_uploadOffset == chunk.Length)
                    {
                        _upload.Dequeue();
                        _uploadOffset = 0;
                    }
                }
                more |= _upload.Count > 0;
            }
            if (more)
            {
                _ringDoorbell?.Invoke();
            }
        }

        private async Task ReadUploadAsync()
        {
            StreamSocket relay;
            lock (_gate)
            {
                relay = _relay;
            }
            var buffer = new Windows.Storage.Streams.Buffer(16384);
            try
            {
                while (true)
                {
                    var read = await relay.InputStream.ReadAsync(buffer, buffer.Capacity, InputStreamOptions.Partial);
                    if (read.Length == 0)
                    {
                        break;
                    }
                    var copy = new byte[read.Length];
                    read.CopyTo(0, copy, 0, (int)read.Length);
                    if (DirectWrite)
                    {
                        Interlocked.Add(ref BytesUp, copy.Length);
                        _toServer.Enqueue(copy);
                        continue;
                    }
                    bool wasEmpty;
                    lock (_gate)
                    {
                        wasEmpty = _upload.Count == 0;
                        _upload.Enqueue(copy);
                    }
                    if (wasEmpty)
                    {
                        _ringDoorbell?.Invoke(); // ask the platform for an event to send it in
                    }
                }
                Close("xelite-core closed the server connection");
            }
            catch (Exception e)
            {
                Close("relay read failed: " + e.Message);
            }
        }

        public void Close(string reason)
        {
            if (Interlocked.Exchange(ref _closed, 1) != 0)
            {
                return;
            }
            Action<string> onClosed;
            lock (_gate)
            {
                onClosed = _onClosed;
            }
            onClosed?.Invoke(reason);
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _closed, 1);
            lock (_gate)
            {
                _relay?.Dispose();
                _relay = null;
                _toCore = null;
            }
            Socket.Dispose();
        }

        /// <summary>Writes byte arrays to a stream one after another, in order.</summary>
        private sealed class DataWriterQueue
        {
            private readonly IOutputStream _stream;
            private readonly Action<Exception> _failed;
            private readonly Queue<byte[]> _queue = new Queue<byte[]>();
            private bool _writing;

            public DataWriterQueue(IOutputStream stream, Action<Exception> failed)
            {
                _stream = stream;
                _failed = failed;
            }

            public void Enqueue(byte[] data)
            {
                lock (_queue)
                {
                    _queue.Enqueue(data);
                    if (_writing)
                    {
                        return;
                    }
                    _writing = true;
                }
                Task.Run(WriteAllAsync);
            }

            private async Task WriteAllAsync()
            {
                while (true)
                {
                    byte[] data;
                    lock (_queue)
                    {
                        if (_queue.Count == 0)
                        {
                            _writing = false;
                            return;
                        }
                        data = _queue.Dequeue();
                    }
                    try
                    {
                        await _stream.WriteAsync(data.AsBuffer());
                    }
                    catch (Exception e)
                    {
                        _failed(e);
                        return;
                    }
                }
            }
        }
    }
}
