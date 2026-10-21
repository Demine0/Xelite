using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Xelite.VpnTask
{
    /// <summary>
    /// Owns the xelite-core.exe child process (Xray + userspace TCP/IP stack).
    /// </summary>
    internal sealed class CoreProcess
    {
        private readonly string _exePath;
        private readonly string _dataDir;
        private IntPtr _process = IntPtr.Zero;

        public CoreProcess(string exePath, string dataDir)
        {
            _exePath = exePath;
            _dataDir = dataDir;
        }

        private string PidFile => Path.Combine(_dataDir, "core.pid");
        private string StatusFile => Path.Combine(_dataDir, "core.status");
        private string StatsFile => Path.Combine(_dataDir, "core.stats");

        /// <summary>Starts the core and waits until it reports "ready".</summary>
        public async Task StartAsync(string configPath, int port, int mtu, bool allowIpv6)
        {
            KillStale();
            if (File.Exists(StatusFile))
            {
                File.Delete(StatusFile);
            }

            var cmd = string.Format("\"{0}\" -config \"{1}\" -port {2} -mtu {3} -status \"{4}\" -stats \"{5}\" -ppid {6}",
                _exePath, configPath, port, mtu, StatusFile, StatsFile, NativeMethods.GetCurrentProcessId());
            if (allowIpv6)
            {
                cmd += " -ipv6";
            }
            var si = new NativeMethods.STARTUPINFO { cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>() };
            NativeMethods.PROCESS_INFORMATION pi;
            if (!NativeMethods.CreateProcessW(_exePath, cmd, IntPtr.Zero, IntPtr.Zero, false,
                    NativeMethods.CREATE_NO_WINDOW, IntPtr.Zero, _dataDir, ref si, out pi))
            {
                throw new InvalidOperationException("CreateProcess failed, error " + Marshal.GetLastWin32Error());
            }
            NativeMethods.CloseHandle(pi.hThread);
            _process = pi.hProcess;
            File.WriteAllText(PidFile, pi.dwProcessId.ToString());

            for (var i = 0; i < 100; i++)
            {
                await Task.Delay(100).ConfigureAwait(false);
                string status = null;
                try
                {
                    if (File.Exists(StatusFile))
                    {
                        status = File.ReadAllText(StatusFile).Trim();
                    }
                }
                catch (IOException)
                {
                    // still being written
                }
                if (status == "ready")
                {
                    return;
                }
                if (status != null && status.StartsWith("error"))
                {
                    Stop();
                    throw new InvalidOperationException("Xray: " + status.Substring(5).TrimStart(':', ' '));
                }
                if (NativeMethods.WaitForSingleObject(_process, 0) != NativeMethods.WAIT_TIMEOUT)
                {
                    uint code;
                    NativeMethods.GetExitCodeProcess(_process, out code);
                    Stop();
                    throw new InvalidOperationException("xelite-core exited with code " + code);
                }
            }
            Stop();
            throw new TimeoutException("xelite-core did not start in 10 seconds");
        }

        public void Stop()
        {
            if (_process != IntPtr.Zero)
            {
                NativeMethods.TerminateProcess(_process, 0);
                NativeMethods.CloseHandle(_process);
                _process = IntPtr.Zero;
            }
            try
            {
                File.Delete(PidFile);
            }
            catch (IOException)
            {
            }
        }

        /// <summary>Kills a core left behind by a crashed background task.</summary>
        private void KillStale()
        {
            try
            {
                int pid;
                if (!File.Exists(PidFile) || !int.TryParse(File.ReadAllText(PidFile), out pid))
                {
                    return;
                }
                var h = NativeMethods.OpenProcess(NativeMethods.PROCESS_TERMINATE, false, pid);
                if (h != IntPtr.Zero)
                {
                    NativeMethods.TerminateProcess(h, 0);
                    NativeMethods.CloseHandle(h);
                }
            }
            catch (Exception)
            {
                // best effort
            }
        }
    }
}
