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
        public async Task StartAsync(string configPath, int port, int mtu, bool allowIpv6, int relayPort, bool xrayDns)
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
            if (relayPort > 0)
            {
                cmd += " -relay " + relayPort;
            }
            if (!xrayDns)
            {
                cmd += " -xraydns=false";
            }
            var si = new NativeMethods.STARTUPINFO { cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>() };
            NativeMethods.PROCESS_INFORMATION pi;
            var env = BuildEnvironment();
            try
            {
                pi = Launch(cmd, env, ref si);
            }
            finally
            {
                Marshal.FreeHGlobal(env);
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

        private NativeMethods.PROCESS_INFORMATION Launch(string cmd, IntPtr env, ref NativeMethods.STARTUPINFO si)
        {
            NativeMethods.PROCESS_INFORMATION pi;
            const uint flags = NativeMethods.CREATE_NO_WINDOW | NativeMethods.CREATE_UNICODE_ENVIRONMENT;
            // Outside the app's job, Windows' app lifecycle manager can't freeze the engine
            // together with the app; not every job allows it, so fall back to a normal child.
            if (NativeMethods.CreateProcessW(_exePath, cmd, IntPtr.Zero, IntPtr.Zero, false,
                    flags | NativeMethods.CREATE_BREAKAWAY_FROM_JOB, env, _dataDir, ref si, out pi))
            {
                StartMode = "outside the app job";
                return pi;
            }
            var breakawayError = Marshal.GetLastWin32Error();
            if (!NativeMethods.CreateProcessW(_exePath, cmd, IntPtr.Zero, IntPtr.Zero, false,
                    flags, env, _dataDir, ref si, out pi))
            {
                throw new InvalidOperationException("CreateProcess failed, error " + Marshal.GetLastWin32Error());
            }
            StartMode = "inside the app job (breakaway refused, error " + breakawayError + ")";
            return pi;
        }

        /// <summary>
        /// The plug-in's environment plus GODEBUG=asyncpreemptoff=1. Go's asynchronous
        /// preemption (SuspendThread/GetThreadContext) hangs on 32-bit Windows ARM, a
        /// port Go marks as broken: the first GC stop-the-world never completes and
        /// every goroutine stalls about a second after start.
        /// </summary>
        private static IntPtr BuildEnvironment()
        {
            // Copy the real block: .NET's Environment API returns too little in the
            // sandbox, and without SystemRoot Winsock fails (WSAPROVIDERFAILEDINIT).
            var vars = new System.Collections.Generic.SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var raw = NativeMethods.GetEnvironmentStringsW();
            if (raw != IntPtr.Zero)
            {
                try
                {
                    var p = raw;
                    while (true)
                    {
                        var entry = Marshal.PtrToStringUni(p);
                        if (string.IsNullOrEmpty(entry))
                        {
                            break;
                        }
                        var eq = entry.IndexOf('=', 1); // entries like "=C:=C:\" start with '='
                        if (eq > 0)
                        {
                            vars[entry.Substring(0, eq)] = entry.Substring(eq + 1);
                        }
                        p = IntPtr.Add(p, (entry.Length + 1) * 2);
                    }
                }
                finally
                {
                    NativeMethods.FreeEnvironmentStringsW(raw);
                }
            }
            if (!vars.ContainsKey("SystemRoot"))
            {
                vars["SystemRoot"] = @"C:\Windows";
            }
            vars["GODEBUG"] = "asyncpreemptoff=1";
            var block = new System.Text.StringBuilder();
            foreach (var kv in vars)
            {
                block.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
            }
            block.Append('\0');
            return Marshal.StringToHGlobalUni(block.ToString());
        }

        /// <summary>How the process was started, for the log.</summary>
        public string StartMode { get; private set; }

        /// <summary>CPU time used so far in ms, or -1 if the process has exited.</summary>
        public long CpuMilliseconds()
        {
            var process = _process;
            if (process == IntPtr.Zero || NativeMethods.WaitForSingleObject(process, 0) != NativeMethods.WAIT_TIMEOUT)
            {
                return -1;
            }
            long created, exited, kernel, user;
            return NativeMethods.GetProcessTimes(process, out created, out exited, out kernel, out user)
                ? (kernel + user) / 10000
                : -2;
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
