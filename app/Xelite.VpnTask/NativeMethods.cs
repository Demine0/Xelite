using System;
using System.Runtime.InteropServices;

namespace Xelite.VpnTask
{
    /// <summary>
    /// Win32 process APIs. They are imported through API sets, which exist on
    /// every Windows 10 edition including Windows 10 Mobile.
    /// </summary>
    internal static class NativeMethods
    {
        private const string ProcessThreads = "api-ms-win-core-processthreads-l1-1-0.dll";
        private const string Handle = "api-ms-win-core-handle-l1-1-0.dll";
        private const string Synch = "api-ms-win-core-synch-l1-1-0.dll";
        private const string ProcessEnvironment = "api-ms-win-core-processenvironment-l1-1-0.dll";

        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const uint PROCESS_TERMINATE = 0x0001;
        public const uint SYNCHRONIZE = 0x00100000;
        public const uint WAIT_TIMEOUT = 0x00000102;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport(ProcessThreads, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcessW(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport(ProcessThreads, SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport(ProcessThreads, SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport(ProcessThreads)]
        public static extern int GetCurrentProcessId();

        [DllImport(ProcessThreads, SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport(ProcessThreads, SetLastError = true)]
        public static extern bool GetProcessTimes(IntPtr hProcess, out long creationTime, out long exitTime,
            out long kernelTime, out long userTime);

        [DllImport(ProcessEnvironment)]
        public static extern IntPtr GetEnvironmentStringsW();

        [DllImport(ProcessEnvironment)]
        public static extern bool FreeEnvironmentStringsW(IntPtr block);

        [DllImport(Synch)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport(Handle)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
