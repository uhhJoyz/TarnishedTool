using System;
using System.Runtime.InteropServices;

namespace TarnishedTool.Memory
{
    internal static class Kernel32
    {
        public const uint MemCommit = 0x1000;
        public const uint MemReserve = 0x2000;
        public const uint PageExecuteReadwrite = 0x40;
        public const uint Th32csSnapmodule = 0x00000008;
        public const uint Th32csSnapmodule32 = 0x00000010;

        [StructLayout(LayoutKind.Sequential)]
        public struct MemoryBasicInformation
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ModuleEntry32
        {
            public uint DwSize;
            public uint Th32ModuleId;
            public uint Th32ProcessId;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr ModBaseAddr;
            public uint ModBaseSize;
            public IntPtr HModule;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string SzModule;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string SzExePath;
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAcess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int iSize,
            ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int iSize,
            int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint flAllocationType = MemCommit | MemReserve,
            uint flProtect = PageExecuteReadwrite
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out MemoryBasicInformation lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool Module32First(IntPtr hSnapshot, ref ModuleEntry32 lpme);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool Module32Next(IntPtr hSnapshot, ref ModuleEntry32 lpme);
    }
}
