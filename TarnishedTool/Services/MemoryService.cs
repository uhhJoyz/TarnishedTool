using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Timers;
using TarnishedTool.Interfaces;
using TarnishedTool.Memory;

namespace TarnishedTool.Services
{
    public class MemoryService : IMemoryService
    {
        public bool IsAttached { get; private set; }
        public Process? TargetProcess { get; private set; }
        public IntPtr ProcessHandle { get; private set; } = IntPtr.Zero;
        public nint BaseAddress { get; private set; }
        public int ModuleMemorySize { get; private set; }
        public string? TargetFileVersion { get; private set; }

        private const int ProcessVmRead = 0x0010;
        private const int ProcessVmWrite = 0x0020;
        private const int ProcessVmOperation = 0x0008;
        private const int ProcessQueryInformation = 0x0400;
        private const int AttachCheckInterval = 2000; //MS

        private const uint MemRelease = 0x00008000;
        private const uint MemCommitState = 0x1000;
        private const uint MemImage = 0x1000000;
        private const uint PageNoAccess = 0x01;
        private const uint PageGuard = 0x100;
        private const long EldenRingDefaultImageBase = 0x140000000;
        
        private const uint CodeCaveSize = 0x5000;
        private const int CodeCaveSearchStart = 0x40000000;
        private const int CodeCaveSearchEnd = 0x30000;
        private const int CodeCaveSearchStep = 0x10000;

        private const string ProcessName = "eldenring";
        private bool _disposed;
        private bool _isAttachCheckRunning;

        private Timer _autoAttachTimer;
        
        
        public string ReadString(IntPtr addr, int maxLength = 32)
        {
            var bytes = ReadBytes(addr, maxLength * 2);

            int stringLength = 0;
            for (int i = 0; i < bytes.Length - 1; i += 2)
            {
                if (bytes[i] == 0 && bytes[i + 1] == 0)
                {
                    stringLength = i;
                    break;
                }
            }

            if (stringLength == 0)
            {
                stringLength = bytes.Length - bytes.Length % 2;
            }

            return Encoding.Unicode.GetString(bytes, 0, stringLength);
        }
        
        
        public byte[] ReadBytes(IntPtr addr, int size)
        {
            var array = new byte[size];
            var lpNumberOfBytesRead = 1;
            Kernel32.ReadProcessMemory(ProcessHandle, addr, array, size, ref lpNumberOfBytesRead);
            return array;
        }

        
        public T Read<T>(IntPtr addr) where T : unmanaged
        {
            int size = Unsafe.SizeOf<T>();
            var bytes = ReadBytes(addr, size);
            return MemoryMarshal.Read<T>(bytes);
        }
        
        public string HexDump(nint addr, int size)
        {
            var data = ReadBytes(addr, size);
            return HexDump(data);
        }
        
        private string HexDump(byte[] data, int? maxBytes = null)
        {
            int bytesToDump = maxBytes.HasValue ? Math.Min(maxBytes.Value, data.Length) : data.Length;
            var sb = new StringBuilder();
    
            for (int i = 0; i < bytesToDump; i += 16)
            {
                int lineLength = Math.Min(16, bytesToDump - i);
                string hex = BitConverter.ToString(data, i, lineLength).Replace("-", " ");
                string ascii = new string(data.Skip(i).Take(lineLength)
                    .Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
                sb.AppendLine($"{i:X4}: {hex,-48} {ascii}");
            }
    
            return sb.ToString();
        }

        public T[] ReadArray<T>(IntPtr addr, int count) where T : unmanaged
        {
            int size = Unsafe.SizeOf<T>() * count;
            var bytes = ReadBytes(addr, size);
            return MemoryMarshal.Cast<byte, T>(bytes).ToArray();
        }

        public void Write<T>(IntPtr addr, T value) where T : unmanaged
        {
            int size = Unsafe.SizeOf<T>();
            var bytes = new byte[size];
            MemoryMarshal.Write(bytes, ref value);
            WriteBytes(addr, bytes);
        }
        
        public void Write(IntPtr addr, bool value) => 
            Write(addr, value ? (byte)1 : (byte)0);


        public void WriteString(IntPtr addr, string value, int maxLength = 32)
        {
            var bytes = new byte[maxLength];
            var stringBytes = Encoding.Unicode.GetBytes(value);
            Array.Copy(stringBytes, bytes, Math.Min(stringBytes.Length, maxLength));
            WriteBytes(addr, bytes);
        }
        
        public void WriteBytes(IntPtr addr, byte[] val)
        {
            Kernel32.WriteProcessMemory(ProcessHandle, addr, val, val.Length, 0);
        }

        public void SetBitValue(IntPtr addr, int flagMask, bool setValue)
        {
            byte currentByte = Read<byte>(addr);
            byte modifiedByte;

            if (setValue)
                modifiedByte = (byte)(currentByte | flagMask);
            else
                modifiedByte = (byte)(currentByte & ~flagMask);
            Write(addr, modifiedByte);
        }

        public bool IsBitSet(IntPtr addr, int flagMask)
        {
            byte currentByte = Read<byte>(addr);

            return (currentByte & flagMask) != 0;
        }

        public void RunThread(nint address, uint timeout = uint.MaxValue)
        {
            IntPtr thread = Kernel32.CreateRemoteThread(ProcessHandle, IntPtr.Zero, 0, address, IntPtr.Zero, 0, IntPtr.Zero);
            var ret = Kernel32.WaitForSingleObject(thread, timeout);
            Kernel32.CloseHandle(thread);
        }

        private bool RunThreadAndWaitForCompletion(IntPtr address, uint timeout = 0xFFFFFFFF)
        {
            IntPtr thread = Kernel32.CreateRemoteThread(ProcessHandle, IntPtr.Zero, 0, address, IntPtr.Zero, 0, IntPtr.Zero);

            if (thread == IntPtr.Zero)
            {
                return false;
            }

            uint waitResult = Kernel32.WaitForSingleObject(thread, timeout);
            Kernel32.CloseHandle(thread);

            return waitResult == 0;
        }

        public nint FollowPointers(nint baseAddress, int[] offsets, bool readFinalPtr, bool derefBase = true)
        {
            nint ptr = derefBase ? Read<nint>(baseAddress) : baseAddress;

            for (int i = 0; i < offsets.Length - 1; i++)
            {
                ptr = Read<nint>(ptr + offsets[i]);
            }

            nint finalAddress = ptr + offsets[offsets.Length - 1];

            if (readFinalPtr)
                return Read<nint>(finalAddress);

            return finalAddress;
        }

        public void AllocateAndExecute(byte[] shellcode)
        {
            IntPtr allocatedMemory = Kernel32.VirtualAllocEx(ProcessHandle, IntPtr.Zero, (uint)shellcode.Length);

            if (allocatedMemory == IntPtr.Zero) return;

            WriteBytes(allocatedMemory, shellcode);
            bool executionSuccess = RunThreadAndWaitForCompletion(allocatedMemory);

            if (!executionSuccess) return;

            Kernel32.VirtualFreeEx(ProcessHandle, allocatedMemory, 0, MemRelease);
        }

        public void AllocCodeCave()
        {
            nint searchRangeStart = BaseAddress - CodeCaveSearchStart;
            nint searchRangeEnd = BaseAddress - CodeCaveSearchEnd;

            for (nint addr = searchRangeEnd; addr > searchRangeStart; addr -= CodeCaveSearchStep)
            {
                var allocatedMemory = Kernel32.VirtualAllocEx(ProcessHandle, addr, CodeCaveSize);

                if (allocatedMemory != IntPtr.Zero)
                {
                    CodeCaveOffsets.Base = allocatedMemory;
                    break;
                }
            }
        }

        public nint AllocateMem(uint size) => Kernel32.VirtualAllocEx(ProcessHandle, IntPtr.Zero, size);

        public void FreeMem(nint addr) => Kernel32.VirtualFreeEx(ProcessHandle, addr, 0, MemRelease);
        
        public void StartAutoAttach()
        {
            _autoAttachTimer = new Timer(AttachCheckInterval);
            _autoAttachTimer.Elapsed += (sender, e) => TryAttachToProcess();
            _autoAttachTimer.Start();
        }
        
        private void TryAttachToProcess()
        {
            if (_isAttachCheckRunning) return;
            _isAttachCheckRunning = true;

            try
            {
                TryAttachToProcessCore();
            }
            catch
            {
                if (ProcessHandle != IntPtr.Zero)
                {
                    Kernel32.CloseHandle(ProcessHandle);
                }

                ProcessHandle = IntPtr.Zero;
                TargetProcess = null;
                TargetFileVersion = null;
                BaseAddress = IntPtr.Zero;
                ModuleMemorySize = 0;
                IsAttached = false;
            }
            finally
            {
                _isAttachCheckRunning = false;
            }
        }

        private void TryAttachToProcessCore()
        {
            if (ProcessHandle != IntPtr.Zero)
            {
                if (TargetProcess == null || TargetProcess.HasExited)
                {
                    Kernel32.CloseHandle(ProcessHandle);
                    ProcessHandle = IntPtr.Zero;
                    TargetProcess = null;
                    TargetFileVersion = null;
                    BaseAddress = IntPtr.Zero;
                    ModuleMemorySize = 0;
                    IsAttached = false;
                }

                return;
            }

            var processes = Process.GetProcessesByName(ProcessName);
            if (processes.Length > 0 && !processes[0].HasExited)
            {
                TargetProcess = processes[0];
                ProcessHandle = Kernel32.OpenProcess(
                    ProcessVmRead | ProcessVmWrite | ProcessVmOperation | ProcessQueryInformation,
                    false,
                    TargetProcess.Id);

                if (ProcessHandle == IntPtr.Zero)
                {
                    Console.WriteLine($@"Attach failed: OpenProcess returned null for PID {TargetProcess.Id}");
                    TargetProcess = null;
                    TargetFileVersion = null;
                    BaseAddress = IntPtr.Zero;
                    ModuleMemorySize = 0;
                    IsAttached = false;
                }
                else
                {
                    if (TryGetTargetModule(ProcessHandle, out var module))
                    {
                        BaseAddress = module.BaseAddress;
                        ModuleMemorySize = module.ModuleMemorySize;
                        TargetFileVersion = module.FileVersion;
                        IsAttached = true;
                        Console.WriteLine($@"Attached to {ProcessName}: base=0x{(long)BaseAddress:X}, size=0x{ModuleMemorySize:X}, version={TargetFileVersion ?? "unknown"}");
                    }
                    else
                    {
                        Console.WriteLine($@"Attach failed: could not resolve module base for PID {TargetProcess.Id}");
                        Kernel32.CloseHandle(ProcessHandle);
                        ProcessHandle = IntPtr.Zero;
                        TargetProcess = null;
                        TargetFileVersion = null;
                        BaseAddress = IntPtr.Zero;
                        ModuleMemorySize = 0;
                        IsAttached = false;
                    }
                }
            }
        }

        private sealed class TargetModuleInfo
        {
            public IntPtr BaseAddress { get; set; }
            public int ModuleMemorySize { get; set; }
            public string FileVersion { get; set; }
        }

        private static bool TryGetTargetModule(IntPtr processHandle, out TargetModuleInfo module)
        {
            module = null;
            return TryGetTargetModuleFromPeb(processHandle, out module)
                   || TryGetTargetModuleAtBase(processHandle, new IntPtr(EldenRingDefaultImageBase), out module)
                   || TryGetTargetModuleFromVirtualMemory(processHandle, out module);
        }

        private static bool TryGetTargetModuleFromPeb(IntPtr processHandle, out TargetModuleInfo module)
        {
            module = null;

            try
            {
                var processInfo = new Kernel32.ProcessBasicInformation();
                var status = Kernel32.NtQueryInformationProcess(
                    processHandle,
                    0,
                    ref processInfo,
                    Marshal.SizeOf(typeof(Kernel32.ProcessBasicInformation)),
                    out _);

                if (status != 0 || processInfo.PebBaseAddress == IntPtr.Zero)
                {
                    return false;
                }

                var imageBaseAddressPtr = IntPtr.Add(processInfo.PebBaseAddress, IntPtr.Size * 2);
                var imageBaseAddress = ReadRemote<IntPtr>(processHandle, imageBaseAddressPtr);
                if (imageBaseAddress == IntPtr.Zero)
                {
                    return false;
                }

                var moduleMemorySize = ReadRemoteModuleMemorySize(processHandle, imageBaseAddress);
                if (moduleMemorySize <= 0)
                {
                    return false;
                }

                module = new TargetModuleInfo
                {
                    BaseAddress = imageBaseAddress,
                    ModuleMemorySize = moduleMemorySize,
                    FileVersion = GetProcessFileVersion(processHandle)
                };
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string GetFileVersion(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return null;

            try
            {
                return FileVersionInfo.GetVersionInfo(filePath).FileVersion;
            }
            catch
            {
                return null;
            }
        }

        private static string GetProcessFileVersion(IntPtr processHandle)
        {
            const int MaxPath = 32767;

            var size = MaxPath;
            var filePath = new StringBuilder(size);
            if (!Kernel32.QueryFullProcessImageName(processHandle, 0, filePath, ref size))
            {
                return null;
            }

            return GetFileVersion(filePath.ToString());
        }

        private static bool TryGetTargetModuleFromVirtualMemory(IntPtr processHandle, out TargetModuleInfo module)
        {
            module = null;

            const long MinAddress = 0x10000;
            var maxAddress = IntPtr.Size == 8 ? 0x7FFFFFFEFFFFL : 0x7FFF0000L;

            for (var address = MinAddress; address < maxAddress;)
            {
                if (Kernel32.VirtualQueryEx(
                        processHandle,
                        new IntPtr(address),
                        out var memoryInfo,
                        (uint)Marshal.SizeOf(typeof(Kernel32.MemoryBasicInformation))) == 0)
                {
                    address += 0x10000;
                    continue;
                }

                var regionSize = memoryInfo.RegionSize.ToInt64();
                if (regionSize <= 0)
                {
                    address += 0x10000;
                    continue;
                }

                if (memoryInfo.State == MemCommitState &&
                    memoryInfo.Type == MemImage &&
                    (memoryInfo.Protect & (PageNoAccess | PageGuard)) == 0 &&
                    TryGetTargetModuleAtBase(processHandle, memoryInfo.AllocationBase, out module))
                {
                    return true;
                }

                address = Math.Max(address + regionSize, address + 0x10000);
            }

            return false;
        }

        private static bool TryGetTargetModuleAtBase(
            IntPtr processHandle,
            IntPtr moduleBase,
            out TargetModuleInfo module)
        {
            module = null;

            if (moduleBase == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                var moduleMemorySize = ReadRemoteModuleMemorySize(processHandle, moduleBase);
                if (moduleMemorySize <= 0)
                {
                    return false;
                }

                module = new TargetModuleInfo
                {
                    BaseAddress = moduleBase,
                    ModuleMemorySize = moduleMemorySize,
                    FileVersion = GetProcessFileVersion(processHandle)
                };
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static int ReadRemoteModuleMemorySize(IntPtr processHandle, IntPtr moduleBase)
        {
            const ushort DosSignature = 0x5A4D;
            const uint PeSignature = 0x00004550;
            const int DosHeaderLfanewOffset = 0x3C;
            const int NtHeadersOptionalHeaderOffset = 0x18;
            const int OptionalHeaderSizeOfImageOffset = 0x38;

            var dosSignature = ReadRemote<ushort>(processHandle, moduleBase);
            if (dosSignature != DosSignature)
            {
                return 0;
            }

            var peHeaderOffset = ReadRemote<int>(processHandle, IntPtr.Add(moduleBase, DosHeaderLfanewOffset));
            if (peHeaderOffset <= 0)
            {
                return 0;
            }

            var ntHeaders = IntPtr.Add(moduleBase, peHeaderOffset);
            var peSignature = ReadRemote<uint>(processHandle, ntHeaders);
            if (peSignature != PeSignature)
            {
                return 0;
            }

            return ReadRemote<int>(
                processHandle,
                IntPtr.Add(ntHeaders, NtHeadersOptionalHeaderOffset + OptionalHeaderSizeOfImageOffset));
        }

        private static T ReadRemote<T>(IntPtr processHandle, IntPtr address) where T : unmanaged
        {
            var size = Unsafe.SizeOf<T>();
            var bytes = new byte[size];
            var bytesRead = 0;

            if (!Kernel32.ReadProcessMemory(processHandle, address, bytes, size, ref bytesRead) || bytesRead != size)
            {
                throw new InvalidOperationException();
            }

            return MemoryMarshal.Read<T>(bytes);
        }

        private void Dispose()
        {
            if (!_disposed)
            {
                if (_autoAttachTimer != null)
                {
                    _autoAttachTimer.Stop();
                    _autoAttachTimer.Dispose();
                    _autoAttachTimer = null;
                }

                if (ProcessHandle != IntPtr.Zero)
                {
                    Kernel32.CloseHandle(ProcessHandle);
                    ProcessHandle = IntPtr.Zero;
                    TargetProcess = null;
                    TargetFileVersion = null;
                    BaseAddress = IntPtr.Zero;
                    ModuleMemorySize = 0;
                    IsAttached = false;
                }

                _disposed = true;
            }

            GC.SuppressFinalize(this);
        }

        ~MemoryService()
        {
            Dispose();
        }
    }
}
