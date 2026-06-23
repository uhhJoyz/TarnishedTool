using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
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
        
        private const uint CodeCaveSize = 0x5000;
        private const int CodeCaveSearchStart = 0x40000000;
        private const int CodeCaveSearchEnd = 0x30000;
        private const int CodeCaveSearchStep = 0x10000;

        private const string ProcessName = "eldenring";
        private bool _disposed;

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

            TryAttachToProcess();

            _autoAttachTimer.Start();
        }
        
        private void TryAttachToProcess()
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
                    TargetProcess = null;
                    TargetFileVersion = null;
                    BaseAddress = IntPtr.Zero;
                    ModuleMemorySize = 0;
                    IsAttached = false;
                }
                else
                {
                    if (TryGetTargetModule(TargetProcess, out var module))
                    {
                        BaseAddress = module.BaseAddress;
                        ModuleMemorySize = module.ModuleMemorySize;
                        TargetFileVersion = module.FileVersion;
                        IsAttached = true;
                    }
                    else
                    {
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

        private static bool TryGetTargetModule(Process process, out TargetModuleInfo module)
        {
            module = null;

            try
            {
                var mainModule = process.MainModule;
                if (IsTargetModule(mainModule))
                {
                    module = CreateTargetModuleInfo(mainModule);
                    return true;
                }
            }
            catch (Exception ex) when (IsModuleLookupException(ex))
            {
            }

            try
            {
                foreach (ProcessModule processModule in process.Modules)
                {
                    if (IsTargetModule(processModule))
                    {
                        module = CreateTargetModuleInfo(processModule);
                        return true;
                    }
                }
            }
            catch (Exception ex) when (IsModuleLookupException(ex))
            {
            }

            return TryGetTargetModuleFromSnapshot(process.Id, out module);
        }

        private static bool IsTargetModule(ProcessModule module)
        {
            if (module == null) return false;

            var moduleName = module.ModuleName;
            if (string.Equals(moduleName, ProcessName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(moduleName, ProcessName + ".exe", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var fileName = Path.GetFileNameWithoutExtension(module.FileName);
            return string.Equals(fileName, ProcessName, StringComparison.OrdinalIgnoreCase);
        }

        private static TargetModuleInfo CreateTargetModuleInfo(ProcessModule module)
        {
            return new TargetModuleInfo
            {
                BaseAddress = module.BaseAddress,
                ModuleMemorySize = module.ModuleMemorySize,
                FileVersion = module.FileVersionInfo.FileVersion
            };
        }

        private static bool TryGetTargetModuleFromSnapshot(int processId, out TargetModuleInfo module)
        {
            module = null;

            var snapshot = Kernel32.CreateToolhelp32Snapshot(
                Kernel32.Th32csSnapmodule | Kernel32.Th32csSnapmodule32,
                (uint)processId);

            if (snapshot == new IntPtr(-1))
            {
                return false;
            }

            try
            {
                var moduleEntry = new Kernel32.ModuleEntry32
                {
                    DwSize = (uint)Marshal.SizeOf(typeof(Kernel32.ModuleEntry32))
                };

                if (!Kernel32.Module32First(snapshot, ref moduleEntry))
                {
                    return false;
                }

                do
                {
                    if (IsTargetModule(moduleEntry))
                    {
                        module = new TargetModuleInfo
                        {
                            BaseAddress = moduleEntry.ModBaseAddr,
                            ModuleMemorySize = checked((int)moduleEntry.ModBaseSize),
                            FileVersion = GetFileVersion(moduleEntry.SzExePath)
                        };
                        return true;
                    }
                } while (Kernel32.Module32Next(snapshot, ref moduleEntry));

                return false;
            }
            catch (OverflowException)
            {
                return false;
            }
            finally
            {
                Kernel32.CloseHandle(snapshot);
            }
        }

        private static bool IsTargetModule(Kernel32.ModuleEntry32 module)
        {
            if (string.Equals(module.SzModule, ProcessName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(module.SzModule, ProcessName + ".exe", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var fileName = Path.GetFileNameWithoutExtension(module.SzExePath);
            return string.Equals(fileName, ProcessName, StringComparison.OrdinalIgnoreCase);
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

        private static bool IsModuleLookupException(Exception ex)
            => ex is ArgumentException
               || ex is ArgumentOutOfRangeException
               || ex is InvalidOperationException
               || ex is NotSupportedException
               || ex is Win32Exception;

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
