// 

using System;
using TarnishedTool.Interfaces;
using TarnishedTool.Memory;
using TarnishedTool.Services;

namespace TarnishedTool.Utilities;

public static class PatchManager
{
    public static bool Initialize(IMemoryService memoryService)
    {
        if (!memoryService.IsAttached) return false;
        var fileVersion = memoryService.TargetFileVersion;
        var moduleBase = memoryService.BaseAddress;
        
        Console.WriteLine($@"Patch: {fileVersion}");

        if (string.IsNullOrEmpty(fileVersion)) return false;

        return Offsets.Initialize(fileVersion, moduleBase);
    }
}
