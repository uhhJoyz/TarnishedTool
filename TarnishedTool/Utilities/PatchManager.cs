// 

using System;
using TarnishedTool.Interfaces;
using TarnishedTool.Memory;
using TarnishedTool.Services;

namespace TarnishedTool.Utilities;

public static class PatchManager
{
    private const string FallbackFileVersion = "2.6.2.0";

    public static bool Initialize(IMemoryService memoryService)
    {
        if (!memoryService.IsAttached) return false;
        var fileVersion = memoryService.TargetFileVersion;
        var moduleBase = memoryService.BaseAddress;

        if (string.IsNullOrEmpty(fileVersion))
        {
            fileVersion = FallbackFileVersion;
            Console.WriteLine($@"Patch: using fallback file version {fileVersion}");
        }
        
        Console.WriteLine($@"Patch: {fileVersion}");

        return Offsets.Initialize(fileVersion, moduleBase);
    }
}
