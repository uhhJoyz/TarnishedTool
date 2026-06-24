using System;
using System.Threading;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;
using TarnishedTool.Memory;

namespace TarnishedTool
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App
    {
        
        private static Mutex _mutex;

        static App()
        {
            ConfigureWineRendering();
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
            Console.WriteLine($@"Runtime: Is64BitProcess={Environment.Is64BitProcess}, Is64BitOperatingSystem={Environment.Is64BitOperatingSystem}");

            const string appName = "TarnishedTool";

            _mutex = new Mutex(true, appName, out var createdNew);

            if (!createdNew)
            {
                Current.Shutdown();
            }

            base.OnStartup(e);
        }

        private static void ConfigureWineRendering()
        {
            if (!IsRunningUnderWine()) return;

            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Avalon.Graphics"))
                {
                    key?.SetValue("DisableHWAcceleration", 1, RegistryValueKind.DWord);
                }
            }
            catch
            {
                // Keep startup working if the Wine prefix registry is unavailable.
            }
        }

        private static bool IsRunningUnderWine()
        {
            try
            {
                var ntdll = Kernel32.GetModuleHandle("ntdll.dll");
                return ntdll != IntPtr.Zero &&
                       Kernel32.GetProcAddress(ntdll, "wine_get_version") != IntPtr.Zero;
            }
            catch
            {
                return false;
            }
        }
    }
}
