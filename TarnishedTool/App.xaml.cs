using System.Reflection;
using System.Threading;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Input;
using System.Windows.Media;

namespace TarnishedTool
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App
    {
        
        private static Mutex _mutex;

        protected override void OnStartup(StartupEventArgs e)
        {
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
            DisableWpfTabletSupport();

            const string appName = "TarnishedTool";

            _mutex = new Mutex(true, appName, out var createdNew);

            if (!createdNew)
            {
                Current.Shutdown();
            }

            base.OnStartup(e);
        }    

        private static void DisableWpfTabletSupport()
        {
            try
            {
                var devices = Tablet.TabletDevices;
                if (devices.Count == 0) return;

                var inputManagerType = typeof(InputManager);
                var stylusLogicProperty = inputManagerType.GetProperty(
                    "StylusLogic",
                    BindingFlags.Instance | BindingFlags.NonPublic);
                var stylusLogic = stylusLogicProperty?.GetValue(InputManager.Current);
                if (stylusLogic == null) return;

                var stylusLogicType = stylusLogic.GetType();
                while (devices.Count > 0)
                {
                    var tabletDevice = devices[0];
                    var idProperty = tabletDevice.GetType().GetProperty(
                        "Id",
                        BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                    var tabletId = idProperty?.GetValue(tabletDevice);
                    if (tabletId == null) return;

                    var previousCount = devices.Count;
                    stylusLogicType.InvokeMember(
                        "OnTabletRemoved",
                        BindingFlags.InvokeMethod | BindingFlags.Instance | BindingFlags.NonPublic,
                        null,
                        stylusLogic,
                        new[] { tabletId });

                    if (devices.Count == previousCount) return;
                }
            }
            catch
            {
                // Best-effort Wine compatibility tweak. If WPF internals change, keep startup working.
            }
        }
    }
}
