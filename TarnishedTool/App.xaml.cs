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
                    stylusLogicType.InvokeMember(
                        "OnTabletRemoved",
                        BindingFlags.InvokeMethod | BindingFlags.Instance | BindingFlags.NonPublic,
                        null,
                        stylusLogic,
                        new object[] { (uint)0 });
                }
            }
            catch
            {
                // Best-effort Wine compatibility tweak. If WPF internals change, keep startup working.
            }
        }
    }
}
