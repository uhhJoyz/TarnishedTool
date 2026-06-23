using System.Threading;
using System.Windows;
using System.Windows.Interop;
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

            const string appName = "TarnishedTool";

            _mutex = new Mutex(true, appName, out var createdNew);

            if (!createdNew)
            {
                Current.Shutdown();
            }

            base.OnStartup(e);
        }    
    }
}
