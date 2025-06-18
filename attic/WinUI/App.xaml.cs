using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using Hardcodet.Wpf.TaskbarNotification;
using Newtonsoft.Json;

namespace WinUI
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private TaskbarIcon tb;

        public App()
        {
            JsonConvert.DefaultSettings = () => new JsonSerializerSettings { MaxDepth = 128 };
        }

        private void InitApplication()
        {
            tb = (TaskbarIcon)FindResource("NotifyIcon");
            tb.Visibility = Visibility.Visible;
        }
    }
}
