using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace WinPrivTests
{
    public static class DialogAutomation
    {
        private const int WM_COMMAND = 0x0111;
        private const int WM_CLOSE = 0x0010;
        private const int IDOK = 1;

        private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassNameW(IntPtr hwnd, StringBuilder className, int maxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int maxCount);

        [DllImport("user32.dll")]
        private static extern IntPtr GetDlgItem(IntPtr hwnd, int itemId);

        [DllImport("user32.dll")]
        private static extern bool PostMessageW(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint desiredAccess);

        [DllImport("user32.dll")]
        private static extern bool CloseDesktop(IntPtr desktop);

        public static bool HasInputDesktop()
        {
            const uint DESKTOP_READOBJECTS = 0x0001;
            const uint DESKTOP_SWITCHDESKTOP = 0x0100;
            IntPtr desktop = OpenInputDesktop(0, false, DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP);
            if (desktop == IntPtr.Zero) return false;
            CloseDesktop(desktop);
            return true;
        }

        public static string Click(uint processId, int buttonId, string expectedTitle, int timeoutMilliseconds)
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMilliseconds);
            while (DateTime.UtcNow < deadline)
            {
                IntPtr dialog = FindDialog(processId, expectedTitle);
                if (dialog != IntPtr.Zero)
                {
                    string title = GetText(dialog);
                    IntPtr button = GetDlgItem(dialog, buttonId);
                    // Notify the dialog directly. BM_CLICK can silently do nothing when the
                    // dialog is not active, which is common for launchers started by the test
                    // runner with redirected output.
                    int message = buttonId == IDOK ? WM_CLOSE : WM_COMMAND;
                    IntPtr command = buttonId == IDOK ? IntPtr.Zero : new IntPtr(buttonId);
                    if (!PostMessageW(dialog, message, command, button))
                    {
                        throw new InvalidOperationException(
                            "Could not post the requested command to WinPriv dialog for process " + processId + ".");
                    }

                    DateTime closeDeadline = DateTime.UtcNow.AddMilliseconds(
                        Math.Min(5000, timeoutMilliseconds));
                    while (DateTime.UtcNow < closeDeadline)
                    {
                        if (FindDialog(processId, expectedTitle) == IntPtr.Zero) return title;
                        Thread.Sleep(50);
                    }
                    throw new TimeoutException(
                        "The matching WinPriv dialog did not close for process " + processId + ".");
                }
                Thread.Sleep(50);
            }
            throw new TimeoutException("No matching WinPriv dialog appeared for process " + processId + ".");
        }

        private static IntPtr FindDialog(uint processId, string expectedTitle)
        {
            IntPtr found = IntPtr.Zero;
            EnumWindows(delegate(IntPtr hwnd, IntPtr ignored)
            {
                uint owner;
                GetWindowThreadProcessId(hwnd, out owner);
                if (owner != processId) return true;
                StringBuilder className = new StringBuilder(64);
                GetClassNameW(hwnd, className, className.Capacity);
                if (!string.Equals(className.ToString(), "#32770", StringComparison.Ordinal)) return true;
                string title = GetText(hwnd);
                if (!string.IsNullOrEmpty(expectedTitle) &&
                    !string.Equals(title, expectedTitle, StringComparison.OrdinalIgnoreCase)) return true;
                found = hwnd;
                return false;
            }, IntPtr.Zero);
            return found;
        }

        private static string GetText(IntPtr hwnd)
        {
            StringBuilder text = new StringBuilder(1024);
            GetWindowTextW(hwnd, text, text.Capacity);
            return text.ToString();
        }
    }
}
