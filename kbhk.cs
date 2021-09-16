using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace kbhk {
  public partial class Form1: Form {

    private struct KBDLLHOOKSTRUCT {
      public int vkCode;
      int scanCode;
      public int flags;
      int time;
      int dwExtraInfo;
    }

    private delegate int LowLevelKeyboardProcDelegate(int nCode, int wParam, ref KBDLLHOOKSTRUCT lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProcDelegate lpfn, IntPtr hMod, int dwThreadId);

    [DllImport("user32.dll")]
    private static extern bool UnhookWindowsHookEx(IntPtr hHook);

    [DllImport("user32.dll")]
    private static extern int CallNextHookEx(int hHook, int nCode, int wParam, ref KBDLLHOOKSTRUCT lParam);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(IntPtr path);

    private IntPtr hHook;
    LowLevelKeyboardProcDelegate hookProc;
    const int WH_KEYBOARD_LL = 13;
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetKernelObjectSecurity(IntPtr Handle, int securityInformation, [Out] byte[] pSecurityDescriptor,
      uint nLength, out uint lpnLengthNeeded);

    public static RawSecurityDescriptor GetProcessSecurityDescriptor(IntPtr processHandle) {
      const int DACL_SECURITY_INFORMATION = 0x00000004;
      byte[] psd = new byte[0];
      uint bufSizeNeeded;

      GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, psd, 0, out bufSizeNeeded);
      if (bufSizeNeeded < 0 || bufSizeNeeded > short.MaxValue)
        throw new Win32Exception();

      if (!GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION,
          psd = new byte[bufSizeNeeded], bufSizeNeeded, out bufSizeNeeded))
        throw new Win32Exception();

      return new RawSecurityDescriptor(psd, 0);
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetKernelObjectSecurity(IntPtr Handle, int securityInformation, [In] byte[] pSecurityDescriptor);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [Flags]
    public enum ProcessAccessRights {
      PROCESS_CREATE_PROCESS = 0x0080,
        PROCESS_CREATE_THREAD = 0x0002,
        PROCESS_DUP_HANDLE = 0x0040,
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
        PROCESS_SET_INFORMATION = 0x0200,
        PROCESS_SET_QUOTA = 0x0100,
        PROCESS_SUSPEND_RESUME = 0x0800,
        PROCESS_TERMINATE = 0x0001,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_READ = 0x0010,
        PROCESS_VM_WRITE = 0x0020,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        SYNCHRONIZE = 0x00100000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        STANDARD_RIGHTS_REQUIRED = 0x000f0000,
        PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF),
    }
    public static void SetProcessSecurityDescriptor(IntPtr processHandle, RawSecurityDescriptor dacl) {
      const int DACL_SECURITY_INFORMATION = 0x00000004;
      byte[] rawsd = new byte[dacl.BinaryLength];
      dacl.GetBinaryForm(rawsd, 0);
      if (!SetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, rawsd))
        throw new Win32Exception();
    }
    public Form1() {
      InitializeComponent();
      Hide();
      IntPtr hModule = GetModuleHandle(IntPtr.Zero);
      hookProc = new LowLevelKeyboardProcDelegate(LowLevelKeyboardProc);
      hHook = SetWindowsHookEx(WH_KEYBOARD_LL, hookProc, hModule, 0);
      if (hHook == IntPtr.Zero) {
        MessageBox.Show("failed to hook | " + Marshal.GetLastWin32Error());
      }

      IntPtr hProcess = GetCurrentProcess();

      var dacl = GetProcessSecurityDescriptor(hProcess);

      dacl.DiscretionaryAcl.InsertAce(
        0,
        new CommonAce(
          AceFlags.None,
          AceQualifier.AccessDenied,
          (int) ProcessAccessRights.PROCESS_ALL_ACCESS,
          new SecurityIdentifier(WellKnownSidType.WorldSid, null),
          false,
          null)
      );

      SetProcessSecurityDescriptor(hProcess, dacl);

    }

    private static int LowLevelKeyboardProc(int nCode, int wParam, ref KBDLLHOOKSTRUCT lParam) {
      if (nCode >= 0)
        switch (wParam) {
        case 256:
        case 257:
        case 260:
        case 261:
          if (
            (lParam.vkCode == 0x09 && lParam.flags == 32) ||
            (lParam.vkCode == 0x1b && lParam.flags == 32) ||
            (lParam.vkCode == 0x73 && lParam.flags == 32) ||
            (lParam.vkCode == 0x1b && lParam.flags == 0) ||
            (lParam.vkCode == 0x5b && lParam.flags == 1) ||
            (lParam.vkCode == 0x5c && lParam.flags == 1)) {
            return 1;
          }
          break;
        }
      return CallNextHookEx(0, nCode, wParam, ref lParam);
    }

    private void Window_Closed(object sender, EventArgs e) {
      UnhookWindowsHookEx(hHook);
    }

  }
}
