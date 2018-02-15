using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Forms;

namespace org.foesmm.helper
{
    // ReSharper disable once InconsistentNaming
    public static class UAC
    {
        private const int BcmFirst = 0x1600; //Normal button
        private const int BcmSetshield = BcmFirst + 0x000C; //Elevated button

        private static WindowsIdentity _currentUserIdentity;

        private static WindowsIdentity CachedOwner
            => _currentUserIdentity ?? (_currentUserIdentity = Owner);

        /// <summary>
        ///     A <see cref="bool" /> value indicating if the current process has full administrative rights
        /// </summary>
        public static bool IsElevated => CachedOwner != null &&
                                         new WindowsPrincipal(CachedOwner).IsInRole(
                                             WindowsBuiltInRole.Administrator);

        /// <summary>
        ///     A <see cref="bool" /> value indicating if UAC virtualization is supported on the current machine
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public static bool IsUACSupported => Environment.OSVersion.Version.Major >= 6;

        /// <summary>
        ///     Returns a <see cref="WindowsIdentity" /> object containing information about the current process owner
        /// </summary>
        public static WindowsIdentity Owner => WindowsIdentity.GetCurrent();

        [DllImport("user32")]
        public static extern uint SendMessage
            (IntPtr hWnd, uint msg, uint wParam, uint lParam);

        public static void AddShieldToButton(Button b)
        {
            b.FlatStyle = FlatStyle.System;
            SendMessage(b.Handle, BcmSetshield, 0, 0xFFFFFFFF);
        }
    }
}