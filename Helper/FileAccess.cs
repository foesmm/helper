using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Forms;

namespace org.foesmm.helper
{
    public static class FileAccess
    {
        public static bool HasWriteAccess(string directory)
        {
            if (!Directory.Exists(directory))
            {
                return false;
            }

            var wid = WindowsIdentity.GetCurrent();

            // ***** check directory ***** 
            var di = new DirectoryInfo(directory);

            var denied = false;
            var allowed = false;

            // ***** check write access ***** 
            try
            {
                var acl = di.GetAccessControl();
                var arc = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
                IList<FileSystemAccessRule> ars = new List<FileSystemAccessRule>(arc.OfType<FileSystemAccessRule>());

                // ***** user, not inherited rules ***** 
                foreach (var rule in ars.Where(r => r.IdentityReference.Equals(wid.User) && !r.IsInherited))
                {
                    denied |= DeniesWriteAccess(rule);
                    allowed |= AllowsWriteAccess(rule);
                }

                // ***** user, inherited rules ***** 
                foreach (var rule in ars.Where(r => r.IdentityReference.Equals(wid.User) && r.IsInherited))
                {
                    denied |= DeniesWriteAccess(rule);
                    allowed |= AllowsWriteAccess(rule);
                }

                if (wid.Groups != null)
                {
                    IList<IdentityReference> widgs = wid.Groups.Where(g =>
                        !g.Equals(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null))).ToList();

                    // ***** groups, not inherited rules ***** 
                    foreach (var rule in ars.Where(r => widgs.Contains(r.IdentityReference) && !r.IsInherited))
                    {
                        denied |= DeniesWriteAccess(rule);
                        allowed |= AllowsWriteAccess(rule);
                    }

                    // ***** groups, inherited rules ***** 
                    foreach (var rule in ars.Where(r => widgs.Contains(r.IdentityReference) && r.IsInherited))
                    {
                        denied |= DeniesWriteAccess(rule);
                        allowed |= AllowsWriteAccess(rule);
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }

            return !denied && allowed;
        }

        private static bool AllowsWriteAccess(FileSystemAccessRule rule)
        {
            return rule.AccessControlType == AccessControlType.Allow
                   && (
                       rule.FileSystemRights.HasFlag(FileSystemRights.Write)
                       || rule.FileSystemRights.HasFlag(FileSystemRights.WriteData)
                       || rule.FileSystemRights.HasFlag(FileSystemRights.CreateDirectories)
                       || rule.FileSystemRights.HasFlag(FileSystemRights.CreateFiles)
                   );
        }

        private static bool DeniesWriteAccess(FileSystemAccessRule rule)
        {
            return rule.AccessControlType == AccessControlType.Deny
                   && (
                       rule.FileSystemRights.HasFlag(FileSystemRights.Write)
                       || rule.FileSystemRights.HasFlag(FileSystemRights.WriteData)
                       || rule.FileSystemRights.HasFlag(FileSystemRights.CreateDirectories)
                       || rule.FileSystemRights.HasFlag(FileSystemRights.CreateFiles)
                   );
        }

        public static bool GrantWriteAccess(string directoryPath)
        {
            if (string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
            {
                return false;
            }
            var sid = WindowsIdentity.GetCurrent().User;
            if (sid == null)
            {
                return false;
            }

            var dInfo = new DirectoryInfo(directoryPath);
            var dSecurity = dInfo.GetAccessControl();

            var accessRule = new FileSystemAccessRule(sid,
                FileSystemRights.Modify,
                InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
                PropagationFlags.None,
                AccessControlType.Allow);

            dSecurity.AddAccessRule(accessRule);

            try
            {
                dInfo.SetAccessControl(dSecurity);
                return true;
            }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }
    }
}