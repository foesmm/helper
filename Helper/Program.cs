using System.Collections.Generic;
using System.Linq;
using NDesk.Options;

namespace org.foesmm.helper
{
    internal class Program
    {
        private static int Main(string[] args)
        {
            var directories = new HashSet<string>();

            var opts = new OptionSet
            {
                {
                    "acl-write=", "Adds filesystem write access for current user to {PATH}", v => directories.Add(v)
                }
            };
            opts.Parse(args);

            if (directories.Where(dir => !FileAccess.HasWriteAccess(dir)).Any(dir => !FileAccess.GrantWriteAccess(dir)))
                return -1;

            return 0;
        }
    }
}