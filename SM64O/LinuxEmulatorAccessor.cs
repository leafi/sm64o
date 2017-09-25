using System;
namespace SM64O
{
	// Memory reading and writing implementation for Linux, *BSD etc.
	// (Via the 'ptrace' interface!)
	// 
	// Cribbed from https://github.com/wine-mirror/wine/blob/1744277bee3c3c77ae657f42d8fac466cfac7924/server/ptrace.c#L332
    // (open_process, read_process_memory, write_process_memory)
	public class LinuxEmulatorAccessor
    {
        public LinuxEmulatorAccessor()
        {
        }
    }
}
