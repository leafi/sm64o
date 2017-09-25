using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SM64O
{
	// Memory reading & writing using the Mach kernel infrastructure
	// (ptrace is present on OS X but not complete enough for our purposes)
	// 
	// Code references:
	// https://github.com/wine-mirror/wine/blob/1744277bee3c3c77ae657f42d8fac466cfac7924/server/mach.c
	// (open_process, read_process_memory, write_process_memory)
	//
	// https://github.com/gdbinit/readmem/blob/master/readmem/main.c
    // ^^^ INCREDIBLE resource!!

	public unsafe class MacOSXEmulatorAccessor : IEmulatorAccessor
    {
        // extern kern_return_t task_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t);
        [DllImport("libSystem.B.dylib")]
        public static extern int task_for_pid(uint target_tport, int pid, out uint t);

        // extern mach_port_t mach_task_self_;
        //[DllImport("libSystem.B.dylib")]
        //public static extern uint mach_task_self_;

        // extern mach_port_t mach_thread_self(void);
        [DllImport("libSystem.B.dylib")]
        public static extern uint mach_thread_self();

        [DllImport("libSystem.B.dylib")]
        public static extern uint mach_host_self();

        // extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address,
        //     mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
        [DllImport("libSystem.B.dylib")]
        public static extern int mach_vm_read_overwrite(uint target_task, ulong address, ulong size, void* data, out ulong outsize);

        // extern kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address,
        //      mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
        [DllImport("libSystem.B.dylib")]
        public static extern int mach_vm_protect(uint target_task, ulong address, ulong size, uint set_maximum, int new_protection);

        // extern kern_return_t mach_vm_region(vm_map_t target_task, mach_vm_address_t *address,
        //      mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info,
        //      mach_msg_type_number_t *infoCnt, mach_port_t *object_name)
        [DllImport("libSystem.B.dylib")]
        public static extern int mach_vm_region(uint target_task, ref ulong address, ref ulong size, int flavor, int* info, ref uint infoCnt, uint* object_name);

        // extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address,
        //      vm_offset_t data, mach_msg_type_number_t dataCnt)
        [DllImport("libSystem.B.dylib")]
        public static extern int mach_vm_write(uint target_task, ulong address, void* data, uint dataCnt);

        [DllImport("/usr/lib/system/libdyld.dylib")]
        public static extern IntPtr dlsym(IntPtr handle, string wat);

        private ulong baseAddress;
        private uint taskH;
        private Process process;
        private int mainModuleAdd;

        private void walkRegionsFindBaseAddress()
        {
            // ASLR is active for OS X executables, so we can't assume things are in a known place.
            // Address of e.g. heap is randomized each time.
            // It seems the executables of more private stuff (e.g. actual exe) are in low bits of memory
            // (0x1000000(0?)+ or so), but then the malloc'd heap is at like 0x7fdd00000000+
            // and then all the upper shared libraries are at 0x7fff00000000+.
            //
            // So, we'll use mach_vm_region to discover memory regions for the process, and invoke
            //  GetBaseAddress() on each one in turn until we finally find the right one.
            // 

        }

		public void Open(string processName, int step = 1024)
		{
            foreach (Process proc in Process.GetProcesses()) {
                if (proc.ProcessName.Contains(processName))
                {
                    process = proc;
                    break;
                }
            }
            //process = Process.GetProcessesByName(processName)[0];

            Console.WriteLine("mach_host_self: " + mach_host_self());
            Console.WriteLine("mach_thread_self: " + mach_thread_self());
            Console.WriteLine("pid: " + process.Id);

            IntPtr RTLD_DEFAULT = new IntPtr(-2);
            IntPtr symMaybe = dlsym(RTLD_DEFAULT, "mach_task_self_");
            Console.WriteLine("mach_task_self_ dlsym:: " + symMaybe.ToString());

            uint mach_task_self_res = (uint)(Marshal.ReadInt32(symMaybe));

            Console.WriteLine("mach_task_self_res: " + mach_task_self_res);

            Console.WriteLine($"Proc!!: {process.PagedMemorySize64} {process.VirtualMemorySize64} {process.PeakVirtualMemorySize64} {process.WorkingSet64} {process.MainWindowTitle}");
            foreach (ProcessModule pm in process.Modules)
            {
                Console.WriteLine("Process.Module: " + pm.ModuleName + ", " + pm.BaseAddress);
                Console.WriteLine($"& {pm.EntryPointAddress} {pm.FileName} {pm.ModuleMemorySize} .. {pm.ToString()}");
            }

            var kr = task_for_pid(mach_task_self_res, process.Id, out taskH);
            if (kr != 0) {
                throw new Exception("Can't execute task_for_pid (" + kr + "); Check permissions/entitlements/root status");
            }

            Console.WriteLine("task_for_pid out task: " + taskH);



            // TODO baseAddress
            // baseAddress = ReadWritingMemory.GetBaseAddress(processName, step, 4);


            Attached = true;
		}

		public int WriteMemory(int offset, byte[] buffer, int bufferLength)
		{
            return WriteMemoryAbs((int)baseAddress + offset, buffer, bufferLength);
		}

		public int ReadMemory(int offset, byte[] buffer, int bufferLength)
		{
            return ReadMemoryAbs(baseAddress + (ulong)offset, buffer, (ulong)bufferLength);
		}

        public int WriteMemoryAbs(int address, byte[] buffer, int bufferLength)
        {
            return WriteMemoryAbs((ulong)address, buffer, (uint)bufferLength);
        }

        public int WriteMemoryAbs(ulong address, byte[] buffer, uint bufferLength)
        {
            // ?????
            /*
            // change protections, write, and restore original protection
			task_suspend(port);
			if ((kr = mach_vm_protect(port, opts->address, (mach_msg_type_number_t)opts->size, FALSE, VM_PROT_WRITE | VM_PROT_READ | VM_PROT_COPY)))
			{
				LOG_ERROR("mach_vm_protect failed with error %d.", kr);
				exit(1);
			}
            */

            int kr;
            fixed (byte* pBuf = buffer)
            {
                kr = mach_vm_write(taskH, address, (void*)pBuf, bufferLength);
            }
            if (kr != 0)
            {
                throw new Exception("mach_vm_write failed (" + kr + ")");
            }

            // ?????
            /*
            // restore original protection
			if ((kr = mach_vm_protect(port, opts->address, (mach_msg_type_number_t)opts->size, FALSE, info.protection)))
			{
				LOG_ERROR("mach_vm_protect failed with error %d.", kr);
				exit(1);
			}
            task_resume(port);
            */

            return (int)bufferLength; // oo-er
        }

        public int ReadMemoryAbs(int address, byte[] buffer, int bufferLength)
        {
            return ReadMemoryAbs((ulong)address, buffer, (ulong)bufferLength);
        }

		public int ReadMemoryAbs(ulong address, byte[] buffer, ulong bufferLength)
		{
            ulong nread = 0;
            int kr;
            fixed (byte* pBuf = buffer) {
                kr = mach_vm_read_overwrite(taskH, address, bufferLength, (void*)pBuf, out nread);
            }
            if (kr != 0) {
                throw new Exception("vm_read_failed (" + kr + ")");
            }
            return (int)nread;
		}

		public int GetModuleBaseAddress(string module)
		{
			throw new NotImplementedException();
		}

        public bool Attached { get; set; }

        public int BaseAddress => (int)baseAddress;

        public int MainModuleAddress => throw new NotImplementedException();

        public string WindowName => throw new NotImplementedException();
    }
}
