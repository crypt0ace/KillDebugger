using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using static KillDebugger.Imports;

namespace KillDebugger
{
    class Program
    {
        static void Main(string[] args)
        {
            uint ProcInfoLength = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));

            IntPtr processHandle = Process.GetCurrentProcess().Handle;

            IntPtr ProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));

            uint retLength = 0;

            NtQueryInformationProcess(processHandle, 0, ProcInfo, ProcInfoLength, ref retLength);

            PROCESS_BASIC_INFORMATION PBI = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(ProcInfo, typeof(PROCESS_BASIC_INFORMATION));
            IntPtr PBIPtr = PBI.PebBaseAddress;

            if (Marshal.ReadByte(PBIPtr + 2) == 1)
            {
                Console.WriteLine("Debugger is present.");
                Console.WriteLine("Attempting to remove the debugger...");
                /*Environment.ExitCode = 0;*/

                IntPtr debugHandle = IntPtr.Zero;
                uint outLen = 0;


                NtQueryInformationProcess(processHandle, (int)PROCESSINFOCLASS.ProcessDebugObjectHandle, ref debugHandle, 8, ref outLen);

                int removedbg = NtRemoveProcessDebug(processHandle, debugHandle);

                if (removedbg == 0)
                {
                    Console.WriteLine("Presence of debugger: {0}", IsDebuggerPresent());
                    Console.WriteLine("Successfully removed debugger");
                    Console.ReadKey();
                }
                else
                {
                    Console.WriteLine("Couldn't get rid of the debugger. Exiting.");
                    Console.ReadKey();
                    /*Environment.ExitCode = 0;*/
                }

            }
            else
            {
                Console.WriteLine("Debugger not present. Proceeding.");
            }
        }
    }

    class Imports
    {
        #region imports
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern bool IsDebuggerPresent();
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, IntPtr ProcessInformation, uint ProcessInformationLength, ref uint ReturnLength);
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, ref IntPtr ProcessInformation, uint ProcessInformationLength, ref uint ReturnLength);
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern int NtRemoveProcessDebug(IntPtr ProcessHandle, IntPtr DebugObjectHandle);
        #endregion

        #region struct
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public int BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }

        public enum PROCESSINFOCLASS
        {
            ProcessBasicInformation = 0x00,
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessExecuteFlags = 0x22,
            ProcessInstrumentationCallback = 0x28,
            MaxProcessInfoClass = 0x64
        }
        #endregion
    }
}
