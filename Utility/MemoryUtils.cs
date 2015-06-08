#region Directives
using System;
using System.Runtime.InteropServices;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    internal static class MemoryUtils
    {
        #region Constants
        private const int HEAP_ZERO_MEMORY = 0x00000008;
        #endregion

        #region API
        [System.Security.SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);

        [System.Security.SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

        [System.Security.SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcessHeap();

        [System.Security.SuppressUnmanagedCodeSecurity]
        [DllImport("Ntdll.dll", SetLastError = false)]
        static extern int RtlFillMemory([In]IntPtr Destination, uint length, byte fill);

        [System.Security.SuppressUnmanagedCodeSecurity]
        [DllImport("Ntdll.dll", SetLastError = true)]
        static extern void RtlZeroMemory(IntPtr Destination, uint length);

        [System.Security.SuppressUnmanagedCodeSecurity]
        [DllImport("Ntdll.dll", SetLastError = false)]
        static extern uint RtlCompareMemory(IntPtr Source1, IntPtr Source2, uint length);

        [System.Security.SuppressUnmanagedCodeSecurity]
        [DllImport("Ntdll.dll", SetLastError = true)]
        static extern void RtlCopyMemory(IntPtr Destination, IntPtr Source, int Length);

        [System.Security.SuppressUnmanagedCodeSecurity]
        [DllImport("Ntdll.dll", SetLastError = true)]
        static extern void RtlMoveMemory(IntPtr Destination, IntPtr Source, int Length);
        #endregion

        #region Public Methods
        /// <summary>
        /// Allocate heap memory
        /// </summary>
        /// 
        /// <param name="Size">size desired</param>
        /// 
        /// <returns>memory address</returns>
        public static IntPtr Alloc(uint Size)
        {
            return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
        }

        /// <summary>
        /// Compare two arrays for equality
        /// </summary>
        /// 
        /// <param name="X">The first array</param>
        /// <param name="Y">The second array</param>
        /// <param name="Length">The number of bytes to compare</param>
        /// 
        /// <returns>The number of bytes that match</returns>
        public static uint Compare(IntPtr X, IntPtr Y, int Length)
        {
            return RtlCompareMemory(X, Y, (uint)Length);
        }

        /// <summary>
        /// Copy a source array to a destination array
        /// </summary>
        /// 
        /// <param name="Destination">The pointer to the destination array</param>
        /// <param name="Source">The pointer to the source array</param>
        /// <param name="Length">The number of bytes to copy</param>
        public static void Copy(IntPtr Destination, IntPtr Source, int Length)
        {
            RtlCopyMemory(Destination, Source, Length);
        }

        /// <summary>
        /// Fill an array with a value
        /// </summary>
        /// 
        /// <param name="Destination">The pointer to the destination array</param>
        /// <param name="Length">The number of bytes to write</param>
        /// <param name="Value">The byte value</param>
        public static void Fill(IntPtr Destination, int Length, byte Value)
        {
            RtlFillMemory(Destination, (uint)Length, Value);
        }

        /// <summary>
        /// Release heap memory
        /// </summary>
        /// 
        /// <param name="Address">memory address</param>
        public static void Free(IntPtr Address)
        {
            HeapFree(GetProcessHeap(), 0, Address);
        }

        /// <summary>
        /// Get the pointer to the process heap
        /// </summary>
        /// 
        /// <returns>The process heap pointer</returns>
        public static IntPtr HeapAddress()
        {
            return GetProcessHeap();
        }

        /// <summary>
        /// Copy a source array to a destination array; supports overlapping memory blocks
        /// </summary>
        /// 
        /// <param name="Destination">The pointer to the destination array</param>
        /// <param name="Source">The pointer to the source array</param>
        /// <param name="Length">The number of bytes to copy</param>
        public static void Move(IntPtr Destination, IntPtr Source, int Length)
        {
            RtlMoveMemory(Destination, Source, Length);
        }

        /// <summary>
        /// Zero the bytes in an array
        /// </summary>
        /// <param name="Destination">The pointer to the destination array</param>
        /// <param name="Length">The number of bytes to write</param>
        public static void ZeroMemory(IntPtr Destination, int Length)
        {
            RtlZeroMemory(Destination, (uint)Length);
        }
        #endregion
    }
}
