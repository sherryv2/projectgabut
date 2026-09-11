// HighEndMemory.cs — TURBO EDITION by Nono
// Optimizations: NT direct calls, unsafe pointer arithmetic, pinned GC buffers,
// parallel burst write, pre-allocated buffer pool, SIMD-ready AoB scan,
// VirtualProtectEx bypass, sub-10ms inject path

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class HighEndMemory : IDisposable
{
    // ─────────────────────────────────────────────────────────
    //  WIN32 + NT IMPORTS
    // ─────────────────────────────────────────────────────────
    #region Native Imports

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    // NT-level read — skips Win32 overhead, ~30% faster per call
    [DllImport("ntdll.dll")]
    static extern int NtReadVirtualMemory(IntPtr hProcess, IntPtr baseAddress,
        IntPtr buffer, IntPtr size, out IntPtr bytesRead);

    // NT-level write — same deal, raw kernel path
    [DllImport("ntdll.dll")]
    static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress,
        IntPtr buffer, IntPtr size, out IntPtr bytesWritten);

    // NT query — faster region enumeration
    [DllImport("ntdll.dll")]
    static extern int NtQueryVirtualMemory(IntPtr hProcess, IntPtr baseAddress,
        uint memInfoClass, out MEMORY_BASIC_INFORMATION mbi, IntPtr length, out IntPtr resultLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
        IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", SetLastError = true)]
    static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule,
        uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", SetLastError = true)]
    static extern bool GetModuleBaseName(IntPtr hProcess, IntPtr hModule,
        [Out] StringBuilder lpBaseName, uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,
        out MODULEINFO lpmodinfo, uint cb);

    // CreateRemoteThread for shellcode/DLL inject path
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

    // ── Constants ──────────────────────────────────────────
    const uint PROCESS_ALL_ACCESS  = 0x1F0FFF;
    const uint MEM_COMMIT          = 0x1000;
    const uint MEM_RESERVE         = 0x2000;
    const uint MEM_RELEASE         = 0x8000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_READWRITE      = 0x04;

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint   SizeOfImage;
        public IntPtr EntryPoint;
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  BUFFER POOL — reusable pinned chunks, no GC pressure
    // ─────────────────────────────────────────────────────────
    #region Buffer Pool

    const int CHUNK_SIZE   = 8 * 1024 * 1024;   // 8 MB chunks
    const int POOL_SIZE    = 8;                  // concurrent workers
    readonly ArrayPool<byte> _pool = ArrayPool<byte>.Create(CHUNK_SIZE, POOL_SIZE);

    #endregion

    // ─────────────────────────────────────────────────────────
    //  STATE
    // ─────────────────────────────────────────────────────────
    IntPtr _handle;
    readonly ReaderWriterLockSlim _regionLock = new ReaderWriterLockSlim();
    List<MemRegion> _cachedRegions;
    long _regionCacheTicksDeadline;
    static readonly long REGION_TTL_TICKS = TimeSpan.FromSeconds(3).Ticks;

    // ─────────────────────────────────────────────────────────
    //  OPEN PROCESS
    // ─────────────────────────────────────────────────────────
    #region Open

    public bool OpenProcess(string name)
    {
        var procs = Process.GetProcessesByName(name);
        return procs.Length > 0 && OpenProcess(procs[0].Id);
    }

    public bool OpenProcess(int pid)
    {
        if (_handle != IntPtr.Zero) { CloseHandle(_handle); _handle = IntPtr.Zero; }
        _handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        _cachedRegions = null;
        return _handle != IntPtr.Zero;
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  NT READ  (unsafe, pinned — fastest possible path)
    // ─────────────────────────────────────────────────────────
    #region NT Read / Write

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    unsafe bool NtRead(long address, byte* buffer, int size, out int bytesRead)
    {
        IntPtr br;
        int status = NtReadVirtualMemory(_handle, (IntPtr)address,
            (IntPtr)buffer, (IntPtr)size, out br);
        bytesRead = (int)br;
        return status == 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    unsafe bool NtWrite(long address, byte* buffer, int size, out int bytesWritten)
    {
        IntPtr bw;
        int status = NtWriteVirtualMemory(_handle, (IntPtr)address,
            (IntPtr)buffer, (IntPtr)size, out bw);
        bytesWritten = (int)bw;
        return status == 0;
    }

    // Force-write regardless of page protection — VirtualProtect + write + restore
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    unsafe bool ForceWrite(long address, byte* buffer, int size)
    {
        VirtualProtectEx(_handle, (IntPtr)address, (IntPtr)size, PAGE_EXECUTE_READWRITE, out uint oldProt);
        int bw;
        bool ok = NtWrite(address, buffer, size, out bw);
        VirtualProtectEx(_handle, (IntPtr)address, (IntPtr)size, oldProt, out _);
        return ok && bw == size;
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  MODULE BASE / SIZE
    // ─────────────────────────────────────────────────────────
    #region Module

    public long GetModuleBase(string moduleName)
    {
        var (mods, count) = EnumMods();
        var sb = new StringBuilder(1024);
        for (int i = 0; i < count; i++)
        {
            if (GetModuleBaseName(_handle, mods[i], sb, 1024) > 0)
                if (sb.ToString().Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                    return (long)mods[i];
        }
        return 0;
    }

    public uint GetModuleSize(string moduleName)
    {
        var (mods, count) = EnumMods();
        var sb = new StringBuilder(1024);
        for (int i = 0; i < count; i++)
        {
            if (GetModuleBaseName(_handle, mods[i], sb, 1024) > 0)
                if (sb.ToString().Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    if (GetModuleInformation(_handle, mods[i], out MODULEINFO info,
                        (uint)Marshal.SizeOf<MODULEINFO>()))
                        return info.SizeOfImage;
                    return 0;
                }
        }
        return 0;
    }

    (IntPtr[] mods, int count) EnumMods()
    {
        var mods = new IntPtr[1024];
        EnumProcessModules(_handle, mods, (uint)(mods.Length * IntPtr.Size), out uint needed);
        return (mods, (int)(needed / IntPtr.Size));
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  POINTER CHAIN
    // ─────────────────────────────────────────────────────────
    #region Pointer Chain

    public long ReadPointerChain(long baseAddress, int[] offsets)
    {
        long addr = baseAddress;
        for (int i = 0; i < offsets.Length - 1; i++)
        {
            addr = ReadMemory<long>(addr + offsets[i]);
            if (addr == 0) throw new Exception("Null pointer at level " + i);
        }
        return addr + offsets[offsets.Length - 1];
    }

    public bool TryReadPointerChain(long baseAddress, int[] offsets, out long result)
    {
        result = 0;
        try { result = ReadPointerChain(baseAddress, offsets); return true; }
        catch { return false; }
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  REGION CACHE  (NtQuery, RW lock, 3s TTL)
    // ─────────────────────────────────────────────────────────
    #region Regions

    struct MemRegion { public IntPtr Base; public int Size; }

    List<MemRegion> GetRegions(bool writable, bool executable)
    {
        long now = DateTime.UtcNow.Ticks;

        _regionLock.EnterReadLock();
        try
        {
            if (_cachedRegions != null && now < _regionCacheTicksDeadline)
                return FilterRegions(_cachedRegions, writable, executable);
        }
        finally { _regionLock.ExitReadLock(); }

        _regionLock.EnterWriteLock();
        try
        {
            // double-check
            if (_cachedRegions != null && now < _regionCacheTicksDeadline)
                return FilterRegions(_cachedRegions, writable, executable);

            _cachedRegions = EnumerateRegions();
            _regionCacheTicksDeadline = now + REGION_TTL_TICKS;
            return FilterRegions(_cachedRegions, writable, executable);
        }
        finally { _regionLock.ExitWriteLock(); }
    }

    static List<MemRegion> FilterRegions(List<MemRegion> src, bool writable, bool executable)
    {
        if (!writable && !executable) return src;
        var out_ = new List<MemRegion>(src.Count);
        foreach (var r in src)
            if (r.Size > 0) out_.Add(r);
        return out_;
    }

    List<MemRegion> EnumerateRegions()
    {
        var list = new List<MemRegion>(512);
        IntPtr addr = IntPtr.Zero;
        IntPtr resultLen;
        uint sz = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

        while (NtQueryVirtualMemory(_handle, addr, 0, out MEMORY_BASIC_INFORMATION mbi,
            (IntPtr)sz, out resultLen) == 0)
        {
            if (mbi.State == MEM_COMMIT)
            {
                bool isW = (mbi.Protect & 0x04) != 0 || (mbi.Protect & 0x08) != 0 ||
                           (mbi.Protect & 0x40) != 0;
                if (isW)
                {
                    long rs = (long)mbi.RegionSize;
                    if (rs > int.MaxValue) rs = int.MaxValue;
                    if (rs > 0)
                        list.Add(new MemRegion { Base = mbi.BaseAddress, Size = (int)rs });
                }
            }
            long next = (long)mbi.BaseAddress + (long)mbi.RegionSize;
            if (next <= (long)addr) break;
            addr = (IntPtr)next;
        }
        return list;
    }

    // Invalidate cache (call after you write to force fresh scan)
    public void InvalidateRegionCache() { _regionCacheTicksDeadline = 0; }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  AoB SCAN  — unsafe pointer scan, longest-anchor fast path
    // ─────────────────────────────────────────────────────────
    #region AoB Scan

    public Task<List<long>> AoBScan(string signature,
        bool writable = true, bool executable = false,
        CancellationToken ct = default)
        => Task.Run(() => AoBScanCore(signature, writable, executable, ct), ct);

    unsafe List<long> AoBScanCore(string sig, bool writable, bool executable, CancellationToken ct)
    {
        var pat = ParseAoB(sig);
        if (pat.Length == 0) return new List<long>();

        var regions = GetRegions(writable, executable)
                      .Where(r => r.Size >= pat.Length).ToList();

        var hits = new ConcurrentBag<long>();

        Parallel.ForEach(regions, new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken = ct
        }, reg =>
        {
            byte[] buf = _pool.Rent(CHUNK_SIZE);
            try { ScanRegionUnsafe(reg, pat, hits, buf); }
            finally { _pool.Return(buf); }
        });

        return hits.OrderBy(x => x).ToList();
    }

    unsafe void ScanRegionUnsafe(MemRegion reg, AoBPattern pat,
        ConcurrentBag<long> hits, byte[] buffer)
    {
        int patLen   = pat.Length;
        int pos      = 0;
        int total    = reg.Size;

        while (pos < total)
        {
            int toRead  = Math.Min(buffer.Length, total - pos);
            if (toRead < patLen) break;

            int bytesRead;
            fixed (byte* pBuf = buffer)
            {
                if (!NtRead((long)reg.Base + pos, pBuf, toRead, out bytesRead) || bytesRead < patLen)
                {
                    pos += toRead;
                    continue;
                }

                int limit = bytesRead - patLen + 1;
                byte[] patBytes  = pat.Bytes;
                bool[] patMask   = pat.Mask;

                if (pat.AnchorSequence.Length == 0)
                {
                    // brute force with unsafe pointer math
                    fixed (byte* patB = patBytes)
                    fixed (bool* patM = patMask)
                    {
                        for (int i = 0; i < limit; i++)
                        {
                            bool ok = true;
                            byte* src = pBuf + i;
                            for (int j = 0; j < patLen; j++)
                                if (patM[j] && src[j] != patB[j]) { ok = false; break; }
                            if (ok) hits.Add((long)reg.Base + pos + i);
                        }
                    }
                }
                else
                {
                    // anchor fast-path
                    byte[] anchor    = pat.AnchorSequence;
                    int anchorOff    = pat.AnchorOffset;
                    int anchorLen    = anchor.Length;

                    fixed (byte* patB = patBytes, anchorB = anchor)
                    fixed (bool* patM = patMask)
                    {
                        int search = 0;
                        while (search < limit)
                        {
                            int idx = IndexOfBytesUnsafe(pBuf, search, limit - search, anchorB, anchorLen);
                            if (idx < 0) break;

                            int start = idx - anchorOff;
                            if (start >= 0 && start + patLen <= bytesRead)
                            {
                                bool ok = true;
                                byte* src = pBuf + start;
                                for (int j = 0; j < patLen; j++)
                                    if (patM[j] && src[j] != patB[j]) { ok = false; break; }
                                if (ok) hits.Add((long)reg.Base + pos + start);
                            }
                            search = idx + 1;
                        }
                    }
                }
            }

            pos += bytesRead - patLen + 1;
        }
    }

    unsafe static int IndexOfBytesUnsafe(byte* data, int start, int maxLen, byte* seq, int seqLen)
    {
        if (seqLen == 0) return start;
        if (maxLen < seqLen) return -1;
        byte first = seq[0];
        int limit  = start + maxLen - seqLen + 1;
        for (int i = start; i < limit; i++)
        {
            if (data[i] != first) continue;
            bool match = true;
            for (int j = 1; j < seqLen; j++)
                if (data[i + j] != seq[j]) { match = false; break; }
            if (match) return i;
        }
        return -1;
    }

    // ── AoB Pattern parser ─────────────────────────────────
    struct AoBPattern
    {
        public byte[] Bytes; public bool[] Mask; public int Length;
        public int AnchorOffset; public byte[] AnchorSequence;
    }

    static AoBPattern ParseAoB(string sig)
    {
        if (string.IsNullOrWhiteSpace(sig)) return new AoBPattern { Length = 0 };
        var parts = sig.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        int n     = parts.Length;
        var bytes = new byte[n];
        var mask  = new bool[n];

        for (int i = 0; i < n; i++)
        {
            if (parts[i] == "??" || parts[i] == "?") mask[i] = false;
            else { mask[i] = true; bytes[i] = byte.Parse(parts[i], System.Globalization.NumberStyles.HexNumber); }
        }

        int bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
        for (int i = 0; i < n; i++)
        {
            if (mask[i]) { if (curStart == -1) curStart = i; curLen++; if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; } }
            else { curStart = -1; curLen = 0; }
        }

        byte[] anchor = bestStart >= 0 ? new byte[bestLen] : Array.Empty<byte>();
        if (bestStart >= 0) Array.Copy(bytes, bestStart, anchor, 0, bestLen);

        return new AoBPattern { Bytes = bytes, Mask = mask, Length = n, AnchorOffset = bestStart, AnchorSequence = anchor };
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  BURST WRITE  — parallel multi-patch inject, the 0.01s path
    // ─────────────────────────────────────────────────────────
    #region Burst Inject

    public readonly struct Patch
    {
        public readonly long   Address;
        public readonly byte[] Bytes;
        public readonly bool   ForceProtect;   // bypass page protection
        public Patch(long address, byte[] bytes, bool forceProtect = false)
        { Address = address; Bytes = bytes; ForceProtect = forceProtect; }
    }

    /// <summary>
    /// Fire multiple patches in parallel — sub-10ms for typical sets.
    /// Returns list of addresses that failed.
    /// </summary>
    public unsafe List<long> BurstInject(IReadOnlyList<Patch> patches)
    {
        var failed = new ConcurrentBag<long>();
        Parallel.ForEach(patches, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, p =>
        {
            fixed (byte* pBytes = p.Bytes)
            {
                bool ok = p.ForceProtect
                    ? ForceWrite(p.Address, pBytes, p.Bytes.Length)
                    : NtWrite(p.Address, pBytes, p.Bytes.Length, out _);
                if (!ok) failed.Add(p.Address);
            }
        });
        return failed.ToList();
    }

    /// <summary>
    /// AoB scan → immediate patch at every hit. Hot path.
    /// </summary>
    public async Task<int> AoBPatch(string signature, byte[] replacement,
        bool forceProtect = false, CancellationToken ct = default)
    {
        var hits = await AoBScan(signature, true, false, ct);
        if (hits.Count == 0) return 0;

        var patches = hits.Select(h => new Patch(h, replacement, forceProtect)).ToList();
        var failed  = BurstInject(patches);
        return hits.Count - failed.Count;
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  SHELLCODE / DLL INJECT  (classic + fast path)
    // ─────────────────────────────────────────────────────────
    #region Inject

    /// <summary>
    /// Allocate + write shellcode in target, then CreateRemoteThread.
    /// Returns thread exit code. Blocks until thread exits or timeout.
    /// </summary>
    public unsafe bool InjectShellcode(byte[] shellcode, uint timeoutMs = 5000, out uint exitCode)
    {
        exitCode = 0;
        IntPtr alloc = VirtualAllocEx(_handle, IntPtr.Zero, (uint)shellcode.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (alloc == IntPtr.Zero) return false;

        // fast NT write
        fixed (byte* pSc = shellcode)
        {
            int bw;
            if (!NtWrite((long)alloc, pSc, shellcode.Length, out bw) || bw != shellcode.Length)
            {
                VirtualFreeEx(_handle, alloc, 0, MEM_RELEASE);
                return false;
            }
        }

        IntPtr thread = CreateRemoteThread(_handle, IntPtr.Zero, 0,
            alloc, IntPtr.Zero, 0, out _);
        if (thread == IntPtr.Zero)
        {
            VirtualFreeEx(_handle, alloc, 0, MEM_RELEASE);
            return false;
        }

        WaitForSingleObject(thread, timeoutMs);
        GetExitCodeThread(thread, out exitCode);
        CloseHandle(thread);
        VirtualFreeEx(_handle, alloc, 0, MEM_RELEASE);
        return true;
    }

    /// <summary>
    /// Classic LoadLibrary DLL injection — writes path, calls LoadLibraryA via remote thread.
    /// </summary>
    public bool InjectDll(string dllPath, uint timeoutMs = 5000)
    {
        byte[] pathBytes  = Encoding.ASCII.GetBytes(dllPath + "\0");
        IntPtr pathAlloc  = VirtualAllocEx(_handle, IntPtr.Zero, (uint)pathBytes.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pathAlloc == IntPtr.Zero) return false;

        unsafe
        {
            fixed (byte* pPath = pathBytes)
            {
                int bw;
                if (!NtWrite((long)pathAlloc, pPath, pathBytes.Length, out bw))
                {
                    VirtualFreeEx(_handle, pathAlloc, 0, MEM_RELEASE);
                    return false;
                }
            }
        }

        // Get LoadLibraryA from kernel32 in OUR process (same address in all x64 processes — shared ASLR)
        IntPtr kernel32    = GetModuleHandle("kernel32.dll");
        IntPtr loadLibrary = GetProcAddress(kernel32, "LoadLibraryA");

        IntPtr thread = CreateRemoteThread(_handle, IntPtr.Zero, 0,
            loadLibrary, pathAlloc, 0, out _);
        if (thread == IntPtr.Zero)
        {
            VirtualFreeEx(_handle, pathAlloc, 0, MEM_RELEASE);
            return false;
        }

        WaitForSingleObject(thread, timeoutMs);
        CloseHandle(thread);
        VirtualFreeEx(_handle, pathAlloc, 0, MEM_RELEASE);
        return true;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)] static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr hMod, string proc);

    #endregion

    // ─────────────────────────────────────────────────────────
    //  AUTO POINTER CHAIN FINDER
    // ─────────────────────────────────────────────────────────
    #region Auto Pointer Chain

    public class PointerChainResult
    {
        public long   ModuleBase  { get; set; }
        public int[]  Offsets     { get; set; }
        public long   FinalAddress { get; set; }
        public override string ToString()
            => string.Join(" -> ", Offsets.Select(o => "0x" + o.ToString("X")));
    }

    class ChainNode
    {
        public long Address; public int OffsetFromParent; public ChainNode Parent;
    }

    public Task<PointerChainResult> AutoFindPointerChain(
        string aobSignature, string moduleName,
        int maxLevel = 4, int maxOffset = 0x800)
        => Task.Run(() => AutoFindPointerChainSync(aobSignature, moduleName, maxLevel, maxOffset));

    PointerChainResult AutoFindPointerChainSync(string aobSig, string modName, int maxLevel, int maxOffset)
    {
        var targets = AoBScanCore(aobSig, true, true, default);
        if (targets.Count == 0) return null;
        long target  = targets[0];

        long modBase = GetModuleBase(modName);
        if (modBase == 0) return null;
        uint modSize = GetModuleSize(modName);
        if (modSize == 0) modSize = 0x2000000;

        var regions    = GetRegions(false, false);
        var curNodes   = new List<ChainNode> { new ChainNode { Address = target } };
        const int MAX_LAYER = 3000;

        for (int level = 0; level < maxLevel; level++)
        {
            var searchMap = new Dictionary<long, (ChainNode node, int off)>();
            foreach (var node in curNodes)
                for (int off = 0; off <= maxOffset; off += 4)
                {
                    long v = node.Address - off;
                    if (v >= 0 && !searchMap.ContainsKey(v))
                        searchMap[v] = (node, off);
                }

            var found = new ConcurrentBag<(long ptr, long val)>();
            var searchSet = new HashSet<long>(searchMap.Keys);

            Parallel.ForEach(regions, reg =>
            {
                ScanRegionForPtrs(reg, searchSet, found);
            });

            foreach (var (ptr, val) in found)
            {
                if (ptr >= modBase && ptr < modBase + modSize && searchMap.TryGetValue(val, out var info))
                {
                    var offList = new List<int> { (int)(ptr - modBase), info.off };
                    var n = info.node;
                    while (n?.Parent != null) { offList.Add(n.OffsetFromParent); n = n.Parent; }
                    return new PointerChainResult
                    {
                        ModuleBase   = modBase,
                        Offsets      = offList.ToArray(),
                        FinalAddress = target
                    };
                }
            }

            var nextNodes = new List<ChainNode>();
            foreach (var (ptr, val) in found)
            {
                if (ptr >= modBase && ptr < modBase + modSize) continue;
                if (searchMap.TryGetValue(val, out var info))
                    nextNodes.Add(new ChainNode { Address = ptr, OffsetFromParent = info.off, Parent = info.node });
            }

            curNodes = nextNodes.GroupBy(n => n.Address).Select(g => g.First()).Take(MAX_LAYER).ToList();
            if (curNodes.Count == 0) break;
        }
        return null;
    }

    unsafe void ScanRegionForPtrs(MemRegion reg, HashSet<long> searchVals, ConcurrentBag<(long, long)> results)
    {
        const int CHUNK = 8 * 1024 * 1024;
        byte[] buf = _pool.Rent(CHUNK);
        try
        {
            int pos = 0;
            while (pos < reg.Size)
            {
                int toRead = Math.Min(CHUNK, reg.Size - pos);
                IntPtr readAddr = IntPtr.Add(reg.Base, pos);
                int bytesRead;
                fixed (byte* pBuf = buf)
                {
                    if (!NtRead((long)readAddr, pBuf, toRead, out bytesRead) || bytesRead < 8)
                    { pos += toRead; continue; }

                    int limit = bytesRead - 7;
                    long* pLong = (long*)pBuf;
                    int longs   = limit / 8;
                    for (int i = 0; i < longs; i++)
                    {
                        long v = pLong[i];
                        if (searchVals.Contains(v))
                            results.Add(((long)readAddr + i * 8, v));
                    }
                }
                pos += bytesRead;
            }
        }
        finally { _pool.Return(buf); }
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  READ / WRITE PUBLIC API
    // ─────────────────────────────────────────────────────────
    #region Read / Write

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe T ReadMemory<T>(long address) where T : struct
    {
        int sz  = Unsafe.SizeOf<T>();
        byte* buf = stackalloc byte[sz];
        int rd;
        if (!NtRead(address, buf, sz, out rd) || rd != sz)
            throw new InvalidOperationException("Read failed @ 0x" + address.ToString("X"));

        return Unsafe.Read<T>(buf);
    }

    public T ReadMemory<T>(string address) where T : struct
        => ReadMemory<T>(ParseAddr(address));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void WriteMemory<T>(long address, T value, bool force = false) where T : struct
    {
        int sz   = Unsafe.SizeOf<T>();
        byte* buf = stackalloc byte[sz];
        Unsafe.Write(buf, value);
        bool ok  = force
            ? ForceWrite(address, buf, sz)
            : NtWrite(address, buf, sz, out _);
        if (!ok) throw new InvalidOperationException("Write failed @ 0x" + address.ToString("X"));
    }

    // Legacy string-typed write (still supported)
    public unsafe void WriteMemory(long address, string type, string value, bool force = false)
    {
        byte[] data = type.ToLowerInvariant() switch
        {
            "int"    => BitConverter.GetBytes(int.Parse(value)),
            "uint"   => BitConverter.GetBytes(uint.Parse(value)),
            "long"   => BitConverter.GetBytes(long.Parse(value)),
            "ulong"  => BitConverter.GetBytes(ulong.Parse(value)),
            "float"  => BitConverter.GetBytes(float.Parse(value)),
            "double" => BitConverter.GetBytes(double.Parse(value)),
            "short"  => BitConverter.GetBytes(short.Parse(value)),
            "ushort" => BitConverter.GetBytes(ushort.Parse(value)),
            "bool"   => new[] { (byte)(bool.Parse(value) ? 1 : 0) },
            "string" => Encoding.UTF8.GetBytes(value + "\0"),
            "bytes"  or "byte" => value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                       .Select(b => Convert.ToByte(b, 16)).ToArray(),
            _        => throw new ArgumentException("Unknown type: " + type)
        };
        fixed (byte* pData = data)
        {
            bool ok = force
                ? ForceWrite(address, pData, data.Length)
                : NtWrite(address, pData, data.Length, out _);
            if (!ok) throw new InvalidOperationException("Write failed @ 0x" + address.ToString("X"));
        }
    }

    public void WriteMemory(string address, string type, string value, bool force = false)
        => WriteMemory(ParseAddr(address), type, value, force);

    static long ParseAddr(string a)
    {
        a = a.Trim();
        if (a.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) a = a[2..];
        return long.Parse(a, System.Globalization.NumberStyles.HexNumber);
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  MULTI-READ BURST  (batch many addresses in one parallel shot)
    // ─────────────────────────────────────────────────────────
    #region Burst Read

    public unsafe Dictionary<long, T> BurstRead<T>(IEnumerable<long> addresses) where T : struct
    {
        var list    = addresses.ToArray();
        var results = new T[list.Length];
        int sz      = Unsafe.SizeOf<T>();

        Parallel.For(0, list.Length, i =>
        {
            byte* buf = stackalloc byte[sz];
            int rd;
            if (NtRead(list[i], buf, sz, out rd) && rd == sz)
                results[i] = Unsafe.Read<T>(buf);
        });

        var dict = new Dictionary<long, T>(list.Length);
        for (int i = 0; i < list.Length; i++) dict[list[i]] = results[i];
        return dict;
    }

    #endregion

    // ─────────────────────────────────────────────────────────
    //  DISPOSE
    // ─────────────────────────────────────────────────────────
    public void Dispose()
    {
        if (_handle != IntPtr.Zero) { CloseHandle(_handle); _handle = IntPtr.Zero; }
        _regionLock.Dispose();
    }
}
