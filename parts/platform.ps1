Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

public static class BinaryPatternScanner {
    public static List<long> Find(byte[] data, int[] pattern, long start, long length) {
        var result = new List<long>();
        if (pattern == null || pattern.Length == 0 || length < pattern.Length)
            return result;

        long end = Math.Min((long)data.Length, start + length) - pattern.Length;
        int anchor = 0;
        while (anchor < pattern.Length && pattern[anchor] < 0)
            anchor++;
        if (anchor == pattern.Length)
            throw new ArgumentException("A pattern cannot consist entirely of wildcards.");

        byte anchorByte = (byte)pattern[anchor];
        for (long pos = start; pos <= end; pos++) {
            if (data[pos + anchor] != anchorByte)
                continue;
            bool matched = true;
            for (int i = 0; i < pattern.Length; i++) {
                if (pattern[i] >= 0 && data[pos + i] != (byte)pattern[i]) {
                    matched = false;
                    break;
                }
            }
            if (matched)
                result.Add(pos);
        }
        return result;
    }

    public static List<long> FindMasked(
        byte[] data, byte[] values, byte[] masks, long start, long length) {
        var result = new List<long>();
        if (values == null || masks == null || values.Length == 0 ||
            values.Length != masks.Length || length < values.Length)
            return result;

        var anchor = 0;
        while (anchor < masks.Length && masks[anchor] == 0)
            anchor++;
        if (anchor == masks.Length)
            throw new ArgumentException("A masked pattern cannot be entirely unconstrained.");

        long end = Math.Min((long)data.Length, start + length) - values.Length;
        for (long pos = start; pos <= end; pos++) {
            if ((data[pos + anchor] & masks[anchor]) != values[anchor])
                continue;
            var matched = true;
            for (var i = 0; i < values.Length; i++) {
                if ((data[pos + i] & masks[i]) != values[i]) {
                    matched = false;
                    break;
                }
            }
            if (matched)
                result.Add(pos);
        }
        return result;
    }
}

public static class Mv2FileIdentity {
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfo {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh;
        public uint WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle, out FileInfo info);
    public static uint Links(FileStream stream) { return Read(stream).Links; }
    public static string Id(FileStream stream) {
        var info = Read(stream);
        return info.Volume.ToString("X8") + ":" + info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8");
    }
    private static FileInfo Read(FileStream stream) {
        FileInfo info;
        if (!GetFileInformationByHandle(stream.SafeFileHandle, out info))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect the DLL file identity.");
        if (info.Links == 0 || (info.Attributes & 0x410) != 0)
            throw new IOException("The DLL must be an ordinary file, not a directory or reparse point.");
        return info;
    }
}

public sealed class RamPatchResult {
    public int ProcessId { get; set; }
    public string ModulePath { get; set; }
    public int PatchCount { get; set; }
}

public static class RamPatchLauncher {
    private const uint DebugOnlyThisProcess = 0x00000002;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExceptionDebugEvent = 1;
    private const uint CreateProcessDebugEvent = 3;
    private const uint ExitProcessDebugEvent = 5;
    private const uint LoadDllDebugEvent = 6;
    private const uint DbgContinue = 0x00010002;
    private const uint DbgExceptionNotHandled = 0x80010001;
    private const uint ExceptionBreakpoint = 0x80000003;
    private const uint PageExecuteReadWrite = 0x40;
    private const int ErrorSemTimeout = 121;
    private const int DebugEventSizeX64 = 176;
    private const int DebugInfoOffsetX64 = 16;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string applicationName, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
        IntPtr environment, string currentDirectory, ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WaitForDebugEventEx(IntPtr debugEvent, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ContinueDebugEvent(int processId, int threadId, uint continueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugSetProcessKillOnExit(bool killOnExit);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugActiveProcessStop(int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr process, IntPtr address, [Out] byte[] buffer, UIntPtr size,
        out UIntPtr bytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr process, IntPtr address, byte[] buffer, UIntPtr size,
        out UIntPtr bytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(
        IntPtr process, IntPtr address, UIntPtr size, uint newProtection,
        out uint oldProtection);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FlushInstructionCache(
        IntPtr process, IntPtr address, UIntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        IntPtr file, StringBuilder path, uint characterCount, uint flags);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argumentCount);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static string[] ParseArguments(string commandLine) {
        if (String.IsNullOrWhiteSpace(commandLine))
            return new string[0];
        if (commandLine.IndexOf('\0') >= 0)
            throw new ArgumentException("Browser arguments must not contain NUL characters.");

        int argumentCount;
        var pointer = CommandLineToArgvW(Quote("chrome.exe") + " " + commandLine,
            out argumentCount);
        if (pointer == IntPtr.Zero)
            throw Error("Could not parse the browser command line");
        try {
            var arguments = new string[Math.Max(0, argumentCount - 1)];
            for (var i = 1; i < argumentCount; i++) {
                var argument = Marshal.ReadIntPtr(pointer, i * IntPtr.Size);
                arguments[i - 1] = Marshal.PtrToStringUni(argument);
            }
            return arguments;
        } finally {
            LocalFree(pointer);
        }
    }

    public static RamPatchResult Launch(
        string chromePath, string dllPath, long[] patchRvas,
        byte[][] expectedBytes, byte[][] replacementBytes,
        string chromeArguments, int timeoutSeconds) {
        if (IntPtr.Size != 8)
            throw new PlatformNotSupportedException("RAM launch supports only x64 Windows.");
        if (patchRvas == null || expectedBytes == null || replacementBytes == null ||
            patchRvas.Length == 0 || patchRvas.Length != expectedBytes.Length ||
            patchRvas.Length != replacementBytes.Length)
            throw new ArgumentException("The RAM patch plan is empty or inconsistent.");

        var startup = new StartupInfo();
        startup.cb = Marshal.SizeOf(typeof(StartupInfo));
        ProcessInformation process;
        var commandLine = new StringBuilder(Quote(chromePath));
        if (chromeArguments != null && chromeArguments.IndexOf('\0') >= 0)
            throw new ArgumentException("Browser arguments must not contain NUL characters.");
        if (!String.IsNullOrWhiteSpace(chromeArguments))
            commandLine.Append(' ').Append(chromeArguments);
        if (!CreateProcessW(chromePath, commandLine, IntPtr.Zero, IntPtr.Zero, false,
            DebugOnlyThisProcess | CreateUnicodeEnvironment, IntPtr.Zero,
            Path.GetDirectoryName(chromePath), ref startup, out process))
            throw Error("Could not start the Chromium browser for RAM patching");

        var detached = false;
        var debugEvent = Marshal.AllocHGlobal(DebugEventSizeX64);
        try {
            if (!DebugSetProcessKillOnExit(false))
                throw Error("Could not configure the browser debug session");
            var timer = Stopwatch.StartNew();
            while (timer.Elapsed < TimeSpan.FromSeconds(timeoutSeconds)) {
                ZeroMemory(debugEvent, DebugEventSizeX64);
                if (!WaitForDebugEventEx(debugEvent, 500)) {
                    var error = Marshal.GetLastWin32Error();
                    if (error == ErrorSemTimeout)
                        continue;
                    throw new Win32Exception(error, "WaitForDebugEventEx failed");
                }

                var eventCode = unchecked((uint)Marshal.ReadInt32(debugEvent, 0));
                var eventProcessId = Marshal.ReadInt32(debugEvent, 4);
                var eventThreadId = Marshal.ReadInt32(debugEvent, 8);
                var continueStatus = DbgContinue;
                if (eventCode == ExceptionDebugEvent &&
                    unchecked((uint)Marshal.ReadInt32(debugEvent, DebugInfoOffsetX64)) != ExceptionBreakpoint)
                    continueStatus = DbgExceptionNotHandled;

                IntPtr eventFile = IntPtr.Zero;
                RamPatchResult result = null;
                try {
                    if (eventCode == CreateProcessDebugEvent || eventCode == LoadDllDebugEvent)
                        eventFile = Marshal.ReadIntPtr(debugEvent, DebugInfoOffsetX64);
                    if (eventCode == LoadDllDebugEvent) {
                        var modulePath = GetPath(eventFile);
                        if (modulePath != null && PathsEqual(modulePath, dllPath)) {
                            var moduleBase = Marshal.ReadIntPtr(debugEvent, DebugInfoOffsetX64 + IntPtr.Size);
                            Patch(process.hProcess, moduleBase, patchRvas, expectedBytes, replacementBytes);
                            result = new RamPatchResult {
                                ProcessId = process.dwProcessId,
                                ModulePath = modulePath,
                                PatchCount = patchRvas.Length
                            };
                        }
                    } else if (eventCode == ExitProcessDebugEvent) {
                        throw new InvalidOperationException("The browser exited before the target DLL could be RAM-patched.");
                    }
                } finally {
                    if (eventFile != IntPtr.Zero && eventFile != new IntPtr(-1))
                        CloseHandle(eventFile);
                    if (!ContinueDebugEvent(eventProcessId, eventThreadId, continueStatus))
                        throw Error("ContinueDebugEvent failed");
                }

                if (result != null) {
                    if (!DebugActiveProcessStop(process.dwProcessId))
                        throw Error("Could not detach the RAM patcher from the browser");
                    detached = true;
                    return result;
                }
            }
            throw new TimeoutException("Timed out waiting for the browser to load the target DLL.");
        } catch {
            if (!detached)
                TerminateProcess(process.hProcess, 0x4D5632);
            throw;
        } finally {
            Marshal.FreeHGlobal(debugEvent);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    }

    private static void Patch(IntPtr process, IntPtr moduleBase, long[] rvas,
        byte[][] expected, byte[][] replacements) {
        var addresses = new IntPtr[rvas.Length];
        for (var i = 0; i < rvas.Length; i++) {
            if (expected[i] == null || replacements[i] == null ||
                expected[i].Length == 0 || expected[i].Length != replacements[i].Length)
                throw new ArgumentException("A RAM patch edit has invalid byte lengths.");
            addresses[i] = new IntPtr(checked(moduleBase.ToInt64() + rvas[i]));
            var observed = Read(process, addresses[i], expected[i].Length);
            if (!StructuralComparisons.StructuralEqualityComparer.Equals(observed, expected[i]))
                throw new InvalidOperationException("Browser memory did not match the verified on-disk patch plan.");
        }

        for (var i = 0; i < addresses.Length; i++) {
            for (var j = 0; j < replacements[i].Length; j++) {
                if (expected[i][j] == replacements[i][j])
                    continue;
                var address = new IntPtr(checked(addresses[i].ToInt64() + j));
                var replacement = new byte[] { replacements[i][j] };
                var size = new UIntPtr(1);
                uint oldProtection;
                if (!VirtualProtectEx(process, address, size, PageExecuteReadWrite, out oldProtection))
                    throw Error("VirtualProtectEx failed at an MV2 target");
                try {
                    UIntPtr written;
                    if (!WriteProcessMemory(process, address, replacement, size, out written) ||
                        written.ToUInt64() != 1)
                        throw Error("WriteProcessMemory failed at an MV2 target");
                    var verified = Read(process, address, 1);
                    if (verified[0] != replacement[0])
                        throw new InvalidOperationException("RAM patch read-back verification failed.");
                    if (!FlushInstructionCache(process, address, size))
                        throw Error("FlushInstructionCache failed");
                } finally {
                    uint ignored;
                    VirtualProtectEx(process, address, size, oldProtection, out ignored);
                }
            }
        }
    }

    private static byte[] Read(IntPtr process, IntPtr address, int count) {
        var bytes = new byte[count];
        UIntPtr read;
        if (!ReadProcessMemory(process, address, bytes, new UIntPtr(unchecked((uint)count)), out read) ||
            read.ToUInt64() != unchecked((ulong)count))
            throw Error("ReadProcessMemory failed at an MV2 target");
        return bytes;
    }

    private static string GetPath(IntPtr file) {
        if (file == IntPtr.Zero || file == new IntPtr(-1))
            return null;
        var path = new StringBuilder(1024);
        var length = GetFinalPathNameByHandleW(file, path, unchecked((uint)path.Capacity), 0);
        if (length == 0)
            return null;
        if (length >= path.Capacity) {
            path.EnsureCapacity(checked((int)length + 1));
            length = GetFinalPathNameByHandleW(file, path, unchecked((uint)path.Capacity), 0);
            if (length == 0)
                return null;
        }
        return Normalize(path.ToString());
    }

    private static bool PathsEqual(string left, string right) {
        return string.Equals(Normalize(left), Normalize(right), StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string path) {
        const string prefix = "\\\\?\\";
        if (path.StartsWith(prefix, StringComparison.Ordinal))
            path = path.Substring(prefix.Length);
        return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
    }

    private static string Quote(string value) {
        var result = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in value) {
            if (character == '\\') {
                backslashes++;
            } else if (character == '"') {
                result.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
            } else {
                result.Append('\\', backslashes).Append(character);
                backslashes = 0;
            }
        }
        result.Append('\\', backslashes * 2).Append('"');
        return result.ToString();
    }

    private static void ZeroMemory(IntPtr address, int count) {
        for (var i = 0; i < count; i++)
            Marshal.WriteByte(address, i, 0);
    }

    private static Win32Exception Error(string message) {
        return new Win32Exception(Marshal.GetLastWin32Error(), message);
    }
}
'@
if (-not ('Mv2SmallScan' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class Mv2SmallScan {
    static int Immediate(byte[] b, int p, int end) {
        if (p+8 >= end || b[p] != 0x83 || (b[p+1]&0x38) != 0x38) return -1;
        int mod=b[p+1]>>6, rm=b[p+1]&7, q=p+2;
        if(mod!=3 && rm==4) { int sib=b[q++]; if(mod==0 && (sib&7)==5) q+=4; }
        if(mod==0 && rm==5) q+=4;
        if(mod==1) q++; else if(mod==2) q+=4;
        return q;
    }
    // Same conservative byte prefilter as V4, with sparse searches and early success.
    public static long[] Seeds(byte[] b, int start, int length) {
        var hits=new List<long>(); int end=checked(start+length), p=start;
        while(p<end-264) {
            p=Array.IndexOf(b,(byte)0x83,p,end-264-p); if(p<0) break;
            int q=Immediate(b,p,end);
            if(q>=0 && b[q]==2) {
                int bits=0; bool typeMask=false;
                for(int k=q+1;k<q+257;k++) {
                    if(k+3<end && b[k]==10 && b[k+1]==1 && b[k+2]==0 && b[k+3]==0) typeMask=true; int v=Immediate(b,k,end); if(v<0) continue;
                    if(b[v]==1) bits|=1; else if(b[v]==5) bits|=2; else if(b[v]==10) bits|=4;
                    if(bits==7 || (bits==6 && typeMask)) break;
                }
                if(bits==7 || (bits==6 && typeMask)) {
                    int seed=p;
                    if(p>start && b[p-1]>=0x40 && b[p-1]<=0x4f) seed--;
                    if(seed>=2 && b[seed-2]==0x31 && b[seed-1]==0xc0) seed-=2; hits.Add(seed);
                    if(hits.Count>64) throw new InvalidOperationException("Broad candidate budget exceeded");
                }
            }
            p++;
        }
        return hits.ToArray();
    }
    public static long[] Masked(byte[] b, byte[] values, byte[] masks, int length) {
        if(values.Length==0 || values.Length!=masks.Length || length>b.Length) throw new ArgumentException("Pattern/buffer shape");
        int anchor=-1, best=0, run=0;
        for(int i=0;i<masks.Length;i++) {
            run=masks[i]==255 ? run+1 : 0;
            if(run>best) { best=run; anchor=i-run+1; }
        }
        if(anchor<0) throw new ArgumentException("A fully fixed anchor is required");
        var hits=new List<long>(); int at=0, limit=length-values.Length;
        while(at<=limit) {
            int found=Array.IndexOf(b,values[anchor],at+anchor,limit-at+1);
            if(found<0) break;
            at=found-anchor;
            bool ok=true;
            for(int i=0;i<values.Length;i++) if((b[at+i]&masks[i])!=values[i]) {ok=false;break;}
            if(ok) {hits.Add(at); if(hits.Count>1024) throw new InvalidOperationException("Pattern candidate budget exceeded");}
            at++;
        }
        return hits.ToArray();
    }
    public static long[] Reasons(byte[] b, int length) {
        var hits=new List<long>();
        for(int p=0;p+8<=length;p++) {
            p=Array.IndexOf(b,(byte)0xc7,p,length-7-p);
            if(p<0) break;
            if(b[p+1]!=0x44 || b[p+2]!=0x24 || b[p+4]!=0 || b[p+5]!=0 || b[p+6]!=0 || b[p+7]!=2) continue;
            for(int q=Math.Max(0,p-32);q+2<p;q++) {
                if(!((b[q]==0x89 && (b[q+1]&0xc7)==0xc1) || (b[q]==0x8b && (b[q+1]&0xf8)==0xc8))) continue;
                int at=q+2; while(at<p && b[at]==0x90) at++;
                if(at+5>p || b[at]!=0xe8) continue;
                int seed=q; if(q>0 && b[q-1]>=0x40 && b[q-1]<=0x47) seed--;
                hits.Add(seed); if(hits.Count>64) throw new InvalidOperationException("Reason candidate budget exceeded");
            }
        }
        return hits.ToArray();
    }}



// Windows DbgEng COM slots from the published IDebugClient/Control/Symbols ABI.
// Only file-backed targets are opened. No process attach or execution API is exposed.
public sealed class Mv2NativeDisassembler : IDisposable {
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int QueryInterfaceCall(IntPtr self, ref Guid iid, out IntPtr result);
    [DllImport("dbgeng.dll", ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int DebugCreate(ref Guid iid, out IntPtr client);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int TextCall(IntPtr self, [MarshalAs(UnmanagedType.LPStr)] string text);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int UIntCall(IntPtr self, uint value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int WaitCall(IntPtr self, uint flags, uint timeout);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ModuleCall(IntPtr self, uint index, out ulong address);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int DisassembleCall(IntPtr self, ulong address, uint flags,
        [Out, MarshalAs(UnmanagedType.LPStr)] StringBuilder text, uint capacity,
        out uint used, out ulong end);
    private IntPtr client, control, symbols;
    private DisassembleCall disassemble;
    private readonly StringBuilder instructionText = new StringBuilder(512);
    private static readonly System.Text.RegularExpressions.Regex instructionPattern =
        new System.Text.RegularExpressions.Regex(@"^\S+\s+([0-9a-f]+)\s+(\S+)\s*(.*)$",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    public ulong ImageBase { get; private set; }
    public Mv2NativeDisassembler(string path) {
        try {
            path = System.IO.Path.GetFullPath(path);
            Guid id = new Guid("27fe5639-8407-4f47-8364-ee118fb08ac8");
            Check(DebugCreate(ref id, out client), "DebugCreate");
            id = new Guid("5182e668-105e-416e-ad92-24ef800424ba");
            Check(Call<QueryInterfaceCall>(client, 0)(client, ref id, out control), "IDebugControl");
            id = new Guid("8c31e98c-983a-48a5-9016-6fe5d667a950");
            Check(Call<QueryInterfaceCall>(client, 0)(client, ref id, out symbols), "IDebugSymbols");
            // No network paths, shell commands, managed support or execution.
            // Image mapping needs module loading, but the symbol search path stays empty.
            Check(Call<UIntCall>(control, 54)(control, 0x00015008), "AddEngineOptions");
            Check(Call<TextCall>(symbols, 41)(symbols, ""), "SetSymbolPath");
            Check(Call<TextCall>(symbols, 44)(symbols, System.IO.Path.GetDirectoryName(path)), "SetImagePath");
            Check(Call<TextCall>(client, 19)(client, path), "OpenDumpFile");
            Check(Call<WaitCall>(control, 93)(control, 0, 10000), "WaitForEvent");
            Check(Call<UIntCall>(control, 48)(control, 0x8664), "SetEffectiveProcessorType");
            disassemble = Call<DisassembleCall>(control, 26);
            ulong imageBase;
            Check(Call<ModuleCall>(symbols, 13)(symbols, 0, out imageBase), "GetModuleByIndex");
            ImageBase = imageBase;
        } catch { Dispose(); throw; }
    }
    private static T Call<T>(IntPtr instance, int slot) where T : class {
        IntPtr entry = Marshal.ReadIntPtr(Marshal.ReadIntPtr(instance), slot * IntPtr.Size);
        return Marshal.GetDelegateForFunctionPointer(entry, typeof(T)) as T;
    }
    private static void Check(int hr, string operation) {
        if (hr < 0) throw new InvalidOperationException(operation + ": 0x" + hr.ToString("X8"));
    }
    public Mv2NativeInstruction Decode(ulong address) {
        StringBuilder text = instructionText;
        text.Length = 0;
        uint used; ulong end;
        Check(disassemble(control, address, 0, text, (uint)text.Capacity, out used, out end), "Disassemble");
        if (end <= address || end - address > 15 || used > text.Capacity || text.ToString().Contains("???"))
            throw new InvalidOperationException("Invalid or truncated instruction: " + text.ToString());
        string value = text.ToString().Trim();
        var match = instructionPattern.Match(value);
        if (!match.Success) throw new InvalidOperationException("Unparsed: " + value);
        string op = match.Groups[2].Value, raw = match.Groups[1].Value;
        long? target = null;
        if (op == "call" || op.StartsWith("j", StringComparison.Ordinal)) {
            byte[] bytes = new byte[raw.Length / 2];
            for (int j = 0; j < bytes.Length; j++) bytes[j] = Convert.ToByte(raw.Substring(2*j, 2), 16);
            if (op == "call" && bytes[0] == 0xe8) target = checked((long)end + BitConverter.ToInt32(bytes, 1));
            if (op.StartsWith("j", StringComparison.Ordinal)) {
                if (bytes[0] == 0x0f && (bytes[1] & 0xf0) == 0x80) target = checked((long)end + BitConverter.ToInt32(bytes, 2));
                else if (bytes[0] == 0xe9) target = checked((long)end + BitConverter.ToInt32(bytes, 1));
                else if ((bytes[0] & 0xf0) == 0x70 || bytes[0] == 0xeb) target = checked((long)end + (bytes[1] < 128 ? bytes[1] : bytes[1] - 256));
                else throw new InvalidOperationException("Indirect branch rejected");
            }
        }
        return new Mv2NativeInstruction { Address = address, End = end, Text = value,
            Op = op, Args = match.Groups[3].Value, Target = target };
    }
    public void Dispose() {
        if (client != IntPtr.Zero) Call<UIntCall>(client, 26)(client, 0);
        if (symbols != IntPtr.Zero) { Marshal.Release(symbols); symbols = IntPtr.Zero; }
        if (control != IntPtr.Zero) { Marshal.Release(control); control = IntPtr.Zero; }
        if (client != IntPtr.Zero) { Marshal.Release(client); client = IntPtr.Zero; }
    }
}
public sealed class Mv2NativeInstruction {
    public ulong Address;
    public ulong End;
    public string Text;
    public string Op;
    public string Args;
    public long? Target;
}

public static class Mv2SnippetDump {
    // A synthetic dump of file bytes, never a snapshot of a running process.
    public static void Write(string path, byte[] source, long[] offsets, ulong[] addresses, ulong imageBase) {
        if (offsets.Length == 0 || offsets.Length != addresses.Length || offsets.Length > 64)
            throw new ArgumentException("Invalid snippet count");
        const int size = 4096, data = 4096;
        using (var f = File.Create(path)) using (var w = new BinaryWriter(f)) {
            f.SetLength(data + offsets.Length * size);
            w.Write(0x504d444dU); w.Write(0xa793U); w.Write(4U); w.Write(32U);
            f.Position = 32;
            foreach (uint n in new uint[] {7,56,80,3,52,136,5,(uint)(4+16*offsets.Length),2048,4,112,208}) w.Write(n);
            f.Position=80; w.Write((ushort)9);
            f.Position=86; w.Write((byte)1); w.Write((byte)1); w.Write(10U); w.Write(0U); w.Write(26100U); w.Write(2U);
            f.Position=136; w.Write(1U); w.Write(1U);
            f.Position=180; w.Write(1232U); w.Write(512U);
            f.Position=208; w.Write(1U); w.Write(imageBase); w.Write(0x20000000U);
            f.Position=232; w.Write(320U);
            f.Position=320; byte[] name=System.Text.Encoding.Unicode.GetBytes("branch-snippet.dll"); w.Write(name.Length); w.Write(name);
            f.Position=560; w.Write(0x100003U);
            f.Position=568; w.Write((ushort)0x33);
            f.Position=578; w.Write((ushort)0x2b); w.Write(0x202U);
            f.Position=664; w.Write(addresses[0]+1024);
            f.Position=760; w.Write(addresses[0]);
            f.Position=2048; w.Write((uint)offsets.Length);
            for(int i=0;i<offsets.Length;i++) {
                if (offsets[i]<0 || offsets[i]+size>source.LongLength) throw new ArgumentException("Truncated snippet");
                w.Write(addresses[i]); w.Write((uint)size); w.Write((uint)(data+i*size));
            }
            for(int i=0;i<offsets.Length;i++) { f.Position=data+i*size; w.Write(source,(int)offsets[i],size); }
        }
    }
}
'@
}
