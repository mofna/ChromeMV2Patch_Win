using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// File-only PE export specialization. No browser image is loaded or executed.
public static class Mv2AdaptiveExports
{
    static void Require(bool ok, string message) { if (!ok) throw new InvalidDataException(message); }
    static long Align(long value, long alignment) { return checked((value + alignment - 1) / alignment * alignment); }
    public static string Hash(byte[] bytes) {
        using (var hash = SHA256.Create()) { return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant(); }
    }
    static bool Equal(byte[] a, int at, byte[] b, int bt, int count) {
        for (int i = 0; i < count; i++) if (a[at + i] != b[bt + i]) return false;
        return true;
    }
    public sealed class Section {
        public long at, size, rva, rawSize, raw, flags;
        public string name;
        public long MappedSize { get { return Math.Max(size, rawSize); } }
    }
    public sealed class Entry {
        public long ordinal, rva;
        public string kind, forwarder;
        public List<string> names = new List<string>();
    }
    public sealed class Image {
        public readonly byte[] bytes;
        public long nt, optional, sectionTable, sectionAlignment, fileAlignment, imageSize, headersSize;
        public long exportRva, exportSize, directory, ordinalBase, functions, names;
        public List<Section> sections = new List<Section>();
        public List<Entry> entries = new List<Entry>();
        public int Range(long at, long size) {
            Require(at >= 0 && size >= 0 && at <= bytes.Length && size <= bytes.Length - at, "PE file range");
            return (int)at;
        }
        public ushort U16(long at) { return BitConverter.ToUInt16(bytes, Range(at, 2)); }
        public uint U32(long at) { return BitConverter.ToUInt32(bytes, Range(at, 4)); }
        public Section Mapped(long rva, long size) {
            Require(rva >= 0 && size >= 0, "Invalid RVA");
            foreach (var section in sections) {
                long delta = rva - section.rva;
                if (delta >= 0 && delta < section.MappedSize) {
                    Require(size <= section.MappedSize - delta, "Unmapped RVA");
                    return section;
                }
            }
            throw new InvalidDataException("Unmapped RVA");
        }
        public int Offset(long rva, long size) {
            var section = Mapped(rva, size);
            long delta = rva - section.rva;
            Require(delta <= section.rawSize && size <= section.rawSize - delta, "RVA has no file bytes");
            return Range(section.raw + delta, size);
        }
        public string String(long rva, long limit) {
            var section = Mapped(rva, 1);
            int start = Offset(rva, 1);
            long available = Math.Min(limit, section.rawSize - (rva - section.rva));
            int end = start;
            while (end - start < available && bytes[end] != 0) {
                Require(bytes[end] >= 0x21 && bytes[end] <= 0x7e, "Non-printable export string");
                end++;
            }
            Require(end > start && end - start < available, "Unterminated PE string");
            return Encoding.ASCII.GetString(bytes, start, end - start);
        }
        public Image(byte[] input, bool dllRequired, bool exportsRequired) {
            bytes = input;
            Require(U16(0) == 0x5a4d, "DOS signature");
            nt = U32(60);
            Require(nt >= 64 && nt <= 1048576, "NT header offset");
            Require(U32(nt) == 0x4550, "PE signature");
            Require(U16(nt + 4) == 0x8664, "Only x64 images are supported");
            if (dllRequired) Require((U16(nt + 22) & 0x2000) != 0, "Expected a DLL");
            int count = U16(nt + 6), optionalSize = U16(nt + 20);
            optional = nt + 24;
            Require(count > 0 && count <= 96 && optionalSize >= 240, "PE headers");
            Range(optional, optionalSize);
            Require(U16(optional) == 0x20b, "PE32+ required");
            Require(U32(optional + 108) >= 16, "Missing data directories");
            sectionAlignment = U32(optional + 32); fileAlignment = U32(optional + 36);
            Require(sectionAlignment >= 4096 && sectionAlignment <= 65536 && (sectionAlignment & (sectionAlignment - 1)) == 0, "Section alignment");
            Require(fileAlignment >= 512 && fileAlignment <= sectionAlignment && (fileAlignment & (fileAlignment - 1)) == 0, "File alignment");
            imageSize = U32(optional + 56); headersSize = U32(optional + 60);
            Require(imageSize >= headersSize && imageSize < 0x80000000L, "Image size");
            Range(0, headersSize);
            sectionTable = optional + optionalSize;
            Require(sectionTable + count * 40 <= headersSize, "Section headers outside headers");
            for (int i = 0; i < count; i++) {
                long at = sectionTable + i * 40;
                var section = new Section { at = at,
                    name = Encoding.ASCII.GetString(bytes, (int)at, 8).Split('\0')[0],
                    size = U32(at + 8), rva = U32(at + 12), rawSize = U32(at + 16), raw = U32(at + 20), flags = U32(at + 36) };
                Require(section.rva % sectionAlignment == 0 && section.rva >= Align(headersSize, sectionAlignment), "Section RVA");
                Require(section.rva <= imageSize && section.MappedSize <= imageSize - section.rva, "Section outside image");
                if (section.rawSize != 0) {
                    Range(section.raw, section.rawSize);
                    Require(section.raw >= headersSize && section.raw % fileAlignment == 0, "Section raw range");
                }
                foreach (var previous in sections) {
                    Require(section.rva >= previous.rva + previous.MappedSize || previous.rva >= section.rva + section.MappedSize, "Overlapping virtual sections");
                    if (section.rawSize != 0 && previous.rawSize != 0)
                        Require(section.raw >= previous.raw + previous.rawSize || previous.raw >= section.raw + section.rawSize, "Overlapping raw sections");
                }
                sections.Add(section);
            }
            long certificate = U32(optional + 144), certificateSize = U32(optional + 148);
            Require((certificate != 0) == (certificateSize != 0), "Incomplete certificate directory");
            if (certificateSize != 0) {
                long rawEnd = 0;
                foreach (var section in sections) rawEnd = Math.Max(rawEnd, section.raw + section.rawSize);
                Require(certificate % 8 == 0 && certificateSize >= 8 && certificate >= rawEnd, "Certificate location");
                Range(certificate, certificateSize);
            }
            exportRva = U32(optional + 112); exportSize = U32(optional + 116);
            if (!exportsRequired && exportRva == 0 && exportSize == 0) return;
            Require(exportSize >= 40, "No export directory");
            directory = Offset(exportRva, exportSize);
            ordinalBase = U32(directory + 16); functions = U32(directory + 20); names = U32(directory + 24);
            Require(ordinalBase >= 1 && functions >= 1 && ordinalBase + functions - 1 <= 65535 && names <= 65535, "Unsupported ordinal range");
            long eat = Offset(U32(directory + 28), 4 * functions);
            long nameTable = names != 0 ? Offset(U32(directory + 32), 4 * names) : 0;
            long ordinals = names != 0 ? Offset(U32(directory + 36), 2 * names) : 0;
            for (int i = 0; i < functions; i++) {
                var entry = new Entry { ordinal = ordinalBase + i, rva = U32(eat + i * 4), kind = "hole" };
                if (entry.rva != 0) {
                    if (entry.rva >= exportRva && entry.rva - exportRva < exportSize) {
                        entry.kind = "forwarder";
                        entry.forwarder = String(entry.rva, exportSize - (entry.rva - exportRva));
                        Require(entry.forwarder.Contains("."), "Malformed forwarder");
                    } else entry.kind = (Mapped(entry.rva, 1).flags & 0x20000000) != 0 ? "function" : "data";
                }
                entries.Add(entry);
            }
            string previousName = "";
            for (int i = 0; i < names; i++) {
                string name = String(U32(nameTable + i * 4), 16384);
                int index = U16(ordinals + i * 2);
                Require(index < functions && entries[index].kind != "hole", "Name points to missing ordinal");
                Require(System.String.CompareOrdinal(name, previousName) > 0, "Export names must be unique and sorted");
                previousName = name;
                entries[index].names.Add(name);
            }
        }
    }
    static string BrowserDllName(string name) {
        Require(name == "msedge.dll" || name == "chrome.dll" || name == "vivaldi.dll" || name == "opera_browser.dll", "Expected a supported browser DLL filename");
        return name;
    }
    public static int CheckStaticImports(byte[] exeBytes, byte[] originalBytes) { return CheckStaticImports(exeBytes, originalBytes, "msedge.dll"); }
    public static int CheckStaticImports(byte[] exeBytes, byte[] originalBytes, string dllName) {
        dllName = BrowserDllName(dllName);
        var exe = new Image(exeBytes, false, false);
        var original = new Image(originalBytes, true, true);
        long rva = exe.U32(exe.optional + 120), size = exe.U32(exe.optional + 124);
        if (rva == 0 && size == 0) return 0;
        Require(size >= 20, "Invalid import directory");
        long start = exe.Offset(rva, size);
        var byName = new Dictionary<string, Entry>(StringComparer.Ordinal);
        foreach (var entry in original.entries) foreach (var name in entry.names) byName.Add(name, entry);
        bool terminated = false;
        int functions = 0;
        for (long at = start; at + 20 <= start + size; at += 20) {
            bool zero = true;
            for (int j = 0; j < 20; j++) if (exeBytes[at + j] != 0) { zero = false; break; }
            if (zero) { terminated = true; break; }
            string[] components = exe.String(exe.U32(at + 12), 16384).Replace('\\', '/').Split('/');
            string moduleName = components[components.Length - 1];
            if (!moduleName.Equals(Path.GetFileNameWithoutExtension(dllName), StringComparison.OrdinalIgnoreCase) && !moduleName.Equals(dllName, StringComparison.OrdinalIgnoreCase)) continue;
            long lookupRva = exe.U32(at);
            Require(lookupRva != 0, "Browser import names are unavailable");
            bool lookupTerminated = false;
            for (int i = 0; i <= 65535; i++) {
                ulong value = BitConverter.ToUInt64(exeBytes, exe.Offset(lookupRva + i * 8L, 8));
                if (value == 0) { lookupTerminated = true; break; }
                Entry entry = null;
                if ((value & 0x8000000000000000UL) != 0) {
                    Require((value & 0x7fffffffffff0000UL) == 0, "Invalid imported ordinal");
                    long index = (long)(value & 65535) - original.ordinalBase;
                    if (index >= 0 && index < original.functions) entry = original.entries[(int)index];
                } else {
                    Require(value < 0xffffffffUL, "Invalid import-name RVA");
                    byName.TryGetValue(exe.String((long)value + 2, 16384), out entry);
                }
                Require(entry != null && entry.kind == "function", "Static data or forwarded browser imports require a distinct original module name; trial refused");
                functions = checked(functions + 1);
            }
            Require(lookupTerminated, "Unterminated import lookup");
        }
        Require(terminated, "Unterminated import directory");
        return functions;
    }
    static long ThunkStart(Image template) {
        int populated = 0;
        Entry marker = null, inspector = null;
        foreach (var entry in template.entries) {
            if (entry.kind != "hole") populated++;
            if (entry.names.Contains("Mv2OrdinalThunks")) marker = entry;
            if (entry.names.Contains("Mv2InspectW")) inspector = entry;
        }
        Require(populated == 2, "Unexpected template exports");
        Require(marker != null && inspector != null && marker.kind == "function" && inspector.kind == "function", "Template marker missing");
        long start = template.Offset(marker.rva, 65535 * 16);
        long dispatcher = 0;
        for (int ordinal = 1; ordinal <= 65535; ordinal++) {
            long at = start + (ordinal - 1) * 16;
            Require(template.U16(at) == 0xba41, "Ordinal thunk opcode");
            Require(template.U32(at + 2) == ordinal, "Ordinal thunk immediate");
            Require(template.bytes[at + 6] == 0xe9, "Ordinal thunk jump");
            long target = marker.rva + (ordinal - 1) * 16 + 11 + BitConverter.ToInt32(template.bytes, template.Range(at + 7, 4));
            if (ordinal == 1) dispatcher = target;
            Require(target == dispatcher, "Thunks do not share a dispatcher");
        }
        Require((template.Mapped(dispatcher, 1).flags & 0x20000000) != 0, "Dispatcher is not executable");
        return marker.rva;
    }
    public sealed class Receipt {
        public string format = "AdaptiveExports1", dllName = "msedge.dll";
        public string templateSHA256, originalSHA256, proxySHA256, browserSHA256, proxyPath;
        public long exportBase, exportSlots, exportNames, functions, data, forwarders, holes;
        public Dictionary<string, int> staticImports;
    }
    public sealed class Result { public byte[] bytes; public Receipt receipt; }
    static void W16(byte[] bytes, long at, long value) { Buffer.BlockCopy(BitConverter.GetBytes(checked((ushort)value)), 0, bytes, checked((int)at), 2); }
    static void W32(byte[] bytes, long at, long value) { Buffer.BlockCopy(BitConverter.GetBytes(checked((uint)value)), 0, bytes, checked((int)at), 4); }
    static long AddString(MemoryStream strings, long start, long rva, string value) {
        long result = rva + start + strings.Length;
        byte[] bytes = Encoding.ASCII.GetBytes(value + "\0");
        strings.Write(bytes, 0, bytes.Length);
        return result;
    }
    public static Result Generate(byte[] templateBytes, byte[] originalBytes) { return Generate(templateBytes, originalBytes, "msedge.dll"); }
    public static Result Generate(byte[] templateBytes, byte[] originalBytes, string dllName) {
        dllName = BrowserDllName(dllName);
        string originalModule = "original\\" + Path.GetFileNameWithoutExtension(dllName);
        var template = new Image(templateBytes, true, true);
        var original = new Image(originalBytes, true, true);
        long start = ThunkStart(template);
        Require(template.U32(template.optional + 144) == 0, "Do not rewrite a signed template");
        Require(template.sections.Count < 96, "No section slot");
        long newHeader = template.sectionTable + template.sections.Count * 40;
        Require(newHeader + 40 <= template.headersSize, "No unused section header");
        for (int i = 0; i < 40; i++) Require(templateBytes[newHeader + i] == 0, "No unused section header");
        foreach (var section in template.sections) Require(section.name != ".mv2exp", "Template already specialized");
        long newRva = Align(template.imageSize, template.sectionAlignment), newRaw = Align(templateBytes.Length, template.fileAlignment);
        var names = new SortedDictionary<string, int>(StringComparer.Ordinal);
        foreach (var entry in original.entries) foreach (var name in entry.names) names.Add(name, (int)(entry.ordinal - original.ordinalBase));
        long eat = 40, nameTable = eat + original.functions * 4, ordinalTable = nameTable + names.Count * 4;
        long stringStart = ordinalTable + names.Count * 2;
        using (var strings = new MemoryStream()) {
            long moduleName = AddString(strings, stringStart, newRva, dllName);
            long[] addresses = new long[original.entries.Count];
            for (int i = 0; i < addresses.Length; i++) {
                var entry = original.entries[i];
                if (entry.kind == "function") addresses[i] = start + (entry.ordinal - 1) * 16;
                else if (entry.kind != "hole") addresses[i] = AddString(strings, stringStart, newRva,
                    entry.kind == "forwarder" ? entry.forwarder : originalModule + ".#" + entry.ordinal);
            }
            var nameRvas = new List<long>();
            foreach (var name in names.Keys) nameRvas.Add(AddString(strings, stringStart, newRva, name));
            long size = stringStart + strings.Length, rawSize = Align(size, template.fileAlignment), imageSize = Align(newRva + size, template.sectionAlignment);
            Require(imageSize < 0x80000000L && newRaw + rawSize <= Int32.MaxValue, "Generated image too large");
            byte[] result = new byte[(int)(newRaw + rawSize)];
            Buffer.BlockCopy(templateBytes, 0, result, 0, templateBytes.Length);
            W16(result, template.nt + 6, template.sections.Count + 1);
            W32(result, template.optional + 8, template.U32(template.optional + 8) + rawSize);
            W32(result, template.optional + 56, imageSize);
            W32(result, template.optional + 64, 0);
            W32(result, template.optional + 112, newRva); W32(result, template.optional + 116, size);
            Buffer.BlockCopy(Encoding.ASCII.GetBytes(".mv2exp"), 0, result, (int)newHeader, 7);
            W32(result, newHeader + 8, size); W32(result, newHeader + 12, newRva);
            W32(result, newHeader + 16, rawSize); W32(result, newHeader + 20, newRaw);
            W32(result, newHeader + 36, 0x40000040); // Read-only, non-executable initialized data.
            W32(result, newRaw + 4, original.U32(original.directory + 4));
            W32(result, newRaw + 12, moduleName); W32(result, newRaw + 16, original.ordinalBase);
            W32(result, newRaw + 20, original.functions); W32(result, newRaw + 24, names.Count);
            W32(result, newRaw + 28, newRva + eat);
            W32(result, newRaw + 32, names.Count != 0 ? newRva + nameTable : 0);
            W32(result, newRaw + 36, names.Count != 0 ? newRva + ordinalTable : 0);
            for (int i = 0; i < addresses.Length; i++) W32(result, newRaw + eat + i * 4, addresses[i]);
            int n = 0;
            foreach (var name in names) {
                W32(result, newRaw + nameTable + n * 4, nameRvas[n]); W16(result, newRaw + ordinalTable + n * 2, name.Value); n++;
            }
            byte[] stringBytes = strings.ToArray();
            Buffer.BlockCopy(stringBytes, 0, result, (int)(newRaw + stringStart), stringBytes.Length);
            var generated = new Image(result, true, true);
            Require(generated.ordinalBase == original.ordinalBase && generated.functions == original.functions && generated.names == original.names, "Generated export counts changed");
            for (int i = 0; i < addresses.Length; i++) {
                var source = original.entries[i]; var output = generated.entries[i];
                Require(output.rva == addresses[i] && output.names.Count == source.names.Count, "Generated export differs");
                for (int j = 0; j < source.names.Count; j++) Require(output.names[j] == source.names[j], "Generated export name differs");
                Require(output.kind == (source.kind == "data" || source.kind == "forwarder" ? "forwarder" : source.kind), "Generated export kind differs");
                if (output.kind == "forwarder") Require(output.forwarder == (source.kind == "forwarder" ? source.forwarder : originalModule + ".#" + source.ordinal), "Generated forwarder differs");
            }
            foreach (var section in template.sections) Require(Equal(result, (int)section.raw, templateBytes, (int)section.raw, (int)section.rawSize), "Template section changed");
            var receipt = new Receipt { dllName = dllName, templateSHA256 = Hash(templateBytes), originalSHA256 = Hash(originalBytes), proxySHA256 = Hash(result),
                exportBase = original.ordinalBase, exportSlots = original.functions, exportNames = original.names };
            foreach (var entry in original.entries) {
                switch (entry.kind) { case "function": receipt.functions++; break; case "data": receipt.data++; break;
                    case "forwarder": receipt.forwarders++; break; default: receipt.holes++; break; }
            }
            return new Result { bytes = result, receipt = receipt };
        }
    }
    static void Ordinary(string path, bool directory) {
        var attributes = File.GetAttributes(path);
        Require((attributes & FileAttributes.ReparsePoint) == 0 && ((attributes & FileAttributes.Directory) != 0) == directory,
            directory ? "Unsafe generation directory" : "Unsafe generated file");
    }
    public static Receipt Prepare(string root, string templatePath, string originalPath, string browserPath) {
        string dllName = BrowserDllName(Path.GetFileName(originalPath).ToLowerInvariant());
        byte[] original = File.ReadAllBytes(originalPath), browser = File.ReadAllBytes(browserPath);
        int imports = CheckStaticImports(browser, original, dllName);
        var generated = Generate(File.ReadAllBytes(templatePath), original, dllName);
        string directory = Path.GetFullPath(root);
        Ordinary(directory, true);
        foreach (string component in new [] { "generated", generated.receipt.templateSHA256, generated.receipt.originalSHA256 }) {
            directory = Path.Combine(directory, component);
            Directory.CreateDirectory(directory);
            Ordinary(directory, true);
        }
        string output = Path.Combine(directory, dllName);
        try {
            using (var stream = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                stream.Write(generated.bytes, 0, generated.bytes.Length); stream.Flush(true);
            }
        } catch (IOException) { if (!File.Exists(output)) throw; }
        Ordinary(output, false);
        byte[] cached = File.ReadAllBytes(output);
        Require(cached.Length == generated.bytes.Length && Equal(cached, 0, generated.bytes, 0, cached.Length), "Previously generated file changed; refusing to replace it");
        generated.receipt.proxyPath = output;
        generated.receipt.staticImports = new Dictionary<string, int> { { "functions", imports } };
        generated.receipt.browserSHA256 = Hash(browser);
        return generated.receipt;
    }
}
