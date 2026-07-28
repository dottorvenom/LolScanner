using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Microsoft.VisualBasic.FileIO;




public class LolScanner
{
    public static void Main(string[] args)
    {
        LolDriversChecker.RunAsync().GetAwaiter().GetResult();
    }
}

public static class PeImportAnalyzer
{
    private const uint PE_SIGNATURE = 0x4550;
    private const ushort MACHINE_I386 = 0x014C;
    private const ushort MACHINE_AMD64 = 0x8664;

    private const int IMPORT_DIR_OFFSET_X86 = 128;
    private const int IMPORT_DIR_OFFSET_X64 = 144;

    private struct SectionInfo
    {
        public uint VirtualAddress;
        public uint VirtualSize;
        public uint PointerToRawData;
    }

    public static List<string> ExtractImportedApis(string filePath, string targetModule)
    {
        var imports = new List<string>();
        try
        {
            using (var fs = File.OpenRead(filePath))
            using (var br = new BinaryReader(fs))
            {
                if (fs.Length < 64) return imports;

                fs.Seek(0, SeekOrigin.Begin);
                if (br.ReadUInt16() != 0x5A4D) return imports;

                fs.Seek(60, SeekOrigin.Begin);
                uint peOff = br.ReadUInt32();
                if ((long)peOff + 248 > fs.Length) return imports;

                fs.Seek(peOff, SeekOrigin.Begin);
                if (br.ReadUInt32() != PE_SIGNATURE) return imports;

                ushort machine = br.ReadUInt16();
                ushort numSections = br.ReadUInt16();
                fs.Seek(peOff + 20, SeekOrigin.Begin);
                ushort optHdrSize = br.ReadUInt16();

                if (machine != MACHINE_I386 && machine != MACHINE_AMD64) return imports;
                bool is64 = (machine == MACHINE_AMD64);

                int importDirAbsOffset = is64 ? IMPORT_DIR_OFFSET_X64 : IMPORT_DIR_OFFSET_X86;
                fs.Seek(peOff + importDirAbsOffset, SeekOrigin.Begin);
                uint importRva = br.ReadUInt32();
                br.ReadUInt32();

                if (importRva == 0) return imports;

                long sectionBase = peOff + 24 + optHdrSize;
                var sections = ReadSections(br, sectionBase, numSections);

                uint importOffset = RvaToOffset(sections, importRva);
                if (importOffset == 0) return imports;

                imports = ReadImportDirectory(br, fs, sections, importOffset, targetModule, is64);
            }
        }
        catch { }

        return imports;
    }

    private static List<SectionInfo> ReadSections(BinaryReader br, long baseOffset, ushort count)
    {
        var list = new List<SectionInfo>(count);
        for (int i = 0; i < count; i++)
        {
            br.BaseStream.Seek(baseOffset + i * 40L, SeekOrigin.Begin);
            br.ReadBytes(8);
            uint virtualSize = br.ReadUInt32();
            uint virtualAddr = br.ReadUInt32();
            br.ReadUInt32();
            uint rawPtr = br.ReadUInt32();
            list.Add(new SectionInfo
            {
                VirtualAddress = virtualAddr,
                VirtualSize = virtualSize,
                PointerToRawData = rawPtr
            });
        }
        return list;
    }

    private static uint RvaToOffset(List<SectionInfo> sections, uint rva)
    {
        foreach (var s in sections)
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize)
                return s.PointerToRawData + (rva - s.VirtualAddress);
        return 0;
    }

    private static List<string> ReadImportDirectory(BinaryReader br, FileStream fs,
        List<SectionInfo> sections, uint tableOffset, string targetModule, bool is64)
    {
        const int maxDescriptors = 4096;

        for (int i = 0; i < maxDescriptors; i++)
        {
            fs.Seek(tableOffset + i * 20L, SeekOrigin.Begin);

            uint origFirstThunk = br.ReadUInt32();
            br.ReadUInt32();
            br.ReadUInt32();
            uint nameRva = br.ReadUInt32();
            uint firstThunk = br.ReadUInt32();

            if (origFirstThunk == 0 && nameRva == 0) break;

            uint lookupRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
            if (nameRva == 0 || lookupRva == 0) continue;

            uint nameOffset = RvaToOffset(sections, nameRva);
            if (nameOffset == 0) continue;

            string dllName = ReadCString(br, fs, nameOffset);
            if (!dllName.Equals(targetModule, StringComparison.OrdinalIgnoreCase)) continue;

            uint lookupOffset = RvaToOffset(sections, lookupRva);
            if (lookupOffset == 0) break;

            return ReadImportNameTable(br, fs, sections, lookupOffset, is64);
        }

        return new List<string>();
    }

    private static List<string> ReadImportNameTable(BinaryReader br, FileStream fs,
        List<SectionInfo> sections, uint tableOffset, bool is64)
    {
        var names = new List<string>();
        int entrySize = is64 ? 8 : 4;
        ulong ordFlag = is64 ? 0x8000000000000000UL : 0x80000000UL;
        const int maxEntries = 8192;

        try
        {
            for (int i = 0; i < maxEntries; i++)
            {
                fs.Seek(tableOffset + i * (long)entrySize, SeekOrigin.Begin);
                ulong entry = is64 ? br.ReadUInt64() : (ulong)br.ReadUInt32();

                if (entry == 0) break;
                if ((entry & ordFlag) != 0) continue;

                uint hintNameRva = (uint)(entry & 0x7FFFFFFF);
                uint hintNameOffset = RvaToOffset(sections, hintNameRva);
                if (hintNameOffset == 0) continue;

                string name = ReadCString(br, fs, hintNameOffset + 2);
                if (!string.IsNullOrEmpty(name))
                    names.Add(name);
            }
        }
        catch { }

        return names;
    }

    private static string ReadCString(BinaryReader br, FileStream fs, uint fileOffset)
    {
        try
        {
            fs.Seek(fileOffset, SeekOrigin.Begin);
            var bytes = new List<byte>(64);
            while (fs.Position < fs.Length)
            {
                byte b = br.ReadByte();
                if (b == 0) break;
                bytes.Add(b);
                if (bytes.Count > 512) break;
            }
            return System.Text.Encoding.ASCII.GetString(bytes.ToArray());
        }
        catch { return string.Empty; }
    }
}

public static class DriverEnumerator
{
    public static List<string> EnumerateSysFilesOnDisk()
    {
        var results = new List<string>();

        string[] rootPaths =
        {
                                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers"),
                                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "DriverStore", "FileRepository"),
                                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64",  "drivers")
                                };

        foreach (var root in rootPaths)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                Console.WriteLine("\n");
                foreach (var f in Directory.EnumerateFiles(root, "*.sys", System.IO.SearchOption.AllDirectories))
                {
                    Console.WriteLine(f + " -> " + CalcolaSha256(f));
                    results.Add(f);
                }
                Console.WriteLine("\n");
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        return results;
    }




    public static List<string> EnumerateDriversViaDriverQuery()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string csvOut = RunDriverQuery();
        if (string.IsNullOrWhiteSpace(csvOut)) return paths.ToList();

        using (var ms = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(csvOut)))
        using (var parser = new TextFieldParser(ms))
        {
            parser.TextFieldType = FieldType.Delimited;
            parser.SetDelimiters(",");
            parser.HasFieldsEnclosedInQuotes = true;

            string[] headers = null;
            int pathColIdx = -1;

            while (!parser.EndOfData)
            {
                string[] fields;
                try { fields = parser.ReadFields(); }
                catch (MalformedLineException) { continue; }
                if (fields == null) continue;

                if (headers == null)
                {
                    headers = fields;

                    pathColIdx = Array.FindIndex(headers,
                        h =>
                        {
                            string t = h.Trim();
                            return t.Equals("Path", StringComparison.OrdinalIgnoreCase)
                                || t.Equals("Percorso", StringComparison.OrdinalIgnoreCase);
                        });

                    continue;
                }

                if (pathColIdx >= 0 && pathColIdx < fields.Length)
                {
                    string raw = fields[pathColIdx]?.Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(raw) && File.Exists(raw))
                    {
                        paths.Add(Path.GetFullPath(raw));
                    }
                }
            }
        }

        if (paths.Count == 0)
        {
            Console.WriteLine("- FALLBACK: Path vuoto in driverquery CSV, ricerca per nome su disco...");
            var driverNames = ExtractDriverNamesFromCsv(csvOut);

            if (driverNames.Count > 0)
            {
                Console.WriteLine("- Trovati " + driverNames.Count + " nomi di driver nel CSV");
                var allDiskFiles = EnumerateSysFilesOnDisk();

                foreach (var diskFile in allDiskFiles)
                {
                    string fileName = Path.GetFileNameWithoutExtension(diskFile);
                    if (driverNames.Contains(fileName))
                        paths.Add(Path.GetFullPath(diskFile));
                }
                Console.WriteLine("- Matched " + paths.Count + " driver su disco");
            }
        }

        return paths.ToList();
    }











    private static HashSet<string> ExtractDriverNamesFromCsv(string csvOut)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var ms = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(csvOut)))
        using (var parser = new TextFieldParser(ms))
        {
            parser.TextFieldType = FieldType.Delimited;
            parser.SetDelimiters(",");
            parser.HasFieldsEnclosedInQuotes = true;

            string[] headers = null;
            int nameColIdx = -1;

            while (!parser.EndOfData)
            {
                string[] fields;
                try { fields = parser.ReadFields(); }
                catch (MalformedLineException) { continue; }
                if (fields == null || fields.Length == 0) continue;

                if (headers == null)
                {
                    headers = fields;
                    nameColIdx = -1;
                    for (int i = 0; i < headers.Length; i++)
                    {
                        string h = headers[i].Trim().ToLowerInvariant();
                        if (h.Contains("modulo") || h.Contains("module"))
                        {
                            nameColIdx = i;
                            break;
                        }
                    }
                    continue;
                }

                if (nameColIdx >= 0 && nameColIdx < fields.Length)
                {
                    string modName = fields[nameColIdx]?.Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(modName))
                        names.Add(modName);
                }
            }
        }
        return names;
    }

    private static string RunDriverQuery()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "driverquery.exe",
                Arguments = "/v /fo csv",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            };
            using (var proc = Process.Start(psi))
            {
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(15000);
                return output;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("- Errore esecuzione driverquery: " + ex.Message);
            return null;
        }
    }

    public static string CalcolaSha256(string filePath)
    {
        try
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                byte[] hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("- Impossibile calcolare hash per " + filePath + ": " + ex.Message);
            return null;
        }
    }
}

public static class LolDriversChecker
{
    private const string LolDriversUrl = "https://www.loldrivers.io/api/drivers.json";
    private const string LocalCachePath = "drivers.json";
    private static readonly TimeSpan CacheMaxAge = TimeSpan.FromHours(12);

    private static readonly Dictionary<string, string> SuspiciousKernelApis =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "ZwTerminateProcess",         ""             },
            { "ZwUnmapViewOfSection",       "" },
            //{ "ZwOpenProcess",              ""          },
            { "ZwAllocateVirtualMemory",    ""        },
            { "ZwWriteVirtualMemory",       ""          },
            { "ZwProtectVirtualMemory",     ""       },
            { "ZwDuplicateToken",     ""       },
        };

    public class LolDriverEntry
    {
        public string Id { get; set; }
        public List<string> Tags { get; set; }
        public string Category { get; set; }
        public List<KnownVulnerableSample> KnownVulnerableSamples { get; set; }
    }

    public class KnownVulnerableSample
    {
        public string Filename { get; set; }
        public string MD5 { get; set; }
        public string SHA1 { get; set; }
        public string SHA256 { get; set; }
        public string OriginalFilename { get; set; }
    }

    public static async Task<string> DownloadDriversJsonAsync(string dest = LocalCachePath)
    {
        System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;

        try
        {
            using (var handler = new HttpClientHandler())
            using (var http = new HttpClient(handler))
            {
                http.Timeout = TimeSpan.FromSeconds(60);
                http.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (DriverAudit/1.0)");

                Console.WriteLine("- Download da " + LolDriversUrl + " ...");
                byte[] data = await http.GetByteArrayAsync(LolDriversUrl);
                File.WriteAllBytes(dest, data);
                Console.WriteLine("- Salvato in " + dest + " (" + data.Length + " bytes)");

                return dest;
            }
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine();
            Console.WriteLine("- Nessuna connessione internet disponibile");
            Environment.Exit(1);
            return null;
        }
        catch (TaskCanceledException ex)
        {
            Console.WriteLine();
            Console.WriteLine("- ERRORE: Timeout connessione internet");
            Environment.Exit(1);
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine("- ERRORE: Problema durante il download");
            Environment.Exit(1);
            return null;
        }
    }

    public static List<LolDriverEntry> ParseDriversJson(string jsonPath)
    {
        string json = File.ReadAllText(jsonPath);
        var serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
        try
        {
            return serializer.Deserialize<List<LolDriverEntry>>(json) ?? new List<LolDriverEntry>();
        }
        catch (Exception ex)
        {
            Console.WriteLine("- Errore parsing JSON: " + ex.Message);
            return new List<LolDriverEntry>();
        }
    }

    public static HashSet<string> ExtractDriverNamesFromTags(List<LolDriverEntry> entries)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (entry.Tags == null) continue;
            foreach (var tag in entry.Tags)
            {
                if (string.IsNullOrWhiteSpace(tag)) continue;
                string t = tag.Trim();
                if (t.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
                    names.Add(t);
            }
        }
        return names;
    }

    public static Dictionary<string, List<LolDriverEntry>> BuildHashIndex(List<LolDriverEntry> entries)
    {
        var index = new Dictionary<string, List<LolDriverEntry>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (entry.KnownVulnerableSamples == null) continue;
            foreach (var sample in entry.KnownVulnerableSamples)
            {
                if (string.IsNullOrWhiteSpace(sample.SHA256)) continue;
                string hash = sample.SHA256.Trim().ToLowerInvariant();
                if (!index.TryGetValue(hash, out var list))
                {
                    list = new List<LolDriverEntry>();
                    index[hash] = list;
                }
                list.Add(entry);
            }
        }
        return index;
    }

    public static void CompareByName(HashSet<string> lolNames, IEnumerable<string> localFiles)
    {
        Console.WriteLine();
        Console.WriteLine("- Confronto per NOME FILE");
        Console.WriteLine(new string('-', 60));

        int matches = 0;
        foreach (var f in localFiles)
        {
            if (!lolNames.Contains(Path.GetFileName(f))) continue;
            matches++;

            string hash = DriverEnumerator.CalcolaSha256(f);

            Console.ForegroundColor = ConsoleColor.Yellow;

            if (hash != null)
                Console.WriteLine("- Nome sospetto: " + f + "  SHA256: " + hash);
            else
                Console.WriteLine("- Nome sospetto: " + f + "  SHA256: impossibile calcolare");
            Console.ResetColor();
        }

        Console.WriteLine(new string('-', 60));
        Console.WriteLine(matches == 0
            ? "- Nessun match per nome."
            : "- " + matches + " match per nome trovati.");
    }

    public static void CompareByHash(Dictionary<string, List<LolDriverEntry>> hashIndex,
        IEnumerable<string> localFiles)
    {
        Console.WriteLine();
        Console.WriteLine("- Confronto per HASH SHA256 (da LolDrivers)");
        Console.WriteLine(new string('-', 60));

        int matches = 0, checked_ = 0;

        foreach (var f in localFiles.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string hash = DriverEnumerator.CalcolaSha256(f);
            if (hash == null) continue;
            checked_++;

            if (!hashIndex.TryGetValue(hash, out var entries)) continue;
            matches++;
            Console.ForegroundColor = ConsoleColor.Red;
            foreach (var e in entries)
                Console.WriteLine("- MATCH: " + f + " | SHA256: " + hash + " | Id: " + e.Id);
            Console.ResetColor();
        }

        Console.WriteLine(new string('-', 60));
        Console.WriteLine("- File verificati: " + checked_);
        Console.WriteLine(matches == 0
            ? "- Nessun driver locale corrisponde a hash noti in LOLDrivers."
            : "- " + matches + " driver locali CONFERMATI come vulnerabili.");
    }

    public static void CheckSuspiciousImports(List<string> driverFiles,
        HashSet<string> knownVulnHashes)
    {
        Console.WriteLine();
        Console.WriteLine("- Analisi API importate da ntoskrnl.exe (BYOVD check con hash)");
        Console.WriteLine(new string('-', 60));

        int suspCount = 0;

        var rtcoreFiles = driverFiles.Where(f => Path.GetFileName(f).IndexOf("rtcore", StringComparison.OrdinalIgnoreCase) >= 0).ToList();
        if (rtcoreFiles.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("--- DEBUG: Analisi rtcore64 ---");
            foreach (var rtFile in rtcoreFiles)
            {
                Console.WriteLine("  File: " + rtFile);
                string hash = DriverEnumerator.CalcolaSha256(rtFile);
                Console.WriteLine("  SHA256: " + (hash ?? "ERRORE"));
                if (hash != null && knownVulnHashes.Contains(hash))
                {
                    Console.WriteLine("  -> Saltato (già confermato vulnerabile per hash)");
                    continue;
                }
                List<string> imports = PeImportAnalyzer.ExtractImportedApis(rtFile, "ntoskrnl.exe");
                Console.WriteLine("  Import da ntoskrnl.exe: " + imports.Count);
                foreach (var imp in imports)
                    Console.WriteLine("    - " + imp);
            }
            Console.WriteLine();
        }

        foreach (var f in driverFiles.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string hash = DriverEnumerator.CalcolaSha256(f);
            if (hash != null && knownVulnHashes.Contains(hash)) continue;

            List<string> imports = PeImportAnalyzer.ExtractImportedApis(f, "ntoskrnl.exe");
            if (imports.Count == 0) continue;

            var found = imports
                .Where(api => SuspiciousKernelApis.ContainsKey(api))
                .Select(api => new { Api = api, Desc = SuspiciousKernelApis[api] })
                .ToList();

            if (found.Count == 0) continue;

            suspCount++;
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("\n- DRIVER SOSPETTO: " + f);
            foreach (var hit in found)
                Console.WriteLine("    Importa: " + hit.Api + " [" + hit.Desc + "]");
            Console.ResetColor();
        }

        Console.WriteLine(new string('-', 60));
        Console.WriteLine(suspCount == 0
            ? "- Nessun driver con API BYOVD-rilevanti trovato."
            : "- " + suspCount + " driver con API rilevati.");
    }

    public static async Task RunAsync()
    {
        string jsonPath = LocalCachePath;
        if (!File.Exists(jsonPath))
        {
            Console.WriteLine("- File cache non trovato – scaricamento in corso...");
            jsonPath = await DownloadDriversJsonAsync();
        }
        else
        {
            Console.WriteLine("- Uso cache locale: " + jsonPath);
        }

        var entries = ParseDriversJson(jsonPath);
        Console.WriteLine("- Caricati " + entries.Count + " driver da LOLDrivers (loldrivers.io)");

        var lolNames = ExtractDriverNamesFromTags(entries);
        var hashIndex = BuildHashIndex(entries);
        Console.WriteLine("- Indicizzati " + hashIndex.Count + " hash SHA256 unici");

        Console.WriteLine();
        Console.WriteLine("- Enumerazione file .sys su disco...");
        var diskFiles = DriverEnumerator.EnumerateSysFilesOnDisk();
        Console.WriteLine("- Trovati " + diskFiles.Count + " file .sys su disco");

        Console.WriteLine("- Esecuzione driverquery /v /fo csv...");
        var dqFiles = DriverEnumerator.EnumerateDriversViaDriverQuery();
        Console.WriteLine("- Trovati " + dqFiles.Count + " driver attivi corrispondenti via driverquery");

        var allFiles = diskFiles
            .Concat(dqFiles)
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        Console.WriteLine("- Totale file unici da verificare: " + allFiles.Count);

        CompareByName(lolNames, allFiles);
        CompareByHash(hashIndex, allFiles);

        var knownVulnHashes = new HashSet<string>(hashIndex.Keys, StringComparer.OrdinalIgnoreCase);

        CheckSuspiciousImports(dqFiles, knownVulnHashes);
        //CheckSuspiciousImports(allFiles, knownVulnHashes);
    }
}

