// ITzMeow80 — snippet di esempio in C#
// Lettura minimale dell'header PE per analisi forense.

using System;
using System.IO;

namespace ItzMeow80.Forensics
{
    /// <summary>Informazioni essenziali estratte da un file PE (EXE/DLL).</summary>
    public sealed class PeInfo
    {
        public ushort Machine { get; init; }
        public ushort NumberOfSections { get; init; }
        public bool Is64Bit { get; init; }
        public bool IsDll { get; init; }
        public uint SizeOfImage { get; init; }
        public string MachineName => Machine switch
        {
            0x014c => "x86 (i386)",
            0x8664 => "x64 (AMD64)",
            0xaa64 => "ARM64",
            _ => $"sconosciuto (0x{Machine:X4})"
        };
    }

    /// <summary>Legge le informazioni dall'header di un file PE.</summary>
    public static class PeInspector
    {
        private const ushort Pe32Magic = 0x10b;
        private const ushort Pe32PlusMagic = 0x20b;

        public static PeInfo Inspect(string path)
        {
            using var fs = File.OpenRead(path);
            using var br = new BinaryReader(fs);

            if (fs.Length < 0x40)
                throw new InvalidDataException("File troppo piccolo per essere un PE.");

            // "MZ"
            if (br.ReadUInt16() != 0x5A4D)
                throw new InvalidDataException("Firma MZ assente.");

            fs.Seek(0x3C, SeekOrigin.Begin);
            uint lfanew = br.ReadUInt32();

            fs.Seek(lfanew, SeekOrigin.Begin);
            if (br.ReadUInt32() != 0x00004550) // "PE\0\0"
                throw new InvalidDataException("Firma PE assente.");

            var machine = br.ReadUInt16();
            var sections = br.ReadUInt16();
            fs.Seek(12, SeekOrigin.Current); // TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
            var sizeOfOptionalHeader = br.ReadUInt16();
            fs.Seek(2, SeekOrigin.Current);  // Characteristics

            if (sizeOfOptionalHeader < 2)
                throw new InvalidDataException("Optional header assente.");

            var magic = br.ReadUInt16();
            bool is64 = magic == Pe32PlusMagic;
            if (magic != Pe32Magic && magic != Pe32PlusMagic)
                throw new InvalidDataException($"Magic non supportato: 0x{magic:X4}");

            // SizeOfImage si trova all'offset 56 dell'optional header
            fs.Seek(56 - 2, SeekOrigin.Current);
            uint sizeOfImage = br.ReadUInt32();

            // Il bit 0x2000 di Characteristics indica "DLL"
            fs.Seek(lfanew + 4 + 18, SeekOrigin.Begin); // Characteristics
            ushort characteristics = br.ReadUInt16();

            return new PeInfo
            {
                Machine = machine,
                NumberOfSections = sections,
                Is64Bit = is64,
                IsDll = (characteristics & 0x2000) != 0,
                SizeOfImage = sizeOfImage
            };
        }

        public static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: PeInspector <file.exe|file.dll>");
                return;
            }

            try
            {
                var info = Inspect(args[0]);
                Console.WriteLine($"Machine    : {info.MachineName}");
                Console.WriteLine($"Sections   : {info.NumberOfSections}");
                Console.WriteLine($"Bitness    : {(info.Is64Bit ? "64-bit" : "32-bit")}");
                Console.WriteLine($"Type       : {(info.IsDll ? "DLL" : "EXE")}");
                Console.WriteLine($"SizeOfImage: 0x{info.SizeOfImage:X8}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Errore: {ex.Message}");
                Environment.ExitCode = 1;
            }
        }
    }
}
