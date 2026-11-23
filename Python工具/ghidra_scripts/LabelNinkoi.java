// Label and export verified PCSG00602 font and script functions.
// @category Ninkoi
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class LabelNinkoi extends GhidraScript {
    private static final String[][] LABELS = {
        {"8105b650", "MountArchivesAndLoadFonts", "Mounts the five CPK files and loads both FFU fonts."},
        {"810cec5a", "QueueFontResourceLoad", "Queues an archive resource for font installation."},
        {"810cebd2", "OnFontResourceLoaded", "Copies the unpacked FFU and calls the installer."},
        {"810c585a", "InstallFontResource", "Initializes the FFU and its texture cache."},
        {"810c2afe", "InitUftFont", "Reads the UFT header and selects the encoded-text mode at FFU +0xC."},
        {"810c2a08", "CheckFontMagicAndEndian", "Recognizes UFT and its alternate endian header."},
        {"810c33cc", "ReadEncodedCharacter", "In the current FFU mode, packs Shift-JIS bytes for glyph lookup."},
        {"810c25a4", "FindUftGlyphRecord", "Uses half-open FFU ranges, then indexes the 8-byte glyph records."},
        {"810c3a08", "CacheUftGlyph", "Finds a glyph record and populates the runtime texture cache."},
        {"810c3026", "DispatchGlyphBitmapConverter", "Reads uint32 bitmap offset at record+4 and dispatches by FFU format."},
        {"81098ede", "StartLoadedScript", "Starts execution of the loaded scenario resource."},
        {"8109a430", "FindStcm2ScriptExport", "Resolves a named STCM2L export and initializes its execution state."},
        {"810367e0", "RegisterSystemStringResource", "Registers a loaded system string library."},
    };

    @Override
    public void run() throws Exception {
        Path output = Path.of(getScriptArgs()[0]);
        Files.createDirectories(output);
        StringBuilder index = new StringBuilder("address\tname\tevidence\n");
        for (String[] label : LABELS) {
            Function function = getFunctionAt(toAddr(label[0]));
            if (function == null) {
                throw new IllegalStateException("Missing function " + label[0]);
            }
            function.setName(label[1], SourceType.USER_DEFINED);
            function.setComment(label[2]);
            index.append(String.join("\t", label)).append('\n');
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            for (String[] label : LABELS) {
                DecompileResults result = decompiler.decompileFunction(getFunctionAt(toAddr(label[0])), 30, monitor);
                if (!result.decompileCompleted()) {
                    throw new IllegalStateException(result.getErrorMessage());
                }
                Files.writeString(output.resolve(label[0] + "_" + label[1] + ".c"),
                    result.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
            }
            Files.writeString(output.resolve("key_functions.tsv"), index, StandardCharsets.UTF_8);
        } finally {
            decompiler.dispose();
        }
    }
}
