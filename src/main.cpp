#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

enum class BinaryType {
    PE,   // Windows Portable Executable
    ELF,  // Linux ELF
    MACHO // macOS Mach-O
};

struct Args {
    fs::path binaryPath;
    fs::path outDir;
    std::vector<fs::path> qmlRoots;
    std::vector<std::string> languages;
};

// Forward declaration for helper used in parseArgs
static std::vector<std::string> splitPaths(const std::string& s, char sep);

static void printUsage(const char* argv0) {
    std::cerr << "Usage: " << argv0 << " --bin <path-to-binary> --out <output-dir> [--qml-root <dir>]... [--languages <lang[,lang...>]>\n";
}

static std::optional<Args> parseArgs(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string_view a(argv[i]);
        if (a == "--bin" && i + 1 < argc) {
            args.binaryPath = fs::path(argv[++i]);
        } else if (a == "--out" && i + 1 < argc) {
            args.outDir = fs::path(argv[++i]);
        } else if (a == "--qml-root" && i + 1 < argc) {
            args.qmlRoots.emplace_back(argv[++i]);
        } else if (a == "--languages" && i + 1 < argc) {
            std::string langs(argv[++i]);
            for (const auto& item : splitPaths(langs, ',')) {
                if (!item.empty()) args.languages.push_back(item);
            }
        } else if (a == "-h" || a == "--help") {
            printUsage(argv[0]);
            return std::nullopt;
        } else {
            std::cerr << "Unknown argument: " << a << "\n";
            printUsage(argv[0]);
            return std::nullopt;
        }
    }
    if (args.binaryPath.empty() || args.outDir.empty()) {
        printUsage(argv[0]);
        return std::nullopt;
    }
    return args;
}

// Detect binary type by reading magic bytes.
// - PE: starts with 'MZ' then PE header at e_lfanew offset contains 'PE\0\0'
// - ELF: 0x7F 'E' 'L' 'F'
// - Mach-O: multiple magic values, e.g., 0xFEEDFACE, 0xFEEDFACF, etc
static std::optional<BinaryType> detectBinaryType(const fs::path& p, std::string& whyNot) {
    std::error_code ec;
    const auto fileSize = fs::file_size(p, ec);
    if (ec) { whyNot = "cannot stat file"; return std::nullopt; }

    std::ifstream f(p, std::ios::binary);
    if (!f) { whyNot = "cannot open file"; return std::nullopt; }

    // Read a small prefix (we’ll read more on demand)
    std::uint8_t buf[16] = {0};
    f.read(reinterpret_cast<char*>(buf), sizeof(buf));
    const std::streamsize n = f.gcount();
    if (n < 4) { whyNot = "file too small"; return std::nullopt; }

    auto u32le_at = [&](std::uint64_t off, std::uint32_t& out) -> bool {
        if (off + 4 > fileSize) return false;
        std::uint8_t t[4];
        f.clear(); f.seekg(static_cast<std::streamoff>(off), std::ios::beg);
        if (!f.read(reinterpret_cast<char*>(t), 4)) return false;
        out = static_cast<std::uint32_t>(t[0]) |
              (static_cast<std::uint32_t>(t[1]) << 8) |
              (static_cast<std::uint32_t>(t[2]) << 16) |
              (static_cast<std::uint32_t>(t[3]) << 24);
        return true;
    };
    auto u32be_at = [&](std::uint64_t off, std::uint32_t& out) -> bool {
        if (off + 4 > fileSize) return false;
        std::uint8_t t[4];
        f.clear(); f.seekg(static_cast<std::streamoff>(off), std::ios::beg);
        if (!f.read(reinterpret_cast<char*>(t), 4)) return false;
        out = (static_cast<std::uint32_t>(t[0]) << 24) |
              (static_cast<std::uint32_t>(t[1]) << 16) |
              (static_cast<std::uint32_t>(t[2]) << 8)  |
               static_cast<std::uint32_t>(t[3]);
        return true;
    };
    auto u32be_from0 = [&]() -> std::uint32_t {
        return (static_cast<std::uint32_t>(buf[0]) << 24) |
               (static_cast<std::uint32_t>(buf[1]) << 16) |
               (static_cast<std::uint32_t>(buf[2]) << 8)  |
                static_cast<std::uint32_t>(buf[3]);
    };

    // ELF: 0x7F 'E' 'L' 'F'
    if (buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
        return BinaryType::ELF; // ELF magic as per ELF spec.
    }

    // PE: 'MZ' then 'PE\0\0' at e_lfanew
    if (buf[0] == 'M' && buf[1] == 'Z') {
        std::uint32_t e_lfanew = 0;
        if (fileSize >= 0x40 && u32le_at(0x3C, e_lfanew)) {
            if (e_lfanew <= fileSize - 4) {
                std::uint8_t sig[4] = {0};
                f.clear(); f.seekg(static_cast<std::streamoff>(e_lfanew), std::ios::beg);
                if (f.read(reinterpret_cast<char*>(sig), 4) && sig[0]=='P' && sig[1]=='E' && sig[2]==0 && sig[3]==0) {
                    return BinaryType::PE;
                }
            }
        }
        // Fall through; some non-PE files start with MZ.
    }

    // Mach-O: thin and fat (universal)
    constexpr std::uint32_t MH_MAGIC     = 0xFEEDFACE;
    constexpr std::uint32_t MH_CIGAM     = 0xCEFAEDFE;
    constexpr std::uint32_t MH_MAGIC_64  = 0xFEEDFACF;
    constexpr std::uint32_t MH_CIGAM_64  = 0xCFFAEDFE;

    constexpr std::uint32_t FAT_MAGIC    = 0xCAFEBABE;
    constexpr std::uint32_t FAT_CIGAM    = 0xBEBAFECA;
    constexpr std::uint32_t FAT_MAGIC_64 = 0xCAFEBABF;
    constexpr std::uint32_t FAT_CIGAM_64 = 0xBFBAFECA;

    const std::uint32_t be = u32be_from0();

    // Thin Mach-O (both endians, 32/64)
    if (be == MH_MAGIC || be == MH_CIGAM || be == MH_MAGIC_64 || be == MH_CIGAM_64) {
        return BinaryType::MACHO;
    }

    // Fat Mach-O (universal)
    if (be == FAT_MAGIC || be == FAT_MAGIC_64 || be == FAT_CIGAM || be == FAT_CIGAM_64) {
        // Quick sanity check to avoid Java .class false positives (also CAFEBABE):
        // Read nfat_arch and ensure it's plausible, and header fits.
        std::uint32_t nfat_arch = 0;
        bool be_header = (be == FAT_MAGIC || be == FAT_MAGIC_64);
        bool ok = be_header ? u32be_at(4, nfat_arch) : u32le_at(4, nfat_arch);
        if (!ok) { whyNot = "truncated fat header"; return std::nullopt; }

        if (nfat_arch == 0 || nfat_arch > 64) { // typical range is small (1–5)
            whyNot = "CAFEBABE but invalid nfat_arch (likely not Mach-O)";
            return std::nullopt;
        }

        // Minimal size check for header + arch table (don’t assume Apple headers available)
        const std::uint64_t minEntrySize = (be == FAT_MAGIC_64 || be == FAT_CIGAM_64) ? 32 /* fat_arch_64 */ : 20 /* fat_arch */;
        const std::uint64_t need = 8 + static_cast<std::uint64_t>(nfat_arch) * minEntrySize;
        if (need > fileSize) { whyNot = "fat header larger than file"; return std::nullopt; }

        return BinaryType::MACHO;
    }

    whyNot = "unknown binary format";
    return std::nullopt;
}

static const char* toString(BinaryType t) {
    switch (t) {
        case BinaryType::PE: return "PE";
        case BinaryType::ELF: return "ELF";
        case BinaryType::MACHO: return "Mach-O";
    }
    return "?";
}

static bool isVerbose() {
    static bool v = [](){ const char* e = std::getenv("CROSSDEPLOYQT_VERBOSE"); return e && *e; }();
    return v;
}

// Stubs for later platform-specific actions
struct DeployPlan {
    BinaryType type;
    fs::path binaryPath;
    fs::path outputRoot;
    std::vector<fs::path> qmlRoots; // optional CLI-provided QML roots
    std::vector<std::string> languages; // optional languages
};

static std::string getEnv(const char* key) {
    const char* v = std::getenv(key);
    return v ? std::string(v) : std::string();
}

static void setEnv(const std::string& key, const std::string& value) {
#if defined(_WIN32)
    _putenv_s(key.c_str(), value.c_str());
#else
    setenv(key.c_str(), value.c_str(), 1);
#endif
}

static std::vector<std::string> splitPaths(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static std::string runCommand(const std::string& cmd, int& exitCode) {
    std::array<char, 4096> buffer{};
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        exitCode = -1;
        return {};
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        result.append(buffer.data());
    }
    exitCode = pclose(pipe);
#if !defined(_WIN32)
    if (exitCode != -1) {
        // Decode wait status if available
        if (WIFEXITED(exitCode)) {
            exitCode = WEXITSTATUS(exitCode);
        }
    }
#endif
    return result;
}

static std::string shellEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (char c : s) {
        if (c == '\'') {
            out += "'\\''"; // end quote, escaped quote, reopen
        } else {
            out.push_back(c);
        }
    }
    out.push_back('\'');
    return out;
}

struct QtPathsInfo {
    fs::path qtInstallLibs;
    fs::path qtInstallBins;
    fs::path qtInstallPrefix;
    fs::path qtInstallPlugins;
    fs::path qtInstallQml;
    fs::path qtInstallTranslations;
};

static QtPathsInfo queryQtPaths() {
    QtPathsInfo info;
    int code = 0;
    std::string qtpathsBin = getEnv("QTPATHS_BIN");
    if (qtpathsBin.empty()) qtpathsBin = "qtpaths";
    auto trim = [](std::string s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
        size_t i = 0;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        return s.substr(i);
    };
    std::string libs = runCommand(qtpathsBin + " --query QT_INSTALL_LIBS", code);
    if (code == 0) info.qtInstallLibs = fs::path(trim(libs));
    std::string bins = runCommand(qtpathsBin + " --query QT_INSTALL_BINS", code);
    if (code == 0) info.qtInstallBins = fs::path(trim(bins));
    std::string prefix = runCommand(qtpathsBin + " --query QT_INSTALL_PREFIX", code);
    if (code == 0) info.qtInstallPrefix = fs::path(trim(prefix));
    std::string plugins = runCommand(qtpathsBin + " --query QT_INSTALL_PLUGINS", code);
    if (code == 0) info.qtInstallPlugins = fs::path(trim(plugins));
    std::string qml = runCommand(qtpathsBin + " --query QT_INSTALL_QML", code);
    if (code == 0) info.qtInstallQml = fs::path(trim(qml));
    std::string trans = runCommand(qtpathsBin + " --query QT_INSTALL_TRANSLATIONS", code);
    if (code == 0) info.qtInstallTranslations = fs::path(trim(trans));
    // Validate that queried directories exist; otherwise, leave empty so we fall back to env paths
    std::error_code ec;
    if (!info.qtInstallQml.empty() && !fs::exists(info.qtInstallQml, ec)) info.qtInstallQml.clear();
    if (!info.qtInstallPlugins.empty() && !fs::exists(info.qtInstallPlugins, ec)) info.qtInstallPlugins.clear();
    if (!info.qtInstallTranslations.empty() && !fs::exists(info.qtInstallTranslations, ec)) info.qtInstallTranslations.clear();
    return info;
}

struct ResolveContext {
    DeployPlan plan;
    QtPathsInfo qt;
    std::vector<fs::path> searchDirs; // directories used to resolve deps
    std::vector<fs::path> qmlImportPaths; // directories for QML imports
    std::vector<fs::path> cliQmlRoots; // from --qml-root
    std::unordered_set<std::string> searchDirSet; // for dedup
};

static char pathListSep() {
#if defined(_WIN32)
    return ';';
#else
    return ':';
#endif
}

static void addSearchDir(ResolveContext& ctx, const fs::path& dir) {
    if (dir.empty()) return;
    std::error_code ec;
    fs::path can = fs::weakly_canonical(dir, ec);
    const std::string key = (ec ? dir : can).string();
    if (ctx.searchDirSet.insert(key).second) {
        ctx.searchDirs.emplace_back(key);
    }
}

static void ensureEnvForResolution(ResolveContext& ctx) {
    // Always include binary directory first
    addSearchDir(ctx, ctx.plan.binaryPath.parent_path());

    const auto qtLibs = ctx.qt.qtInstallLibs;
    const auto qtBins = ctx.qt.qtInstallBins;

    if (ctx.plan.type == BinaryType::ELF) {
        // LD_LIBRARY_PATH
        std::string ld = getEnv("LD_LIBRARY_PATH");
        std::vector<std::string> ldv = splitPaths(ld, pathListSep());
        for (const auto& p : ldv) if (!p.empty()) addSearchDir(ctx, p);
        if (!qtLibs.empty()) addSearchDir(ctx, qtLibs);
        // Prepend Qt libs to LD_LIBRARY_PATH for subprocesses
        if (!qtLibs.empty()) {
            std::string newLd = qtLibs.string();
            if (!ld.empty()) newLd += std::string(1, pathListSep()) + ld;
            setEnv("LD_LIBRARY_PATH", newLd);
        }
    } else if (ctx.plan.type == BinaryType::PE) {
        // PATH search for .dll
        std::string path = getEnv("PATH");
        std::vector<std::string> pv = splitPaths(path, pathListSep());
        for (const auto& p : pv) if (!p.empty()) addSearchDir(ctx, p);
        if (!qtBins.empty()) addSearchDir(ctx, qtBins); // MinGW Qt DLLs live in bin
        // Prepend Qt bins to PATH
        if (!qtBins.empty()) {
            std::string newPath = qtBins.string();
            if (!path.empty()) newPath += std::string(1, pathListSep()) + path;
            setEnv("PATH", newPath);
        }
        // Derive QML import paths from MinGW PATH bin entries: ../qml and ../lib/qt-6/qml
        for (const auto& p : pv) {
            if (p.size() > 4 && p.rfind("/bin", p.size() - 4) != std::string::npos) {
                fs::path base = fs::path(p).parent_path();
                std::error_code ec2;
                fs::path q1 = base / "qml";
                if (fs::exists(q1, ec2)) ctx.qmlImportPaths.push_back(q1);
                ec2.clear();
                fs::path q2 = base / "lib" / "qt-6" / "qml";
                if (fs::exists(q2, ec2)) ctx.qmlImportPaths.push_back(q2);
            }
        }
    } else {
        // Mach-O: DYLD paths and frameworks
        std::string dyld = getEnv("DYLD_LIBRARY_PATH");
        for (const auto& p : splitPaths(dyld, pathListSep())) if (!p.empty()) addSearchDir(ctx, p);
        std::string dyldfw = getEnv("DYLD_FRAMEWORK_PATH");
        for (const auto& p : splitPaths(dyldfw, pathListSep())) if (!p.empty()) addSearchDir(ctx, p);
        if (!qtLibs.empty()) addSearchDir(ctx, qtLibs);
        // Prepend Qt libs to DYLD vars for subprocesses
        if (!qtLibs.empty()) {
            std::string newDyld = qtLibs.string();
            if (!dyld.empty()) newDyld += std::string(1, pathListSep()) + dyld;
            setEnv("DYLD_LIBRARY_PATH", newDyld);
            std::string newDyldFw = qtLibs.string();
            if (!dyldfw.empty()) newDyldFw += std::string(1, pathListSep()) + dyldfw;
            setEnv("DYLD_FRAMEWORK_PATH", newDyldFw);
        }
    }

    // Build QML import paths: include QT_INSTALL_QML and env QML2_IMPORT_PATH
    if (!ctx.qt.qtInstallQml.empty()) {
        std::error_code ec;
        if (fs::exists(ctx.qt.qtInstallQml, ec)) ctx.qmlImportPaths.push_back(ctx.qt.qtInstallQml);
    }
    std::string qml2Env = getEnv("QML2_IMPORT_PATH");
    for (const auto& p : splitPaths(qml2Env, pathListSep())) {
        if (p.empty()) continue;
        std::error_code ec;
        if (fs::exists(p, ec)) ctx.qmlImportPaths.emplace_back(p);
    }
    // Attach CLI-provided roots
    for (const auto& r : ctx.plan.qmlRoots) ctx.cliQmlRoots.push_back(r);
    // Env QML_ROOT may be colon-separated for multiple roots
    std::string envRoots = getEnv("QML_ROOT");
    for (const auto& p : splitPaths(envRoots, pathListSep())) if (!p.empty()) ctx.cliQmlRoots.emplace_back(p);
}

// --- ELF and Mach-O token expansion helpers ---
// Forward declaration used by resolve helpers
static std::optional<fs::path> findLibrary(const std::string& nameOrPath, const ResolveContext& ctx);

static std::string expandElfOrigin(std::string p, const fs::path& subject) {
    const std::string base = subject.parent_path().string();
    auto sub = [&](const char* pat){
        size_t pos = 0;
        const size_t n = std::strlen(pat);
        while ((pos = p.find(pat, pos)) != std::string::npos) {
            p.replace(pos, n, base);
            pos += base.size();
        }
    };
    sub("${ORIGIN}");
    sub("$ORIGIN");
    return p;
}

struct MachORpaths { std::vector<std::string> rpaths; };

static MachORpaths parseMachORpaths(const fs::path& bin) {
    MachORpaths r;
    int code = 0;
    std::string out = runCommand(std::string("llvm-otool -l ") + shellEscape(bin.string()), code);
    if (code != 0 || out.empty()) return r;
    std::istringstream iss(out);
    std::string line;
    bool inRpath = false;
    while (std::getline(iss, line)) {
        if (line.find("cmd LC_RPATH") != std::string::npos) { inRpath = true; continue; }
        if (inRpath) {
            auto pos = line.find("path ");
            if (pos != std::string::npos) {
                std::string s = line.substr(pos + 5);
                auto paren = s.find(" (");
                if (paren != std::string::npos) s = s.substr(0, paren);
                // trim
                while (!s.empty() && (s.back()=='\n' || s.back()=='\r' || s.back()==' ' || s.back()=='\t')) s.pop_back();
                size_t i=0; while (i<s.size() && (s[i]==' '||s[i]=='\t')) ++i; s = s.substr(i);
                if (!s.empty()) r.rpaths.push_back(s);
                inRpath = false;
            }
        }
    }
    return r;
}

static fs::path expandMachOToken(const std::string& p, const fs::path& subjectBin, const fs::path& mainExe) {
    fs::path dir = subjectBin.parent_path();
    if (p.rfind("@loader_path/", 0) == 0)        return fs::weakly_canonical(dir / p.substr(13));
    if (p.rfind("@executable_path/", 0) == 0)    return fs::weakly_canonical(mainExe.parent_path() / p.substr(17));
    return fs::path(p);
}

// --- Parse result caching (declared later after ParseResult) ---

static std::optional<fs::path> resolveELFRef(const std::string& ref,
                                             const fs::path& subject,
                                             const std::vector<std::string>& subjectRpaths,
                                             const ResolveContext& ctx) {
    std::error_code ec;
    fs::path p(ref);
    if (p.is_absolute() && fs::exists(p, ec)) return fs::weakly_canonical(p, ec);
    // Try subject rpaths first
    for (const auto& rp : subjectRpaths) {
        fs::path base = expandElfOrigin(rp, subject);
        fs::path cand = base / ref;
        std::error_code ec2;
        if (fs::exists(cand, ec2)) return fs::weakly_canonical(cand, ec2);
    }
    // Fallback: global search dirs
    return findLibrary(ref, ctx);
}

static std::optional<fs::path> resolveMachORef(const std::string& ref,
                                               const fs::path& subject,
                                               const std::vector<std::string>& subjectRpaths,
                                               const ResolveContext& ctx,
                                               const fs::path& mainExe) {
    std::error_code ec;
    fs::path p(ref);
    if (p.is_absolute() && fs::exists(p, ec)) return fs::weakly_canonical(p, ec);
    if (ref.rfind("@loader_path/", 0) == 0 || ref.rfind("@executable_path/", 0) == 0) {
        fs::path cand = expandMachOToken(ref, subject, mainExe);
        if (fs::exists(cand, ec)) return fs::weakly_canonical(cand, ec);
    }
    if (ref.rfind("@rpath/", 0) == 0) {
        const std::string tail = ref.substr(7);
        for (const auto& rp : subjectRpaths) {
            fs::path base = expandMachOToken(rp, subject, mainExe);
            fs::path cand = base / tail;
            std::error_code ec2;
            if (fs::exists(cand, ec2)) return fs::weakly_canonical(cand, ec2);
        }
    }
    // Fallback: global search dirs
    return findLibrary(ref, ctx);
}

static bool isQtLibraryName(const std::string& name) {
    // Simple heuristic for Qt 6 libs across platforms
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
    return lower.find("qt6") != std::string::npos || lower.rfind("qt", 0) == 0;
}

static bool shouldDeployLibrary(const fs::path& libPath, const std::string& sonameOrDll, BinaryType type, const ResolveContext& ctx) {
    // Exclude obvious system libraries; include Qt and anything within Qt paths or alongside the binary
    const fs::path dir = libPath.has_parent_path() ? libPath.parent_path() : fs::path();
    const std::string base = libPath.filename().string();
    auto inQtPath = [&]() -> bool {
        if (!ctx.qt.qtInstallLibs.empty() && libPath.string().find(ctx.qt.qtInstallLibs.string()) == 0) return true;
        if (!ctx.qt.qtInstallBins.empty() && libPath.string().find(ctx.qt.qtInstallBins.string()) == 0) return true;
        if (!ctx.qt.qtInstallPrefix.empty() && libPath.string().find(ctx.qt.qtInstallPrefix.string()) == 0) return true;
        return false;
    };
    if (type == BinaryType::ELF) {
        if (libPath.string().rfind("/lib", 0) == 0 || libPath.string().rfind("/usr/lib", 0) == 0) {
            return isQtLibraryName(base) || inQtPath();
        }
        return isQtLibraryName(base) || inQtPath() || dir == ctx.plan.binaryPath.parent_path();
    } else if (type == BinaryType::PE) {
        std::string lower = base; std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        static const char* systemPrefixes[] = {"api-ms-win-", "ext-ms-win-"};
        for (auto p : systemPrefixes) { if (lower.rfind(p, 0) == 0) return false; }
        static const char* systemDlls[] = {
            "kernel32.dll","user32.dll","gdi32.dll","shell32.dll","ole32.dll","advapi32.dll","ws2_32.dll",
            "ntdll.dll","sechost.dll","shlwapi.dll","comdlg32.dll","imm32.dll","version.dll","winmm.dll","cfgmgr32.dll"
        };
        for (auto d : systemDlls) if (lower == d) return false;
        // Include if path is within Nix store (cross env), Qt-ish, in Qt path, or alongside binary
        const bool inNixStore = libPath.string().rfind("/nix/store/", 0) == 0;
        return inNixStore || isQtLibraryName(base) || inQtPath() || dir == ctx.plan.binaryPath.parent_path();
    } else { // Mach-O
        std::string s = libPath.string();
        if (s.rfind("/System/Library/Frameworks/", 0) == 0 || s.rfind("/usr/lib/", 0) == 0) return false;
        return isQtLibraryName(base) || inQtPath() || dir == ctx.plan.binaryPath.parent_path();
    }
}

static std::optional<fs::path> findLibrary(const std::string& nameOrPath, const ResolveContext& ctx) {
    fs::path p(nameOrPath);
    // Absolute path resolves directly
    std::error_code ec;
    if (p.is_absolute() && fs::exists(p, ec)) return fs::weakly_canonical(p, ec);
    // Relative path might include @rpath etc., ignore those here
    // Search in known directories
    for (const auto& dir : ctx.searchDirs) {
        fs::path cand = dir / nameOrPath;
        std::error_code ec2;
        if (fs::exists(cand, ec2)) return fs::weakly_canonical(cand, ec2);
    }
    return std::nullopt;
}

struct ParseResult {
    std::vector<std::string> dependencies; // names or paths
    std::vector<std::string> rpaths;        // for ELF (RPATH/RUNPATH)
};

// Forward declarations for platform parsers used by cache helpers
static ParseResult parsePE(const fs::path& bin);
static ParseResult parseELF(const fs::path& bin);
static ParseResult parseMachO(const fs::path& bin);

// Now that ParseResult is known, define caching helpers
struct ParseCache {
    std::unordered_map<std::string, ParseResult> parseByPath;
    std::unordered_map<std::string, std::vector<std::string>> machoRpathsByPath;
};

static std::string canonicalKey(const fs::path& p) {
    std::error_code ec;
    fs::path c = fs::weakly_canonical(p, ec);
    return (ec ? p : c).string();
}

static const ParseResult& parseDepsCached(const fs::path& subject, BinaryType type, ParseCache& cache) {
    const std::string key = canonicalKey(subject);
    auto it = cache.parseByPath.find(key);
    if (it != cache.parseByPath.end()) return it->second;
    ParseResult pr;
    if (type == BinaryType::ELF) pr = parseELF(subject);
    else if (type == BinaryType::PE) pr = parsePE(subject);
    else pr = parseMachO(subject);
    auto [insIt, _] = cache.parseByPath.emplace(key, std::move(pr));
    return insIt->second;
}

static const std::vector<std::string>& machoRpathsFor(const fs::path& subject, ParseCache& cache) {
    const std::string key = canonicalKey(subject);
    auto it = cache.machoRpathsByPath.find(key);
    if (it != cache.machoRpathsByPath.end()) return it->second;
    auto r = parseMachORpaths(subject);
    auto [insIt, _] = cache.machoRpathsByPath.emplace(key, std::move(r.rpaths));
    return insIt->second;
}

static ParseResult parsePE(const fs::path& bin) {
    ParseResult r;
    int code = 0;
    std::string out = runCommand("x86_64-w64-mingw32-objdump -p " + shellEscape(bin.string()), code);
    if (code != 0) return r;
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        //   DLL Name: Qt6Core.dll
        auto pos = line.find("DLL Name:");
        if (pos != std::string::npos) {
            std::string name = line.substr(pos + 9);
            // trim
            size_t i = 0; while (i < name.size() && (name[i] == ' ' || name[i] == '\t')) ++i;
            name = name.substr(i);
            while (!name.empty() && (name.back() == '\r' || name.back() == '\n' || name.back() == ' ' || name.back() == '\t')) name.pop_back();
            if (!name.empty()) r.dependencies.push_back(name);
        }
    }
    return r;
}

static ParseResult parseELF(const fs::path& bin) {
    ParseResult r;
    int code = 0;
    std::string out = runCommand("objdump -p " + shellEscape(bin.string()), code);
    if (code != 0) return r;
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        //  NEEDED               libQt6Core.so.6
        //  RPATH                /foo:/bar
        //  RUNPATH              /foo:/bar
        auto npos = line.find("NEEDED");
        if (npos != std::string::npos) {
            auto pos = line.find_last_of(' ');
            if (pos != std::string::npos && pos + 1 < line.size()) {
                std::string name = line.substr(pos + 1);
                while (!name.empty() && (name.back() == '\r' || name.back() == '\n')) name.pop_back();
                if (!name.empty()) r.dependencies.push_back(name);
            }
        }
        auto rppos = line.find("RPATH");
        if (rppos != std::string::npos) {
            auto pos = line.find_last_of(' ');
            if (pos != std::string::npos && pos + 1 < line.size()) {
                std::string paths = line.substr(pos + 1);
                for (const auto& p : splitPaths(paths, ':')) r.rpaths.push_back(p);
            }
        }
        auto runpos = line.find("RUNPATH");
        if (runpos != std::string::npos) {
            auto pos = line.find_last_of(' ');
            if (pos != std::string::npos && pos + 1 < line.size()) {
                std::string paths = line.substr(pos + 1);
                for (const auto& p : splitPaths(paths, ':')) r.rpaths.push_back(p);
            }
        }
    }
    return r;
}

static std::optional<std::string> queryElfSoname(const fs::path& soPath) {
    int code = 0;
    std::string out = runCommand("objdump -p " + shellEscape(soPath.string()), code);
    if (code != 0) return std::nullopt;
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        auto pos = line.find("SONAME");
        if (pos != std::string::npos) {
            auto sp = line.find_last_of(' ');
            if (sp != std::string::npos && sp + 1 < line.size()) {
                std::string name = line.substr(sp + 1);
                while (!name.empty() && (name.back() == '\r' || name.back() == '\n')) name.pop_back();
                if (!name.empty()) return name;
            }
        }
    }
    return std::nullopt;
}

static ParseResult parseMachO(const fs::path& bin) {
    ParseResult r;
    int code = 0;
    std::string out = runCommand("llvm-otool -L " + shellEscape(bin.string()), code);
    if (code != 0) return r;
    std::istringstream iss(out);
    std::string line;
    bool first = true;
    while (std::getline(iss, line)) {
        if (first) { first = false; continue; } // skip header line containing the binary path
        //   /path/to/QtCore.framework/Versions/A/QtCore (compatibility version ..., current version ...)
        // or @rpath/QtCore.framework/...
        // Extract token until first space or '(' character
        size_t start = 0; while (start < line.size() && std::isspace(static_cast<unsigned char>(line[start]))) ++start;
        size_t end = start;
        while (end < line.size() && !std::isspace(static_cast<unsigned char>(line[end])) && line[end] != '(') ++end;
        if (end > start) {
            r.dependencies.push_back(line.substr(start, end - start));
        }
    }
    return r;
}

static std::vector<fs::path> resolveAndRecurse(const DeployPlan& plan) {
    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    ensureEnvForResolution(ctx);

    // Parse initial dependencies (per-platform) with cache
    ParseCache cache;
    const ParseResult& pr = parseDepsCached(plan.binaryPath, plan.type, cache);

    std::vector<fs::path> stack;
    std::vector<std::string> initial = pr.dependencies;
    for (const auto& dep : initial) {
        std::optional<fs::path> found;
        if (plan.type == BinaryType::ELF) {
            found = resolveELFRef(dep, plan.binaryPath, pr.rpaths, ctx);
        } else if (plan.type == BinaryType::PE) {
            found = findLibrary(dep, ctx);
        } else {
            const auto& rps = machoRpathsFor(plan.binaryPath, cache);
            found = resolveMachORef(dep, plan.binaryPath, rps, ctx, plan.binaryPath);
        }
        if (found) {
            if (shouldDeployLibrary(*found, dep, plan.type, ctx)) stack.push_back(*found);
        } else if (isQtLibraryName(dep)) {
            throw std::runtime_error("Required Qt library not found in search paths: " + dep);
        }
    }

    std::unordered_set<std::string> visited; // canonical path strings
    while (!stack.empty()) {
        fs::path cur = stack.back();
        stack.pop_back();
        if (isVerbose()) std::cout << "[resolve] Inspect: " << cur << "\n";
        std::error_code ec;
        fs::path canon = fs::weakly_canonical(cur, ec);
        std::string key = ec ? cur.string() : canon.string();
        if (visited.count(key)) continue;
        visited.insert(key);

        const ParseResult& prChild = parseDepsCached(cur, plan.type, cache);

        for (const auto& dep : prChild.dependencies) {
            if (isVerbose()) std::cout << "[resolve]   dep: " << dep << "\n";
            std::optional<fs::path> found;
            if (plan.type == BinaryType::ELF) {
                found = resolveELFRef(dep, cur, prChild.rpaths, ctx);
            } else if (plan.type == BinaryType::PE) {
                found = findLibrary(dep, ctx);
            } else {
                const auto& rps = machoRpathsFor(cur, cache);
                found = resolveMachORef(dep, cur, rps, ctx, plan.binaryPath);
            }
            if (found) {
                if (shouldDeployLibrary(*found, dep, plan.type, ctx)) {
                    if (isVerbose()) std::cout << "[resolve]     push: " << *found << "\n";
                    stack.push_back(*found);
                }
            } else {
                // Only error if looks like a Qt lib or within Qt path token patterns
                if (isQtLibraryName(dep)) {
                    throw std::runtime_error("Required Qt library not found in search paths: " + dep);
                }
            }
        }
    }

    std::vector<fs::path> libs;
    libs.reserve(visited.size());
    for (const auto& k : visited) {
        if (k == plan.binaryPath.string()) continue;
        libs.emplace_back(k);
    }
    return libs;
}

static void ensureOutputLayout(const DeployPlan& plan) {
    std::error_code ec;
    if (!fs::exists(plan.outputRoot)) {
        fs::create_directories(plan.outputRoot, ec);
        if (ec) {
            throw std::runtime_error("failed to create output root: " + plan.outputRoot.string());
        }
    }
    switch (plan.type) {
        case BinaryType::PE: {
            // On Windows/Linux dist style: plugins/, qml/, translations/
            fs::create_directories(plan.outputRoot / "plugins", ec);
            fs::create_directories(plan.outputRoot / "plugins" / "platforms", ec);
            fs::create_directories(plan.outputRoot / "plugins" / "imageformats", ec);
            fs::create_directories(plan.outputRoot / "qml", ec);
            fs::create_directories(plan.outputRoot / "translations", ec);
            break;
        }
        case BinaryType::ELF: {
            fs::create_directories(plan.outputRoot / "plugins", ec);
            fs::create_directories(plan.outputRoot / "plugins" / "platforms", ec);
            fs::create_directories(plan.outputRoot / "plugins" / "imageformats", ec);
            fs::create_directories(plan.outputRoot / "qml", ec);
            fs::create_directories(plan.outputRoot / "translations", ec);
            break;
        }
        case BinaryType::MACHO: {
            // Basic macOS bundle-like layout stub; refined later
            fs::create_directories(plan.outputRoot / "Contents" / "MacOS", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "Frameworks", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "Resources" / "qml", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "PlugIns" / "quick", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "PlugIns" / "platforms", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "PlugIns" / "imageformats", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "Resources" / "translations", ec);
            break;
        }
    }
}

// Dependency resolution stubs to implement next
static bool copyFileOverwrite(const fs::path& from, const fs::path& to) {
    std::error_code ec;
    fs::create_directories(to.parent_path(), ec);
    ec.clear();
    // Skip if destination exists with same size and timestamp newer-or-equal to source
    std::error_code se1, se2;
    auto srcStatus = fs::status(from, se1);
    auto dstStatus = fs::status(to, se2);
    if (!se2 && fs::exists(to) && fs::is_regular_file(dstStatus)) {
        std::error_code te1, te2;
        auto srcSize = fs::file_size(from, te1);
        auto dstSize = fs::file_size(to, te2);
        std::error_code le1, le2;
        auto srcTime = fs::last_write_time(from, le1);
        auto dstTime = fs::last_write_time(to, le2);
        if (!te1 && !te2 && !le1 && !le2 && srcSize == dstSize && dstTime >= srcTime) {
            if (isVerbose()) std::cout << "[copy-skip] " << from << " -> " << to << "\n";
            return true;
        }
    }
    bool ok = fs::copy_file(from, to, fs::copy_options::overwrite_existing, ec);
    if (!ok && isVerbose()) std::cout << "[copy-fail] " << from << " -> " << to << ": " << ec.message() << "\n";
    return ok;
}

static void writeQtConfIfNeeded(const DeployPlan& plan) {
    if (plan.type == BinaryType::MACHO) return;
    fs::path conf = plan.outputRoot / "qt.conf";
    std::ofstream ofs(conf);
    if (!ofs) return;
    ofs << "[Paths]\n";
    ofs << "Prefix=." << "\n";
    ofs << "Plugins=plugins" << "\n";
    ofs << "Qml2Imports=qml" << "\n";
    ofs << "Translations=translations" << "\n";
}

static void copyResolvedForPE(const DeployPlan& plan, const std::vector<fs::path>& libs) {
    for (const auto& lib : libs) {
        fs::path dest = plan.outputRoot / lib.filename();
        if (!copyFileOverwrite(lib, dest)) {
            std::cerr << "Warning: failed to copy " << lib << " -> " << dest << "\n";
        }
    }
    writeQtConfIfNeeded(plan);
}

static void copyPluginsPE(const ResolveContext& ctx, const DeployPlan& plan, const std::vector<fs::path>& resolvedLibs) {
    // Build candidate plugin roots for MinGW target
    std::vector<fs::path> pluginRoots;
    if (!ctx.qt.qtInstallPlugins.empty()) pluginRoots.push_back(ctx.qt.qtInstallPlugins);
    // From env MINGW_QT_PLUGINS (colon-separated)
    std::string mingwPlugins = getEnv("MINGW_QT_PLUGINS");
    for (const auto& p : splitPaths(mingwPlugins, ':')) if (!p.empty()) pluginRoots.emplace_back(p);
    // Derive from PATH entries that end with /bin → ../plugins
    std::string path = getEnv("PATH");
    for (const auto& p : splitPaths(path, ':')) {
        if (p.size() > 4 && p.rfind("/bin", p.size() - 4) != std::string::npos) {
            fs::path base = fs::path(p).parent_path();
            std::error_code ec;
            fs::path root1 = base / "plugins";
            if (fs::exists(root1, ec)) pluginRoots.push_back(root1);
            ec.clear();
            fs::path root2 = base / "lib" / "qt-6" / "plugins";
            if (fs::exists(root2, ec)) pluginRoots.push_back(root2);
        }
    }
    // Derive from resolved Qt6Core.dll location(s)
    for (const auto& lib : resolvedLibs) {
        std::string base = lib.filename().string();
        std::string lower = base; std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        if (lower == "qt6core.dll") {
            fs::path binDir = lib.parent_path();
            std::error_code ec;
            fs::path root1 = binDir.parent_path() / "plugins";
            if (fs::exists(root1, ec)) pluginRoots.push_back(root1);
            ec.clear();
            fs::path root2 = binDir.parent_path() / "lib" / "qt-6" / "plugins";
            if (fs::exists(root2, ec)) pluginRoots.push_back(root2);
        }
    }

    // Dedup
    std::sort(pluginRoots.begin(), pluginRoots.end());
    pluginRoots.erase(std::unique(pluginRoots.begin(), pluginRoots.end()), pluginRoots.end());

    // Copy from first root that contains expected files
    for (const auto& src : pluginRoots) {
        fs::path platformDll = src / "platforms" / "qwindows.dll";
        if (!fs::exists(platformDll)) continue;
        copyFileOverwrite(platformDll, plan.outputRoot / "plugins" / "platforms" / platformDll.filename());
        for (const char* name : {"qjpeg.dll","qico.dll","qgif.dll","qpng.dll"}) {
            fs::path p = src / "imageformats" / name;
            if (fs::exists(p)) copyFileOverwrite(p, plan.outputRoot / "plugins" / "imageformats" / p.filename());
        }
        break;
    }
}

static void copyResolvedForELF(const DeployPlan& plan, const std::vector<fs::path>& libs) {
    fs::path libDir = plan.outputRoot / "lib";
    std::error_code ec;
    fs::create_directories(libDir, ec);
    for (const auto& lib : libs) {
        fs::path dest = libDir / lib.filename();
        if (!copyFileOverwrite(lib, dest)) {
            std::cerr << "Warning: failed to copy " << lib << " -> " << dest << "\n";
            continue;
        }
        // Create SONAME symlink if needed (e.g., libFoo.so.6 -> libFoo.so.6.X.Y)
        auto soname = queryElfSoname(lib);
        if (soname) {
            const std::string destName = dest.filename().string();
            if (*soname != destName) {
                fs::path linkPath = libDir / *soname;
                std::error_code sec;
                if (fs::exists(linkPath)) fs::remove(linkPath, sec);
                sec.clear();
                try {
                    fs::create_symlink(dest.filename(), linkPath);
                } catch (...) {
                    // Fallback: copy again under SONAME
                    copyFileOverwrite(dest, linkPath);
                }
            }
        }
    }
    writeQtConfIfNeeded(plan);
}

static void copyPluginsELF(const ResolveContext& ctx, const DeployPlan& plan) {
    if (ctx.qt.qtInstallPlugins.empty()) return;
    const fs::path src = ctx.qt.qtInstallPlugins;
    // platform plugin
    fs::path platformSo = src / "platforms" / "libqxcb.so";
    if (fs::exists(platformSo)) copyFileOverwrite(platformSo, plan.outputRoot / "plugins" / "platforms" / platformSo.filename());
    // imageformats
    for (const char* name : {"libqjpeg.so","libqico.so","libqgif.so","libqpng.so"}) {
        fs::path p = src / "imageformats" / name;
        if (fs::exists(p)) copyFileOverwrite(p, plan.outputRoot / "plugins" / "imageformats" / p.filename());
    }
    // Set RUNPATH on plugins to $ORIGIN/../lib
    int code = 0;
    std::string pluginsDir = (plan.outputRoot / "plugins").string();
    std::string cmd = std::string("find ") + shellEscape(pluginsDir) + " -type f -name '*.so*' -exec patchelf --set-rpath '$ORIGIN/../lib' {} +";
    runCommand(cmd, code);
}

static void copyMainAndPatchELF(const DeployPlan& plan) {
    // Copy main binary into output root
    fs::path dest = plan.outputRoot / plan.binaryPath.filename();
    if (!copyFileOverwrite(plan.binaryPath, dest)) {
        std::cerr << "Warning: failed to copy main binary: " << plan.binaryPath << " -> " << dest << "\n";
        return;
    }
    // Set RUNPATH to $ORIGIN/lib
    int code = 0;
    std::string cmd = std::string("patchelf --set-rpath '$ORIGIN/lib' ") + shellEscape(dest.string());
    runCommand(cmd, code);
    if (code != 0) {
        std::cerr << "Warning: patchelf failed to set RUNPATH on " << dest << "\n";
    }
}

// (removed unused findFrameworkRoot)

static void copyResolvedForMachO(const DeployPlan& plan, const std::vector<fs::path>& libs) {
    fs::path fwDir = plan.outputRoot / "Contents" / "Frameworks";
    std::error_code ec;
    fs::create_directories(fwDir, ec);
    std::unordered_set<std::string> copiedFrameworks;
    for (const auto& lib : libs) {
        if (isVerbose()) std::cout << "[macho-copy] lib: " << lib << "\n";
        // Detect frameworks by traversing parents
        fs::path candidate = lib;
        fs::path frameworkRoot;
        fs::path cur = candidate.parent_path();
        while (!cur.empty() && cur.has_parent_path()) {
            if (cur.extension() == ".framework") { frameworkRoot = cur; break; }
            cur = cur.parent_path();
        }
        if (!frameworkRoot.empty()) {
            fs::path dst = fwDir / frameworkRoot.filename();
            std::string key = frameworkRoot.filename().string();
            if (!copiedFrameworks.count(key)) {
                copiedFrameworks.insert(key);
                // copy entire framework directory
                if (isVerbose()) std::cout << "[macho-copy] framework: " << frameworkRoot << " -> " << dst << "\n";
                fs::copy(frameworkRoot, dst, fs::copy_options::recursive | fs::copy_options::overwrite_existing | fs::copy_options::skip_symlinks, ec);
                if (ec) {
                    std::cerr << "Warning: failed to copy framework " << frameworkRoot << " -> " << dst << ": " << ec.message() << "\n";
                }
            }
        } else {
            // regular .dylib
            fs::path dest = fwDir / lib.filename();
            if (isVerbose()) std::cout << "[macho-copy] dylib: " << lib << " -> " << dest << "\n";
            if (!copyFileOverwrite(lib, dest)) {
                std::cerr << "Warning: failed to copy " << lib << " -> " << dest << "\n";
            }
        }
    }
}

static void copyPluginsMachO(const ResolveContext& ctx, const DeployPlan& plan) {
    if (ctx.qt.qtInstallPlugins.empty()) return;
    const fs::path src = ctx.qt.qtInstallPlugins;
    fs::path dstBase = plan.outputRoot / "Contents" / "PlugIns";
    // platform plugin
    fs::path cocoa = src / "platforms" / "libqcocoa.dylib";
    if (fs::exists(cocoa)) copyFileOverwrite(cocoa, dstBase / "platforms" / cocoa.filename());
    // imageformats
    for (const char* name : {"libqjpeg.dylib","libqico.dylib","libqgif.dylib","libqpng.dylib"}) {
        fs::path p = src / "imageformats" / name;
        if (fs::exists(p)) copyFileOverwrite(p, dstBase / "imageformats" / p.filename());
    }
    // Add rpath to plugins so they can find Frameworks via loader path (per-file for compatibility)
    std::error_code ec;
    if (fs::exists(dstBase, ec)) {
        for (auto it = fs::recursive_directory_iterator(dstBase, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(ec) && it->path().extension() == ".dylib") {
                int code = 0;
                // From Contents/PlugIns/(...)/<lib>.dylib to Contents/Frameworks is ../../Frameworks
                std::string cmd = std::string("llvm-install-name-tool -add_rpath '@loader_path/../../Frameworks' ") + shellEscape(it->path().string());
                runCommand(cmd, code);
            }
        }
    }
}

// --- QML import scanning and copying ---

struct QmlModuleEntry {
    fs::path sourcePath;    // absolute path to module directory
    std::string relativePath; // relative install path under qml/
};

static std::vector<fs::path> discoverQmlRoots(const ResolveContext& ctx) {
    std::vector<fs::path> roots;
    // CLI-provided roots take precedence
    for (const auto& r : ctx.cliQmlRoots) roots.push_back(r);
    // Allow override via env QML_ROOT
    std::string envRoot = getEnv("QML_ROOT");
    if (!envRoot.empty()) roots.emplace_back(envRoot);
    // Try current working directory
    std::error_code ec;
    fs::path cwd = fs::current_path(ec);
    auto hasQml = [](const fs::path& d) -> bool {
        std::error_code e;
        if (!fs::exists(d, e) || !fs::is_directory(d, e)) return false;
        for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, e);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(e) && it->path().extension() == ".qml") return true;
        }
        return false;
    };
    if (!envRoot.empty() || !ctx.cliQmlRoots.empty()) {
        // already added
    } else {
        if (!cwd.empty() && hasQml(cwd)) roots.push_back(cwd);
        fs::path binDir = ctx.plan.binaryPath.parent_path();
        if (!binDir.empty() && hasQml(binDir)) roots.push_back(binDir);
    }
    // Deduplicate
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    return roots;
}

static std::vector<QmlModuleEntry> runQmlImportScanner(const ResolveContext& ctx, const std::vector<fs::path>& roots) {
    std::vector<QmlModuleEntry> result;
    if (roots.empty()) return result;
    // Build importPath args
    std::string importArgs;
    for (const auto& p : ctx.qmlImportPaths) {
        importArgs += " -importPath " + shellEscape(p.string());
    }
    for (const auto& root : roots) {
        int code = 0;
        std::string cmd = std::string("qmlimportscanner -rootPath ") + shellEscape(root.string()) + importArgs;
        std::string out = runCommand(cmd, code);
        if (code != 0 || out.empty()) continue;
        // naive JSON scan for "path" and "relativePath"
        std::istringstream iss(out);
        std::string line;
        QmlModuleEntry current;
        bool inObject = false;
        while (std::getline(iss, line)) {
            if (line.find('{') != std::string::npos) { inObject = true; current = QmlModuleEntry(); }
            if (inObject) {
                auto ppos = line.find("\"path\"");
                if (ppos != std::string::npos) {
                    auto q1 = line.find('"', ppos + 6);
                    auto q2 = q1 == std::string::npos ? std::string::npos : line.find('"', q1 + 1);
                    if (q1 != std::string::npos && q2 != std::string::npos) {
                        current.sourcePath = fs::path(line.substr(q1 + 1, q2 - q1 - 1));
                    }
                }
                auto rpos = line.find("\"relativePath\"");
                if (rpos != std::string::npos) {
                    auto q1 = line.find('"', rpos + 14);
                    auto q2 = q1 == std::string::npos ? std::string::npos : line.find('"', q1 + 1);
                    if (q1 != std::string::npos && q2 != std::string::npos) {
                        current.relativePath = line.substr(q1 + 1, q2 - q1 - 1);
                    }
                }
            }
            if (line.find('}') != std::string::npos && inObject) {
                inObject = false;
                if (!current.sourcePath.empty()) {
                    // Fallback for relativePath: try to strip QT_INSTALL_QML prefix
                    if (current.relativePath.empty()) {
                        std::string sp = current.sourcePath.string();
                        std::string qp = ctx.qt.qtInstallQml.string();
                        if (!qp.empty() && sp.rfind(qp, 0) == 0) {
                            std::string rel = sp.substr(qp.size());
                            if (!rel.empty() && (rel[0] == '/' || rel[0] == '\\')) rel.erase(0, 1);
                            current.relativePath = rel;
                        } else {
                            current.relativePath = current.sourcePath.filename().string();
                        }
                    }
                    result.push_back(current);
                }
            }
        }
    }
    // Deduplicate by sourcePath
    std::sort(result.begin(), result.end(), [](const QmlModuleEntry& a, const QmlModuleEntry& b){ return a.sourcePath < b.sourcePath; });
    result.erase(std::unique(result.begin(), result.end(), [](const QmlModuleEntry& a, const QmlModuleEntry& b){ return a.sourcePath == b.sourcePath; }), result.end());
    return result;
}

static void copyQmlModules(const ResolveContext& ctx, const DeployPlan& plan) {
    auto roots = discoverQmlRoots(ctx);
    if (roots.empty()) return;
    if (isVerbose()) {
        std::cout << "[qml] roots:";
        for (auto& r : roots) std::cout << " " << r;
        std::cout << "\n";
    }
    auto modules = runQmlImportScanner(ctx, roots);
    if (modules.empty()) return;
    std::error_code ec;
    fs::path qmlDestBase = plan.type == BinaryType::MACHO
        ? plan.outputRoot / "Contents" / "Resources" / "qml"
        : plan.outputRoot / "qml";
    for (const auto& m : modules) {
        if (isVerbose()) std::cout << "[qml] module: " << m.sourcePath << " -> " << (qmlDestBase / m.relativePath) << "\n";
        fs::path dst = qmlDestBase / m.relativePath;
        fs::create_directories(dst, ec);
        ec.clear();
        // Copy recursively
        try {
            // Prefer copying files first, skipping symlinks for speed and to avoid re-traversal via links
            for (auto it = fs::recursive_directory_iterator(m.sourcePath, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); ++it) {
                if (it->is_directory(ec)) continue;
                if (it->is_symlink(ec)) continue;
                fs::path rel = fs::relative(it->path(), m.sourcePath, ec);
                fs::path out = dst / rel;
                copyFileOverwrite(it->path(), out);
                if (plan.type == BinaryType::MACHO && out.extension() == ".dylib") {
                    // Move dylib to PlugIns/quick and leave a symlink
                    fs::path quickDir = plan.outputRoot / "Contents" / "PlugIns" / "quick";
                    fs::create_directories(quickDir, ec);
                    fs::path moved = quickDir / out.filename();
                    if (isVerbose()) std::cout << "[qml] move dylib: " << out << " -> " << moved << "\n";
                    copyFileOverwrite(out, moved);
                    std::error_code sec;
                    fs::remove(out, sec);
                    try { fs::create_symlink(fs::relative(moved, out.parent_path()), out); } catch (...) {}
                }
            }
        } catch (...) {
            std::cerr << "Warning: failed to traverse QML module: " << m.sourcePath << "\n";
        }
    }
}

static std::vector<fs::path> listQmlPluginLibraries(const DeployPlan& plan) {
    std::vector<fs::path> libs;
    std::error_code ec;
    fs::path qmlBase = plan.type == BinaryType::MACHO
        ? plan.outputRoot / "Contents" / "Resources" / "qml"
        : plan.outputRoot / "qml";
    if (!fs::exists(qmlBase, ec)) return libs;
    std::string ext = plan.type == BinaryType::PE ? ".dll" : (plan.type == BinaryType::ELF ? ".so" : ".dylib");
    std::unordered_set<std::string> seen;
    for (auto it = fs::recursive_directory_iterator(qmlBase, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); ++it) {
        if (!it->is_regular_file(ec)) continue;
        if (it->path().extension() == ext) {
            std::string key = fs::weakly_canonical(it->path(), ec).string();
            if (!seen.count(key)) { seen.insert(key); libs.push_back(it->path()); }
        }
    }
    // On macOS, actual dylibs are relocated to PlugIns/quick
    if (plan.type == BinaryType::MACHO) {
        fs::path quick = plan.outputRoot / "Contents" / "PlugIns" / "quick";
        if (fs::exists(quick, ec)) {
            for (auto it = fs::recursive_directory_iterator(quick, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); ++it) {
                if (it->is_regular_file(ec) && it->path().extension() == ".dylib") {
                    std::string key = fs::weakly_canonical(it->path(), ec).string();
                    if (!seen.count(key)) { seen.insert(key); libs.push_back(it->path()); }
                }
            }
        }
    }
    return libs;
}

static void resolveQmlPluginDependencies(const DeployPlan& plan) {
    // Single-pass BFS over dependencies starting from all plugin libs
    auto qmlLibs = listQmlPluginLibraries(plan);
    if (qmlLibs.empty()) return;

    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    ensureEnvForResolution(ctx);

    // Seed stack with plugin libs
    std::vector<fs::path> stack;
    for (const auto& lib : qmlLibs) {
        if (isVerbose()) std::cout << "[qml-deps] seed: " << lib << "\n";
        stack.push_back(lib);
    }

    std::unordered_set<std::string> visited;
    std::unordered_set<std::string> result;
    while (!stack.empty()) {
        fs::path cur = stack.back();
        stack.pop_back();
        std::error_code ec;
        fs::path canon = fs::weakly_canonical(cur, ec);
        std::string key = ec ? cur.string() : canon.string();
        if (visited.count(key)) continue;
        visited.insert(key);

        static ParseCache cache; // local cache per run
        const ParseResult& prChild = parseDepsCached(cur, plan.type, cache);

        for (const auto& dep : prChild.dependencies) {
            if (isVerbose()) std::cout << "[qml-deps]   dep: " << dep << "\n";
            std::optional<fs::path> found;
            if (plan.type == BinaryType::ELF) {
                found = resolveELFRef(dep, cur, prChild.rpaths, ctx);
            } else if (plan.type == BinaryType::PE) {
                found = findLibrary(dep, ctx);
            } else {
                const auto& rps = machoRpathsFor(cur, cache);
                found = resolveMachORef(dep, cur, rps, ctx, plan.binaryPath);
            }
            if (found) {
                // We want to deploy library dependencies (not the plugin lib itself)
                if (shouldDeployLibrary(*found, dep, plan.type, ctx)) {
                    // Add to result set if not one of the plugin libs themselves
                    std::string fkey = fs::weakly_canonical(*found, ec).string();
                    if (isVerbose()) std::cout << "[qml-deps]     push: " << *found << "\n";
                    if (!visited.count(fkey)) stack.push_back(*found);
                    result.insert(fkey);
                }
            }
        }
    }

    std::vector<fs::path> uniqueDeps;
    for (const auto& k : result) uniqueDeps.emplace_back(k);
    if (uniqueDeps.empty()) return;
    if (plan.type == BinaryType::PE) {
        copyResolvedForPE(plan, uniqueDeps);
    } else if (plan.type == BinaryType::ELF) {
        copyResolvedForELF(plan, uniqueDeps);
    } else {
        copyResolvedForMachO(plan, uniqueDeps);
    }
}

// --- macOS install_name/rpath fixups ---

static bool pathStartsWith(const fs::path& p, const fs::path& prefix) {
    std::error_code ec;
    auto pc = fs::weakly_canonical(p, ec);
    auto pr = fs::weakly_canonical(prefix, ec);
    std::string ps = pc.string();
    std::string prs = pr.string();
    if (prs.empty()) return false;
    if (ps.size() < prs.size()) return false;
    return ps.compare(0, prs.size(), prs) == 0;
}

static std::pair<std::optional<std::string>, std::vector<std::string>> parseOtoolDepsWithId(const fs::path& bin) {
    int code = 0;
    std::string out = runCommand("llvm-otool -L " + shellEscape(bin.string()), code);
    std::optional<std::string> id;
    std::vector<std::string> deps;
    if (code != 0 || out.empty()) return {id, deps};
    std::istringstream iss(out);
    std::string line;
    bool first = true;
    bool tookId = false;
    while (std::getline(iss, line)) {
        if (first) { first = false; continue; }
        size_t start = 0; while (start < line.size() && std::isspace(static_cast<unsigned char>(line[start]))) ++start;
        size_t end = start;
        while (end < line.size() && !std::isspace(static_cast<unsigned char>(line[end])) && line[end] != '(') ++end;
        if (end <= start) continue;
        std::string token = line.substr(start, end - start);
        if (!tookId) { id = token; tookId = true; continue; }
        deps.push_back(token);
    }
    return {id, deps};
}

static std::string frameworkInstallNameFromPath(const fs::path& binPath, const fs::path& bundleRoot) {
    // Expect .../Contents/Frameworks/Name.framework/Versions/<V>/Name
    std::error_code ec;
    auto rel = fs::relative(binPath, bundleRoot, ec).string();
    // Find "Frameworks/Name.framework/Versions/<V>/Name"
    auto posFw = rel.find("Frameworks/");
    if (posFw != std::string::npos) {
        std::string after = rel.substr(posFw + std::string("Frameworks/").size());
        auto posFramework = after.find(".framework/");
        if (posFramework != std::string::npos) {
            std::string name = after.substr(0, posFramework);
            // Try to get version segment
            std::string tail = after.substr(posFramework + std::string(".framework/").size());
            std::string version = "A";
            auto posVersions = tail.find("Versions/");
            if (posVersions != std::string::npos) {
                std::string afterVersions = tail.substr(posVersions + std::string("Versions/").size());
                auto slash = afterVersions.find('/');
                if (slash != std::string::npos) version = afterVersions.substr(0, slash);
            }
            return std::string("@rpath/") + name + ".framework/Versions/" + version + "/" + name;
        }
    }
    // Fallback to @rpath/<filename>
    return std::string("@rpath/") + binPath.filename().string();
}

static void fixInstallNamesMachO(const DeployPlan& plan) {
    fs::path bundle = plan.outputRoot;
    fs::path macOSDir = bundle / "Contents" / "MacOS";
    fs::path fwDir = bundle / "Contents" / "Frameworks";
    fs::path pluginsDir = bundle / "Contents" / "PlugIns";
    std::error_code ec;

    // Helper: find the actual framework binary inside a .framework root
    auto findFrameworkBinary = [&](const fs::path& frameworkRoot) -> std::optional<fs::path> {
        // Framework name is the last path component without .framework suffix
        std::string name = frameworkRoot.filename().string();
        const std::string suffix = ".framework";
        if (name.size() > suffix.size() && name.rfind(suffix) == name.size() - suffix.size()) {
            name = name.substr(0, name.size() - suffix.size());
        }
        fs::path versions = frameworkRoot / "Versions";
        std::error_code lec;
        if (fs::exists(versions, lec) && fs::is_directory(versions, lec)) {
            // Prefer Current symlink if present
            fs::path current = versions / "Current";
            if (fs::exists(current, lec)) {
                fs::path cand = current / name;
                if (fs::exists(cand, lec) && fs::is_regular_file(cand, lec)) return cand;
            }
            // Fallback: try common letter versions (A, B, etc.)
            for (const char v : std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ")) {
                fs::path cand = versions / std::string(1, v) / name;
                if (fs::exists(cand, lec) && fs::is_regular_file(cand, lec)) return cand;
            }
            // As last resort, scan versions subdirs
            for (auto it = fs::directory_iterator(versions, lec); it != fs::directory_iterator(); ++it) {
                if (!it->is_directory(lec)) continue;
                fs::path cand = it->path() / name;
                if (fs::exists(cand, lec) && fs::is_regular_file(cand, lec)) return cand;
            }
        }
        return std::nullopt;
    };

    // Collect binaries to process
    std::vector<fs::path> bins;
    if (fs::exists(macOSDir, ec)) {
        for (auto it = fs::directory_iterator(macOSDir, ec); it != fs::directory_iterator(); ++it) {
            if (it->is_regular_file(ec)) bins.push_back(it->path());
        }
    }
    if (fs::exists(fwDir, ec)) {
        // Add each framework binary once
        for (auto it = fs::recursive_directory_iterator(fwDir, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (!it->is_directory(ec)) continue;
            if (it->path().extension() != ".framework") continue;
            auto bin = findFrameworkBinary(it->path());
            if (bin) bins.push_back(*bin);
        }
        // Include standalone dylibs inside Frameworks (rare but possible)
        for (auto it = fs::recursive_directory_iterator(fwDir, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(ec) && it->path().extension() == ".dylib") bins.push_back(it->path());
        }
    }
    if (fs::exists(pluginsDir, ec)) {
        for (auto it = fs::recursive_directory_iterator(pluginsDir, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(ec) && it->path().extension() == ".dylib") bins.push_back(it->path());
        }
    }

    // De-dupe
    std::sort(bins.begin(), bins.end());
    bins.erase(std::unique(bins.begin(), bins.end()), bins.end());

    // First, set IDs for bundle-local libraries
    for (const auto& b : bins) {
        // Only set -id for items under Frameworks (dylibs/frameworks)
        if (pathStartsWith(b, fwDir)) {
            std::string newId = frameworkInstallNameFromPath(b, bundle);
            int code = 0;
            std::string cmd = std::string("llvm-install-name-tool -id ") + shellEscape(newId) + " " + shellEscape(b.string());
            runCommand(cmd, code);
        }
    }

    // Then, rewrite dependency references in all binaries to use @rpath for bundle-local frameworks/dylibs
    for (const auto& b : bins) {
        auto pr = parseOtoolDepsWithId(b);
        for (const auto& dep : pr.second) {
            fs::path depPath(dep);
            if (pathStartsWith(depPath, fwDir)) {
                std::string newRef = frameworkInstallNameFromPath(depPath, bundle);
                int code = 0;
                std::string cmd = std::string("llvm-install-name-tool -change ") + shellEscape(dep) + " " + shellEscape(newRef) + " " + shellEscape(b.string());
                runCommand(cmd, code);
            }
        }
    }
}

static void copyMainAndPatchMachO(const DeployPlan& plan) {
    fs::path macOSDir = plan.outputRoot / "Contents" / "MacOS";
    std::error_code ec;
    fs::create_directories(macOSDir, ec);
    fs::path dest = macOSDir / plan.binaryPath.filename();
    if (!copyFileOverwrite(plan.binaryPath, dest)) {
        std::cerr << "Warning: failed to copy main binary: " << plan.binaryPath << " -> " << dest << "\n";
        return;
    }
    // Add rpath to Frameworks directory
    int code = 0;
    std::string cmd = std::string("llvm-install-name-tool -add_rpath '@executable_path/../Frameworks' ") + shellEscape(dest.string());
    runCommand(cmd, code);
    if (code != 0) {
        std::cerr << "Warning: llvm-install-name-tool failed to add rpath on " << dest << "\n";
    }
}

static void copyMainPE(const DeployPlan& plan) {
    fs::path dest = plan.outputRoot / plan.binaryPath.filename();
    if (!copyFileOverwrite(plan.binaryPath, dest)) {
        std::cerr << "Warning: failed to copy main binary: " << plan.binaryPath << " -> " << dest << "\n";
    }
}

// --- Translations deployment ---

static std::vector<std::string> detectLanguagesFromEnv() {
    // Prefer LC_ALL, then LANG. Basic parse like en_US.UTF-8 -> en
    std::vector<std::string> langs;
    auto parse = [](const std::string& s) -> std::string {
        if (s.empty()) return {};
        // expected form: ll[_CC][.codeset][@modifier]
        size_t end = s.find_first_of("_.@ ");
        std::string base = (end == std::string::npos) ? s : s.substr(0, end);
        // Normalize to lowercase
        std::string out = base;
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c){ return std::tolower(c); });
        return out;
    };
    std::string lcAll = getEnv("LC_ALL");
    std::string lang = getEnv("LANG");
    std::string pick = !lcAll.empty() ? lcAll : lang;
    std::string one = parse(pick);
    if (!one.empty()) langs.push_back(one);
    // Always include English fallback
    if (std::find(langs.begin(), langs.end(), std::string("en")) == langs.end()) langs.push_back("en");
    return langs;
}

static std::vector<std::string> computeLanguages(const DeployPlan& plan) {
    if (!plan.languages.empty()) return plan.languages;
    return detectLanguagesFromEnv();
}

static fs::path translationsOutputDir(const DeployPlan& plan) {
    if (plan.type == BinaryType::MACHO) return plan.outputRoot / "Contents" / "Resources" / "translations";
    return plan.outputRoot / "translations";
}

static std::vector<fs::path> listModuleCatalogsForLang(const fs::path& qtTransDir, const std::string& lang) {
    // Approximate windeployqt translationNameFilters: gather qtbase, qt*, and module catalogs for the language
    std::vector<fs::path> files;
    std::error_code ec;
    if (!fs::exists(qtTransDir, ec) || !fs::is_directory(qtTransDir, ec)) return files;
    for (auto it = fs::directory_iterator(qtTransDir, ec); it != fs::directory_iterator(); ++it) {
        if (!it->is_regular_file(ec)) continue;
        std::string name = it->path().filename().string();
        // match *_<lang>.qm where * is a module catalog name
        std::string suffix = std::string("_") + lang + ".qm";
        if (name.size() > suffix.size() && name.rfind(suffix) == name.size() - suffix.size()) {
            files.push_back(it->path());
        }
    }
    return files;
}

static bool runLconvert(const std::vector<fs::path>& inputs, const fs::path& outputQm) {
    if (inputs.empty()) return false;
    int code = 0;
    std::ostringstream cmd;
    cmd << "lconvert -o " << shellEscape(outputQm.string());
    for (const auto& in : inputs) cmd << " -i " << shellEscape(in.string());
    runCommand(cmd.str(), code);
    return code == 0 && fs::exists(outputQm);
}

static void copyIfExists(const fs::path& src, const fs::path& dstDir) {
    std::error_code ec;
    if (fs::exists(src, ec)) {
        fs::path dst = dstDir / src.filename();
        copyFileOverwrite(src, dst);
    }
}

static void deployTranslations(const ResolveContext& ctx, const DeployPlan& plan) {
    const fs::path qtTransDir = ctx.qt.qtInstallTranslations;
    if (qtTransDir.empty()) return;
    auto langs = computeLanguages(plan);
    std::error_code ec;
    fs::path outDir = translationsOutputDir(plan);
    fs::create_directories(outDir, ec);
    for (const auto& lang : langs) {
        auto catalogs = listModuleCatalogsForLang(qtTransDir, lang);
        if (catalogs.empty()) continue;
        // Preferred: aggregate to qt_<lang>.qm
        fs::path aggregated = outDir / (std::string("qt_") + lang + ".qm");
        bool ok = runLconvert(catalogs, aggregated);
        if (!ok) {
            // Fallback: copy each catalog
            for (const auto& c : catalogs) copyIfExists(c, outDir);
        }
    }
}

static void resolveDependenciesPE(const DeployPlan& plan) {
    auto libs = resolveAndRecurse(plan);
    if (!libs.empty()) {
        std::cout << "Resolved shared libraries (filtered):\n";
        for (const auto& p : libs) std::cout << "  " << p << "\n";
    }
    copyResolvedForPE(plan, libs);
    copyMainPE(plan);
    // Copy a minimal plugin set
    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    // pass CLI qml roots
    // Pull from Args by re-parsing? Instead, read from env QML_ROOT only; simple workaround:
    // We'll allow users to pass multiple --qml-root via setting QML_ROOT as colon-separated as well.
    ensureEnvForResolution(ctx);
    copyPluginsPE(ctx, plan, libs);
    copyQmlModules(ctx, plan);
    deployTranslations(ctx, plan);
    resolveQmlPluginDependencies(plan);
}

static void resolveDependenciesELF(const DeployPlan& plan) {
    auto libs = resolveAndRecurse(plan);
    if (!libs.empty()) {
        std::cout << "Resolved shared libraries (filtered):\n";
        for (const auto& p : libs) std::cout << "  " << p << "\n";
    }
    copyResolvedForELF(plan, libs);
    copyMainAndPatchELF(plan);
    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    ensureEnvForResolution(ctx);
    copyPluginsELF(ctx, plan);
    copyQmlModules(ctx, plan);
    deployTranslations(ctx, plan);
    resolveQmlPluginDependencies(plan);
}

static void resolveDependenciesMachO(const DeployPlan& plan) {
    auto libs = resolveAndRecurse(plan);
    if (!libs.empty()) {
        std::cout << "Resolved shared libraries (filtered):\n";
        for (const auto& p : libs) std::cout << "  " << p << "\n";
    }
    copyResolvedForMachO(plan, libs);
    copyMainAndPatchMachO(plan);
    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    ensureEnvForResolution(ctx);
    copyPluginsMachO(ctx, plan);
    copyQmlModules(ctx, plan);
    deployTranslations(ctx, plan);
    resolveQmlPluginDependencies(plan);
    // Ensure rpaths and install names are correct for app, frameworks, and plugins
    fixInstallNamesMachO(plan);
}

int main(int argc, char** argv) {
    try {
        auto maybeArgs = parseArgs(argc, argv);
        if (!maybeArgs) {
            return 2;
        }
        Args args = *maybeArgs;

        if (!fs::exists(args.binaryPath)) {
            std::cerr << "Binary does not exist: " << args.binaryPath << "\n";
            return 2;
        }

        if (!fs::is_regular_file(args.binaryPath)) {
            std::cerr << "Binary path is not a file: " << args.binaryPath << "\n";
            return 2;
        }

        std::string detectFail;
        auto maybeType = detectBinaryType(args.binaryPath, detectFail);
        if (!maybeType) {
            std::cerr << "Failed to detect binary type: " << detectFail << "\n";
            return 2;
        }

        DeployPlan plan{*maybeType, args.binaryPath, args.outDir, args.qmlRoots, args.languages};
        std::cout << "Detected: " << toString(plan.type) << "\n";

        ensureOutputLayout(plan);

        switch (plan.type) {
            case BinaryType::PE: resolveDependenciesPE(plan); break;
            case BinaryType::ELF: resolveDependenciesELF(plan); break;
            case BinaryType::MACHO: resolveDependenciesMachO(plan); break;
        }

        std::cout << "Scaffold complete at: " << plan.outputRoot << "\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}


