#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
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
// - Mach-O: multiple magic values, e.g., 0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE (fat), 0xCAFED00D (fat 64)
static std::optional<BinaryType> detectBinaryType(const fs::path& p, std::string& whyNot) {
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        whyNot = "cannot open file";
        return std::nullopt;
    }

    // Read first 4096 bytes to be safe
    std::vector<unsigned char> buf(4096, 0);
    f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    std::streamsize n = f.gcount();
    if (n < 4) {
        whyNot = "file too small";
        return std::nullopt;
    }

    // ELF
    if (buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
        return BinaryType::ELF;
    }

    // PE: 'M' 'Z' at start and 'PE\0\0' at e_lfanew
    if (buf[0] == 'M' && buf[1] == 'Z') {
        if (n >= 0x40) {
            // e_lfanew at 0x3C
            uint32_t e_lfanew = static_cast<uint32_t>(buf[0x3C]) |
                                 (static_cast<uint32_t>(buf[0x3D]) << 8) |
                                 (static_cast<uint32_t>(buf[0x3E]) << 16) |
                                 (static_cast<uint32_t>(buf[0x3F]) << 24);
            if (e_lfanew + 4 < static_cast<uint32_t>(n)) {
                if (buf[e_lfanew] == 'P' && buf[e_lfanew + 1] == 'E' && buf[e_lfanew + 2] == 0 && buf[e_lfanew + 3] == 0) {
                    return BinaryType::PE;
                }
            } else {
                // Read more if necessary
                f.clear();
                f.seekg(e_lfanew, std::ios::beg);
                unsigned char peSig[4] = {0};
                f.read(reinterpret_cast<char*>(peSig), 4);
                if (f.gcount() == 4 && peSig[0] == 'P' && peSig[1] == 'E' && peSig[2] == 0 && peSig[3] == 0) {
                    return BinaryType::PE;
                }
            }
        }
    }

    // Mach-O magic numbers (both endians, 32/64, fat)
    auto readU32 = [&](size_t off) -> uint32_t {
        if (off + 4 > static_cast<size_t>(n)) return 0;
        return (static_cast<uint32_t>(buf[off]) << 24) |
               (static_cast<uint32_t>(buf[off + 1]) << 16) |
               (static_cast<uint32_t>(buf[off + 2]) << 8) |
               (static_cast<uint32_t>(buf[off + 3]));
    };
    auto be = readU32(0);
    auto le = static_cast<uint32_t>(buf[0]) |
              (static_cast<uint32_t>(buf[1]) << 8) |
              (static_cast<uint32_t>(buf[2]) << 16) |
              (static_cast<uint32_t>(buf[3]) << 24);

    const uint32_t MH_MAGIC = 0xFEEDFACE;
    const uint32_t MH_CIGAM = 0xCEFAEDFE;
    const uint32_t MH_MAGIC_64 = 0xFEEDFACF;
    const uint32_t MH_CIGAM_64 = 0xCFFAEDFE;
    const uint32_t FAT_MAGIC = 0xCAFEBABE;
    const uint32_t FAT_CIGAM = 0xBEBAFECA;
    const uint32_t FAT_MAGIC_64 = 0xCAFED00D;
    const uint32_t FAT_CIGAM_64 = 0xD00DFECA;

    if (be == MH_MAGIC || be == MH_MAGIC_64 ||
        be == MH_CIGAM || be == MH_CIGAM_64 ||
        be == FAT_MAGIC || be == FAT_MAGIC_64 ||
        be == FAT_CIGAM || be == FAT_CIGAM_64) {
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
};

static void ensureEnvForResolution(ResolveContext& ctx) {
    // Always include binary directory first
    ctx.searchDirs.push_back(ctx.plan.binaryPath.parent_path());

    const auto qtLibs = ctx.qt.qtInstallLibs;
    const auto qtBins = ctx.qt.qtInstallBins;

    if (ctx.plan.type == BinaryType::ELF) {
        // LD_LIBRARY_PATH
        std::string ld = getEnv("LD_LIBRARY_PATH");
        std::vector<std::string> ldv = splitPaths(ld, ':');
        for (const auto& p : ldv) if (!p.empty()) ctx.searchDirs.emplace_back(p);
        if (!qtLibs.empty()) ctx.searchDirs.push_back(qtLibs);
        // Prepend Qt libs to LD_LIBRARY_PATH for subprocesses
        if (!qtLibs.empty()) {
            std::string newLd = qtLibs.string();
            if (!ld.empty()) newLd += ":" + ld;
            setEnv("LD_LIBRARY_PATH", newLd);
        }
    } else if (ctx.plan.type == BinaryType::PE) {
        // PATH search for .dll
        std::string path = getEnv("PATH");
        std::vector<std::string> pv = splitPaths(path, ':');
        for (const auto& p : pv) if (!p.empty()) ctx.searchDirs.emplace_back(p);
        if (!qtBins.empty()) ctx.searchDirs.push_back(qtBins); // MinGW Qt DLLs live in bin
        // Prepend Qt bins to PATH
        if (!qtBins.empty()) {
            std::string newPath = qtBins.string();
            if (!path.empty()) newPath += ":" + path;
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
        for (const auto& p : splitPaths(dyld, ':')) if (!p.empty()) ctx.searchDirs.emplace_back(p);
        std::string dyldfw = getEnv("DYLD_FRAMEWORK_PATH");
        for (const auto& p : splitPaths(dyldfw, ':')) if (!p.empty()) ctx.searchDirs.emplace_back(p);
        if (!qtLibs.empty()) ctx.searchDirs.push_back(qtLibs);
        // Prepend Qt libs to DYLD vars for subprocesses
        if (!qtLibs.empty()) {
            std::string newDyld = qtLibs.string();
            if (!dyld.empty()) newDyld += ":" + dyld;
            setEnv("DYLD_LIBRARY_PATH", newDyld);
            std::string newDyldFw = qtLibs.string();
            if (!dyldfw.empty()) newDyldFw += ":" + dyldfw;
            setEnv("DYLD_FRAMEWORK_PATH", newDyldFw);
        }
    }

    // Build QML import paths: include QT_INSTALL_QML and env QML2_IMPORT_PATH
    if (!ctx.qt.qtInstallQml.empty()) {
        std::error_code ec;
        if (fs::exists(ctx.qt.qtInstallQml, ec)) ctx.qmlImportPaths.push_back(ctx.qt.qtInstallQml);
    }
    std::string qml2Env = getEnv("QML2_IMPORT_PATH");
    for (const auto& p : splitPaths(qml2Env, ':')) {
        if (p.empty()) continue;
        std::error_code ec;
        if (fs::exists(p, ec)) ctx.qmlImportPaths.emplace_back(p);
    }
    // Attach CLI-provided roots
    for (const auto& r : ctx.plan.qmlRoots) ctx.cliQmlRoots.push_back(r);
    // Env QML_ROOT may be colon-separated for multiple roots
    std::string envRoots = getEnv("QML_ROOT");
    for (const auto& p : splitPaths(envRoots, ':')) if (!p.empty()) ctx.cliQmlRoots.emplace_back(p);
}

static bool isQtLibraryName(const std::string& name) {
    // Simple heuristic for Qt 6 libs across platforms
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
    return lower.find("qt6") != std::string::npos || lower.rfind("qt", 0) == 0 || lower.find("/qt") != std::string::npos;
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
        std::string lower = base; std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
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
    if (p.is_absolute() && fs::exists(p)) return p;
    // Relative path might include @rpath etc., ignore those here
    // Search in known directories
    for (const auto& dir : ctx.searchDirs) {
        fs::path cand = dir / nameOrPath;
        if (fs::exists(cand)) return fs::canonical(cand);
    }
    return std::nullopt;
}

struct ParseResult {
    std::vector<std::string> dependencies; // names or paths
    std::vector<std::string> rpaths;        // for ELF (RPATH/RUNPATH)
};

static ParseResult parsePE(const fs::path& bin) {
    ParseResult r;
    int code = 0;
    std::string out = runCommand("x86_64-w64-mingw32-objdump -p '" + bin.string() + "'", code);
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
    std::string out = runCommand("objdump -p '" + bin.string() + "'", code);
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
    std::string out = runCommand("objdump -p '" + soPath.string() + "'", code);
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
    std::string out = runCommand("llvm-otool -L '" + bin.string() + "'", code);
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
    ResolveContext ctx{plan, queryQtPaths(), {}};
    ensureEnvForResolution(ctx);

    // For ELF: include RPATH/RUNPATH from the main binary
    ParseResult pr;
    if (plan.type == BinaryType::ELF) {
        pr = parseELF(plan.binaryPath);
        for (const auto& rpath : pr.rpaths) ctx.searchDirs.emplace_back(rpath);
    } else if (plan.type == BinaryType::PE) {
        pr = parsePE(plan.binaryPath);
    } else {
        pr = parseMachO(plan.binaryPath);
    }

    std::vector<fs::path> stack;
    std::vector<std::string> initial = pr.dependencies;
    for (const auto& dep : initial) {
        auto found = findLibrary(dep, ctx);
        if (found) stack.push_back(*found);
        else {
            // If it's a system lib we skip silently; otherwise error
            if (isQtLibraryName(dep)) {
                throw std::runtime_error("Required Qt library not found in search paths: " + dep);
            }
        }
    }

    std::set<std::string> visited; // canonical path strings
    while (!stack.empty()) {
        fs::path cur = stack.back();
        stack.pop_back();
        std::error_code ec;
        fs::path canon = fs::weakly_canonical(cur, ec);
        std::string key = ec ? cur.string() : canon.string();
        if (visited.count(key)) continue;
        visited.insert(key);

        ParseResult prChild;
        if (plan.type == BinaryType::ELF) {
            prChild = parseELF(cur);
            for (const auto& rp : prChild.rpaths) ctx.searchDirs.emplace_back(rp);
        } else if (plan.type == BinaryType::PE) {
            prChild = parsePE(cur);
        } else {
            prChild = parseMachO(cur);
        }

        for (const auto& dep : prChild.dependencies) {
            auto found = findLibrary(dep, ctx);
            if (found) {
                if (shouldDeployLibrary(*found, dep, plan.type, ctx)) {
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
    return fs::copy_file(from, to, fs::copy_options::overwrite_existing, ec);
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
        std::string lower = base; std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
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

static fs::path findFrameworkRoot(const fs::path& binaryInsideFramework) {
    fs::path p = binaryInsideFramework;
    // climb up until a parent ending with .framework
    while (!p.empty() && p.has_parent_path()) {
        if (p.extension() == ".framework") return p;
        p = p.parent_path();
    }
    return {};
}

static void copyResolvedForMachO(const DeployPlan& plan, const std::vector<fs::path>& libs) {
    fs::path fwDir = plan.outputRoot / "Contents" / "Frameworks";
    std::error_code ec;
    fs::create_directories(fwDir, ec);
    std::set<std::string> copiedFrameworks;
    for (const auto& lib : libs) {
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
                fs::copy(frameworkRoot, dst, fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
                if (ec) {
                    std::cerr << "Warning: failed to copy framework " << frameworkRoot << " -> " << dst << ": " << ec.message() << "\n";
                }
            }
        } else {
            // regular .dylib
            fs::path dest = fwDir / lib.filename();
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
    // Add rpath to plugins so they can find Frameworks via loader path
    int code = 0;
    std::string pluginsDir = (dstBase).string();
    std::string cmd = std::string("find ") + shellEscape(pluginsDir) + " -type f -name '*.dylib' -exec llvm-install-name-tool -add_rpath '@loader_path/../Frameworks' {} +";
    runCommand(cmd, code);
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
    auto modules = runQmlImportScanner(ctx, roots);
    if (modules.empty()) return;
    std::error_code ec;
    fs::path qmlDestBase = plan.type == BinaryType::MACHO
        ? plan.outputRoot / "Contents" / "Resources" / "qml"
        : plan.outputRoot / "qml";
    for (const auto& m : modules) {
        fs::path dst = qmlDestBase / m.relativePath;
        fs::create_directories(dst, ec);
        ec.clear();
        // Copy recursively
        try {
            for (auto it = fs::recursive_directory_iterator(m.sourcePath, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); ++it) {
                if (it->is_directory(ec)) continue;
                fs::path rel = fs::relative(it->path(), m.sourcePath, ec);
                fs::path out = dst / rel;
                copyFileOverwrite(it->path(), out);
                if (plan.type == BinaryType::MACHO && out.extension() == ".dylib") {
                    // Move dylib to PlugIns/quick and leave a symlink
                    fs::path quickDir = plan.outputRoot / "Contents" / "PlugIns" / "quick";
                    fs::create_directories(quickDir, ec);
                    fs::path moved = quickDir / out.filename();
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
    std::set<std::string> seen;
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
    // Resolve and copy dependencies of QML plugin libraries to the appropriate locations
    auto qmlLibs = listQmlPluginLibraries(plan);
    if (qmlLibs.empty()) return;
    std::set<std::string> all;
    for (const auto& pluginLib : qmlLibs) {
        DeployPlan sub{plan.type, pluginLib, plan.outputRoot, plan.qmlRoots, plan.languages};
        auto deps = resolveAndRecurse(sub);
        for (const auto& d : deps) {
            std::error_code ec;
            std::string key = fs::weakly_canonical(d, ec).string();
            all.insert(key);
        }
    }
    std::vector<fs::path> uniqueDeps;
    for (const auto& k : all) uniqueDeps.emplace_back(k);
    if (uniqueDeps.empty()) return;
    if (plan.type == BinaryType::PE) {
        copyResolvedForPE(plan, uniqueDeps);
    } else if (plan.type == BinaryType::ELF) {
        copyResolvedForELF(plan, uniqueDeps);
    } else {
        copyResolvedForMachO(plan, uniqueDeps);
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
    ResolveContext ctx{plan, queryQtPaths(), {}};
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
    ResolveContext ctx{plan, queryQtPaths(), {}};
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
    ResolveContext ctx{plan, queryQtPaths(), {}};
    ensureEnvForResolution(ctx);
    copyPluginsMachO(ctx, plan);
    copyQmlModules(ctx, plan);
    deployTranslations(ctx, plan);
    resolveQmlPluginDependencies(plan);
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


