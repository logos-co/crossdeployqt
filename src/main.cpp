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
};

static void printUsage(const char* argv0) {
    std::cerr << "Usage: " << argv0 << " --bin <path-to-binary> --out <output-dir>\n";
}

static std::optional<Args> parseArgs(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string_view a(argv[i]);
        if (a == "--bin" && i + 1 < argc) {
            args.binaryPath = fs::path(argv[++i]);
        } else if (a == "--out" && i + 1 < argc) {
            args.outDir = fs::path(argv[++i]);
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

struct QtPathsInfo {
    fs::path qtInstallLibs;
    fs::path qtInstallBins;
    fs::path qtInstallPrefix;
};

static QtPathsInfo queryQtPaths() {
    QtPathsInfo info;
    int code = 0;
    auto trim = [](std::string s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
        size_t i = 0;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        return s.substr(i);
    };
    std::string libs = runCommand("qtpaths --query QT_INSTALL_LIBS", code);
    if (code == 0) info.qtInstallLibs = fs::path(trim(libs));
    std::string bins = runCommand("qtpaths --query QT_INSTALL_BINS", code);
    if (code == 0) info.qtInstallBins = fs::path(trim(bins));
    std::string prefix = runCommand("qtpaths --query QT_INSTALL_PREFIX", code);
    if (code == 0) info.qtInstallPrefix = fs::path(trim(prefix));
    return info;
}

struct ResolveContext {
    DeployPlan plan;
    QtPathsInfo qt;
    std::vector<fs::path> searchDirs; // directories used to resolve deps
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
        // Include if Qt-ish, in Qt path, or alongside binary
        return isQtLibraryName(base) || inQtPath() || dir == ctx.plan.binaryPath.parent_path();
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

static void resolveAndRecurse(const DeployPlan& plan) {
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

    // Print summary of resolved libraries to stdout for now
    std::cout << "Resolved shared libraries (filtered):\n";
    for (const auto& k : visited) {
        if (k == plan.binaryPath.string()) continue;
        std::cout << "  " << k << "\n";
    }
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
            fs::create_directories(plan.outputRoot / "qml", ec);
            fs::create_directories(plan.outputRoot / "translations", ec);
            break;
        }
        case BinaryType::ELF: {
            fs::create_directories(plan.outputRoot / "plugins", ec);
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
            fs::create_directories(plan.outputRoot / "Contents" / "Resources" / "translations", ec);
            break;
        }
    }
}

// Dependency resolution stubs to implement next
static void resolveDependenciesPE(const DeployPlan& plan) {
    resolveAndRecurse(plan);
}

static void resolveDependenciesELF(const DeployPlan& plan) {
    resolveAndRecurse(plan);
}

static void resolveDependenciesMachO(const DeployPlan& plan) {
    resolveAndRecurse(plan);
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

        DeployPlan plan{*maybeType, args.binaryPath, args.outDir};
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


