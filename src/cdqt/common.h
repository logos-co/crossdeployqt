#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace cdqt {

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
    std::vector<fs::path> overlays; // optional overlay roots to merge into output
};

struct DeployPlan {
    BinaryType type;
    fs::path binaryPath;
    fs::path outputRoot;
    std::vector<fs::path> qmlRoots;       // optional CLI-provided QML roots
    std::vector<std::string> languages;   // optional languages
    std::vector<fs::path> overlays;       // optional overlay roots
};

const char* toString(BinaryType t);
fs::path ensurePlatformOutputRoot(BinaryType type, const fs::path& requestedOutDir, const fs::path& binaryPath);

} // namespace cdqt


