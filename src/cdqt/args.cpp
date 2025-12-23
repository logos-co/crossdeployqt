#include "args.h"

#include <iostream>
#include <string>
#include <string_view>

#include "util.h"

namespace cdqt {

void printUsage(const char* argv0) {
    std::cerr << "Usage: " << argv0
              << " --bin <path-to-binary> --out <output-dir> [--qml-root <dir>]..."
              << " [--languages <lang[,lang...]>] [--overlay <dir>]...\n";
}

std::optional<Args> parseArgs(int argc, char** argv) {
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
        } else if (a == "--overlay" && i + 1 < argc) {
            args.overlays.emplace_back(argv[++i]);
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

} // namespace cdqt


