#include "common.h"

#include <string>

#include "util.h"

namespace cdqt {

const char* toString(BinaryType t) {
    switch (t) {
        case BinaryType::PE: return "PE";
        case BinaryType::ELF: return "ELF";
        case BinaryType::MACHO: return "Mach-O";
    }
    return "?";
}

fs::path ensurePlatformOutputRoot(BinaryType type, const fs::path& requestedOutDir, const fs::path& binaryPath) {
    const std::string req = requestedOutDir.string();
    const std::string baseName = binaryPath.filename().string();
    if (type == BinaryType::ELF) {
        if (endsWith(req, ".AppDir")) return requestedOutDir;
        return requestedOutDir / (baseName + ".AppDir");
    } else if (type == BinaryType::MACHO) {
        if (endsWith(req, ".app")) return requestedOutDir;
        return requestedOutDir / (baseName + ".app");
    }
    return requestedOutDir; // Windows: keep flat dir
}

} // namespace cdqt


