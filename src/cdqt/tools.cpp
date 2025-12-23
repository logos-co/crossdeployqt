#include "tools.h"

#include "util.h"

namespace cdqt {

std::vector<std::string> computeMissingTools(BinaryType type) {
    std::vector<std::string> missing;

    std::string qtpathsBin = getEnv("QTPATHS_BIN");
    bool haveQtpaths = !qtpathsBin.empty() ? fileExistsExecutable(qtpathsBin) : programOnPath("qtpaths");
    if (!haveQtpaths) missing.push_back(qtpathsBin.empty() ? std::string("qtpaths") : (qtpathsBin + " (from QTPATHS_BIN)"));

    if (!programOnPath("qmlimportscanner")) missing.push_back("qmlimportscanner");
    if (!programOnPath("lconvert")) missing.push_back("lconvert");

    if (type == BinaryType::ELF) {
        if (!programOnPath("objdump")) missing.push_back("objdump");
        if (!programOnPath("patchelf")) missing.push_back("patchelf");
    } else if (type == BinaryType::PE) {
        if (!programOnPath("x86_64-w64-mingw32-objdump")) missing.push_back("x86_64-w64-mingw32-objdump");
    } else { // Mach-O
        if (!programOnPath("llvm-otool")) missing.push_back("llvm-otool");
        if (!programOnPath("llvm-install-name-tool")) missing.push_back("llvm-install-name-tool");
    }

    return missing;
}

} // namespace cdqt


