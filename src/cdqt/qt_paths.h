#pragma once

#include <filesystem>

namespace cdqt {

namespace fs = std::filesystem;

struct QtPathsInfo {
    fs::path qtInstallLibs;
    fs::path qtInstallBins;
    fs::path qtInstallPrefix;
    fs::path qtInstallPlugins;
    fs::path qtInstallQml;
    fs::path qtInstallTranslations;
};

QtPathsInfo queryQtPaths();

} // namespace cdqt


