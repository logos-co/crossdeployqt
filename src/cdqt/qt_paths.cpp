#include "qt_paths.h"

#include <string>

#include "util.h"

namespace cdqt {

QtPathsInfo queryQtPaths() {
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

    // Validate directories exist; otherwise leave empty
    std::error_code ec;
    if (!info.qtInstallQml.empty() && !fs::exists(info.qtInstallQml, ec)) info.qtInstallQml.clear();
    if (!info.qtInstallPlugins.empty() && !fs::exists(info.qtInstallPlugins, ec)) info.qtInstallPlugins.clear();
    if (!info.qtInstallTranslations.empty() && !fs::exists(info.qtInstallTranslations, ec)) info.qtInstallTranslations.clear();

    return info;
}

} // namespace cdqt


