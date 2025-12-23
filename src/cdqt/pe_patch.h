#pragma once

#include <filesystem>

namespace cdqt {

namespace fs = std::filesystem;

// Windows (PE): patch Qt6Core.dll internal qt_prfxpath/qt_epfxpath/qt_hpfxpath strings for relocatability.
bool patchQtCoreDllPrefixInfixPE(const fs::path& qtCorePath);

} // namespace cdqt


