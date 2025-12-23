#include "translations.h"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "fs_ops.h"
#include "util.h"

namespace cdqt {

static std::vector<std::string> detectLanguagesFromEnv() {
    std::vector<std::string> langs;
    auto parse = [](const std::string& s) -> std::string {
        if (s.empty()) return {};
        size_t end = s.find_first_of("_.@ ");
        std::string base = (end == std::string::npos) ? s : s.substr(0, end);
        std::string out = base;
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c){ return std::tolower(c); });
        return out;
    };
    std::string lcAll = getEnv("LC_ALL");
    std::string lang = getEnv("LANG");
    std::string pick = !lcAll.empty() ? lcAll : lang;
    std::string one = parse(pick);
    if (!one.empty()) langs.push_back(one);
    if (std::find(langs.begin(), langs.end(), std::string("en")) == langs.end()) langs.push_back("en");
    return langs;
}

static std::vector<std::string> computeLanguages(const DeployPlan& plan) {
    if (!plan.languages.empty()) return plan.languages;
    return detectLanguagesFromEnv();
}

static fs::path translationsOutputDir(const DeployPlan& plan) {
    if (plan.type == BinaryType::MACHO) return plan.outputRoot / "Contents" / "Resources" / "translations";
    if (plan.type == BinaryType::ELF) return plan.outputRoot / "usr" / "translations";
    return plan.outputRoot / "translations";
}

static std::vector<fs::path> listModuleCatalogsForLang(const fs::path& qtTransDir, const std::string& lang) {
    std::vector<fs::path> files;
    std::error_code ec;
    if (!fs::exists(qtTransDir, ec) || !fs::is_directory(qtTransDir, ec)) return files;
    for (auto it = fs::directory_iterator(qtTransDir, ec); it != fs::directory_iterator(); ++it) {
        if (!it->is_regular_file(ec)) continue;
        std::string name = it->path().filename().string();
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

void deployTranslations(const ResolveContext& ctx, const DeployPlan& plan) {
    const fs::path qtTransDir = ctx.qt.qtInstallTranslations;
    if (qtTransDir.empty()) return;
    auto langs = computeLanguages(plan);
    std::error_code ec;
    fs::path outDir = translationsOutputDir(plan);
    fs::create_directories(outDir, ec);
    for (const auto& lang : langs) {
        auto catalogs = listModuleCatalogsForLang(qtTransDir, lang);
        if (catalogs.empty()) continue;
        fs::path aggregated = outDir / (std::string("qt_") + lang + ".qm");
        bool ok = runLconvert(catalogs, aggregated);
        if (!ok) {
            for (const auto& c : catalogs) copyIfExists(c, outDir);
        }
    }
}

} // namespace cdqt


