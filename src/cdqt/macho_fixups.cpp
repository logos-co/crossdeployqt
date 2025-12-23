#include "macho_fixups.h"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

#include "deps_parse.h"
#include "util.h"

namespace cdqt {

static bool pathStartsWith(const fs::path& p, const fs::path& prefix) {
    std::error_code ec;
    auto pc = fs::weakly_canonical(p, ec);
    auto pr = fs::weakly_canonical(prefix, ec);
    std::string ps = pc.string();
    std::string prs = pr.string();
    if (prs.empty()) return false;
    if (ps.size() < prs.size()) return false;
    return ps.compare(0, prs.size(), prs) == 0;
}

static std::string frameworkInstallNameFromPath(const fs::path& binPath, const fs::path& bundleRoot) {
    std::error_code ec;
    auto rel = fs::relative(binPath, bundleRoot, ec).string();
    auto posFw = rel.find("Frameworks/");
    if (posFw != std::string::npos) {
        std::string after = rel.substr(posFw + std::string("Frameworks/").size());
        auto posFramework = after.find(".framework/");
        if (posFramework != std::string::npos) {
            std::string name = after.substr(0, posFramework);
            std::string tail = after.substr(posFramework + std::string(".framework/").size());
            std::string version = "A";
            auto posVersions = tail.find("Versions/");
            if (posVersions != std::string::npos) {
                std::string afterVersions = tail.substr(posVersions + std::string("Versions/").size());
                auto slash = afterVersions.find('/');
                if (slash != std::string::npos) version = afterVersions.substr(0, slash);
            }
            return std::string("@rpath/") + name + ".framework/Versions/" + version + "/" + name;
        }
    }
    return std::string("@rpath/") + binPath.filename().string();
}

void fixInstallNamesMachO(const DeployPlan& plan) {
    fs::path bundle = plan.outputRoot;
    fs::path macOSDir = bundle / "Contents" / "MacOS";
    fs::path fwDir = bundle / "Contents" / "Frameworks";
    fs::path pluginsDir = bundle / "Contents" / "PlugIns";
    std::error_code ec;

    auto findFrameworkBinary = [&](const fs::path& frameworkRoot) -> std::optional<fs::path> {
        std::string name = frameworkRoot.filename().string();
        const std::string suffix = ".framework";
        if (name.size() > suffix.size() && name.rfind(suffix) == name.size() - suffix.size()) {
            name = name.substr(0, name.size() - suffix.size());
        }
        fs::path versions = frameworkRoot / "Versions";
        std::error_code lec;
        if (fs::exists(versions, lec) && fs::is_directory(versions, lec)) {
            fs::path current = versions / "Current";
            if (fs::exists(current, lec)) {
                fs::path cand = current / name;
                if (fs::exists(cand, lec) && fs::is_regular_file(cand, lec)) return cand;
            }
            for (const char v : std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ")) {
                fs::path cand = versions / std::string(1, v) / name;
                if (fs::exists(cand, lec) && fs::is_regular_file(cand, lec)) return cand;
            }
            for (auto it = fs::directory_iterator(versions, lec); it != fs::directory_iterator(); ++it) {
                if (!it->is_directory(lec)) continue;
                fs::path cand = it->path() / name;
                if (fs::exists(cand, lec) && fs::is_regular_file(cand, lec)) return cand;
            }
        }
        return std::nullopt;
    };

    std::vector<fs::path> bins;
    if (fs::exists(macOSDir, ec)) {
        for (auto it = fs::directory_iterator(macOSDir, ec); it != fs::directory_iterator(); ++it) {
            if (it->is_regular_file(ec)) bins.push_back(it->path());
        }
    }
    if (fs::exists(fwDir, ec)) {
        for (auto it = fs::recursive_directory_iterator(fwDir, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (!it->is_directory(ec)) continue;
            if (it->path().extension() != ".framework") continue;
            auto bin = findFrameworkBinary(it->path());
            if (bin) bins.push_back(*bin);
        }
        for (auto it = fs::recursive_directory_iterator(fwDir, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(ec) && it->path().extension() == ".dylib") bins.push_back(it->path());
        }
    }
    if (fs::exists(pluginsDir, ec)) {
        for (auto it = fs::recursive_directory_iterator(pluginsDir, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(ec) && it->path().extension() == ".dylib") bins.push_back(it->path());
        }
    }

    std::sort(bins.begin(), bins.end());
    bins.erase(std::unique(bins.begin(), bins.end()), bins.end());

    for (const auto& b : bins) {
        if (pathStartsWith(b, fwDir)) {
            std::string newId = frameworkInstallNameFromPath(b, bundle);
            int code = 0;
            std::string cmd = std::string("llvm-install-name-tool -id ") + shellEscape(newId) + " " + shellEscape(b.string());
            runCommand(cmd, code);
        }
    }

    for (const auto& b : bins) {
        auto pr = parseOtoolDepsWithId(b);
        for (const auto& dep : pr.second) {
            fs::path depPath(dep);
            if (pathStartsWith(depPath, fwDir)) {
                std::string newRef = frameworkInstallNameFromPath(depPath, bundle);
                int code = 0;
                std::string cmd = std::string("llvm-install-name-tool -change ") + shellEscape(dep) + " " + shellEscape(newRef) + " " + shellEscape(b.string());
                runCommand(cmd, code);
            }
        }
    }
}

} // namespace cdqt


