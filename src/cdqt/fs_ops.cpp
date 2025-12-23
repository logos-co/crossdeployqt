#include "fs_ops.h"

#include <fstream>
#include <iostream>

#include "util.h"

namespace cdqt {

void ensureOutputLayout(const DeployPlan& plan) {
    std::error_code ec;
    if (!fs::exists(plan.outputRoot)) {
        fs::create_directories(plan.outputRoot, ec);
        if (ec) {
            throw std::runtime_error("failed to create output root: " + plan.outputRoot.string());
        }
    }
    switch (plan.type) {
        case BinaryType::PE: {
            fs::create_directories(plan.outputRoot / "plugins", ec);
            fs::create_directories(plan.outputRoot / "plugins" / "platforms", ec);
            fs::create_directories(plan.outputRoot / "plugins" / "imageformats", ec);
            fs::create_directories(plan.outputRoot / "qml", ec);
            fs::create_directories(plan.outputRoot / "translations", ec);
            break;
        }
        case BinaryType::ELF: {
            fs::create_directories(plan.outputRoot / "usr" / "bin", ec);
            fs::create_directories(plan.outputRoot / "usr" / "lib", ec);
            fs::create_directories(plan.outputRoot / "usr" / "plugins", ec);
            fs::create_directories(plan.outputRoot / "usr" / "plugins" / "platforms", ec);
            fs::create_directories(plan.outputRoot / "usr" / "plugins" / "imageformats", ec);
            fs::create_directories(plan.outputRoot / "usr" / "qml", ec);
            fs::create_directories(plan.outputRoot / "usr" / "translations", ec);
            break;
        }
        case BinaryType::MACHO: {
            fs::create_directories(plan.outputRoot / "Contents" / "MacOS", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "Frameworks", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "Resources" / "qml", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "PlugIns" / "quick", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "PlugIns" / "platforms", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "PlugIns" / "imageformats", ec);
            fs::create_directories(plan.outputRoot / "Contents" / "Resources" / "translations", ec);
            break;
        }
    }
}

bool copyFileOverwrite(const fs::path& from, const fs::path& to) {
    std::error_code ec;
    fs::create_directories(to.parent_path(), ec);
    ec.clear();

    // Skip if destination exists with same size and timestamp newer-or-equal to source
    std::error_code se1, se2;
    auto dstStatus = fs::status(to, se2);
    if (!se2 && fs::exists(to) && fs::is_regular_file(dstStatus)) {
        std::error_code te1, te2;
        auto srcSize = fs::file_size(from, te1);
        auto dstSize = fs::file_size(to, te2);
        std::error_code le1, le2;
        auto srcTime = fs::last_write_time(from, le1);
        auto dstTime = fs::last_write_time(to, le2);
        if (!te1 && !te2 && !le1 && !le2 && srcSize == dstSize && dstTime >= srcTime) {
            if (isVerbose()) std::cout << "[copy-skip] " << from << " -> " << to << "\n";
            return true;
        }
    }

    bool ok = fs::copy_file(from, to, fs::copy_options::overwrite_existing, ec);
    if (!ok && isVerbose()) std::cout << "[copy-fail] " << from << " -> " << to << ": " << ec.message() << "\n";
    // Ensure destination is owner-writable so we can patch rpaths later
    std::error_code pec;
    fs::permissions(to, fs::perms::owner_write, fs::perm_options::add, pec);
    return ok;
}

void mergeDirectoryTree(const fs::path& srcRoot, const fs::path& dstRoot) {
    std::error_code ec;
    if (srcRoot.empty() || dstRoot.empty()) return;
    if (!fs::exists(srcRoot, ec) || !fs::is_directory(srcRoot, ec)) return;
    for (auto it = fs::recursive_directory_iterator(srcRoot, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); ++it) {
        const fs::path src = it->path();
        std::error_code rec;
        fs::path rel = fs::relative(src, srcRoot, rec);
        if (rec) rel = src.filename();
        fs::path dst = dstRoot / rel;
        if (it->is_directory(ec)) {
            std::error_code mk;
            fs::create_directories(dst, mk);
            continue;
        }
        {
            std::error_code mk;
            fs::create_directories(dst.parent_path(), mk);
        }
        std::error_code isLinkEc;
        const bool isLink = it->is_symlink(isLinkEc);
        if (isLink && !isLinkEc) {
            std::error_code rm;
            fs::remove(dst, rm);
            std::error_code le;
            fs::path target = fs::read_symlink(src, le);
            if (!le) {
                try {
                    fs::create_symlink(target, dst);
                    continue;
                } catch (...) {
                }
                std::error_code absEc;
                fs::path absTarget = fs::weakly_canonical(src.parent_path() / target, absEc);
                if (!absEc && fs::is_regular_file(absTarget)) {
                    copyFileOverwrite(absTarget, dst);
                    continue;
                }
            }
            continue;
        }
        if (it->is_regular_file(ec)) {
            copyFileOverwrite(src, dst);
        }
    }
}

void applyOverlays(const DeployPlan& plan) {
    for (const auto& ov : plan.overlays) {
        if (ov.empty()) continue;
        std::error_code ec;
        if (!fs::exists(ov, ec) || !fs::is_directory(ov, ec)) continue;
        if (isVerbose()) std::cout << "[overlay] merge " << ov << " -> " << plan.outputRoot << "\n";
        mergeDirectoryTree(ov, plan.outputRoot);
    }
}

void writeQtConfIfNeeded(const DeployPlan& plan) {
    if (plan.type == BinaryType::MACHO) return;
    fs::path conf;
    if (plan.type == BinaryType::ELF) conf = plan.outputRoot / "usr" / "bin" / "qt.conf";
    else conf = plan.outputRoot / "qt.conf";

    std::ofstream ofs(conf);
    if (!ofs) return;
    ofs << "[Paths]\n";
    if (plan.type == BinaryType::ELF) {
        ofs << "Prefix=..\n";
        ofs << "Plugins=../plugins\n";
        ofs << "Qml2Imports=../qml\n";
        ofs << "Translations=../translations\n";
    } else {
        ofs << "Prefix=.\n";
        ofs << "Plugins=plugins\n";
        ofs << "Qml2Imports=qml\n";
        ofs << "Translations=translations\n";
    }
}

} // namespace cdqt


