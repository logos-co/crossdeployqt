#include "deps_parse.h"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "util.h"

namespace cdqt {

std::string canonicalKey(const fs::path& p) {
    std::error_code ec;
    fs::path c = fs::weakly_canonical(p, ec);
    return (ec ? p : c).string();
}

const ParseResult& parseDepsCached(const fs::path& subject, BinaryType type, ParseCache& cache) {
    const std::string key = canonicalKey(subject);
    auto it = cache.parseByPath.find(key);
    if (it != cache.parseByPath.end()) return it->second;
    ParseResult pr;
    if (type == BinaryType::ELF) pr = parseELF(subject);
    else if (type == BinaryType::PE) pr = parsePE(subject);
    else pr = parseMachO(subject);
    auto [insIt, _] = cache.parseByPath.emplace(key, std::move(pr));
    return insIt->second;
}

const std::vector<std::string>& machoRpathsFor(const fs::path& subject, ParseCache& cache) {
    const std::string key = canonicalKey(subject);
    auto it = cache.machoRpathsByPath.find(key);
    if (it != cache.machoRpathsByPath.end()) return it->second;
    auto r = parseMachORpaths(subject);
    auto [insIt, _] = cache.machoRpathsByPath.emplace(key, std::move(r.rpaths));
    return insIt->second;
}

ParseResult parsePE(const fs::path& bin) {
    ParseResult r;
    int code = 0;
    std::string out = runCommand("x86_64-w64-mingw32-objdump -p " + shellEscape(bin.string()), code);
    if (code != 0) return r;
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        auto pos = line.find("DLL Name:");
        if (pos != std::string::npos) {
            std::string name = line.substr(pos + 9);
            size_t i = 0; while (i < name.size() && (name[i] == ' ' || name[i] == '\t')) ++i;
            name = name.substr(i);
            while (!name.empty() && (name.back() == '\r' || name.back() == '\n' || name.back() == ' ' || name.back() == '\t')) name.pop_back();
            if (!name.empty()) r.dependencies.push_back(name);
        }
    }
    return r;
}

ParseResult parseELF(const fs::path& bin) {
    ParseResult r;
    int code = 0;
    std::string out = runCommand("objdump -p " + shellEscape(bin.string()), code);
    if (code != 0) return r;
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        auto npos = line.find("NEEDED");
        if (npos != std::string::npos) {
            auto pos = line.find_last_of(' ');
            if (pos != std::string::npos && pos + 1 < line.size()) {
                std::string name = line.substr(pos + 1);
                while (!name.empty() && (name.back() == '\r' || name.back() == '\n')) name.pop_back();
                if (!name.empty()) r.dependencies.push_back(name);
            }
        }
        auto rppos = line.find("RPATH");
        if (rppos != std::string::npos) {
            auto pos = line.find_last_of(' ');
            if (pos != std::string::npos && pos + 1 < line.size()) {
                std::string paths = line.substr(pos + 1);
                for (const auto& p : splitPaths(paths, ':')) r.rpaths.push_back(p);
            }
        }
        auto runpos = line.find("RUNPATH");
        if (runpos != std::string::npos) {
            auto pos = line.find_last_of(' ');
            if (pos != std::string::npos && pos + 1 < line.size()) {
                std::string paths = line.substr(pos + 1);
                for (const auto& p : splitPaths(paths, ':')) r.rpaths.push_back(p);
            }
        }
    }
    return r;
}

std::optional<std::string> queryElfSoname(const fs::path& soPath) {
    int code = 0;
    std::string out = runCommand("objdump -p " + shellEscape(soPath.string()), code);
    if (code != 0) return std::nullopt;
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        auto pos = line.find("SONAME");
        if (pos != std::string::npos) {
            auto sp = line.find_last_of(' ');
            if (sp != std::string::npos && sp + 1 < line.size()) {
                std::string name = line.substr(sp + 1);
                while (!name.empty() && (name.back() == '\r' || name.back() == '\n')) name.pop_back();
                if (!name.empty()) return name;
            }
        }
    }
    return std::nullopt;
}

ParseResult parseMachO(const fs::path& bin) {
    ParseResult r;
    int code = 0;
    std::string out = runCommand("llvm-otool -L " + shellEscape(bin.string()), code);
    if (code != 0) return r;
    std::istringstream iss(out);
    std::string line;
    bool first = true;
    while (std::getline(iss, line)) {
        if (first) { first = false; continue; }
        size_t start = 0; while (start < line.size() && std::isspace(static_cast<unsigned char>(line[start]))) ++start;
        size_t end = start;
        while (end < line.size() && !std::isspace(static_cast<unsigned char>(line[end])) && line[end] != '(') ++end;
        if (end > start) r.dependencies.push_back(line.substr(start, end - start));
    }
    return r;
}

MachORpaths parseMachORpaths(const fs::path& bin) {
    MachORpaths r;
    int code = 0;
    std::string out = runCommand(std::string("llvm-otool -l ") + shellEscape(bin.string()), code);
    if (code != 0 || out.empty()) return r;
    std::istringstream iss(out);
    std::string line;
    bool inRpath = false;
    while (std::getline(iss, line)) {
        if (line.find("cmd LC_RPATH") != std::string::npos) { inRpath = true; continue; }
        if (inRpath) {
            auto pos = line.find("path ");
            if (pos != std::string::npos) {
                std::string s = line.substr(pos + 5);
                auto paren = s.find(" (");
                if (paren != std::string::npos) s = s.substr(0, paren);
                while (!s.empty() && (s.back()=='\n' || s.back()=='\r' || s.back()==' ' || s.back()=='\t')) s.pop_back();
                size_t i=0; while (i<s.size() && (s[i]==' '||s[i]=='\t')) ++i; s = s.substr(i);
                if (!s.empty()) r.rpaths.push_back(s);
                inRpath = false;
            }
        }
    }
    return r;
}

std::pair<std::optional<std::string>, std::vector<std::string>> parseOtoolDepsWithId(const fs::path& bin) {
    int code = 0;
    std::string out = runCommand("llvm-otool -L " + shellEscape(bin.string()), code);
    std::optional<std::string> id;
    std::vector<std::string> deps;
    if (code != 0 || out.empty()) return {id, deps};
    std::istringstream iss(out);
    std::string line;
    bool first = true;
    bool tookId = false;
    while (std::getline(iss, line)) {
        if (first) { first = false; continue; }
        size_t start = 0; while (start < line.size() && std::isspace(static_cast<unsigned char>(line[start]))) ++start;
        size_t end = start;
        while (end < line.size() && !std::isspace(static_cast<unsigned char>(line[end])) && line[end] != '(') ++end;
        if (end <= start) continue;
        std::string token = line.substr(start, end - start);
        if (!tookId) { id = token; tookId = true; continue; }
        deps.push_back(token);
    }
    return {id, deps};
}

} // namespace cdqt


