#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "common.h"

namespace cdqt {

struct ParseResult {
    std::vector<std::string> dependencies; // names or paths
    std::vector<std::string> rpaths;       // for ELF (RPATH/RUNPATH)
};

struct MachORpaths { std::vector<std::string> rpaths; };

struct ParseCache {
    std::unordered_map<std::string, ParseResult> parseByPath;
    std::unordered_map<std::string, std::vector<std::string>> machoRpathsByPath;
};

ParseResult parsePE(const fs::path& bin);
ParseResult parseELF(const fs::path& bin);
ParseResult parseMachO(const fs::path& bin);
MachORpaths parseMachORpaths(const fs::path& bin);

std::optional<std::string> queryElfSoname(const fs::path& soPath);

std::string canonicalKey(const fs::path& p);
const ParseResult& parseDepsCached(const fs::path& subject, BinaryType type, ParseCache& cache);
const std::vector<std::string>& machoRpathsFor(const fs::path& subject, ParseCache& cache);

// Mach-O fixups need to parse otool output with the dylib ID (first token line).
std::pair<std::optional<std::string>, std::vector<std::string>> parseOtoolDepsWithId(const fs::path& bin);

} // namespace cdqt


