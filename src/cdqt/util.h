#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace cdqt {

namespace fs = std::filesystem;

bool isVerbose();

std::string getEnv(const char* key);
void setEnv(const std::string& key, const std::string& value);

std::vector<std::string> splitPaths(const std::string& s, char sep);
char pathListSep();

std::string runCommand(const std::string& cmd, int& exitCode);
std::string shellEscape(const std::string& s);

bool programOnPath(const std::string& name);
bool fileExistsExecutable(const fs::path& p);

bool endsWith(const std::string& s, const std::string& suffix);

} // namespace cdqt


