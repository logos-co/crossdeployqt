#include "util.h"

#include <array>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <system_error>

#if !defined(_WIN32)
#include <sys/wait.h>
#endif

namespace cdqt {

bool isVerbose() {
    static bool v = [](){
        const char* e = std::getenv("CROSSDEPLOYQT_VERBOSE");
        return e && *e;
    }();
    return v;
}

std::string getEnv(const char* key) {
    const char* v = std::getenv(key);
    return v ? std::string(v) : std::string();
}

void setEnv(const std::string& key, const std::string& value) {
#if defined(_WIN32)
    _putenv_s(key.c_str(), value.c_str());
#else
    setenv(key.c_str(), value.c_str(), 1);
#endif
}

std::vector<std::string> splitPaths(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

char pathListSep() {
#if defined(_WIN32)
    return ';';
#else
    return ':';
#endif
}

std::string runCommand(const std::string& cmd, int& exitCode) {
    std::array<char, 4096> buffer{};
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        exitCode = -1;
        return {};
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        result.append(buffer.data());
    }
    exitCode = pclose(pipe);
#if !defined(_WIN32)
    if (exitCode != -1) {
        if (WIFEXITED(exitCode)) {
            exitCode = WEXITSTATUS(exitCode);
        }
    }
#endif
    return result;
}

std::string shellEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (char c : s) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out.push_back(c);
        }
    }
    out.push_back('\'');
    return out;
}

bool programOnPath(const std::string& name) {
    int code = 0;
    runCommand(std::string("command -v ") + name + " >/dev/null 2>&1", code);
    return code == 0;
}

bool fileExistsExecutable(const fs::path& p) {
    if (p.empty()) return false;
    std::error_code ec;
    auto st = fs::status(p, ec);
    if (ec) return false;
    return fs::is_regular_file(st) || fs::is_symlink(st);
}

bool endsWith(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
}

} // namespace cdqt


