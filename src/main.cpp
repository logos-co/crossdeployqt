#include <iostream>
#include <string>

#include "cdqt/args.h"
#include "cdqt/binary_detect.h"
#include "cdqt/common.h"
#include "cdqt/deploy.h"
#include "cdqt/tools.h"

int main(int argc, char** argv) {
    try {
        auto maybeArgs = cdqt::parseArgs(argc, argv);
        if (!maybeArgs) {
            return 2;
        }
        cdqt::Args args = *maybeArgs;

        if (!cdqt::fs::exists(args.binaryPath)) {
            std::cerr << "Binary does not exist: " << args.binaryPath << "\n";
            return 2;
        }

        if (!cdqt::fs::is_regular_file(args.binaryPath)) {
            std::cerr << "Binary path is not a file: " << args.binaryPath << "\n";
            return 2;
        }

        std::string detectFail;
        auto maybeType = cdqt::detectBinaryType(args.binaryPath, detectFail);
        if (!maybeType) {
            std::cerr << "Failed to detect binary type: " << detectFail << "\n";
            return 2;
        }

        cdqt::fs::path normalizedOut = cdqt::ensurePlatformOutputRoot(*maybeType, args.outDir, args.binaryPath);
        cdqt::DeployPlan plan{*maybeType, args.binaryPath, normalizedOut, args.qmlRoots, args.languages, args.overlays};
        std::cout << "Detected: " << cdqt::toString(plan.type) << "\n";

        // Verify external tool availability for this platform
        {
            std::vector<std::string> missing = cdqt::computeMissingTools(plan.type);
            if (!missing.empty()) {
                std::cerr << "Missing required external tools for processing this binary:" << "\n";
                for (const auto& t : missing) std::cerr << "  - " << t << "\n";
                std::cerr << "Please install them or ensure they are on PATH." << "\n";
                return 2;
            }
        }

        cdqt::deploy(plan);

        std::cout << "Scaffold complete at: " << plan.outputRoot << "\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}