{
  description = "crossdeployqt";

  inputs = {
    nixpkgs.url     = "github:logos-co/nixpkgs/patch/mingw-qt6";
    flake-utils.url = "github:numtide/flake-utils";
  };

  nixConfig = {
    substituters = [
      "https://cache.nixos.org/"
      "https://nix-community.cachix.org"
      "https://experiments.cachix.org"
    ];
    trusted-public-keys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
      "experiments.cachix.org-1:Gg91e1XhvoSF/vp+I5cyI+RLzLSICT5VDh7hI3BPr+o="
      "nixbuild.net/IJTO3N-1:MuSvw7HC3Nhv5BtO3wTED7DFpNT9kMDtf5aikzgKXYg="
    ];
  };

  outputs = { self, nixpkgs, flake-utils, poetry2nix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
          };
          overlays = [
          ];
        };

        windowsTriple = "x86_64-w64-mingw32";
        mingw = pkgs.pkgsCross.mingwW64;

        common = with pkgs; [
          cmake
          ninja
          pkg-config

          qt6.qtbase # qtpaths
          qt6.qtdeclarative # qmlimportscanner

          llvmPackages.llvm # macOS llvm-otool and llvm-install-name-tool
          patchelf          # Linux RUNPATH updates
          pkgsCross.mingwW64.buildPackages.binutils # x86_64-w64-mingw32-objdump
        ];
           
      in
      {

        devShells = {
          default = pkgs.mkShell {
            packages = common;

            shellHook = ''
              # Host Qt search paths for plugins and QML (used by Qt tools and for runtime testing)
              export QT_PLUGIN_PATH=${pkgs.qt6.qtbase}/lib/qt-6/plugins
              export QML2_IMPORT_PATH=${pkgs.qt6.qtdeclarative}/lib/qt-6/qml
              # Ensure qmlimportscanner is on PATH (Qt6 installs it under libexec)
              export PATH="${pkgs.qt6.qtdeclarative}/libexec:$PATH"
              # Hint for our tool if multiple Qt versions are present
              export QTPATHS_BIN=${pkgs.qt6.qtbase}/bin/qtpaths

              # Make Windows (MinGW) Qt DLLs discoverable for PE dependency scanning
              export MINGW_QT_BIN=${mingw.qt6.qtbase}/bin:${mingw.qt6.qtdeclarative}/bin
              export MINGW_RUNTIME_LIBS=${mingw.stdenv.cc.cc.lib}/${windowsTriple}/lib
              export MINGW_EXTRA_DLLS=\
"${mingw.windows.pthreads}/bin:\
${mingw.zlib}/bin:\
${mingw.pcre2}/bin:\
${mingw.zstd}/bin:\
${mingw.libb2}/bin:\
${mingw.double-conversion}/bin:\
${mingw.libpng}/bin:\
${mingw.openssl}/bin"
              export PATH="$MINGW_QT_BIN:$MINGW_RUNTIME_LIBS:$MINGW_EXTRA_DLLS:$PATH"
              # Provide plugin roots for MinGW (both legacy and Qt6 layout)
              export MINGW_QT_PLUGINS=${mingw.qt6.qtbase}/plugins:${mingw.qt6.qtdeclarative}/plugins:${mingw.qt6.qtbase}/lib/qt-6/plugins:${mingw.qt6.qtdeclarative}/lib/qt-6/plugins

              echo "cmake -S . -B build"
              echo "cmake --build build -j"
              echo "./build/crossdeployqt --bin ~/experiments/logos-app/build-windows/bin/logos.exe --out ./dist-win/"
              echo "./build/crossdeployqt --bin ~/experiments/logos-app/build/bin/logos --out ./dist-linux/"
              echo "./build/crossdeployqt --bin ~/experiments/logos-app/build-macos/bin/logos.app/Contents/MacOS/logos --out ./dist-macos/"
            '';
          };
        };
      });
}
