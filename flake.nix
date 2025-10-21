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
            permittedInsecurePackages = [
              "dotnet-sdk-6.0.428" # Needed to generate nuget-deps/vpk-deps.json
            ];
          };
          overlays = [
          ];
        };

        lib = pkgs.lib;
        isLinux  = pkgs.stdenv.hostPlatform.isLinux;

        velopackPkgs = import ./nix/velopack.nix { inherit pkgs; };
        appimagetoolPkgs = import ./nix/appimagetool.nix { inherit pkgs; };

        windowsTriple = "x86_64-w64-mingw32";
        mingw = pkgs.pkgsCross.mingwW64;

        common = with pkgs; [
          cmake
          ninja
          pkg-config

          qt6.qtbase # qtpaths
          qt6.qtdeclarative # qmlimportscanner
          qt6.qttools # lconvert

          llvmPackages.llvm # macOS llvm-otool and llvm-install-name-tool
        ]
        ++ lib.optionals isLinux [
          patchelf          # Linux RUNPATH updates
          pkgsCross.mingwW64.buildPackages.binutils # x86_64-w64-mingw32-objdump
        ];
           
      in
      {
        packages =
          let
            pname = "crossdeployqt";
            version = (self.rev or "dev");
            linuxExtraTools = lib.optionals isLinux [
              pkgs.patchelf
              pkgs.pkgsCross.mingwW64.buildPackages.binutils # x86_64-w64-mingw32-objdump
            ];
            # Tools needed by the program at runtime
            runtimeTools = [
              pkgs.binutils                 # objdump
              pkgs.qt6.qtbase               # qtpaths, QT_PLUGIN_PATH root
              pkgs.qt6.qtdeclarative        # qmlimportscanner (in libexec), QML2_IMPORT_PATH root
              pkgs.qt6.qttools              # lconvert
              pkgs.llvmPackages.llvm        # llvm-otool, llvm-install-name-tool
              pkgs.findutils                # find used for patchelf pass on plugins
            ] ++ linuxExtraTools;
            mingwPaths = lib.optionalString isLinux ( # macOS complains about somethign upstream
              ":${mingw.qt6.qtbase}/bin"
              + ":${mingw.qt6.qtdeclarative}/bin"
              + ":${mingw.stdenv.cc.cc.lib}/${windowsTriple}/lib"
              + ":${mingw.windows.pthreads}/bin"
              + ":${mingw.zlib}/bin"
              + ":${mingw.pcre2}/bin"
              + ":${mingw.zstd}/bin"
              + ":${mingw.libb2}/bin"
              + ":${mingw.double-conversion}/bin"
              + ":${mingw.libpng}/bin"
              + ":${mingw.openssl}/bin"
            );
            wrapPath = lib.concatStringsSep ":" ([
              "${pkgs.qt6.qtdeclarative}/libexec"  # qmlimportscanner
              "${pkgs.qt6.qttools}/bin"            # lconvert
              "${pkgs.llvmPackages.llvm}/bin"      # llvm-otool, llvm-install-name-tool
              "${pkgs.binutils}/bin"               # objdump
              "${pkgs.findutils}/bin"              # find
            ]
            ++ lib.optionals isLinux [
              "${pkgs.patchelf}/bin"               # patchelf
              "${pkgs.pkgsCross.mingwW64.buildPackages.binutils}/bin" # x86_64-w64-mingw32-objdump
            ]);
          in
          {
            default = pkgs.stdenv.mkDerivation {
              inherit pname version;
              src = self;

              nativeBuildInputs = [
                pkgs.cmake
                pkgs.ninja
                pkgs.pkg-config
                pkgs.makeWrapper
              ];

              buildInputs = [ ];

              # Use an out-of-source Ninja build and install the single binary
              configurePhase = ''
                cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
              '';
              buildPhase = ''
                cmake --build build -j$NIX_BUILD_CORES
              '';
              installPhase = ''
                install -Dm755 build/crossdeployqt "$out/bin/crossdeployqt"
                # Wrap to provide required tools and helpful env defaults
                wrapProgram "$out/bin/crossdeployqt" \
                  --set QTPATHS_BIN "${pkgs.qt6.qtbase}/bin/qtpaths" \
                  --set QT_PLUGIN_PATH "${pkgs.qt6.qtbase}/lib/qt-6/plugins" \
                  --set QML2_IMPORT_PATH "${pkgs.qt6.qtdeclarative}/lib/qt-6/qml" \
                  --prefix PATH : "${wrapPath}${mingwPaths}"
              '';

              # Keep runtime tool deps in the closure by referencing them
              passthru.runtimeTools = runtimeTools;
              meta = with lib; {
                description = "Collect dependencies and assets for Qt 6 apps (Linux/macOS/Windows)";
                homepage = "https://github.com/logos-co/crossdeployqt";
                license = licenses.mit;
                platforms = platforms.unix;
                maintainers = [ ];
              };
            };
            crossdeployqt = self.packages.${system}.default;
            inherit (velopackPkgs) velopack-libc vpk vpkDev;
            inherit (appimagetoolPkgs) appimagetool appimagetool-full;
          };

        apps = {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/crossdeployqt";
          };
          vpkDev = {
            type = "app";
            program = "${self.packages.${system}.vpkDev}/bin/vpk";
          };
        };

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
            ''
            + lib.optionalString isLinux ''
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
            ''
            + ''
              echo "cmake -S . -B build"
              echo "cmake --build build -j"
              echo "./build/crossdeployqt --bin <PATH TO>/foo.exe --out ./dist-win/"
              echo "./build/crossdeployqt --bin <PATH TO>/foo --out ./dist-linux/"
              echo "./build/crossdeployqt --bin <PATH TO>/foo.app/Contents/MacOS/bar --out ./dist-macos/"
            '';
          };
        };
      });
}
