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

        common = with pkgs; [
          cmake
          ninja
          pkg-config

          qt6.qtbase # qtpaths

          llvmPackages.llvm # macOS llvm-otool and llvm-install-name-tool
          pkgsCross.mingwW64.buildPackages.binutils # x86_64-w64-mingw32-objdump
        ];
           
      in
      {

        devShells = {
          default = pkgs.mkShell {
            packages = common;

            shellHook = ''
              echo "cmake -S . -B build"
              echo "cmake --build build -j"
              echo "./build/crossdeployqt --bin ~/experiments/logos-app/build-windows/bin/logos.exe --out ./dist-win/"
              echo "./build/crossdeployqt --bin ~/experiments/logos-app/build/bin/logos --out ./dist-linux
              echo "./build/crossdeployqt --bin ~/experiments/logos-app/build-macos/bin/logos.app/Contents/MacOS/logos --out ./dist-macos/"
            '';
          };
        };
      });
}
