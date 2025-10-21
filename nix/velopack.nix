{ pkgs }:

let
  inherit (pkgs) stdenvNoCC lib fetchzip;
in rec {

  # Velopack C/C++ precompiled library bundle (libc zip)
  # and exposes a prefix with include/, lib/ and lib-static/ where present.
  velopack-libc = stdenvNoCC.mkDerivation rec {
    pname = "velopack-libc";
    version = "0.0.1369-g1d5c984";

    src = fetchzip {
      url = "https://github.com/velopack/velopack/releases/download/${version}/velopack_libc_${version}.zip";
      hash = "sha256-mrl4SpEda/Zd6/WVwWtWfq+8Z7bh7c9Z9u5pdMRoack=";
      stripRoot = false;
    };

    # Needed to derive GNU import libraries (.dll.a) from the shipped MSVC DLLs
    nativeBuildInputs = [
      pkgs.llvmPackages.llvm
      pkgs.llvmPackages.bintools
    ];

    dontConfigure = true;
    dontBuild = true;

    installPhase = ''
      runHook preInstall
      mkdir -p "$out"

      # Preserve common structure from the archive if present
      if [ -d include ]; then
        mkdir -p "$out/include"
        cp -R include/. "$out/include/"
      fi

      if [ -d lib ]; then
        mkdir -p "$out/lib"
        cp -R lib/. "$out/lib/"
      fi

      if [ -d lib-static ]; then
        mkdir -p "$out/lib-static"
        cp -R lib-static/. "$out/lib-static/"
      fi

      # If Windows DLLs are present, generate GNU import libs for MinGW consumers
      gen_import() {
        local dll="$1"; local machine="$2"
        [ -f "$dll" ] || return 0
        echo "Generating MinGW import library for $(basename "$dll")"
        local base="$(basename "$dll" .dll)"
        local def="$TMPDIR/$base.def"
        local outlib="$out/lib/$base.dll.a"
        echo "LIBRARY $(basename "$dll")" > "$def"
        echo "EXPORTS" >> "$def"
        # Prefer llvm-readobj; fallback to llvm-objdump if needed
        if ! llvm-readobj --coff-exports "$dll" \
            | sed -n 's/^ *Symbol: \([^ ]*\).*/\1/p' >> "$def"; then
          llvm-objdump -p "$dll" \
            | awk '/Export Table:/,0 { if ($1 ~ /^[0-9]+$/) print $3 }' >> "$def"
        fi
        llvm-dlltool -m "$machine" -d "$def" -D "$(basename "$dll")" -l "$outlib"
      }

      gen_import "$out/lib/velopack_libc_win_x64_msvc.dll" "i386:x86-64"
      gen_import "$out/lib/velopack_libc_win_x86_msvc.dll" "i386"
      gen_import "$out/lib/velopack_libc_win_arm64_msvc.dll" "arm64"

      runHook postInstall
    '';

    meta = with lib; {
      description = "Velopack precompiled C/C++ library bundle (headers and libs)";
      homepage = "https://github.com/velopack/velopack";
      license = licenses.mit;
      platforms = platforms.all;
    };
  };

  # Velopack CLI (.NET global tool) wrapped to:
  # - ensure squashfsTools (mksquashfs) is on PATH
  # - unset SOURCE_DATE_EPOCH to avoid conflict with -mkfs-time
  vpk = let
    vpkRaw = pkgs.buildDotnetGlobalTool {
      pname = "vpk";
      version = "0.0.1369-g1d5c984";
      nugetSha256 = "sha256-8XR8AmaDVjmF+/7XtdJiar/xpzrjk+h/7sOavsf0ozQ=";
      # dotnet-sdk = pkgs.dotnetCorePackages.dotnet_8.sdk;
      dotnet-runtime = pkgs.dotnetCorePackages.runtime_8_0;
    };
  in pkgs.stdenvNoCC.mkDerivation {
    pname = "vpk-wrapped";
    version = "0.0.1369-g1d5c984";
    dontUnpack = true;
    nativeBuildInputs = [ pkgs.makeWrapper ];
    installPhase = ''
      runHook preInstall
      mkdir -p "$out/bin"
      makeWrapper "${vpkRaw}/bin/vpk" "$out/bin/vpk" \
        --unset SOURCE_DATE_EPOCH \
        --prefix PATH : "${pkgs.lib.makeBinPath [ pkgs.squashfsTools ]}"
      runHook postInstall
    '';
    meta = with lib; {
      description = "Velopack CLI with squashfsTools in PATH and SOURCE_DATE_EPOCH unset";
      homepage = "https://github.com/velopack/velopack";
      license = licenses.mit;
      platforms = platforms.all;
    };
  };
}