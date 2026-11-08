{
  description = "wtCVSS: a random CVSS v3.1 vector for a given score";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAllSystems =
        f:
        lib.genAttrs [
          "x86_64-linux"
          "aarch64-linux"
          "x86_64-darwin"
          "aarch64-darwin"
        ] (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.stdenvNoCC.mkDerivation {
          pname = "wtcvss";
          version = self.shortRev or self.dirtyShortRev;
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./elm.json
              ./src
            ];
          };
          nativeBuildInputs = [ pkgs.elmPackages.elm ];
          # Regenerate both files with `elm2nix convert > elm-srcs.nix` and
          # `elm2nix snapshot` after changing dependencies.
          configurePhase = pkgs.elmPackages.fetchElmDeps {
            elmPackages = import ./elm-srcs.nix;
            elmVersion = "0.19.2";
            registryDat = ./registry.dat;
          };
          buildPhase = ''
            runHook preBuild
            elm make src/Main.elm --optimize --output=index.html
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            install -Dm644 index.html $out/index.html
            runHook postInstall
          '';
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.elm2nix
          ]
          ++ (with pkgs.elmPackages; [
            elm
            elm-format
            elm-test
          ]);
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
