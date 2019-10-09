{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    buildInputs = with pkgs.elmPackages; [ 
      elm
      elm-analyse
      elm-format
      elm-live
      elm-test
    ];
}
