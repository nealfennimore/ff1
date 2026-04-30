{
  pkgs ? import <nixpkgs> { },
}:
with pkgs;
mkShell {
  buildInputs = [

  ];

  shellHook = ''

  '';

  packages = [
    rustc
    cargo
    wasm-pack
    lld
  ];
}
