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
    rustup
    cargo
    wasm-pack
    lld
    rustfmt
    gnuplot
  ];
}
