{
    description = "Environment for creating examples for SENO";

    inputs = {
        nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
    };

    outputs = {
        nixpkgs,
        ...
    }: let
        system = "x86_64-linux";
    in {
        devShells."${system}".default = let
            pkgs = import nixpkgs {
                inherit system;
            };
        in pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
                # for the main application
                python314
                # for building examples
                gcc15
                pkgsCross.aarch64-multiplatform.buildPackages.gcc15
                cmake
            ];
        };
    };
}
