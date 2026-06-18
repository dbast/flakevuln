{ ... }:
{
  perSystem =
    { config, pkgs, ... }:
    {
      # `nix fmt` runs the same pre-commit hooks that gate CI.
      formatter =
        let
          inherit (config.pre-commit.settings) package configFile;
        in
        pkgs.writeShellScriptBin "pre-commit-run" ''
          exec ${pkgs.lib.getExe package} run --all-files --config ${configFile}
        '';
    };
}
