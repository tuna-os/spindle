{
  description = "Spindle, a Matrix homeserver in one binary over an embedded store";

  # flake.lock pins nixpkgs. `nix flake update` moves it; commit the result.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # The release image's feature set (FEATURES in .github/workflows/release.yml).
      features = "mas-import,synapse-import";

      mkSpindle =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "spindle";
          version = "0.1.0";
          src = pkgs.lib.cleanSource ./.;
          # vendor/ruma-state-res is a path crate named by [patch.crates-io];
          # it is part of the source tree, so the lock file needs no hash for it.
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "-p"
            "spindle-server"
            "--bin"
            "spindle"
            "--features"
            features
          ];
          # nixpkgs' cargo hook sets AWS_LC_SYS_USE_SYSTEM=1, so aws-lc-sys
          # links the system AWS-LC and must find it through pkg-config.
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.aws-lc ];
          # The test suite is CI's job; building it here would double the build.
          doCheck = false;
          meta = {
            description = "Matrix homeserver in one binary over an embedded store";
            homepage = "https://github.com/tuna-os/spindle";
            license = [
              pkgs.lib.licenses.mit
              pkgs.lib.licenses.asl20
            ];
            mainProgram = "spindle";
          };
        };
    in
    {
      # The toolchain is nixpkgs' rustc, not rust-toolchain.toml's 1.90.0.
      # Cargo.toml sets rust-version = "1.90", and nixos-unstable carries 1.90
      # or newer, so the minimum holds.
      packages = forAll (pkgs: rec {
        spindle = mkSpindle pkgs;
        default = spindle;
      });

      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.spindle;
          toml = pkgs.formats.toml { };
          # An operator's settings win; the store path is the unit's own state directory.
          settings = lib.recursiveUpdate { storage.path = "/var/lib/spindle"; } cfg.settings;
          generated = toml.generate "spindle.toml" settings;
        in
        {
          options.services.spindle = {
            enable = lib.mkEnableOption "the Spindle Matrix homeserver";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression "spindle.packages.\${system}.default";
              description = "The Spindle package to run.";
            };
            settings = lib.mkOption {
              type = toml.type;
              default = { };
              example = lib.literalExpression ''{ server.name = "example.org"; }'';
              description = ''
                Contents of spindle.toml. See spindle.example.toml for every key.
                The file goes to the Nix store, which any local user can read:
                keep secrets out of it and use `configFile` instead.
              '';
            };
            configFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = ''
                A config file outside the Nix store, such as a sops-nix secret.
                When set, `settings` is ignored.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.spindle = {
              description = "Spindle Matrix homeserver";
              documentation = [ "https://github.com/tuna-os/spindle/blob/main/docs/deploy.md" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              wantedBy = [ "multi-user.target" ];
              # Mirrors deploy/systemd/spindle.service. Keep the two in step.
              serviceConfig = {
                Type = "simple";
                ExecStart = "${lib.getExe cfg.package} \${CREDENTIALS_DIRECTORY}/spindle.toml";
                LoadCredential = "spindle.toml:${if cfg.configFile != null then cfg.configFile else generated}";
                Restart = "on-failure";
                RestartSec = "5s";
                TimeoutStopSec = "60s";
                LimitNOFILE = 65536;
                DynamicUser = true;
                StateDirectory = "spindle";
                StateDirectoryMode = "0700";
                WorkingDirectory = "/var/lib/spindle";
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                PrivateDevices = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectKernelLogs = true;
                ProtectControlGroups = true;
                ProtectClock = true;
                ProtectHostname = true;
                ProtectProc = "invisible";
                ProcSubset = "pid";
                LockPersonality = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                RestrictNamespaces = true;
                RestrictAddressFamilies = [
                  "AF_INET"
                  "AF_INET6"
                  "AF_UNIX"
                ];
                CapabilityBoundingSet = "";
                AmbientCapabilities = "";
                SystemCallArchitectures = "native";
                SystemCallFilter = [
                  "@system-service"
                  "~@privileged @resources"
                ];
                UMask = "0077";
              };
            };
          };
        };

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ (mkSpindle pkgs) ];
          packages = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
            rust-analyzer
          ];
        };
      });

      formatter = forAll (pkgs: pkgs.nixfmt-rfc-style);
    };
}
