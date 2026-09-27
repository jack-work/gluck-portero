{
  description = "gluck-portero: invite links for guest accounts on spain";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.gluck-service-lib.url = "github:jack-work/gluck-service-lib";
  inputs.gluck-service-lib.inputs.nixpkgs.follows = "nixpkgs";

  outputs =
    { self, nixpkgs, gluck-service-lib, ... }:
    let
      nixosModule =
        { config, lib, pkgs, ... }:
        let
          cfg = config.services.gluck-portero;
          setPasswordBin = "${pkgs.lldap}/bin/lldap_set_password";
        in
        {
          options.services.gluck-portero = {
            enable = lib.mkEnableOption "gluck-portero: guest account invite links";

            inviteKeyFile = lib.mkOption {
              type = lib.types.path;
              description = ''
                Path to the invite signing key, at least 32 bytes. A sops secret.

                Both halves read it: mint signs, redeem verifies. It is delivered
                by LoadCredential, so it lives in a per-unit tmpfs at mode 0400
                and never in the Nix store, never in argv, never in a unit file.

                Rotating it invalidates every outstanding invite, which is the
                intended blast radius.
              '';
            };

            adminPasswordFile = lib.mkOption {
              type = lib.types.path;
              description = ''
                lldap password for the account the MINT half authenticates as.
                Needs to create and delete users, so it is an lldap_admin.
                Reached only through Authelia.
              '';
            };

            redeemPasswordFile = lib.mkOption {
              type = lib.types.path;
              description = ''
                lldap password for the account the REDEEM half authenticates as.

                This account must be in `lldap_password_manager` and NOT in
                `lldap_admin`. It fronts the only unauthenticated endpoint on the
                estate that touches the directory, so it must be unable to create
                a user, change a group, or escalate. See doc/THREAT-MODEL.md.
              '';
            };

            adminUser = lib.mkOption {
              type = lib.types.str;
              default = "admin";
              description = "lldap account the mint half logs in as.";
            };

            redeemUser = lib.mkOption {
              type = lib.types.str;
              default = "portero-redeem";
              description = "lldap account the redeem half logs in as.";
            };

            requiredGroup = lib.mkOption {
              type = lib.types.str;
              default = "portero-admin";
              description = ''
                Group a caller must hold to mint an invite. Enforced by the mint
                app against Remote-Groups, not by Caddy and not by Authelia.
              '';
            };

            grantableGroups = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "site-share-access" ];
              description = ''
                The ONLY groups a mint call may put an invitee into. An allowlist,
                not a pattern, because this half holds `lldap_admin`: without it a
                request could ask for `lldap_admin` and get it.

                Keep this to site-access groups. Capability groups belong to the
                app that defines them, and lldap matching is case-sensitive, so
                these strings must be exact.

                Granting at mint time is safe because the account has no
                credential until the invite is redeemed, and it avoids Authelia's
                profile-refresh window: the invitee's first session is created
                after the grant, so it is born holding the group.
              '';
            };

            mintSubdomain = lib.mkOption {
              type = lib.types.str;
              default = "portero";
              description = "Gated hostname for minting.";
            };

            redeemSubdomain = lib.mkOption {
              type = lib.types.str;
              default = "invite";
              description = ''
                PUBLIC hostname for redeeming. Deliberately unauthenticated:
                the invitee has no account yet, so there is nothing to
                authenticate with. The token is the only authorization.
              '';
            };

            mintPort = lib.mkOption {
              type = lib.types.port;
              default = 9101;
            };

            redeemPort = lib.mkOption {
              type = lib.types.port;
              default = 9102;
            };

            defaultTtlSeconds = lib.mkOption {
              type = lib.types.int;
              default = 72 * 3600;
              description = "Default invite lifetime when a caller does not say.";
            };

            maxTtlSeconds = lib.mkOption {
              type = lib.types.int;
              default = 14 * 24 * 3600;
              description = "Ceiling on invite lifetime, enforced at mint time.";
            };

            minPasswordLength = lib.mkOption {
              type = lib.types.int;
              default = 12;
            };
          };

          config = lib.mkIf cfg.enable (lib.mkMerge [
            (gluck-service-lib.lib.mkPythonService {
              inherit config lib pkgs;
              name = "gluck-portero-mint";
              subdomain = cfg.mintSubdomain;
              port = cfg.mintPort;
              requireAuth = true;
              requiredGroups = [ cfg.requiredGroup ];
              entrypoint = ./portero/mint.py;
              pythonPackages = ps: with ps; [ flask waitress requests ];
              stateDirectory = "gluck-portero-mint";
              environment = {
                PORTERO_ADMIN_USER = cfg.adminUser;
                PORTERO_REQUIRED_GROUP = cfg.requiredGroup;
                PORTERO_GRANTABLE_GROUPS = lib.concatStringsSep "," cfg.grantableGroups;
                PORTERO_DEFAULT_TTL = toString cfg.defaultTtlSeconds;
                PORTERO_MAX_TTL = toString cfg.maxTtlSeconds;
                PORTERO_REDEEM_BASE = "https://${cfg.redeemSubdomain}.${
                  lib.head config.services.kelliher-web.baseDomains
                }";
              };
              extraServiceConfig = {
                LoadCredential = [
                  "invite_key:${cfg.inviteKeyFile}"
                  "admin_password:${cfg.adminPasswordFile}"
                ];
                MemoryMax = "192M";
                CPUQuota = "40%";
              };
            })

            (gluck-service-lib.lib.mkPythonService {
              inherit config lib pkgs;
              name = "gluck-portero-redeem";
              subdomain = cfg.redeemSubdomain;
              port = cfg.redeemPort;
              requireAuth = false;
              entrypoint = ./portero/redeem.py;
              pythonPackages = ps: with ps; [ flask waitress requests ];
              stateDirectory = "gluck-portero-redeem";
              environment = {
                PORTERO_REDEEM_USER = cfg.redeemUser;
                PORTERO_MIN_PASSWORD = toString cfg.minPasswordLength;
                PORTERO_SET_PASSWORD_BIN = setPasswordBin;
                PORTERO_LOGIN_URL = "https://auth.${
                  lib.head config.services.kelliher-web.baseDomains
                }";
              };
              extraServiceConfig = {
                LoadCredential = [
                  "invite_key:${cfg.inviteKeyFile}"
                  "redeem_password:${cfg.redeemPasswordFile}"
                ];
                MemoryMax = "192M";
                CPUQuota = "40%";
              };
            })

            {
              assertions = [
                {
                  assertion = cfg.mintPort != cfg.redeemPort;
                  message = "gluck-portero: mintPort and redeemPort must differ.";
                }
                {
                  assertion = cfg.redeemPasswordFile != cfg.adminPasswordFile;
                  message =
                    "gluck-portero: the redeem half must NOT share the mint half's "
                    + "directory credential. Redeem fronts a public endpoint and must "
                    + "hold lldap_password_manager only, never lldap_admin. "
                    + "See doc/THREAT-MODEL.md.";
                }
                {
                  assertion = cfg.maxTtlSeconds >= cfg.defaultTtlSeconds;
                  message = "gluck-portero: defaultTtlSeconds exceeds maxTtlSeconds.";
                }
                {
                  assertion = cfg.minPasswordLength >= 10;
                  message = "gluck-portero: minPasswordLength below 10 is not acceptable.";
                }
              ];
            }
          ]);
        };

      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
    in
    {
      nixosModules.default = nixosModule;
      nixosModules.gluck-portero = nixosModule;

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          py = pkgs.python3.withPackages (ps: with ps; [ flask waitress requests ]);
          suite = name: file: pkgs.runCommand "portero-${name}" { } ''
            # pipefail is load-bearing: without it the pipeline reports tee's
            # exit status and a failing test builds green.
            set -o pipefail
            cp ${./portero}/*.py .
            ${py}/bin/python3 ${file} 2>&1 | tee $out
          '';
        in {
          invites = suite "invites" "test_invites.py";
          spent = suite "spent" "test_spent.py";
          redeem = suite "redeem" "test_redeem.py";
          mint = suite "mint" "test_mint.py";
        });
    };
}
