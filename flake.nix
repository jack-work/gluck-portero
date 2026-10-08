{
  description = "gluck-portero: invite links for guest accounts on spain";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.gluck-service-lib.url = "github:jack-work/gluck-service-lib";
  inputs.gluck-service-lib.inputs.nixpkgs.follows = "nixpkgs";

  outputs =
    { self, nixpkgs, gluck-service-lib, ... }:
    let
      # The runtime package, as a DIRECTORY. Shared by the module and by the
      # packaging check, deliberately: when the test built its own flat copy of
      # every .py file, it passed while production shipped one file and died on
      # `ModuleNotFoundError`. The check and the deploy now consume the same
      # derivation, so they cannot disagree about what ships.
      porteroSrc = pkgs: pkgs.runCommand "gluck-portero-src" { } ''
        mkdir -p $out
        cp ${./portero/invites.py}       $out/invites.py
        cp ${./portero/spent.py}         $out/spent.py
        cp ${./portero/budget.py}        $out/budget.py
        cp ${./portero/pending.py}       $out/pending.py
        cp ${./portero/pending_admin.py} $out/pending_admin.py
        cp ${./portero/mailer.py}        $out/mailer.py
        cp ${./portero/mint.py}          $out/mint.py
        cp ${./portero/redeem.py}        $out/redeem.py
        cp ${./portero/intake.py}        $out/intake.py
      '';

      nixosModule =
        { config, lib, pkgs, ... }:
        let
          cfg = config.services.gluck-portero;
          setPasswordBin = "${pkgs.lldap}/bin/lldap_set_password";
          intakeGroup = "portero-intake";
          py = pkgs.python3.withPackages (ps: with ps; [ flask waitress ]);

          # The entrypoints import sibling modules, so the package has to reach
          # the store as a DIRECTORY. Passing `./portero/mint.py` copies that one
          # file and nothing beside it, and the unit dies at startup on
          # `ModuleNotFoundError: No module named 'invites'`.
          src = porteroSrc pkgs;
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
              default = [ "site-files-access" ];
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

            intakePort = lib.mkOption {
              type = lib.types.port;
              default = 9103;
              description = ''
                Loopback port for the intake unit, which is served under
                `/intake` on the PUBLIC redeem hostname rather than on a name
                of its own. One fewer public hostname, and no DNS record to
                add.
              '';
            };

            intakeCap = lib.mkOption {
              type = lib.types.int;
              default = 200;
              description = ''
                Ceiling on PENDING intake rows. Enforced by a sqlite trigger
                rather than by the application, so the public unit needs no
                statement that reads the table back. Approving or rejecting a
                row frees its slot.
              '';
            };

            intakeDirectory = lib.mkOption {
              type = lib.types.str;
              default = "/var/lib/gluck-portero-intake";
              description = ''
                Directory holding the intake table. The intake unit writes it
                and the mint unit reads it; both reach it through the
                `portero-intake` group, and neither has any other path in
                common.

                This is state OUTSIDE the closure. Rolling spain back past this
                change leaves the directory and its rows in place; removing it
                is the revocation, and it is one `rm -rf`.
              '';
            };

            smtpPasswordFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = ''
                SES SMTP password for the MINT half, delivered by
                LoadCredential. Null means this estate sends no invite mail and
                the operator carries the link himself; the mail routes then
                answer 502 and say so.

                The redeem and intake halves never receive this. Only the
                authenticated half can cause mail to be sent.
              '';
            };

            smtpHost = lib.mkOption {
              type = lib.types.str;
              default = "email-smtp.us-east-1.amazonaws.com";
            };

            smtpPort = lib.mkOption {
              type = lib.types.port;
              default = 587;
            };

            smtpUser = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "SES SMTP username. Not a secret; the password is.";
            };

            smtpSender = lib.mkOption {
              type = lib.types.str;
              default = "kelliher.info <auth@kelliher.info>";
              description = ''
                Envelope and header sender. SES authorizes this credential for
                one identity, so a value it cannot send as fails at send time
                and not at build time.
              '';
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
              entrypoint = "${src}/mint.py";
              pythonPackages = ps: with ps; [ flask waitress requests ];
              stateDirectory = "gluck-portero-mint";
              environment = {
                PORTERO_ADMIN_USER = cfg.adminUser;
                PORTERO_REQUIRED_GROUP = cfg.requiredGroup;
                PORTERO_GRANTABLE_GROUPS = lib.concatStringsSep "," cfg.grantableGroups;
                PORTERO_DEFAULT_TTL = toString cfg.defaultTtlSeconds;
                PORTERO_MAX_TTL = toString cfg.maxTtlSeconds;
                PORTERO_INTAKE_DB = "${cfg.intakeDirectory}/intake.db";
                PORTERO_INTAKE_CAP = toString cfg.intakeCap;
                PORTERO_SMTP_HOST = cfg.smtpHost;
                PORTERO_SMTP_PORT = toString cfg.smtpPort;
                PORTERO_SMTP_USER = lib.optionalString (cfg.smtpPasswordFile != null) cfg.smtpUser;
                PORTERO_SMTP_SENDER = cfg.smtpSender;
                PORTERO_REDEEM_BASE = "https://${cfg.redeemSubdomain}.${
                  lib.head config.services.kelliher-web.baseDomains
                }";
              };
              extraServiceConfig = {
                LoadCredential = [
                  "invite_key:${cfg.inviteKeyFile}"
                  "admin_password:${cfg.adminPasswordFile}"
                ] ++ lib.optional (cfg.smtpPasswordFile != null)
                  "smtp_password:${cfg.smtpPasswordFile}";
                SupplementaryGroups = [ intakeGroup ];
                ReadWritePaths = [ cfg.intakeDirectory ];
                UMask = "0007";
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
              entrypoint = "${src}/redeem.py";
              pythonPackages = ps: with ps; [ flask waitress requests ];
              stateDirectory = "gluck-portero-redeem";
              environment = {
                PORTERO_REDEEM_USER = cfg.redeemUser;
                PORTERO_MIN_PASSWORD = toString cfg.minPasswordLength;
                PORTERO_SET_PASSWORD_BIN = setPasswordBin;
                # lldap_set_password builds a reqwest client, and reqwest loads a
                # CA bundle even for an http:// base url. Without one it PANICS
                # with a bare "No such file or directory" and exit 101, which
                # reads like a missing binary. Pinning the store bundle makes it
                # independent of /etc and of this unit's ProtectSystem=strict.
                SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
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
              users.groups.${intakeGroup} = { };

              systemd.tmpfiles.rules = [
                "d ${cfg.intakeDirectory} 2770 root ${intakeGroup} -"
              ];

              systemd.services.gluck-portero-intake = {
                description = "gluck-portero-intake: the public write-only signup table";
                after = [ "network.target" "systemd-tmpfiles-setup.service" ];
                requires = [ "systemd-tmpfiles-setup.service" ];
                wantedBy = [ "multi-user.target" ];
                environment = {
                  PORT = toString cfg.intakePort;
                  PORTERO_INTAKE_DB = "${cfg.intakeDirectory}/intake.db";
                  PORTERO_INTAKE_CAP = toString cfg.intakeCap;
                };
                serviceConfig = gluck-service-lib.lib.defaultHardened // {
                  DynamicUser = true;
                  SupplementaryGroups = [ intakeGroup ];
                  ReadWritePaths = [ cfg.intakeDirectory ];
                  UMask = "0007";
                  ExecStart = "${py}/bin/python ${src}/intake.py";
                  Restart = "on-failure";
                  RestartSec = 5;
                  MemoryMax = "128M";
                  CPUQuota = "25%";
                };
              };

              services.kelliher-web.sites.gluck-portero-mint.trustsRemoteHeaders = true;

              services.kelliher-web.sites.gluck-portero-redeem.extraConfig = ''
                handle /intake* {
                  reverse_proxy localhost:${toString cfg.intakePort}
                }
              '';

              assertions = [
                {
                  assertion = cfg.mintPort != cfg.redeemPort;
                  message = "gluck-portero: mintPort and redeemPort must differ.";
                }
                {
                  assertion =
                    cfg.intakePort != cfg.mintPort && cfg.intakePort != cfg.redeemPort;
                  message = "gluck-portero: intakePort collides with another half.";
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
                {
                  assertion = cfg.intakeCap >= 1;
                  message = "gluck-portero: intakeCap below 1 accepts no signup at all.";
                }
                {
                  assertion = cfg.smtpPasswordFile == null || cfg.smtpUser != "";
                  message =
                    "gluck-portero: smtpPasswordFile is set but smtpUser is empty, so "
                    + "mint would hold a mail credential it cannot authenticate with "
                    + "and every send would fail at the SMTP greeting.";
                }
                {
                  assertion =
                    cfg.smtpPasswordFile == null
                    || (cfg.smtpPasswordFile != cfg.redeemPasswordFile
                        && cfg.smtpPasswordFile != cfg.inviteKeyFile);
                  message =
                    "gluck-portero: smtpPasswordFile aliases another credential.";
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
          budget = suite "budget" "test_budget.py";
          pending = suite "pending" "test_pending.py";
          intake = suite "intake" "test_intake.py";

          # The loop against a REAL lldap. No mocks, because mocks lied twice:
          # one returned {"user": None} where lldap raises a GraphQL error, and
          # every unit suite stayed green while mint 500'd on its first call.
          # A mock that encodes your assumption cannot falsify it.
          #
          # This is the only test that caught anything, so it runs in CI rather
          # than by hand. It asserts the two properties the design rests on:
          # zero credential (no login until redemption) and single use.
          integration = pkgs.runCommand "portero-integration"
            {
              nativeBuildInputs = [ py pkgs.lldap pkgs.curl pkgs.coreutils pkgs.gnused pkgs.gnugrep pkgs.cacert ];
            } ''
              set -o pipefail
              export SRC=${porteroSrc pkgs}
              export HOME=$TMPDIR
              export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
              bash ${./portero/integration.sh} 2>&1 | tee $out
            '';

          # The intake pipeline, against the same real lldap and a real SMTP
          # server on a scratch port. The message asserted here left the mint
          # process over a socket, so "it mails the link" is observed rather
          # than inferred from a stubbed sender.
          pipeline = pkgs.runCommand "portero-pipeline"
            {
              nativeBuildInputs = [
                py pkgs.lldap pkgs.curl pkgs.coreutils pkgs.gnused pkgs.gnugrep
                pkgs.sqlite pkgs.cacert
              ];
            } ''
              set -o pipefail
              export SRC=${porteroSrc pkgs}
              export SRC_TESTS=${./portero}
              export HOME=$TMPDIR
              export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
              bash ${./portero/pipeline.sh} 2>&1 | tee $out
            '';

          # The check the unit tests could not make. They assembled their own
          # flat directory of every .py file, so they proved the CODE and said
          # nothing about what the module SHIPS. This one imports both
          # entrypoints out of the exact derivation the systemd units execute,
          # which is where `ModuleNotFoundError: No module named 'invites'`
          # actually lived. Negative control: drop a module from porteroSrc and
          # this fails while all four suites above stay green.
          packaging = pkgs.runCommand "portero-packaging" { } ''
            set -o pipefail
            SRC=${porteroSrc pkgs}

            # Everything the units import must be present in the shipped tree.
            for m in invites.py spent.py budget.py pending.py pending_admin.py \
                     mailer.py mint.py redeem.py intake.py; do
              test -f "$SRC/$m" || { echo "MISSING from shipped tree: $m"; exit 1; }
            done

            # Tests must not ship.
            if ls "$SRC" | grep -q '^test_'; then
              echo "test files leaked into the runtime closure"; exit 1
            fi
            if test -e "$SRC/fakesmtp.py"; then
              echo "the SMTP test sink leaked into the runtime closure"; exit 1
            fi

            creds=$(mktemp -d); state=$(mktemp -d); intake=$(mktemp -d)
            head -c 48 /dev/zero | tr '\0' 'k' > "$creds/invite_key"
            echo stub > "$creds/admin_password"
            echo stub > "$creds/redeem_password"

            # The intake entrypoint is imported with NO credentials directory,
            # because the unit that runs it is given none. mint and redeem both
            # refuse to start without one, so this also proves the three are not
            # quietly sharing a startup path.
            PORTERO_INTAKE_DB=$intake/intake.db \
            ${py}/bin/python3 - <<PY 2>&1 | tee $out
            import sys
            sys.path.insert(0, "$SRC")
            import intake
            assert hasattr(intake, "offer"), "intake entrypoint incomplete"
            assert not hasattr(intake, "mailer"), "the public half imports a mailer"
            routes = sorted(str(r) for r in intake.app.url_map.iter_rules()
                            if not str(r).startswith("/static"))
            assert routes == ["/healthz", "/intake", "/intake"], routes
            print("intake imports and serves three routes with no credential")
            PY

            CREDENTIALS_DIRECTORY=$creds STATE_DIRECTORY=$state \
            PORTERO_INTAKE_DB=$intake/intake.db \
            ${py}/bin/python3 - <<PY 2>&1 | tee -a $out
            import sys
            sys.path.insert(0, "$SRC")
            import mint, redeem
            assert hasattr(mint, "create_invite"), "mint entrypoint incomplete"
            assert hasattr(mint, "approve_intake"), "mint lacks the intake routes"
            assert hasattr(mint, "send_intake"), "mint lacks send by id"
            assert hasattr(redeem, "redeem"), "redeem entrypoint incomplete"
            assert "mailer" not in dir(redeem), "the redeem half imports a mailer"
            assert "pending_admin" not in dir(redeem), "redeem holds a read path"
            print("both entrypoints import from the shipped tree")
            PY

            for half in redeem intake; do
              if grep -Eq '^(import mailer|from mailer)' "$SRC/$half.py"; then
                echo "$half.py imports the mailer: a public half can send mail"
                exit 1
              fi
            done
            echo "neither public half can send mail" | tee -a $out
          '';
        });
    };
}
