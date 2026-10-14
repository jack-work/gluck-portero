{ pkgs, module, probe }:

pkgs.testers.runNixOSTest {
  name = "portero-spool-sandbox";

  nodes.m = { lib, pkgs, ... }: {
    imports = [
      module
      {
        options.services.kelliher-web = {
          sites = lib.mkOption {
            type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
            default = { };
          };
          baseDomains = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ "example.test" ];
          };
        };
      }
    ];
    services.gluck-portero = {
      enable = true;
      inviteKeyFile = pkgs.writeText "invite_key" "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
      adminPasswordFile = pkgs.writeText "admin_password" "fixture-admin";
      redeemPasswordFile = pkgs.writeText "redeem_password" "fixture-redeem";
    };
    environment.systemPackages = [ pkgs.acl pkgs.e2fsprogs pkgs.curl ];

    # A mirror of what kelliher-web 6a8d9c4 gives a proxySocket site, so mint
    # can start. The socket mechanism itself is checks.socket's subject.
    systemd.tmpfiles.rules = [ "d /run/kweb 0750 root root -" ];
    systemd.sockets.kweb-gluck-portero-mint = {
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/kweb/gluck-portero-mint.sock";
        SocketMode = "0600";
        Service = "gluck-portero-mint.service";
      };
    };
    systemd.services.gluck-portero-mint = {
      requires = [ "kweb-gluck-portero-mint.socket" ];
      after = [ "kweb-gluck-portero-mint.socket" ];
      serviceConfig.Sockets = [ "kweb-gluck-portero-mint.socket" ];
      serviceConfig.SocketBindDeny = "any";
    };
  };

  testScript = ''
    import re

    spool = "/var/lib/gluck-portero-intake/spool.jsonl"
    probe = "${pkgs.python3}/bin/python3 ${probe}"
    every = "read append open_without_append ftruncate pwrite_at_zero"
    admin = "-H 'Remote-User: admin' -H 'Remote-Groups: portero-admin'"
    mint = "--unix-socket /run/kweb/gluck-portero-mint.sock http://mint"

    def run_probe(unit, restart=True):
        d = f"/run/systemd/system/{unit}.service.d"
        m.succeed(f"mkdir -p {d}")
        m.succeed(
            f"printf '[Service]\\nType=oneshot\\nRestart=no\\nExecStart=\\n"
            f"ExecStart={probe} {spool} {every}\\n' > {d}/probe.conf"
        )
        m.succeed("systemctl daemon-reload")
        m.succeed(f"systemctl reset-failed {unit}.service")
        m.succeed(f"systemctl restart {unit}.service")
        inv = m.succeed(f"systemctl show -P InvocationID {unit}.service").strip()
        m.succeed("journalctl --sync")
        out = m.succeed(f"journalctl -o cat _SYSTEMD_INVOCATION_ID={inv}")
        m.succeed(f"rm {d}/probe.conf && systemctl daemon-reload")
        m.succeed(f"systemctl reset-failed {unit}.service")
        if restart:
            m.succeed(f"systemctl restart {unit}.service")
            m.wait_for_unit(f"{unit}.service")
        found = dict(re.findall(r"^PROBE (\S+) (\S+)", out, re.M))
        print(f"[{unit}] {found}")
        assert len(found) == 5, f"probe did not report every step: {out}"
        return found

    def layout():
        return m.succeed(
            f"stat -c '%a %U:%G %n' /var/lib/gluck-portero-intake {spool}; "
            f"getfacl -cp {spool}; lsattr {spool}"
        )

    m.wait_for_unit("multi-user.target")
    m.wait_for_unit("gluck-portero-intake.service")
    m.wait_for_unit("gluck-portero-mint.service")
    print(m.succeed("systemctl --version | head -1"))
    print(m.succeed("stat -f -c 'var/lib fs: %T' /var/lib"))

    with subtest("positive control: the probe sees F1 under the layout spain runs today"):
        m.succeed("systemctl stop gluck-portero-intake gluck-portero-mint")
        m.succeed(f"chattr -a {spool}; setfacl -b {spool}")
        m.succeed(f"chown root:portero-intake {spool}; chmod 0660 {spool}")
        m.succeed("chown root:portero-intake /var/lib/gluck-portero-intake")
        m.succeed("chmod 2770 /var/lib/gluck-portero-intake")
        m.succeed(f"printf '%s\\n' '{{\"email\":\"victim@example.com\",\"note\":\"\",\"at\":1}}' > {spool}")
        m.succeed("systemctl start gluck-portero-intake gluck-portero-mint")
        old = run_probe("gluck-portero-intake")
        assert old["read"] == "OK", old
        assert old["ftruncate"] == "OK", old

    with subtest("migration: activation's tmpfiles run applies the new layout"):
        m.succeed("systemctl restart systemd-tmpfiles-resetup.service")
        print(layout())
        m.succeed(f"stat -c '%U:%G' {spool} | grep -qx root:portero-spool-reader")
        m.succeed("stat -c '%a %U:%G' /var/lib/gluck-portero-intake | grep -qx '711 root:root'")
        m.succeed(f"getfacl -cp {spool} | grep -qx 'group::r--'")
        m.succeed(f"getfacl -cp {spool} | grep -qx 'group:portero-intake:-w-'")
        m.succeed(f"getfacl -cp {spool} | grep -qx 'mask::rw-'")
        m.succeed(f"lsattr {spool} | cut -c1-22 | grep -q a")

    with subtest("intake: append only, nothing else"):
        m.succeed(f"chattr -a {spool}")
        m.succeed(f"printf '%s\\n' '{{\"email\":\"victim@example.com\",\"note\":\"\",\"at\":1}}' > {spool}")
        m.succeed(f"chattr +a {spool}")
        before = m.succeed(f"head -c 1 {spool}")
        got = run_probe("gluck-portero-intake")
        assert got["read"] == "EACCES", got
        assert got["append"] == "OK", got
        assert got["open_without_append"] == "EPERM", got
        assert got["ftruncate"] == "EPERM", got
        assert got["pwrite_at_zero"] == "OK", got
        assert m.succeed(f"head -c 1 {spool}") == before, "pwrite overwrote the first record"
        m.succeed(f"grep -q victim@example.com {spool}")

    with subtest("mint: reads, and cannot write"):
        got = run_probe("gluck-portero-mint")
        assert got["read"] == "OK", got
        for step in ("append", "open_without_append", "ftruncate", "pwrite_at_zero"):
            assert got[step] != "OK", (step, got)

    with subtest("the real reset, with the real chattr"):
        m.succeed("systemctl start gluck-portero-intake-reset.service")
        m.succeed(f"test $(stat -c %s {spool}) = 0")
        m.succeed(f"lsattr {spool} | cut -c1-22 | grep -q a")
        m.succeed(f"getfacl -cp {spool} | grep -qx 'group:portero-intake:-w-'")
        m.wait_for_unit("gluck-portero-intake.service")
        m.wait_for_unit("gluck-portero-mint.service")
        m.succeed("journalctl -o cat -u gluck-portero-intake-reset | grep -qx 'INFO intake spool reset spool_bytes=0'")

    def signup_reaches_mint(email):
        m.wait_until_succeeds("curl -fs http://127.0.0.1:9103/healthz")
        m.wait_until_succeeds(f"curl -fs {mint}/healthz")
        code = m.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -X POST http://127.0.0.1:9103/intake -d email={email}"
        )
        assert code == "202", code
        listing = m.succeed(f"curl -fs {admin} {mint}/intake")
        assert email in listing, listing

    with subtest("the real units, end to end"):
        signup_reaches_mint("first@example.com")
        m.succeed("journalctl -o cat -u gluck-portero-intake | grep -q 'outcome=written'")

    with subtest("a second tmpfiles run changes nothing and breaks nothing"):
        before = layout()
        m.succeed("systemctl restart systemd-tmpfiles-resetup.service")
        assert layout() == before, (before, layout())
        signup_reaches_mint("second@example.com")

    with subtest("rollback: the previous release's rules over the new file"):
        # Emulates what a rollback to gluck-portero 27acc90 does to this file:
        # its two tmpfiles lines, verbatim, applied as systemd-tmpfiles-resetup
        # applies them, and mint back in portero-intake, its old group. No old
        # rule removes the ACL or +a, so both survive. Units are the real ones.
        print(m.succeed("systemctl show -P ExecStart systemd-tmpfiles-resetup.service"))
        m.succeed(
            "printf '%s\\n' "
            "'d /var/lib/gluck-portero-intake 0750 root portero-intake -' "
            "'f /var/lib/gluck-portero-intake/spool.jsonl 0660 root portero-intake -' "
            "> /run/portero-rollback.conf"
        )
        m.succeed("systemd-tmpfiles --create --remove /run/portero-rollback.conf")
        print(layout())
        m.succeed(f"stat -c '%a %U:%G' {spool} | grep -qx '660 root:portero-intake'")
        m.succeed(f"getfacl -cp {spool} | grep -qx 'group:portero-intake:-w-'")
        m.succeed(f"lsattr {spool} | cut -c1-22 | grep -q a")
        d = "/run/systemd/system/gluck-portero-mint.service.d"
        m.succeed(f"mkdir -p {d}")
        m.succeed(f"printf '[Service]\\nSupplementaryGroups=\\nSupplementaryGroups=portero-intake\\n' > {d}/rollback.conf")
        m.succeed("systemctl daemon-reload && systemctl reset-failed gluck-portero-mint.service")
        m.succeed("systemctl restart gluck-portero-mint.service")
        mint_after = run_probe("gluck-portero-mint")
        assert mint_after["read"] == "OK", mint_after
        intake_after = run_probe("gluck-portero-intake")
        assert intake_after["append"] == "OK", intake_after
        assert intake_after["read"] == "OK", ("old layout: intake reads through the owning group", intake_after)
        signup_reaches_mint("rolledback@example.com")
        m.fail(f"truncate -s 0 {spool}")

    with subtest("the revocation: setfacl -b alone would stall signups"):
        m.succeed("systemctl stop gluck-portero-intake.service gluck-portero-mint.service")
        m.succeed(f"chattr -a {spool} && setfacl -b {spool}")
        m.succeed(f"stat -c %a {spool} | grep -qx 640")
        m.succeed("systemctl start gluck-portero-mint.service")
        stalled = run_probe("gluck-portero-intake", restart=False)
        assert stalled["append"] == "EACCES", ("setfacl -b drops the group write", stalled)

    with subtest("the revocation as the brief prints it: the old layout, whole"):
        m.succeed(
            "systemctl stop gluck-portero-intake.service gluck-portero-mint.service && "
            f"chattr -a {spool} && setfacl -b {spool} && chmod 0660 {spool} && "
            "systemctl start gluck-portero-mint.service gluck-portero-intake.service"
        )
        print(layout())
        m.succeed(f"stat -c '%a %U:%G' {spool} | grep -qx '660 root:portero-intake'")
        m.succeed(f"test $(getfacl -cp {spool} | grep -c .) = 3")
        m.fail(f"lsattr {spool} | cut -c1-22 | grep -q a")
        revoked = run_probe("gluck-portero-intake")
        assert revoked["append"] == "OK", revoked
        assert run_probe("gluck-portero-mint")["read"] == "OK"
        m.succeed(f"truncate -s 0 {spool}")
        signup_reaches_mint("revoked@example.com")

    with subtest("roll forward: this release's rules restore the new layout"):
        m.succeed(f"rm {d}/rollback.conf && systemctl daemon-reload")
        m.succeed("systemctl restart systemd-tmpfiles-resetup.service")
        m.succeed("systemctl reset-failed gluck-portero-mint.service && systemctl restart gluck-portero-mint.service")
        print(layout())
        m.succeed(f"stat -c '%U:%G' {spool} | grep -qx root:portero-spool-reader")
        m.succeed(f"getfacl -cp {spool} | grep -qx 'group:portero-intake:-w-'")
        m.succeed(f"lsattr {spool} | cut -c1-22 | grep -q a")
        forward = run_probe("gluck-portero-intake")
        assert forward["read"] == "EACCES" and forward["ftruncate"] == "EPERM", forward
        signup_reaches_mint("forward@example.com")

    with subtest("after a reboot, with new dynamic uids"):
        m.shutdown()
        m.start()
        m.wait_for_unit("gluck-portero-intake.service")
        m.wait_for_unit("gluck-portero-mint.service")
        print(layout())
        signup_reaches_mint("third@example.com")
        got = run_probe("gluck-portero-intake")
        assert got["read"] == "EACCES", got
        assert got["ftruncate"] == "EPERM", got
  '';
}
