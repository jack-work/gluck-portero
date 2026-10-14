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
    system.switch.enable = true;
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
    import json
    import re

    spool = "/var/lib/gluck-portero-intake/spool.jsonl"
    probe = "${pkgs.python3}/bin/python3 ${probe}"
    every = "read append open_without_append ftruncate pwrite_at_zero"
    admin = "-H 'Remote-User: admin' -H 'Remote-Groups: portero-admin'"
    mint = "--unix-socket /run/kweb/gluck-portero-mint.sock http://mint"
    L = "gluck-portero-spool-layout.service"
    noop = f"/run/systemd/system/{L}.d/absent.conf"
    switch = "/run/current-system/bin/switch-to-configuration test 2>&1"

    def layout_unit_absent():
        m.succeed(f"mkdir -p $(dirname {noop}) && printf '[Service]\\nExecStart=\\nExecStart=/run/current-system/sw/bin/true\\n' > {noop}")
        m.succeed("systemctl daemon-reload")

    def layout_unit_present():
        m.succeed(f"rm -f {noop} && systemctl daemon-reload")

    def layout_line():
        m.succeed("journalctl --sync")
        return m.succeed(f"journalctl -u {L} -o cat | grep 'intake spool layout' | tail -1").strip()

    def show_result():
        return m.succeed(f"systemctl show -P Result {L}").strip()

    def run_layout():
        m.succeed(f"systemctl reset-failed {L}")
        return m.execute(f"systemctl start {L}")[0]

    def activate():
        m.succeed(f"systemctl reset-failed {L}")
        code, out = m.execute(switch)
        print(out)
        return code, out

    def mint_ingest_lines(priority):
        m.succeed("journalctl --sync")
        return m.succeed(f"journalctl -u gluck-portero-mint -p {priority} -o cat | grep 'mint ingest' || true")

    def run_probe(unit, restart=True, steps=None):
        steps = steps or every
        d = f"/run/systemd/system/{unit}.service.d"
        m.succeed(f"mkdir -p {d}")
        m.succeed(
            f"printf '[Service]\\nType=oneshot\\nRestart=no\\nExecStart=\\n"
            f"ExecStart={probe} {spool} {steps}\\n' > {d}/probe.conf"
        )
        m.succeed("systemctl daemon-reload")
        m.succeed(f"systemctl reset-failed {unit}.service {L}")
        m.succeed(f"systemctl restart {unit}.service")
        inv = m.succeed(f"systemctl show -P InvocationID {unit}.service").strip()
        m.succeed("journalctl --sync")
        out = m.succeed(f"journalctl -o cat _SYSTEMD_INVOCATION_ID={inv}")
        m.succeed(f"rm {d}/probe.conf && systemctl daemon-reload")
        m.succeed(f"systemctl reset-failed {unit}.service {L}")
        if restart:
            m.succeed(f"systemctl restart {unit}.service")
            m.wait_for_unit(f"{unit}.service")
        found = dict(re.findall(r"^PROBE (\S+) (\S+)", out, re.M))
        print(f"[{unit}] {found}")
        assert len(found) == len(steps.split()), f"probe did not report every step: {out}"
        return found

    def layout():
        return m.succeed(
            f"stat -c '%a %U:%G %n' /var/lib/gluck-portero-intake {spool}; "
            f"getfacl -cp {spool}; lsattr {spool}"
        )

    def ctime():
        return m.succeed(f"stat -c %z {spool}").strip()

    m.wait_for_unit("multi-user.target")
    m.wait_for_unit("gluck-portero-intake.service")
    m.wait_for_unit("gluck-portero-mint.service")
    print(m.succeed("systemctl --version | head -1"))
    print(m.succeed("stat -f -c 'var/lib fs: %T' /var/lib"))

    with subtest("positive control: the probe sees F1 under the layout spain runs today"):
        layout_unit_absent()
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

    with subtest("migration: one activation applies the new layout"):
        layout_unit_present()
        m.succeed("systemctl restart systemd-tmpfiles-resetup.service")
        code, out = activate()
        assert code == 0, (code, out)
        line = layout_line()
        assert line.startswith("WARNING intake spool layout repaired: owner=root:portero-intake ") and line.endswith(" append_only=no"), line
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

    with subtest("an unchanged layout is left alone: same ctime, +a never lifted"):
        before, c0 = layout(), ctime()
        m.succeed("sleep 1.1")
        code, out = activate()
        assert code == 0, (code, out)
        assert layout_line() == "INFO intake spool layout ok", layout_line()
        assert (layout(), ctime()) == (before, c0), (before, c0, layout(), ctime())
        m.fail("systemctl is-failed --quiet systemd-tmpfiles-resetup.service")
        signup_reaches_mint("second@example.com")

    with subtest("drift is repaired, named, and changes ctime"):
        good = layout()
        for name, drift, field in (
            ("mode", f"chattr -a {spool} && chmod 0640 {spool} && chattr +a {spool}", "mode=640"),
            ("acl", f"chattr -a {spool} && setfacl -x group:portero-intake {spool} && chattr +a {spool}", "acl="),
            ("append_only", f"chattr -a {spool}", "append_only=no"),
            ("owner", f"chattr -a {spool} && chown root:root {spool} && chattr +a {spool}", "owner=root:root"),
        ):
            m.succeed(drift)
            assert layout() != good, ("drift did not take", name)
            c0 = ctime()
            m.succeed("sleep 1.1")
            assert run_layout() == 0, name
            line = layout_line()
            print(f"DRIFT {name}: {line}")
            assert line.startswith("WARNING intake spool layout repaired: ") and field in line, (name, line)
            assert layout() == good, (name, layout(), good)
            assert ctime() != c0, ("a repair must show in ctime, or the ctime control proves nothing", name)
        signup_reaches_mint("drift@example.com")

    with subtest("a filesystem that cannot hold the layout: success only with the layout read back"):
        m.succeed("systemctl stop gluck-portero-intake gluck-portero-mint")
        m.succeed("truncate -s 16M /tmp/noacl.img && mkfs.ext4 -F -q /tmp/noacl.img")
        for fs, mount in (
            ("tmpfs", "mount -t tmpfs -o mode=0711 tmpfs /var/lib/gluck-portero-intake"),
            ("ext4-noacl", "mount -o loop,noacl /tmp/noacl.img /var/lib/gluck-portero-intake && chmod 0711 /var/lib/gluck-portero-intake"),
        ):
            m.succeed(mount)
            code = run_layout()
            line = layout_line()
            print(f"FS {fs}: exit {code}: {line}")
            if code == 0:
                assert line.startswith("WARNING intake spool layout repaired"), (fs, line)
                m.succeed(f"getfacl -cp {spool} | grep -qx 'group:portero-intake:-w-'")
                m.succeed(f"lsattr {spool} | cut -c1-22 | grep -q a")
            else:
                assert show_result() == "exit-code", (fs, show_result())
                assert line.startswith("ERROR intake spool layout"), (fs, line)
            if fs == "ext4-noacl":
                assert code != 0, "a filesystem without ACLs must fail the unit"
            m.succeed(f"chattr -a {spool} 2>/dev/null; umount /var/lib/gluck-portero-intake")
        assert run_layout() == 0
        m.succeed("systemctl start gluck-portero-mint gluck-portero-intake")
        signup_reaches_mint("fs@example.com")

    with subtest("a step forced to fail fails the unit, restores +a, keeps intake down, and fails activation"):
        m.succeed(f"chattr -a {spool} && chmod 0600 {spool} && chattr +i {spool}")
        assert run_layout() != 0
        assert show_result() == "exit-code", show_result()
        assert layout_line() == 'ERROR intake spool layout failed at: chown -- "$WANT_OWNER" "$PORTERO_SPOOL"', layout_line()
        m.succeed(f"lsattr {spool} | cut -c1-22 | grep -q a")
        pid = m.succeed("systemctl show -P MainPID gluck-portero-intake").strip()
        m.succeed(f"systemctl reset-failed {L}")
        code, _ = m.execute("systemctl restart gluck-portero-intake")
        assert code != 0, "intake restarted over a failed layout"
        m.fail("systemctl is-active --quiet gluck-portero-intake")
        print("intake after a refused restart:", m.succeed("systemctl show -P ActiveState,Result gluck-portero-intake"), "was pid", pid)
        code, out = activate()
        assert code != 0 and re.search(rf"the following units failed: .*{re.escape(L)}", out), (code, out)
        m.succeed(f"chattr -i {spool}")
        assert run_layout() == 0
        assert layout_line().startswith("WARNING intake spool layout repaired"), layout_line()
        m.succeed("systemctl reset-failed gluck-portero-intake && systemctl start gluck-portero-intake")
        signup_reaches_mint("forced@example.com")

    with subtest("rollback: the previous release's rules cannot re-own the spool"):
        layout_unit_absent()
        # Emulates what a rollback to gluck-portero 27acc90 does to this file:
        # its two tmpfiles lines, verbatim, applied as systemd-tmpfiles-resetup
        # applies them, and mint back in portero-intake, its old group. Units
        # are the real ones. The previous release has no rule that clears +a,
        # and +a refuses chown even to root.
        print(m.succeed("systemctl show -P ExecStart systemd-tmpfiles-resetup.service"))
        m.succeed(
            "printf '%s\\n' "
            "'d /var/lib/gluck-portero-intake 0750 root portero-intake -' "
            "'f /var/lib/gluck-portero-intake/spool.jsonl 0660 root portero-intake -' "
            "> /run/portero-rollback.conf"
        )
        code, out = m.execute("systemd-tmpfiles --create --remove /run/portero-rollback.conf 2>&1")
        print(f"old rules: exit {code}: {out}")
        assert code == 73 and "fchownat" in out and "Operation not permitted" in out, (code, out)
        print(layout())
        m.succeed(f"stat -c '%U:%G' {spool} | grep -qx root:portero-spool-reader")
        d = "/run/systemd/system/gluck-portero-mint.service.d"
        m.succeed(f"mkdir -p {d}")
        m.succeed(f"printf '[Service]\\nSupplementaryGroups=\\nSupplementaryGroups=portero-intake\\n' > {d}/rollback.conf")
        m.succeed("systemctl daemon-reload && systemctl reset-failed gluck-portero-mint.service")
        m.succeed("systemctl restart gluck-portero-mint.service")
        print("resetup SuccessExitStatus:", m.succeed("systemctl show -P SuccessExitStatus systemd-tmpfiles-resetup.service"))
        mint_after = run_probe("gluck-portero-mint", steps="read append")
        intake_after = run_probe("gluck-portero-intake", steps="read append")
        print(f"after rollback: mint {mint_after} intake {intake_after}")
        assert mint_after["read"] == "EACCES", ("old mint cannot read: signups stall", mint_after)
        assert intake_after["append"] == "OK", intake_after
        m.wait_until_succeeds("curl -fs http://127.0.0.1:9103/healthz")
        m.wait_until_succeeds(f"curl -fs {mint}/healthz")
        http = m.succeed(
            "curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:9103/intake -d email=stalled@example.com"
        )
        assert http == "202", http
        stalled = json.loads(m.succeed(f"curl -fs {admin} {mint}/intake"))
        assert "stalled@example.com" not in [r["email"] for r in stalled["rows"]], ("expected a stall", stalled)
        assert (stalled["ingest"], stalled["ingest_errno"], stalled["ingested_now"]) == ("error", "EACCES", None), stalled
        assert stalled["spool_bytes"] > stalled["spool_consumed"], stalled
        err = mint_ingest_lines("err")
        assert re.search(r"^ERROR mint ingest outcome=error offset=\d+ spool_bytes=\d+ errno=EACCES$", err, re.M), err
        assert "outcome=ok" not in err, ("an ok line at priority err: the -p filter is not filtering", err)
        assert "outcome=ok" in mint_ingest_lines("info"), "control: ok lines exist below err"
        m.succeed(f"grep -q stalled@example.com {spool}")
        m.fail(f"truncate -s 0 {spool}")

    with subtest("the revocation BEFORE switching back: the old rules then apply cleanly, and the stalled signup lands"):
        m.succeed(
            "systemctl stop gluck-portero-intake.service gluck-portero-mint.service && "
            f"chattr -a {spool} && setfacl -b {spool} && chown root:portero-intake {spool} && chmod 0660 {spool}"
        )
        code, out = m.execute("systemd-tmpfiles --create --remove /run/portero-rollback.conf 2>&1")
        assert code == 0, ("after the revocation the old rules must apply cleanly", code, out)
        m.succeed("systemctl start gluck-portero-mint.service gluck-portero-intake.service")
        print(layout())
        m.succeed(f"stat -c '%a %U:%G' {spool} | grep -qx '660 root:portero-intake'")
        m.succeed(f"test $(getfacl -cp {spool} | grep -c .) = 3")
        m.fail(f"lsattr {spool} | cut -c1-22 | grep -q a")
        m.wait_until_succeeds("curl -fs http://127.0.0.1:9103/healthz")
        m.wait_until_succeeds(f"curl -fs {mint}/healthz")
        landed = m.succeed(f"curl -fs {admin} {mint}/intake")
        assert "stalled@example.com" in landed, ("the stall must defer, not lose", landed)
        assert run_probe("gluck-portero-mint", steps="read")["read"] == "OK"
        assert run_probe("gluck-portero-intake", steps="append")["append"] == "OK"
        m.succeed(f"truncate -s 0 {spool}")

    with subtest("roll forward: one activation restores the new layout"):
        m.succeed(f"rm {d}/rollback.conf")
        layout_unit_present()
        m.succeed("systemctl restart systemd-tmpfiles-resetup.service")
        code, out = activate()
        assert code == 0, (code, out)
        assert layout_line().startswith("WARNING intake spool layout repaired"), layout_line()
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
        m.fail("systemctl is-failed --quiet systemd-tmpfiles-setup.service")
        m.succeed(f"journalctl -b -u {L} -o cat | grep -q 'intake spool layout'")
        assert show_result() == "success", show_result()
        signup_reaches_mint("third@example.com")
        got = run_probe("gluck-portero-intake")
        assert got["read"] == "EACCES", got
        assert got["ftruncate"] == "EPERM", got
  '';
}
