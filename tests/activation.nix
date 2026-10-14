{ pkgs, module }:

let
  node = extra: { lib, pkgs, ... }: {
    imports = [
      module
      extra
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
in
pkgs.testers.runNixOSTest {
  name = "portero-activation";

  nodes.m = node { };

  nodes.c = node ({ lib, ... }: {
    systemd.services.gluck-portero-spool-layout = {
      before = lib.mkForce [ ];
      requiredBy = lib.mkForce [ ];
    };
  });

  testScript = ''
    spool = "/var/lib/gluck-portero-intake/spool.jsonl"
    L = "gluck-portero-spool-layout.service"
    I = "gluck-portero-intake.service"
    M = "gluck-portero-mint.service"
    switch = "/run/current-system/bin/switch-to-configuration test 2>&1"
    mint = "curl -s -o /dev/null -w '%{http_code}' --unix-socket /run/kweb/gluck-portero-mint.sock http://mint/"

    def show(n, unit, p):
        return n.succeed(f"systemctl show -P {p} {unit}").strip()

    def layout_lines(n):
        n.succeed("journalctl --sync")
        return int(n.succeed(f"journalctl -u {L} -o cat | grep -c 'intake spool layout' || true").strip())

    def snap(n):
        n.succeed(mint)
        n.wait_for_unit(M)
        s = {
            "layout_inv": show(n, L, "InvocationID"),
            "layout_lines": layout_lines(n),
            "intake_pid": show(n, I, "MainPID"),
            "mint_pid": show(n, M, "MainPID"),
            "intake_enter": show(n, I, "ActiveEnterTimestampMonotonic"),
            "mint_enter": show(n, M, "ActiveEnterTimestampMonotonic"),
        }
        assert s["layout_inv"], ("no InvocationID: the layout never ran", s)
        assert s["layout_lines"] > 0, ("no layout line in the journal", s)
        assert s["intake_pid"] not in ("", "0"), s
        assert s["mint_pid"] not in ("", "0"), s
        print(f"[{n.name}] {s}")
        return s

    start_all()
    for n in (m, c):
        n.wait_for_unit("multi-user.target")
        n.wait_for_unit(I)
    print(m.succeed("systemctl --version | head -1"))
    print(m.succeed("stat -f -c 'var/lib fs: %T' /var/lib"))
    print(m.succeed(f"systemctl cat {L} | grep -E '^(Before|RequiredBy|RemainAfterExit|Type)='  || true"))
    print(m.succeed(f"systemctl list-dependencies --reverse --plain {L}"))

    with subtest("control: nothing re-runs the layout or restarts portero between two reads"):
        for n in (m, c):
            a = snap(n)
            n.succeed("systemctl daemon-reload")
            b = snap(n)
            assert a == b, (n.name, a, b)

    with subtest("control: an explicit layout restart DOES restart intake and mint"):
        a = snap(m)
        m.succeed(f"systemctl restart {L}")
        m.wait_for_unit(I)
        b = snap(m)
        assert b["layout_inv"] != a["layout_inv"], (a, b)
        assert b["intake_pid"] != a["intake_pid"], ("Requires= did not propagate the restart", a, b)
        assert b["mint_pid"] != a["mint_pid"], ("Requires= did not propagate the restart", a, b)

    with subtest("control: without the sysinit-reactivation wiring, a no-change switch does not run the layout"):
        a = snap(c)
        rc, out = c.execute(switch)
        print(out)
        assert rc == 0, (rc, out)
        b = snap(c)
        assert b == a, (a, b)

    with subtest("(a)+(b): a no-change switch runs the layout and leaves intake and mint running"):
        a = snap(m)
        rc, out = m.execute(switch)
        print(out)
        assert rc == 0, (rc, out)
        b = snap(m)
        assert b["layout_inv"] != a["layout_inv"], ("(a) failed: layout did not run", a, b)
        assert b["layout_lines"] == a["layout_lines"] + 1, ("(a) failed: no new layout line", a, b)
        for k in ("intake_pid", "mint_pid", "intake_enter", "mint_enter"):
            assert b[k] == a[k], (f"(b) failed: {k} moved", a, b)
        assert show(m, L, "Result") == "success"

    def break_layout(n):
        n.succeed(f"chattr -a {spool} && chmod 0600 {spool} && chattr +i {spool}")

    def mend_layout(n):
        n.succeed(f"chattr -i {spool}")
        n.succeed(f"systemctl reset-failed {L}")
        n.succeed(f"systemctl start {L}")
        n.succeed("journalctl --sync")
        n.succeed(f"journalctl -u {L} -o cat | grep 'intake spool layout' | tail -1 | grep -q repaired")
        n.succeed(f"lsattr {spool} | cut -c1-22 | grep -q a")
        n.succeed(f"stat -c %a {spool} | grep -qx 660")

    with subtest("control: without the wiring, a broken layout leaves the switch green"):
        a = snap(c)
        break_layout(c)
        rc, out = c.execute(switch)
        print(out)
        assert rc == 0, (rc, out)
        assert L not in out, out
        assert show(c, L, "InvocationID") == a["layout_inv"]
        mend_layout(c)

    with subtest("(c): a broken layout fails the switch, by name"):
        a = snap(m)
        break_layout(m)
        rc, out = m.execute(switch)
        print(out)
        assert rc != 0, ("(c) failed: switch exited 0", out)
        assert L in out, ("(c) failed: switch did not name the layout unit", out)
        assert show(m, L, "Result") != "success"
        assert show(m, L, "InvocationID") != a["layout_inv"]
        m.succeed("journalctl --sync")
        print(m.succeed(f"journalctl -u {L} -o cat | tail -3"))
        m.succeed(f"journalctl -u {L} -o cat | grep 'intake spool layout' | tail -1 | grep -q 'failed at'")
        m.wait_until_fails(f"systemctl is-active --quiet {I}", timeout=20)
        assert show(m, M, "MainPID") == a["mint_pid"], ("mint must keep running: it only reads", a)
        mend_layout(m)
  '';
}
