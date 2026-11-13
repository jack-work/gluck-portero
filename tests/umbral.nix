{ pkgs, module }:

let
  adminPass = pkgs.writeText "lldap-admin" "fixture-admin-password";
  jwt = pkgs.writeText "lldap-jwt" "fixture-jwt-secret-fixture-jwt-secret";
  append = pkgs.writeText "append.py" ''
    import os, sys
    fd = os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND)
    os.write(fd, (sys.argv[2] + "\n").encode())
    os.close(fd)
  '';
  readit = pkgs.writeText "read.py" ''
    import sys
    open(sys.argv[1], "rb").read()
  '';
in
pkgs.testers.runNixOSTest {
  name = "portero-umbral";

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
    services.lldap = {
      enable = true;
      settings = {
        ldap_base_dn = "dc=example,dc=test";
        ldap_user_pass_file = "${adminPass}";
        force_ldap_user_pass_reset = "always";
        jwt_secret_file = "${jwt}";
      };
    };
    services.gluck-portero = {
      enable = true;
      inviteKeyFile = pkgs.writeText "invite_key" "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
      adminPasswordFile = adminPass;
      redeemPasswordFile = pkgs.writeText "redeem_password" "fixture-redeem";
      grantableGroups = [ "friends" ];
      umbral = {
        enable = true;
        notify.mail = "gluck@example.test";
      };
    };
    users.users.umbral = { isSystemUser = true; group = "umbral"; extraGroups = [ "umbral-spool" ]; };
    users.groups.umbral = { };
    users.users.mallory = { isSystemUser = true; group = "mallory"; };
    users.groups.mallory = { };
    environment.systemPackages = [ pkgs.acl pkgs.e2fsprogs pkgs.curl pkgs.jq pkgs.openldap ];

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
      requires = [ "kweb-gluck-portero-mint.socket" "lldap.service" ];
      after = [ "kweb-gluck-portero-mint.socket" "lldap.service" ];
      environment.PORTERO_INGEST_SECONDS = "1";
      serviceConfig.Sockets = [ "kweb-gluck-portero-mint.socket" ];
    };
  };

  testScript = ''
    import json

    spool = "/var/lib/umbral-spool/requests.jsonl"
    py = "${pkgs.python3}/bin/python3"
    admin = "-H 'Remote-User: gluck' -H 'Remote-Groups: portero-admin'"
    mint = "--unix-socket /run/kweb/gluck-portero-mint.sock http://mint"
    link = "/run/gluck-portero/link.sock"

    def record(subject, email="nora@example.test"):
        return json.dumps({"v": 1, "provider": "google", "subject": subject, "email": email,
                           "name": "Nora", "at": "2026-11-12T23:00:00Z"})

    def gql(query):
        tok = m.succeed("curl -fsS localhost:17170/auth/simple/login -H 'Content-Type: application/json' "
                        "-d '{\"username\":\"admin\",\"password\":\"fixture-admin-password\"}' | jq -r .token").strip()
        body = json.dumps({"query": query})
        return json.loads(m.succeed(f"curl -fsS localhost:17170/api/graphql -H 'Authorization: Bearer {tok}' "
                                    f"-H 'Content-Type: application/json' -d '{body}'"))

    m.wait_for_unit("lldap.service")
    m.wait_for_open_port(17170)
    m.wait_for_unit("sockets.target")
    gql('mutation{createGroup(name:"friends"){id}}')
    m.succeed(f"curl -fsS {mint}/healthz")

    with subtest("U6: mint created both link attributes admin-only"):
        a = {x["name"]: x for x in gql("query{schema{userSchema{attributes{name isVisible isEditable}}}}")["data"]["schema"]["userSchema"]["attributes"]}
        for n in ("umbral-google-sub", "umbral-github-id"):
            assert (a[n]["isVisible"], a[n]["isEditable"]) == (False, False), a[n]

    with subtest("U10: the layout unit made the spool root-owned, 0660, write-only ACL for umbral, +a"):
        assert m.succeed(f"stat -c %U:%G:%a {spool}").strip() == "root:portero-spool-reader:660"
        assert "a" in m.succeed(f"lsattr -d {spool}").split()[0]
        assert "group:umbral-spool:-w-" in m.succeed(f"getfacl -cp {spool}")

    with subtest("umbral appends, cannot read; nobody else can append"):
        m.succeed(f"runuser -u umbral -- {py} ${append} {spool} '{record('777')}'")
        m.fail(f"runuser -u umbral -- {py} ${readit} {spool}")
        m.fail(f"runuser -u mallory -- {py} ${append} {spool} '{record('666')}'")

    with subtest("mint ingests a spool whose layout holds"):
        m.wait_until_succeeds("journalctl -u gluck-portero-mint -o cat | grep -q 'umbral ingest outcome=ok landed=1'", timeout=30)
        rows = json.loads(m.succeed(f"curl -fsS {admin} {mint}/umbral/requests"))["rows"]
        assert [r["subject"] for r in rows] == ["777"], rows

    with subtest("U10: a spool without +a is refused at read"):
        m.succeed(f"chattr -a {spool}")
        m.succeed(f"runuser -u umbral -- {py} ${append} {spool} '{record('778', 'other@example.test')}'")
        m.wait_until_succeeds("journalctl -u gluck-portero-mint -o cat | grep -q 'umbral ingest outcome=refused reason=append_only=no'", timeout=30)
        rows = json.loads(m.succeed(f"curl -fsS {admin} {mint}/umbral/requests"))["rows"]
        assert [r["subject"] for r in rows] == ["777"], rows
        m.succeed("systemctl restart umbral-spool-layout.service")
        m.wait_until_succeeds(f"curl -fsS {admin} {mint}/umbral/requests | jq -e '.rows | length == 2'", timeout=30)

    with subtest("approval makes a credential-less account carrying the subject"):
        rid = [r["id"] for r in json.loads(m.succeed(f"curl -fsS {admin} {mint}/umbral/requests"))["rows"] if r["subject"] == "777"][0]
        out = json.loads(m.succeed(f"curl -sS {admin} -H 'Content-Type: application/json' -X POST {mint}/umbral/requests/{rid}/approve "
                                   "-d '{\"username\":\"nora\",\"site_access_groups\":[\"friends\"]}'"))
        assert out["username"] == "nora", out
        m.succeed("ldapsearch -LLL -x -H ldap://localhost:3890 -D uid=admin,ou=people,dc=example,dc=test -w fixture-admin-password "
                  "-b ou=people,dc=example,dc=test '(umbral-google-sub=777)' uid | grep -q 'uid: nora'")
        m.fail("curl -fsS localhost:17170/auth/simple/login -H 'Content-Type: application/json' -d '{\"username\":\"nora\",\"password\":\"\"}'")

    with subtest("N3: the link socket serves umbral's uid and refuses every other peer"):
        gql('mutation{createUser(user:{id:"gluck",email:"gluck@example.test"}){id}}')
        body = json.dumps({"uid": "gluck", "provider": "github", "subject": "4242", "email": "gluck@example.test"})
        call = f"curl -sS --unix-socket {link} -H 'Content-Type: application/json' -X POST http://portero/link -d '{body}'"
        m.fail(f"runuser -u mallory -- {call}")
        m.fail(f"runuser -u portero-mint -- {call}")
        root = m.execute(call)
        assert root[0] != 0 or "linked" not in root[1], root
        m.wait_until_succeeds("journalctl -u gluck-portero-mint -o cat | grep -q 'link socket refused peer uid=0'", timeout=10)
        out = json.loads(m.succeed(f"runuser -u umbral -- {call}"))
        assert out == {"linked": "gluck"}, out
        again = json.loads(m.succeed(f"runuser -u umbral -- {call}"))
        assert "error" in again, again

    with subtest("the link shows in the dashboard with its time, and Gluck was told"):
        ev = json.loads(m.succeed(f"curl -fsS {admin} {mint}/umbral/events"))["events"]
        links = [e for e in ev if e["action"] == "link"]
        assert len(links) == 1 and links[0]["uid"] == "gluck" and links[0]["subject"] == "4242" and links[0]["at"] > 0, ev
        assert links[0]["notified"] in ("mail", "failed"), links[0]
  '';
}
