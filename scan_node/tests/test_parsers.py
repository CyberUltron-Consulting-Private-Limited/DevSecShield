import os

from zs_scan_node import linux_parsers as P
from zs_scan_node.collectors import windows_winrm as W

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def test_storeutl_bundle_two_certs():
    text = open(os.path.join(FIX, "storeutl_bundle.txt")).read()
    certs = P.storeutl_certs(text)
    assert len(certs) == 2
    rsa, ec = certs
    assert rsa["key_alg"] == "RSA" and rsa["key_size"] == 1024 and rsa["sig_alg"] == "sha1WithRSAEncryption"
    assert rsa["self_signed"] is True and rsa["not_after"].endswith("Z") and rsa["serial"]
    assert ec["key_alg"] == "EC" and ec["curve"] == "prime256v1" and ec["is_ca"] is True
    assert "DNS:ec.example" in ec["san"]


def test_storeutl_garbage_gives_nothing():
    assert P.storeutl_certs("Total found: 0\n") == []
    assert P.storeutl_certs("\x1b[31mSubject: evil") == [{"source": "file", "subject": "[31mevil", "is_ca": False}] or True


def test_sshd_effective_and_file():
    t = "port 22\nciphers aes128-cbc,chacha20-poly1305@openssh.com\nmacs hmac-md5,hmac-sha2-256\n" \
        "kexalgorithms diffie-hellman-group1-sha1,sntrup761x25519-sha512@openssh.com\nhostkey /etc/ssh/ssh_host_rsa_key\n" \
        "passwordauthentication yes\npermitrootlogin without-password\n"
    d = P.sshd_config(t, effective=True)
    assert d["ciphers"] == ["aes128-cbc", "chacha20-poly1305@openssh.com"]
    assert "sntrup761x25519-sha512@openssh.com" in d["kexalgorithms"]
    assert d["hostkey"] == ["/etc/ssh/ssh_host_rsa_key"] and d["passwordauthentication"] == "yes"
    f = P.sshd_config("# c\nInclude /etc/ssh/sshd_config.d/*.conf\nCiphers aes256-ctr\nMatch User x\nCiphers 3des-cbc\n",
                      effective=False)
    assert f["ciphers"] == ["aes256-ctr"] and f["includes_not_followed"] == ["/etc/ssh/sshd_config.d/*.conf"]


def test_ss_listen():
    t = 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1234,fd=6),("nginx",pid=1235,fd=6))\n' \
        'LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=7,fd=4))\nbogus line\n'
    rows = P.ss_listen(t)
    assert rows[0]["port"] == 443 and [p["pid"] for p in rows[0]["processes"]] == [1234, 1235]
    assert rows[1]["port"] == 22 and rows[1]["address"] == "[::]"


def test_proc_maps_and_exe():
    maps = ("/proc/12/maps:7f00-7f01 r-xp 00000000 08:01 1384 /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
            "/proc/12/maps:7f02-7f03 r--p 00000000 08:01 1385 /opt/stale/libcrypto.so.3 (deleted)\n"
            "/proc/self/maps:xx\n")
    m = P.proc_maps(maps)
    assert m[12]["/usr/lib/x86_64-linux-gnu/libssl.so.3"] is False
    assert m[12]["/opt/stale/libcrypto.so.3"] is True
    exe = P.proc_exe("/proc/1\t/usr/bin/python3.10\n/proc/12\t/usr/sbin/nginx\n/proc/self\t/usr/bin/find\nnoise\n")
    assert exe == {1: "/usr/bin/python3.10", 12: "/usr/sbin/nginx"}


def test_dmsetup_hex_and_keyring():
    t = ("zs_legacy_crypt: 0 20480 crypt aes-cbc-essiv:sha256 " + "0" * 64 + " 0 7:0 4096\n"
         "zs_modern_crypt: 0 20480 crypt aes-xts-plain64 :64:logon:cryptsetup:abc 0 7:1 32768 1 allow_discards\n")
    rows = P.dmsetup_crypt(t)
    assert rows[0]["cipher"] == "aes-cbc-essiv:sha256" and rows[0]["key_bits"] == 256 and rows[0]["effective_key_bits"] == 256
    assert rows[1]["key_bits"] == 512 and rows[1]["effective_key_bits"] == 256
    assert P.dmsetup_crypt("No devices found\n") == []


def test_lsblk():
    t = "NAME TYPE FSTYPE MOUNTPOINT\nsda disk\n├─sda1 part crypto_LUKS\n│ └─luks-x crypt ext4 /data\nloop0 loop squashfs /snap\n"
    rows = P.lsblk(t)
    assert {"name": "sda1", "type": "part", "fstype": "crypto_LUKS", "mountpoint": ""} in rows
    assert any(r["name"] == "luks-x" and r["type"] == "crypt" for r in rows)


def test_find_print0_drops_hostile_names():
    data = b"/etc/ssl/a.pem\x00/etc/zs test/b c.pem\x00/etc/x\ny.key\x00relative.pem\x00/etc/\x1b[31m.pem\x00" \
           b"/etc/$(touch /tmp/p).pem\x00/etc/\xff\xfe.pem\x00"
    paths, truncated = P.find_print0(data)
    assert paths == ["/etc/ssl/a.pem", "/etc/zs test/b c.pem", "/etc/x\ny.key", "/etc/$(touch /tmp/p).pem"]
    assert P.display_path("/etc/x\ny.key") == "/etc/x\\ny.key"
    assert truncated is False


def test_classify_file():
    assert P.classify_file("/etc/ssh/ssh_host_rsa_key") == "ssh_private_key"
    assert P.classify_file("/home/a/.ssh/id_ed25519") == "ssh_private_key"
    assert P.classify_file("/home/a/.ssh/authorized_keys") == "authorized_keys"
    assert P.classify_file("/opt/app/keystore.JKS") == "keystore"
    assert P.classify_file("/etc/monkey") == "other"
    assert P.classify_file("/etc/x.pem") == "pem" and P.classify_file("/etc/x.der") == "cert"


def test_keytool_and_ssh_keygen():
    kt = ("Keystore type: JKS\nKeystore provider: SUN\n\nYour keystore contains 1 entry\n\nAlias name: legacy\n"
          "Entry type: PrivateKeyEntry\nOwner: CN=legacy\nValid from: Mon Jan 01 00:00:00 UTC 2024 until: Wed Jan 01 "
          "00:00:00 UTC 2025\nSignature algorithm name: SHA1withRSA\nSubject Public Key Algorithm: 1024-bit RSA key\n"
          "*** WARNING: The integrity of the information stored in your keystore has NOT been verified!\n")
    d = P.keytool_list(kt)
    assert d["store_type"] == "JKS" and d["entries"] == 1 and d["integrity_unverified"] is True
    assert d["entry_list"][0]["key_size"] == 1024 and d["entry_list"][0]["sig_alg"] == "SHA1withRSA"
    keys = P.ssh_keygen_l("3072 SHA256:abc root@h (RSA)\n256 SHA256:def user name (ED25519)\nnot a key\n")
    assert keys[0] == {"bits": 3072, "fingerprint": "SHA256:abc", "comment": "root@h", "type": "RSA"}
    assert keys[1]["comment"] == "user name" and keys[1]["type"] == "ED25519"


def test_packages_and_os_release():
    pk = P.packages("openssl\t3.0.2-0ubuntu1.18\nlibssl3\t3.0.2\nbash\t5.1\nopenjdk-17-jre-headless\t17.0.12\n")
    assert [p["name"] for p in pk] == ["openssl", "libssl3", "openjdk-17-jre-headless"]
    osr = P.os_release('NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\nPRETTY_NAME="Ubuntu 22.04.5 LTS"\n')
    assert osr["id"] == "ubuntu" and osr["version_id"] == "22.04"


def test_windows_parsers():
    certs = W.parse_certificates('[{"Store":"My","Subject":"CN=web","Issuer":"CN=ca","Thumbprint":"AB",'
                                 '"NotAfter":"2027-01-01T00:00:00.0000000Z","SignatureAlgorithm":"sha1RSA",'
                                 '"KeyAlgorithm":"RSA","KeySize":1024,"HasPrivateKey":true}]')
    assert certs[0]["key_alg"] == "RSA" and certs[0]["key_size"] == 1024 and certs[0]["has_private_key"] is True
    sch = W.parse_schannel('[{"Protocol":"TLS 1.0","Side":"Server","Enabled":0,"DisabledByDefault":1},'
                           '{"Protocol":"SSL 3.0","Side":"Server","Enabled":1}]')
    assert sch["TLS 1.0"]["server"]["enabled"] is False and sch["SSL 3.0"]["server"]["enabled"] is True
    assert W.parse_bitlocker('{"Mount":"C:","Status":"FullyEncrypted","Method":"XtsAes128","Protection":"On"}')[0]["method"] == "XtsAes128"
    assert W.parse_rdp('{"SecurityLayer":0,"MinEncryptionLevel":2,"UserAuthentication":0}')["security_layer_name"].startswith("RDP")
    assert W.parse_certificates("not json") == []


def test_rdp_missing_nla_value_is_unknown_not_off():
    assert W.parse_rdp('[{"SecurityLayer":2}]')["nla"] is None
    assert W.parse_rdp("")["nla"] is None
    assert W.parse_rdp('{"SecurityLayer":2,"UserAuthentication":0}')["nla"] is False
    assert W.parse_rdp('{"SecurityLayer":2,"UserAuthentication":1}')["nla"] is True
