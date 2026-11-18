import unittest
from cli.devsec import (
    analyze_cidr,
    audit_jwt,
    profile_and_convert_csv,
    scan_log_text,
    transpile_firewall_rule,
)


class TestDevSecOpsToolkit(unittest.TestCase):
    def test_analyze_cidr_and_vlsm_split(self):
        result = analyze_cidr("192.168.10.0/24", split=4)
        self.assertEqual(result["network"], "192.168.10.0")
        self.assertEqual(result["netmask"], "255.255.255.0")
        self.assertEqual(result["wildcard"], "0.0.0.255")
        self.assertEqual(result["usable_hosts"], 254)
        self.assertTrue(result["is_private"])
        self.assertEqual(len(result["subnets"]), 4)
        self.assertEqual(result["subnets"][0]["cidr"], "192.168.10.0/26")
        self.assertEqual(result["subnets"][0]["usable_hosts"], 62)

    def test_transpile_firewall_vendors(self):
        fg = transpile_firewall_rule(
            vendor="fortigate",
            name="BLOCK-IOT",
            action="deny",
            src_cidr="10.99.0.0/24",
            dst_cidr="0.0.0.0/0",
        )
        self.assertIn("config firewall policy", fg)
        self.assertIn("set subnet 10.99.0.0 255.255.255.0", fg)

        pf = transpile_firewall_rule(
            vendor="pfsense",
            name="BLOCK-IOT",
            action="deny",
            src_cidr="10.99.0.0/24",
            dst_cidr="0.0.0.0/0",
        )
        self.assertIn("block drop in log quick", pf)

        aruba = transpile_firewall_rule(
            vendor="aruba",
            name="BLOCK-IOT",
            action="deny",
            src_cidr="10.99.0.0/24",
            dst_cidr="0.0.0.0/0",
            vlan=99,
        )
        self.assertIn("ip access-list extended", aruba)
        self.assertIn("0.0.0.255", aruba)

    def test_scan_log_iocs_and_attacks(self):
        sample = (
            '185.220.101.45 GET /login?user=admin\' OR \'1\'=\'1 '
            'CVE-2024-3400 AKIAIOSFODNN7EXAMPLE src=10.10.0.5'
        )
        report = scan_log_text(sample, defang=True)
        self.assertEqual(report["public_ips_count"], 1)
        self.assertEqual(report["private_ips_count"], 1)
        self.assertEqual(report["top_public_ips"][0]["ip"], "185[.]220[.]101[.]45")
        self.assertIn("CVE-2024-3400", report["cves"])
        self.assertIn("SQL Injection (SQLi)", report["detections"])
        self.assertIn("AWS Access Key Leak", report["detections"])

    def test_audit_jwt(self):
        token = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJzdWIiOiIxMjMiLCJwYXNzd29yZCI6InNlY3JldCJ9."
        )
        audit = audit_jwt(token)
        self.assertFalse(audit["signature_present"])
        self.assertTrue(any("alg: none" in w for w in audit["warnings"]))
        self.assertTrue(any("Sensitive keys" in w for w in audit["warnings"]))

    def test_profile_and_convert_csv(self):
        csv_data = "id,host,role\n1,fw-01,firewall\n2,sw-01,\n"
        res = profile_and_convert_csv(csv_data, table_name="assets")
        self.assertEqual(res["rows"], 2)
        self.assertEqual(res["columns"]["role"]["nulls"], 1)
        self.assertIn("CREATE TABLE assets", res["sql"])
        self.assertIn("INSERT INTO assets", res["sql"])


if __name__ == "__main__":
    unittest.main()
