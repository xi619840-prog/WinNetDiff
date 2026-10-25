import csv
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import windows_net_diffdiag as app


def fixture(**changes):
    data = {"service_registry": [], "drivers_wmi": [], "driverquery": [],
            "services_wmi": [], "installed_apps": [], "files": [], "antivirus_products": [],
            "errors": [], "completeness": {"installed_apps": True, "service_registry": True}}
    data.update(changes)
    return data


class SecurityTests(unittest.TestCase):
    def test_surfshark_endpoint_without_installed_application(self):
        service = {"Name": "EndpointProtectionService", "PathName": app.ENDPOINT_SDK_PATH,
                   "RegistryStart": 2, "RegistryType": 16}
        data = fixture(service_registry=[service], services_wmi=[dict(service, State="Running")],
                       files=[{"Path": app.ENDPOINT_SDK_PATH, "Exists": True,
                               "SignatureStatus": "Valid", "Publisher": "CN=Surfshark B.V."}])
        record = app.classify_security(data)[0]
        self.assertEqual(record["Group"], "Surfshark")
        self.assertEqual(record["Status"], "orphan_candidate")
        self.assertEqual(record["Severity"], "高優先級")

    def test_bdnet_and_bdsentry_running_are_shared_not_proven_malicious(self):
        for name in ("BdNet", "BdSentry"):
            with self.subTest(name=name):
                data = fixture(service_registry=[{"Name": name}],
                               drivers_wmi=[{"Name": name, "State": "Running"}])
                record = app.classify_security(data)[0]
                self.assertTrue(record["Running"])
                self.assertEqual(record["Group"], "SharedEndpoint")
                self.assertEqual(record["Status"], "owner_unknown")
                self.assertNotIn("惡意", "".join(record["Reasons"]))

    def test_driver_enumerated_after_registration_deleted(self):
        data = fixture(driverquery=[{"Name": "BdNet", "DisplayName": "Avira Network Filter",
                                    "State": "Running", "PathName": r"C:\Windows\System32\drivers\BdNet.sys"}])
        record = app.classify_security(data)[0]
        self.assertEqual(record["Status"], "registration_missing")
        self.assertEqual(record["Severity"], "高優先級")

    def test_incomplete_permissions_do_not_imply_missing_service(self):
        data = fixture(driverquery=[{"Name": "BdNet", "State": "Running"}],
                       completeness={"installed_apps": False, "service_registry": False})
        record = app.classify_security(data)[0]
        self.assertEqual(record["Status"], "inventory_incomplete")
        self.assertEqual(record["Severity"], "資訊")

    def test_renamed_service_same_binary_is_not_missing_registration(self):
        path = r"C:\Windows\System32\drivers\BdNet.sys"
        data = fixture(driverquery=[{"Name": "BdNet", "State": "Running", "PathName": path}],
                       service_registry=[{"Name": "OtherServiceAlias", "PathName": path}])
        record = next(x for x in app.classify_security(data) if x["Name"] == "BdNet")
        self.assertNotEqual(record["Status"], "registration_missing")

    def test_virtualbox_docker_and_npcap_owned_components_are_information(self):
        for product in ("VirtualBox", "Docker", "Npcap"):
            with self.subTest(product=product):
                data = fixture(service_registry=[{"Name": product + "Filter"}],
                    installed_apps=[{"DisplayName": product, "InstallLocation": "C:\\Program Files\\" + product}])
                record = app.classify_security(data)[0]
                self.assertEqual(record["Status"], "owner_installed")
                self.assertEqual(record["Severity"], "資訊")
                for finding in app.security_findings(data):
                    self.assertFalse(any("delete" in c.lower() for c in finding.commands))

    def test_shared_driver_under_other_active_product_path(self):
        image = r"C:\Program Files\Other Protection\BdNet.sys"
        data = fixture(service_registry=[{"Name": "BdNet", "PathName": image}],
            installed_apps=[{"DisplayName": "Other Protection", "InstallLocation": r"C:\Program Files\Other Protection"}])
        record = app.classify_security(data)[0]
        self.assertEqual(record["Status"], "owner_installed")
        self.assertEqual(record["OwnerApps"], ["Other Protection"])

    def test_uninstall_command_keyword_is_not_installed_product_identity(self):
        data = fixture(service_registry=[{"Name": "SurfsharkService", "State": "Running"}],
            installed_apps=[{"DisplayName": "Unrelated Tool", "Publisher": "Other Company",
                             "UninstallString": r"C:\Tools\surfshark_cleanup_reference\uninstall.exe"}])
        record = app.classify_security(data)[0]
        self.assertEqual(record["Status"], "orphan_candidate")
        self.assertEqual(record["OwnerApps"], [])

    def test_security_center_provider_without_product_file(self):
        image = r"C:\Program Files\Surfshark\Surfshark.exe"
        data = fixture(antivirus_products=[{"displayName": "Surfshark Antivirus", "pathToSignedProductExe": image}],
            files=[{"Path": image, "Exists": False}])
        record = app.classify_security(data)[0]
        self.assertEqual(record["Status"], "orphan_security_provider")
        self.assertEqual(record["Severity"], "高優先級")

    def test_file_without_service_is_suspicion_not_loaded_driver(self):
        data = fixture(files=[{"Path": r"C:\Windows\System32\drivers\BdNet.sys", "Exists": True}])
        record = app.classify_security(data)[0]
        self.assertEqual(record["Status"], "file_without_service")
        self.assertFalse(record["Running"])

    def test_complete_app_present_is_not_orphan(self):
        data = fixture(service_registry=[{"Name": "SurfsharkService"}],
            installed_apps=[{"DisplayName": "Surfshark", "Publisher": "Surfshark B.V."}])
        self.assertEqual(app.classify_security(data)[0]["Status"], "owner_installed")

    def test_driver_csv_with_chinese_and_embedded_comma(self):
        stream = io.StringIO()
        csv.writer(stream).writerow(["BdNet", "網路防護，中文", "中文路徑,資訊", "Kernel", "Auto", "Running",
            "OK", "FALSE", "FALSE", "4096", "8192", "0", "2026/10/24", r"C:\程式\安全\BdNet.sys", "4096"])
        record = app.parse_driverquery_csv(stream.getvalue())[0]
        self.assertEqual(record["DisplayName"], "網路防護，中文")
        self.assertEqual(record["PathName"], r"C:\程式\安全\BdNet.sys")

    def test_bad_csv_does_not_return_empty_success(self):
        with self.assertRaises(ValueError):
            app.parse_driverquery_csv('"BdNet","Running"')

    def test_unresolved_nt_device_path_is_unknown_not_missing(self):
        with patch.object(app, "ps_json", return_value=([], "")):
            rows, errors = app.inspect_security_files([r"\Device\HarddiskVolume4\BdNet.sys"])
        self.assertIsNone(rows[0]["Exists"])
        self.assertTrue(errors)

    def test_service_binary_path_normalization(self):
        with patch.dict(app.os.environ, {"SystemRoot": r"C:\Windows"}):
            for value, expected in (
                ('"C:\\中文 程式\\endpointprotection.exe" -service', r"C:\中文 程式\endpointprotection.exe"),
                (r"\SystemRoot\System32\drivers\BdNet.sys", r"C:\Windows\System32\drivers\BdNet.sys"),
                (r"\??\C:\Windows\System32\drivers\BdNet.sys", r"C:\Windows\System32\drivers\BdNet.sys"),
                (r"System32\drivers\BdNet.sys", r"C:\Windows\System32\drivers\BdNet.sys")):
                with self.subTest(value=value):
                    self.assertEqual(app.normalize_binary_path(value), expected)

    def test_failed_wmi_is_recorded_not_absent(self):
        with patch.object(app, "ps_json", return_value=([], "Access is denied")), \
             patch.object(app, "registry_services_inventory", return_value=([], ["Access denied"])), \
             patch.object(app, "installed_apps_inventory", return_value=([], ["Access denied"])), \
             patch.object(app, "run_command", return_value={"ok": False, "stdout": "", "stderr": "Access denied"}), \
             patch.object(app, "inspect_security_files", return_value=([], ["Access denied"])):
            result = app.collect_security()
        self.assertFalse(result["completeness"]["antivirus_products"])
        self.assertFalse(result["completeness"]["installed_apps"])
        self.assertTrue(result["errors"])
        self.assertFalse(any(x["Status"] == "orphan_security_provider" for x in result["evidence"]))

    def test_sdk_candidate_never_automatically_applicable(self):
        metadata = {"Path": app.ENDPOINT_SDK_PATH, "Exists": True,
                    "SignatureStatus": "Valid", "Publisher": "CN=Surfshark B.V."}
        with patch.object(app, "ps_json", return_value=([], "")), \
             patch.object(app, "registry_services_inventory", return_value=([], [])), \
             patch.object(app, "installed_apps_inventory", return_value=([], [])), \
             patch.object(app, "run_command", return_value={"ok": True, "stdout": "", "stderr": ""}), \
             patch.object(app, "inspect_security_files", return_value=([metadata], [])):
            result = app.collect_security()
        candidate = result["advanced_candidates"][0]
        self.assertTrue(candidate["file_identity_verified"])
        self.assertFalse(candidate["applicable"])

    def test_wfp_stream_summary_and_cancel(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "wfp.xml"
            path.write_text('<wfpstate><providers><item><displayData><name>Surfshark provider</name></displayData></item></providers>'
                '<filters><item><name>Normal Windows filter</name></item></filters><callouts><item><name>BdNet callout</name></item></callouts></wfpstate>', encoding="utf-8")
            result = app.summarize_wfp_xml(path)
            self.assertEqual(result["counts"], {"providers": 1, "filters": 1, "callouts": 1})
            self.assertEqual(len(result["matches"]), 2)
            cancelled = threading.Event()
            cancelled.set()
            self.assertTrue(app.summarize_wfp_xml(path, cancelled)["cancelled"])

    def test_wfp_export_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "existing.xml"
            path.write_text("existing", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                app.export_wfp(path)
            self.assertEqual(path.read_text(encoding="utf-8"), "existing")

    def test_inf_provider_rejects_traversal_or_remote_paths(self):
        for name in (r"..\other.inf", r"C:\other.inf", r"\\server\share\other.inf"):
            with self.subTest(name=name):
                result = app.inspect_inf_provider(name)
                self.assertIsNone(result["ProviderName"])
                self.assertTrue(result["Error"])

    @unittest.skipUnless(app.os.name == "nt", "Windows SetupAPI native fixture")
    def test_native_inf_provider_resolves_unicode_strings_without_installation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test_provider.inf"
            path.write_text('[Version]\nSignature="$Windows NT$"\nClass=NetService\n'
                'ClassGUID={4D36E974-E325-11CE-BFC1-08002BE10318}\nProvider=%Vendor%\n'
                '[Strings]\nVendor="測試廠商 中文 Provider"\n', encoding="utf-16")
            result = app.inspect_inf_provider(path.name, _directory=temp)
            self.assertEqual(result["Error"], "")
            self.assertEqual(result["ProviderName"], "測試廠商 中文 Provider")
            self.assertEqual(result["Class"], "NetService")

    @unittest.skipUnless(app.os.name == "nt", "Windows SetupAPI native fixture")
    def test_native_inf_provider_failure_preserves_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            result = app.inspect_inf_provider("absent.inf", _directory=temp)
        self.assertIsNone(result["ProviderName"])
        self.assertTrue(result["Error"])


if __name__ == "__main__":
    unittest.main()
