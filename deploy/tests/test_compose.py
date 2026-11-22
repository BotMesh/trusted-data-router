"""Render the production topology without starting services or reading credentials."""
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ComposeTest(unittest.TestCase):
    def test_tls_boundary_and_managed_state(self):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("TRUSTED_ROUTER_", "COMPOSE_"))}
        env.update(TRUSTED_ROUTER_IMAGE="router:test", TRUSTED_ROUTER_ISSUER="issuer",
                   TRUSTED_ROUTER_ID="relay", TRUSTED_ROUTER_FLEET_URL="https://fleet.example/",
                   TRUSTED_ROUTER_STATE="/private/state", TRUSTED_ROUTER_CONFIG="/private/config",
                   TRUSTED_ROUTER_TLS="/private/tls")
        result = subprocess.run(
            ["docker", "compose", "--env-file", "/dev/null", "-f",
             str(ROOT / "deploy/docker-compose.yml"), "config", "--format", "json"],
            env=env, check=True, capture_output=True, text=True)
        services = json.loads(result.stdout)["services"]
        router, tls = services["router"], services["tls"]
        self.assertEqual(tls["network_mode"], "service:router")
        self.assertEqual(router["command"][1], "127.0.0.1:7800")
        self.assertEqual([p["target"] for p in router["ports"]], [8443])
        self.assertNotIn("ports", tls)
        self.assertEqual(router["environment"]["TRUSTED_ROUTER_ID"], "relay")
        for service in services.values():
            self.assertTrue(service["read_only"])
            self.assertIn("ALL", service["cap_drop"])
            self.assertEqual(service["user"], "10001:10001")
            for mount in service["volumes"]:
                self.assertFalse(mount["bind"].get("create_host_path", False))
                self.assertEqual(mount.get("read_only", False), mount["target"] != "/var/lib/router")
        self.assertEqual(tls["depends_on"]["router"]["restart"], True)


if __name__ == "__main__":
    unittest.main()
