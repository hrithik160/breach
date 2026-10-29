import asyncio
import json
import unittest
from fastapi.testclient import TestClient

from main import app, state, resolver, bus, replay_adapter, cloud_adapter, ws_source_adapter, siem_adapter


class TestPersonAAndBIntegration(unittest.TestCase):
    def setUp(self):
        state._initial_graph = state._load_initial_topology()
        state.reset()
        resolver.rebuild_from_graph(state.snapshot())
        cloud_adapter.seed_from_graph(state.snapshot())
        bus.recorded_events.clear()

    def test_person_b_topology_and_manual_map_alignment(self):
        # Verify Person B's node IDs and aliases resolve properly
        self.assertIn("node-printer", state.nodes)
        self.assertIn("node-prod-crown-jewel", state.nodes)
        self.assertEqual(resolver.resolve("192.168.1.105"), "node-printer")
        self.assertEqual(resolver.resolve("10.0.99.100"), "node-prod-crown-jewel")
        self.assertEqual(resolver.resolve("prod-customer-db.internal"), "node-prod-crown-jewel")

    def test_replay_stream_matches_person_b_contracts(self):
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            snap = ws.receive_json()
            self.assertEqual(snap["kind"], "snapshot")
            self.assertEqual(len(snap["graph"]["nodes"]), 15)
            self.assertEqual(len(snap["graph"]["edges"]), 30)

            ws.send_json({"kind": "replay_control", "action": "start", "speed": 100.0})
            ev = ws.receive_json()
            self.assertEqual(ev["kind"], "event")
            self.assertEqual(ev["event"]["id"], "node-printer")
            self.assertEqual(ev["event"]["type"], "node_compromised")

            ws.send_json({"kind": "replay_control", "action": "reset"})
            while True:
                msg = ws.receive_json()
                if msg["kind"] == "snapshot":
                    printer = next(n for n in msg["graph"]["nodes"] if n["id"] == "node-printer")
                    self.assertEqual(printer["status"], "secure")
                    break

    def test_dynamic_outbreak_on_real_scanned_infrastructure(self):
        client = TestClient(app)
        scan_res = client.post("/cloud/poll").json()
        self.assertGreaterEqual(scan_res["discovered_nodes"], 3)

        with client.websocket_connect("/ws") as ws:
            ws.receive_json()
            ws.send_json({"kind": "replay_control", "action": "start", "speed": 100.0})
            ev = ws.receive_json()
            self.assertEqual(ev["kind"], "event")
            self.assertIn(ev["event"]["id"], state.nodes)


if __name__ == "__main__":
    unittest.main(verbosity=2)