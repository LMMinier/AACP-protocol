from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from measure_bounded_agent import (
    FakeBackend,
    ItemResult,
    RouteProfile,
    WorkItem,
    route_prompt,
    run_item,
    self_test,
    theoretical_peak_ram_mb,
    validate_results,
    write_json,
    write_svg,
)


class RoutingTests(unittest.TestCase):
    def test_router_routes_narrow_tasks_first(self) -> None:
        self.assertEqual(route_prompt("Debug this Python function"), "code")
        self.assertEqual(route_prompt("Calculate 19 * 7"), "math")
        self.assertEqual(route_prompt("Explain why the sky is blue"), "chat")
        self.assertEqual(route_prompt("Translate hello to Spanish"), "fast")

    def test_peak_ram_bound(self) -> None:
        self.assertEqual(theoretical_peak_ram_mb(100, 5, 5, [400, 900, 600], 10), 1020)
        with self.assertRaises(ValueError):
            theoretical_peak_ram_mb(100, 5, 5, [])

    def test_fake_backend_preserves_single_residency(self) -> None:
        backend = FakeBackend()
        profiles = {"code": RouteProfile("code", "code:3b")}
        result, samples = run_item(
            backend,
            profiles,
            WorkItem("one", "code", "Debug Python"),
            backend.list_models(),
            sample_interval_s=0.01,
        )
        self.assertTrue(result.valid_single_resident)
        self.assertLessEqual(result.max_simultaneous_models, 1)
        self.assertTrue(samples)

    def test_validation_rejects_overlap(self) -> None:
        result = ItemResult(
            item_id="bad",
            requested_route="auto",
            selected_route="code",
            model="code:3b",
            route_correct=True,
            wall_time_s=1.0,
            total_duration_s=1.0,
            prompt_eval_count=1,
            eval_count=1,
            eval_duration_s=1.0,
            tokens_per_second=1.0,
            response_sha256="0" * 64,
            resident_model_sets=[["code:3b", "chat:1.5b"]],
            max_simultaneous_models=2,
            peak_host_used_mb=100.0,
            peak_process_rss_mb=10.0,
            valid_single_resident=False,
        )
        self.assertTrue(validate_results([result]))

    def test_writers_emit_parseable_artifacts(self) -> None:
        report = self_test()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "results.json", {"profiles": {}}, report["results"])
            write_svg(root / "ram.svg", report["samples"])
            parsed = json.loads((root / "results.json").read_text(encoding="utf-8"))
            self.assertEqual(parsed["schema_version"], "1.0")
            self.assertIn("<svg", (root / "ram.svg").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
