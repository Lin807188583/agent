import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from mcp_ci.baseline import (
    BaselineError,
    apply_baseline,
    create_baseline,
    load_baseline,
    write_baseline,
)
from mcp_ci.models import CheckReport
from mcp_ci.probe import ProbeEvidence


def response(result: object) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": 1, "result": result}


def evidence() -> ProbeEvidence:
    tool = {
        "name": "read_note",
        "description": "Read a public note.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "default": "secret-baseline-value"}
            },
        },
    }
    return ProbeEvidence(
        target="baseline-fixture",
        requested_protocol_version="2025-11-25",
        initialize_response=response(
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            }
        ),
        first_tools_response=response({"tools": [tool]}),
        tools_list_pages=[response({"tools": [tool]})],
        resources_list_pages=[
            response(
                {
                    "resources": [
                        {
                            "uri": "https://user:password@example.invalid/private?token=secret",
                            "name": "Private source",
                        }
                    ]
                }
            )
        ],
        resource_templates_list_pages=[
            response(
                {
                    "resourceTemplates": [
                        {"uriTemplate": "secret-store://{tenant}/{id}", "name": "Secret"}
                    ]
                }
            )
        ],
        prompts_list_pages=[
            response(
                {
                    "prompts": [
                        {
                            "name": "summarize",
                            "description": "Internal prompt text must not enter a baseline.",
                        }
                    ]
                }
            )
        ],
        pagination_observations={"resources": {"termination": "complete"}},
        transport_observations={"session_id_issued": True},
    )


class BaselineTests(unittest.TestCase):
    def test_snapshot_is_deterministic_and_redacts_raw_metadata(self) -> None:
        first = create_baseline(evidence())
        second = create_baseline(evidence())

        serialized = json.dumps(first, sort_keys=True)
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], 1)
        self.assertIn("read_note", serialized)
        self.assertIn("summarize", serialized)
        for secret in (
            "user:password",
            "token=secret",
            "secret-baseline-value",
            "secret-store",
            "Internal prompt text",
        ):
            self.assertNotIn(secret, serialized)

    def test_baseline_round_trip_is_strict(self) -> None:
        snapshot = create_baseline(evidence())
        with TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "mcp-ci-baseline.json"
            write_baseline(path, snapshot)
            loaded = load_baseline(path)

        self.assertEqual(loaded, snapshot)

    def test_protocol_capability_and_manifest_drift_have_stable_ids(self) -> None:
        expected = create_baseline(evidence())
        changed = evidence()
        changed.initialize_response = response(
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
            }
        )
        changed.tools_list_pages = [response({"tools": []})]
        changed.resources_list_pages = [response({"resources": []})]
        changed.resource_templates_list_pages = [response({"resourceTemplates": []})]
        changed.prompts_list_pages = [response({"prompts": []})]
        report = CheckReport(target="changed")

        apply_baseline(report, changed, expected)

        ids = {finding.rule_id for finding in report.findings}
        self.assertEqual(
            ids,
            {"BASE001", "BASE002", "BASE003", "BASE004", "BASE005"},
        )
        self.assertEqual(report.observations["baseline"]["finding_count"], 5)

    def test_malformed_or_unknown_baseline_fields_are_rejected(self) -> None:
        invalid = [
            {},
            {"schema_version": 2},
            {**create_baseline(evidence()), "unknown": True},
            {
                **create_baseline(evidence()),
                "manifests": {**create_baseline(evidence())["manifests"], "tools": []},
            },
        ]
        for payload in invalid:
            with self.subTest(payload=payload), TemporaryDirectory() as directory:
                path = Path(directory) / "baseline.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(BaselineError):
                    load_baseline(path)


if __name__ == "__main__":
    unittest.main()
