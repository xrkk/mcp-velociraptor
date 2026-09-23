from __future__ import annotations

import asyncio
import copy
import unittest

from tests import scenario_runner as runner


class FakeResult:
    def __init__(self, structured, *, is_error=False):
        self.structured_content = structured
        self.is_error = is_error


class FakeSession:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, copy.deepcopy(arguments)))
        return self.results.pop(0)


class PointerAndAssertionTests(unittest.TestCase):
    def test_json_pointer_decodes_and_rejects_escape_paths(self):
        value = {"a/b": {"~key": [7]}}
        self.assertEqual(runner.pointer_get(value, "/a~1b/~0key/0"), 7)
        for pointer in ("", "/../x", "/__proto__/x", "/_private", "/bad~2escape"):
            with self.assertRaises(runner.ScenarioInputError):
                runner.pointer_tokens(pointer)

    def test_resolve_value_only_uses_completed_steps_and_fixture(self):
        completed = {"first": {"structuredContent": {"flow_id": "F.1"}}}
        fixture = {"files": [{"path": "C:/fixture.txt"}]}
        value = runner.resolve_value(
            {
                "flow_id": {"$ref": "/steps/first/structuredContent/flow_id"},
                "path": {"$fixture": "/files/0/path"},
            },
            completed,
            fixture,
        )
        self.assertEqual(value, {"flow_id": "F.1", "path": "C:/fixture.txt"})
        with self.assertRaises(runner.ScenarioInputError):
            runner.resolve_value({"$ref": "/steps/future/structuredContent/x"}, completed, fixture)

    def test_all_assertion_operators_have_fixed_direction(self):
        result = {
            "isError": False,
            "structuredContent": {
                "array": ["a", "b"],
                "object": {"b": 2, "a": 1},
                "state": "FINISHED",
                "text": "alpha-beta",
            },
        }
        cases = [
            ({"actual": "/structuredContent/state", "op": "exists"}, True),
            ({"actual": "/structuredContent/missing", "op": "not_exists"}, True),
            ({"actual": "/structuredContent/state", "op": "eq", "expected": "FINISHED"}, True),
            ({"actual": "/structuredContent/state", "op": "ne", "expected": "ERROR"}, True),
            ({"actual": "/structuredContent/state", "op": "in", "expected": ["FINISHED", "ERROR"]}, True),
            ({"actual": "/structuredContent/array", "op": "contains", "expected": "b"}, True),
            ({"actual": "/structuredContent/text", "op": "contains", "expected": "beta"}, True),
            ({"actual": "/structuredContent/object", "op": "len_eq", "expected": 2}, True),
            ({"actual": "/structuredContent/array", "op": "len_gte", "expected": 2}, True),
            ({"actual": "/structuredContent/state", "op": "matches", "expected": "FIN.*"}, True),
            ({"actual": "/isError", "op": "is_error", "expected": False}, True),
        ]
        for assertion, expected in cases:
            with self.subTest(op=assertion["op"]):
                self.assertEqual(runner.evaluate_assertion(assertion, result, {})["passed"], expected)

    def test_bool_is_not_equal_to_number(self):
        result = {"isError": False, "structuredContent": {"value": True}}
        row = runner.evaluate_assertion(
            {"actual": "/structuredContent/value", "op": "eq", "expected": 1},
            result,
            {},
        )
        self.assertFalse(row["passed"])

    def test_assertion_shape_rejects_ambiguous_cases(self):
        invalid = [
            {"actual": "/x", "op": "exists", "expected": 1},
            {"actual": "/x", "op": "eq"},
            {"actual": "/structuredContent/x", "op": "is_error", "expected": False},
            {"actual": "/isError", "op": "matches", "expected": "(?i)x"},
        ]
        for assertion in invalid:
            with self.subTest(assertion=assertion), self.assertRaises(runner.ScenarioInputError):
                runner.validate_assertion_spec(assertion)

    def test_indexed_representative_scenario_loads(self):
        scenario, row, digest, index_path = runner.load_indexed_scenario("p05-flow-triage-repair-initial")
        self.assertEqual(scenario["scenario_id"], row["scenario_id"])
        self.assertEqual(digest, row["sha256"])
        self.assertEqual(index_path, runner.P05_INDEX_PATH)
        self.assertEqual(row["required_snapshot"], runner.SNAPSHOT_187)
        self.assertEqual(row["snapshot_stage"], "P05_REPAIR_INITIAL")

        candidate, candidate_row, _, _ = runner.load_indexed_scenario(
            "p05-flow-triage-repair-candidate"
        )
        self.assertEqual(candidate["required_snapshot"], runner.SNAPSHOT_189)
        self.assertEqual(candidate_row["snapshot_stage"], "P05_REPAIR_CANDIDATE")

    def test_forward_reference_and_command_cleanup_are_rejected(self):
        scenario, _, _, _ = runner.load_indexed_scenario("p05-flow-triage-repair-initial")
        invalid = copy.deepcopy(scenario)
        invalid["steps"][0]["arguments"] = {
            "flow_id": {"$ref": "/steps/wait_ascii/structuredContent/flow_id"}
        }
        with self.assertRaises(runner.ScenarioInputError):
            runner.validate_scenario_semantics(invalid)
        invalid = copy.deepcopy(scenario)
        invalid["cleanup"] = [
            {
                "kind": "tool",
                "id": "bad_cleanup",
                "tool": "run_vql",
                "arguments": {"query": "SELECT 1 FROM scope()"},
                "assertions": [],
                "when": "always",
            }
        ]
        with self.assertRaises(runner.ScenarioInputError):
            runner.validate_scenario_semantics(invalid)


class AsyncExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_repeat_until_counts_each_real_call(self):
        session = FakeSession(
            [
                FakeResult({"state": "RUNNING"}),
                FakeResult({"state": "FINISHED"}),
            ]
        )
        step = {
            "id": "wait",
            "tool": "get_flow_status",
            "arguments": {"flow_id": "F.1"},
            "assertions": [],
            "repeat_until": {
                "max_attempts": 2,
                "interval_seconds": 0,
                "assertions": [
                    {"actual": "/structuredContent/state", "op": "eq", "expected": "FINISHED"}
                ],
            },
        }
        calls = []
        result, assertions = await runner.execute_tool_step(session, step, {}, {}, calls)
        self.assertEqual(result["structuredContent"]["state"], "FINISHED")
        self.assertTrue(assertions[0]["passed"])
        self.assertEqual(len(calls), 2)

    async def test_error_only_passes_when_explicitly_asserted(self):
        explicit = FakeSession([FakeResult({"code": "NOT_FOUND"}, is_error=True)])
        step = {
            "id": "expected_error",
            "tool": "get_flow_status",
            "arguments": {"flow_id": "F.missing"},
            "assertions": [{"actual": "/isError", "op": "is_error", "expected": True}],
        }
        result, assertions = await runner.execute_tool_step(explicit, step, {}, {}, [])
        self.assertTrue(result["isError"])
        self.assertTrue(assertions[0]["passed"])

        unexpected = FakeSession([FakeResult({"code": "NOT_FOUND"}, is_error=True)])
        bad = copy.deepcopy(step)
        bad["assertions"] = [{"actual": "/isError", "op": "is_error", "expected": False}]
        with self.assertRaises(runner.ScenarioFailure):
            await runner.execute_tool_step(unexpected, bad, {}, {}, [])


if __name__ == "__main__":
    unittest.main()
