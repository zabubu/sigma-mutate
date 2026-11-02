import unittest

from sigma_mutate.matcher import matches
from sigma_mutate.synth import SynthError, synthesize


def rule(detection):
    return {"title": "t", "detection": detection}


class SynthTests(unittest.TestCase):
    def test_example_rule(self):
        r = rule({"selection": {"Image|endswith": "\\certutil.exe",
                                "CommandLine|contains|all": ["-urlcache", "http"]},
                  "condition": "selection"})
        ev = synthesize(r)
        self.assertTrue(matches(r, ev))

    def test_not_filter_is_avoided(self):
        r = rule({"sel": {"CommandLine|contains": "http"},
                  "flt": {"CommandLine|contains": "good.example"},
                  "condition": "sel and not flt"})
        self.assertTrue(matches(r, synthesize(r)))

    def test_or_condition(self):
        r = rule({"a": {"CommandLine|contains": "aaa"}, "b": {"CommandLine|contains": "bbb"},
                  "condition": "a or b"})
        self.assertTrue(matches(r, synthesize(r)))

    def test_two_selections_same_field(self):
        r = rule({"a": {"Image|endswith": "\\x.exe"}, "b": {"Image|startswith": "C:\\"},
                  "condition": "a and b"})
        self.assertTrue(matches(r, synthesize(r)))

    def test_list_of_maps_uses_first_alternative(self):
        r = rule({"sel": [{"CommandLine|contains": "one"}, {"CommandLine|contains": "two"}],
                  "condition": "sel"})
        self.assertTrue(matches(r, synthesize(r)))

    def test_one_of_pattern(self):
        r = rule({"selection_a": {"CommandLine|contains": "aaa"},
                  "selection_b": {"CommandLine|contains": "bbb"},
                  "condition": "1 of selection_*"})
        self.assertTrue(matches(r, synthesize(r)))

    def test_all_of_them_and_not_filter_family(self):
        r = rule({"s1": {"CommandLine|contains": "one"}, "s2": {"CommandLine|contains": "two"},
                  "filter_x": {"CommandLine|contains": "bad"},
                  "condition": "all of s* and not 1 of filter_*"})
        ev = synthesize(r)
        self.assertTrue(matches(r, ev))
        self.assertNotIn("bad", ev["CommandLine"])

    def test_many_selections(self):
        det = {f"selection_{i}": {"CommandLine|contains": f"tok{i}"} for i in range(15)}
        det["condition"] = "1 of selection_*"
        r = rule(det)
        self.assertTrue(matches(r, synthesize(r)))

    def test_unsupported_things_are_reported_not_guessed(self):
        bad = [
            rule({"sel": {"CommandLine|re": "a.*"}, "condition": "sel"}),
            rule({"sel": {"CommandLine|contains": "a*b"}, "condition": "sel"}),
            rule({"sel": {"CommandLine": None}, "condition": "sel"}),
            rule({"sel": ["keyword"], "condition": "sel"}),
        ]
        for r in bad:
            with self.assertRaises(SynthError):
                synthesize(r)


if __name__ == "__main__":
    unittest.main()
