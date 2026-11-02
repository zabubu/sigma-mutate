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

    def test_sigma_escapes_admin_share_rule(self):
        BS = chr(92)
        # Rule text with doubled backslashes: it means \\127.0.0.1\admin$\ once unescaped.
        rule_text = BS * 4 + "127.0.0.1" + BS * 2 + "admin$" + BS * 2
        wanted = BS * 2 + "127.0.0.1" + BS + "admin$" + BS
        r = rule({"selection_redirect": {"CommandLine|contains": ">"},
                  "selection_share": {"CommandLine|contains": [rule_text]},
                  "condition": "all of selection_*"})
        ev = synthesize(r)
        self.assertTrue(matches(r, ev))
        self.assertIn(wanted, ev["CommandLine"])
        self.assertNotIn(BS * 4, ev["CommandLine"])

    def test_null_filters_get_filler_values(self):
        # pattern of many SigmaHQ rules: filters that fire when the field is absent or empty
        r = rule({
            "selection": [{"Image|endswith": [":\\\\Windows\\\\System32\\\\bash.exe"]},
                          {"OriginalFileName": "Bash.exe"}],
            "filter_main_cli_flag": {"CommandLine|contains": ["bash.exe -", "bash -"]},
            "filter_main_no_cli": {"CommandLine": None},
            "filter_main_empty": {"CommandLine": ""},
            "condition": "selection and not 1 of filter_main_*",
        })
        ev = synthesize(r)
        self.assertTrue(matches(r, ev))
        self.assertIn("CommandLine", ev)

    def test_alternatives_are_combined_consistently(self):
        # first alternatives conflict (ParentCommandLine contains /c vs equals /../../): must try others
        r = rule({
            "selection_img": [{"ParentImage|endswith": "\\cmd.exe"}, {"Image|endswith": "\\cmd.exe"}],
            "selection_flags": [{"ParentCommandLine|contains": ["/c", "/k"]},
                                {"CommandLine|contains": ["/c", "/k"]}],
            "selection_trav": [{"ParentCommandLine": "/../../"}, {"CommandLine|contains": "/../../"}],
            "filter_java": {"CommandLine|contains": "java"},
            "condition": "all of selection_* and not 1 of filter_*",
        })
        ev = synthesize(r)
        self.assertTrue(matches(r, ev))
        self.assertIn("CommandLine", ev)

    def test_windash_rule(self):
        r = rule({"sel": {"CommandLine|contains|windash": " -urlcache "}, "condition": "sel"})
        self.assertTrue(matches(r, synthesize(r)))

    def test_null_field_stays_absent(self):
        r = rule({"sel": {"CommandLine|contains": "x", "Hashes": None}, "condition": "sel"})
        ev = synthesize(r)
        self.assertNotIn("Hashes", ev)
        self.assertTrue(matches(r, ev))

    def test_wildcard_inside_contains(self):
        r = rule({"sel": {"CommandLine|contains": "abc*xyz"}, "condition": "sel"})
        self.assertTrue(matches(r, synthesize(r)))

    def test_unsupported_things_are_reported_not_guessed(self):
        bad = [
            rule({"sel": {"CommandLine|re": "a.*"}, "condition": "sel"}),
            rule({"sel": {"CommandLine|contains": ["a", None]}, "condition": "sel"}),
            rule({"sel": ["keyword"], "condition": "sel"}),
        ]
        for r in bad:
            with self.assertRaises(SynthError):
                synthesize(r)


if __name__ == "__main__":
    unittest.main()
