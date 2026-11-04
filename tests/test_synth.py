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

    def test_command_line_starts_with_the_program_name(self):
        r = rule({"selection": {"Image|endswith": chr(92) + "certutil.exe", "CommandLine|contains": "-urlcache"},
                  "condition": "selection"})
        ev = synthesize(r)
        self.assertTrue(ev["CommandLine"].startswith("certutil.exe "))
        self.assertTrue(matches(r, ev))

    def test_startswith_constraint_keeps_working(self):
        r = rule({"selection": {"CommandLine|startswith": "-x"}, "condition": "selection"})
        self.assertTrue(matches(r, synthesize(r)))

    def test_only_minimal_selection_sets(self):
        from sigma_mutate.synth import iter_satisfying
        det = {"a": {"CommandLine|contains": "x"}, "b": {"Image|endswith": "y"}, "condition": "a or b"}
        self.assertEqual(sorted(map(tuple, iter_satisfying(det))), [("a",), ("b",)])

    def test_or_alternative_is_not_kept_alongside_the_command_line_path(self):
        from sigma_mutate.synth import field_independent, synthesize_ex
        r = rule({"selection_img": {"Image|endswith": chr(92) + "certify.exe"},
                  "selection_cli_a": {"CommandLine|contains": " find "},
                  "selection_cli_b": {"CommandLine|contains": " /ca:"},
                  "condition": "selection_img or all of selection_cli_*"})
        ev, positive = synthesize_ex(r)
        self.assertNotIn("Image", ev)                       # the redundant alternative is not added
        self.assertTrue(ev["CommandLine"].startswith("certify.exe "))   # but the program name is hinted
        self.assertTrue(field_independent(r))               # the rule can also fire by binary name
        only_cli = rule({"sel": {"CommandLine|contains": "x"}, "condition": "sel"})
        self.assertFalse(field_independent(only_cli))

    def test_program_name_is_not_duplicated(self):
        # rundll32 rule: the CommandLine pattern 'rundll32' already provides the program name
        r = rule({"selection_img": [{"Image|endswith": chr(92) + "rundll32.exe"}, {"CommandLine|contains": "rundll32"}],
                  "selection_cli": {"CommandLine|contains": ["#+", "#0"]},
                  "condition": "all of selection_*"})
        ev = synthesize(r)
        self.assertTrue(matches(r, ev))
        self.assertEqual(ev["CommandLine"].lower().count("rundll32"), 1)

    def test_rule_program(self):
        from sigma_mutate.synth import rule_program, synthesize_ex
        r = rule({"selection": {"CommandLine|contains": "whoami*>"}, "condition": "selection"})
        ev, _ = synthesize_ex(r)
        self.assertIsNone(rule_program(r, ev))
        r2 = rule({"selection": {"Image|endswith": chr(92) + "whoami.exe", "CommandLine|contains": "x"},
                   "condition": "selection"})
        self.assertEqual(rule_program(r2, synthesize(r2)), "whoami.exe")

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

    def test_regex_rules(self):
        for det in [
            {"sel": {"CommandLine|re": r"://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"},
             "flag": {"CommandLine|contains": "-GetCACAPS"}, "condition": "all of *"},
            {"sel": {"CommandLine|re": r"(?:[Pp]rogram[Dd]ata|\\[Aa]pp[Dd]ata\\(?:[Ll]ocal|[Rr]oaming))\\[^\\]{1,256}$"},
             "condition": "sel"},
            {"sel": {"CommandLine|re": [r"\s-[FTd]\s", r"\s-sT\s"]}, "condition": "sel"},
            {"sel": {"CommandLine|re|i": r"echo.*clip.*&&.*(?:Clipboard|i`?n`?v`?o`?k`?e`?)"}, "condition": "sel"},
        ]:
            r = rule(det)
            self.assertTrue(matches(r, synthesize(r)), det)

    def test_base64offset_rule(self):
        r = rule({"sel": {"CommandLine|base64offset|contains": ["IEX (New", "iex (New"]}, "condition": "sel"})
        self.assertTrue(matches(r, synthesize(r)))

    def test_unsupported_things_are_reported_not_guessed(self):
        bad = [
            rule({"sel": {"CommandLine|fieldref": "Image"}, "condition": "sel"}),
            rule({"sel": {"CommandLine|contains": ["a", None]}, "condition": "sel"}),
            rule({"sel": ["keyword"], "condition": "sel"}),
        ]
        for r in bad:
            with self.assertRaises(SynthError):
                synthesize(r)


if __name__ == "__main__":
    unittest.main()
