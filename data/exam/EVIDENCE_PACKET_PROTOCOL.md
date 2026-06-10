# Evidence packet protocol

Hand-curated evidence biased toward the chosen verdict turns the probe (b) arm
into "context selected by an answer-knowing human" rather than "context an
automatic extractor could supply". This invalidates the gate decision because
tree-sitter MVP later cannot reproduce the result.

## Mechanical protocol — follow strictly

Include in the `evidence_packet` field exactly these elements, in this order:

1. **Enclosing function body** — the entire function containing the snippet
   line range, not just the snippet lines.
2. **File-level imports** — all import / use / include / require statements
   from the top of the file.
3. **Up to 2 callers** — find with repo-wide grep on the function name (or
   language equivalent). Paste the enclosing function context of each caller,
   not whole files.
4. **Sanitizer-keyword lines** — all lines in this same file that contain any
   of: `sanitize`, `escape`, `validate`, `clean`, `encode`, `prepare`,
   `parametr` (matches `parametrize`, `parameterized`, etc.), `htmlspecial`,
   `strip`, `filter`.

That's the entire menu. Do **not** include:
- Other files (except for the 2 callers' function context)
- Tests
- Documentation
- README sections
- Lines that you "know" prove the verdict but do not match the keyword set
- Anything else, however helpful it seems

## Exceptions

If the case genuinely cannot be packaged this way (e.g., the vulnerability is in
a configuration file, the snippet is not inside a function, the language has no
imports concept), set `evidence_packet_protocol_compliance = false` and note
the deviation in `comments`. These cases are excluded from the strict (b) arm
metric and tallied separately.

## Why so strict

The (b) arm answers the question: "does evidence packet, as an automatic
extractor would deliver it, change frontier's behaviour?" If a human curates,
the answer is yes by construction. The strict protocol simulates the extractor.
