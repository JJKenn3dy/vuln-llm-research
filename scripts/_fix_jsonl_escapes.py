"""Repair lone backslashes that broke JSON parsing in hand-label JSONL."""
import json
from pathlib import Path

VALID_ESCAPES = set('"\\/bfnrtu')

BACKSLASH = chr(92)


def fix_line(line: str) -> str:
    out = []
    i = 0
    L = len(line)
    while i < L:
        c = line[i]
        if c == BACKSLASH and i + 1 < L:
            nxt = line[i + 1]
            if nxt in VALID_ESCAPES:
                out.append(c)
                out.append(nxt)
                i += 2
                continue
            else:
                out.append(BACKSLASH + BACKSLASH)
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def main() -> None:
    p = Path("f:/vuln-llm-research/data/exam/sastbench250_handlabel/ai_pass1_labels.jsonl")
    lines = p.read_text(encoding="utf-8").splitlines()
    out = []
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            fixed = fix_line(line)
            j = json.loads(fixed)
            print(f"fixed line {i}")
        out.append(j)
    print(f"parsed {len(out)} lines")
    with p.open("w", encoding="utf-8", newline="\n") as f:
        for j in out:
            f.write(json.dumps(j, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
