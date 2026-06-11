"""Map Bandit rule IDs to CWE identifiers.

Bandit (SARIF formatter) does not write CWE into result properties.
Without CWE, our triage model loses signal — we observed claimed_cwe=None
giving p_tp ≈ 0 frac-above-0.5 on rpg_life and talkito Bandit findings.

Usage:
  python -m src.product.bandit_cwe in.sarif out.sarif

Source for mappings: https://bandit.readthedocs.io/en/latest/plugins/index.html
plus CWE references in each plugin doc. Pinned to Bandit 1.7+.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


BANDIT_TO_CWE: dict[str, str] = {
    # Misc
    "B101": "CWE-703",  # assert_used (in production code, weak handling)
    "B102": "CWE-78",   # exec_used
    "B103": "CWE-732",  # set_bad_file_permissions
    "B104": "CWE-605",  # hardcoded_bind_all_interfaces
    "B105": "CWE-259",  # hardcoded_password_string
    "B106": "CWE-259",  # hardcoded_password_funcarg
    "B107": "CWE-259",  # hardcoded_password_default
    "B108": "CWE-377",  # hardcoded_tmp_directory
    "B110": "CWE-703",  # try_except_pass
    "B112": "CWE-703",  # try_except_continue
    "B113": "CWE-400",  # request_without_timeout
    # Flask
    "B201": "CWE-489",  # flask_debug_true
    "B202": "CWE-22",   # tarfile_unsafe_members
    # Misc crypto / parsing
    "B301": "CWE-502",  # pickle
    "B302": "CWE-502",  # marshal
    "B303": "CWE-327",  # md5/sha1 (insecure hash)
    "B304": "CWE-327",  # ciphers (insecure)
    "B305": "CWE-327",  # cipher_modes (insecure)
    "B306": "CWE-377",  # mktemp_q
    "B307": "CWE-95",   # eval
    "B308": "CWE-79",   # mark_safe (Django)
    "B309": "CWE-295",  # httpsconnection (insecure)
    "B310": "CWE-918",  # urllib_urlopen
    "B311": "CWE-330",  # random
    "B312": "CWE-319",  # telnetlib
    "B313": "CWE-611",  # xml_bad_cElementTree
    "B314": "CWE-611",  # xml_bad_ElementTree
    "B315": "CWE-611",  # xml_bad_expatreader
    "B316": "CWE-611",  # xml_bad_expatbuilder
    "B317": "CWE-611",  # xml_bad_sax
    "B318": "CWE-611",  # xml_bad_minidom
    "B319": "CWE-611",  # xml_bad_pulldom
    "B320": "CWE-611",  # xml_bad_etree
    "B321": "CWE-319",  # ftplib
    "B322": "CWE-20",   # input (py2 raw_input)
    "B323": "CWE-295",  # unverified_context
    "B324": "CWE-327",  # hashlib_new_insecure_functions
    "B325": "CWE-377",  # tempnam
    # Imports (warnings only, but still tag with CWE for triage signal)
    "B401": "CWE-319",  # import_telnetlib
    "B402": "CWE-319",  # import_ftplib
    "B403": "CWE-502",  # import_pickle
    "B404": "CWE-78",   # import_subprocess
    "B405": "CWE-611",  # import_xml_etree
    "B406": "CWE-611",  # import_xml_sax
    "B407": "CWE-611",  # import_expat
    "B408": "CWE-611",  # import_minidom
    "B409": "CWE-611",  # import_pulldom
    "B410": "CWE-611",  # import_lxml
    "B411": "CWE-611",  # import_xmlrpclib
    "B412": "CWE-918",  # import_httpoxy
    "B413": "CWE-327",  # import_pycrypto
    "B414": "CWE-327",  # import_pycryptodome
    "B415": "CWE-319",  # import_pyghmi
    # Crypto / SSL
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B502": "CWE-326",  # ssl_with_bad_version
    "B503": "CWE-326",  # ssl_with_bad_defaults
    "B504": "CWE-326",  # ssl_with_no_version
    "B505": "CWE-326",  # weak_cryptographic_key
    "B506": "CWE-502",  # yaml_load
    "B507": "CWE-295",  # ssh_no_host_key_verification
    "B508": "CWE-319",  # snmp_insecure_version
    "B509": "CWE-326",  # snmp_weak_cryptography
    # Subprocess / shell
    "B601": "CWE-78",   # paramiko_calls
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_with_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions
    "B609": "CWE-78",   # linux_commands_wildcard_injection
    "B610": "CWE-89",   # django_extra_used
    "B611": "CWE-89",   # django_rawsql_used
    "B612": "CWE-117",  # logging_config_insecure_listen
    # Templating
    "B701": "CWE-79",   # jinja2_autoescape_false
    "B702": "CWE-79",   # use_of_mako_templates
    "B703": "CWE-79",   # django_mark_safe
    "B704": "CWE-79",   # markupsafe_markup_xss
}


def lookup_cwe(rule_id: str) -> str | None:
    """Return CWE-NNN for a Bandit rule id, or None if not mapped."""
    if not rule_id:
        return None
    key = rule_id.strip().upper()
    if key.startswith("BANDIT_"):
        key = key[len("BANDIT_"):]
    return BANDIT_TO_CWE.get(key)


def annotate_sarif(doc: dict[str, Any]) -> tuple[dict[str, Any], int, int]:
    """Add properties.cwe + properties.tags=['CWE-NNN'] to each Bandit result.

    Returns (annotated_doc, n_annotated, n_unknown).
    """
    n_annotated = 0
    n_unknown = 0
    for run in doc.get("runs", []):
        # Index rules so we can also tag rule defs themselves
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", []) or []
        for rule in rules:
            cwe = lookup_cwe(rule.get("id", ""))
            if cwe is None:
                continue
            props = rule.setdefault("properties", {})
            tags = props.setdefault("tags", [])
            if cwe not in tags:
                tags.append(cwe)
            props["cwe"] = cwe

        for result in run.get("results", []) or []:
            rid = result.get("ruleId") or ""
            cwe = lookup_cwe(rid)
            if cwe is None:
                n_unknown += 1
                continue
            props = result.setdefault("properties", {})
            tags = props.setdefault("tags", [])
            if cwe not in tags:
                tags.append(cwe)
            props["cwe"] = cwe
            n_annotated += 1
    return doc, n_annotated, n_unknown


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) < 2:
        print("usage: bandit_cwe.py in.sarif out.sarif", file=sys.stderr)
        return 2
    in_path = Path(argv[0])
    out_path = Path(argv[1])
    doc = json.loads(in_path.read_text(encoding="utf-8"))
    doc, n_ann, n_unk = annotate_sarif(doc)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"annotated: {n_ann} results, unmapped: {n_unk}, mapping size: {len(BANDIT_TO_CWE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
