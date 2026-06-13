"""Controlled CWE-79 testbed, Part A: matched minimal pairs.

Each pair shares one realistic XSS sink and differs ONLY by the presence of
correct output escaping. The sink is always visible in the snippet (no
snippet-window confound). This isolates the question: does the model decide
on the actual escaping, or on surface features?

- vuln variant  -> TRUE_POSITIVE  (raw user input reaches an HTML sink)
- safe variant  -> FALSE_POSITIVE (same sink, correct context-aware escape)

Semi-synthetic by design: real sink/escape APIs, minimal controlled context.
NOT for training (a model could learn the template); this is a DIAGNOSTIC
probe of the current model + a frontier reference. Emitted in the standard
triage eval message format so run_triage_eval / logprob extractor accept it.

Output: data/eval/cwe79_controlled_pairs.json
"""
import json
from pathlib import Path

ROOT = Path("f:/vuln-llm-research")
OUT = ROOT / "data/eval/cwe79_controlled_pairs.json"

SYSTEM = ("You are a security triage assistant. Given a code snippet and a SAST finding "
          "(alleged vulnerability), decide whether the finding is a true positive or a "
          "false positive. Always output plain text in the structured format requested.")

USER_TMPL = """A static analysis tool flagged the following code as potentially vulnerable.
Decide whether this finding is a true positive (real bug) or a false positive (noise).

SAST tool: semgrep
Claimed CWE: CWE-79
Claimed severity: MEDIUM
File: {fname}
Lines: see snippet

Code:
{code}

Output exactly these fields:
Verdict: TRUE_POSITIVE or FALSE_POSITIVE
Confidence: HIGH, MEDIUM, or LOW
Reasoning: <one paragraph explaining the decision>
RealCWE: <CWE if TP and differs from claim, else same as claimed>
SuggestedFix: <one paragraph if TP, else "N/A">"""

# (pair_id, lang, fname, mechanism, vuln_code, safe_code)
PAIRS = [
    ("php_echo", "php", "profile.php", "echo + htmlspecialchars",
     """<?php
$name = $_GET['name'];
?>
<div class="greeting">
  Hello, <?php echo $name; ?>!
</div>""",
     """<?php
$name = $_GET['name'];
?>
<div class="greeting">
  Hello, <?php echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8'); ?>!
</div>"""),

    ("php_printf", "php", "search.php", "printf %s + htmlspecialchars",
     """<?php
$q = $_REQUEST['query'];
printf('<p>Results for: %s</p>', $q);""",
     """<?php
$q = $_REQUEST['query'];
printf('<p>Results for: %s</p>', htmlspecialchars($q, ENT_QUOTES, 'UTF-8'));"""),

    ("php_attr", "php", "form.php", "value attribute + htmlspecialchars(ENT_QUOTES)",
     """<?php
$q = $_GET['q'];
echo '<input type="text" name="q" value="' . $q . '">';""",
     """<?php
$q = $_GET['q'];
echo '<input type="text" name="q" value="' . htmlspecialchars($q, ENT_QUOTES, 'UTF-8') . '">';"""),

    ("php_comment", "php", "post.php", "echo comment body + htmlentities",
     """<?php
$comment = $_POST['comment'];
$html = "<div class='comment'>" . $comment . "</div>";
echo $html;""",
     """<?php
$comment = $_POST['comment'];
$html = "<div class='comment'>" . htmlentities($comment, ENT_QUOTES, 'UTF-8') . "</div>";
echo $html;"""),

    ("js_innerhtml", "javascript", "widget.js", "innerHTML vs textContent",
     """function showName(req) {
  const name = new URLSearchParams(location.search).get('name');
  document.getElementById('out').innerHTML = 'Hi ' + name;
}""",
     """function showName(req) {
  const name = new URLSearchParams(location.search).get('name');
  document.getElementById('out').textContent = 'Hi ' + name;
}"""),

    ("js_dompurify", "javascript", "render.js", "innerHTML raw vs DOMPurify",
     """function render(userBio) {
  const el = document.querySelector('#bio');
  el.innerHTML = userBio;
}""",
     """function render(userBio) {
  const el = document.querySelector('#bio');
  el.innerHTML = DOMPurify.sanitize(userBio);
}"""),

    ("js_docwrite", "javascript", "banner.js", "document.write vs escaped",
     """const msg = decodeURIComponent(location.hash.slice(1));
document.write('<h2>' + msg + '</h2>');""",
     """const msg = decodeURIComponent(location.hash.slice(1));
const safe = msg.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
document.write('<h2>' + safe + '</h2>');"""),

    ("js_insertadjacent", "javascript", "list.js", "insertAdjacentHTML vs textContent node",
     """function addItem(input) {
  const v = input.value;
  list.insertAdjacentHTML('beforeend', '<li>' + v + '</li>');
}""",
     """function addItem(input) {
  const v = input.value;
  const li = document.createElement('li');
  li.textContent = v;
  list.appendChild(li);
}"""),

    ("react_dangerously", "javascript", "Comment.jsx", "dangerouslySetInnerHTML vs JSX",
     """function Comment({ body }) {
  return <div className="c" dangerouslySetInnerHTML={{ __html: body }} />;
}""",
     """function Comment({ body }) {
  return <div className="c">{body}</div>;
}"""),

    ("handlebars", "javascript", "tpl.hbs", "Handlebars triple vs double brace",
     """<div class="user-card">
  <span class="name">{{{userName}}}</span>
</div>""",
     """<div class="user-card">
  <span class="name">{{userName}}</span>
</div>"""),

    ("ejs", "javascript", "view.ejs", "EJS unescaped <%- %> vs <%= %>",
     """<h1>Welcome</h1>
<p>Your note: <%- note %></p>""",
     """<h1>Welcome</h1>
<p>Your note: <%= note %></p>"""),

    ("jinja_safe", "python", "page.html.j2", "Jinja2 |safe vs autoescape",
     """<div class="bio">
  {{ profile.bio | safe }}
</div>""",
     """<div class="bio">
  {{ profile.bio }}
</div>"""),

    ("flask_markup", "python", "views.py", "Flask Markup raw vs escape",
     """from flask import request
from markupsafe import Markup

@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    return Markup('<h1>Hello ' + name + '</h1>')""",
     """from flask import request
from markupsafe import Markup, escape

@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    return Markup('<h1>Hello %s</h1>') % escape(name)"""),

    ("express_send", "javascript", "routes.js", "res.send concat vs escape-html",
     """app.get('/q', (req, res) => {
  const term = req.query.term;
  res.send('<p>You searched: ' + term + '</p>');
});""",
     """const escapeHtml = require('escape-html');
app.get('/q', (req, res) => {
  const term = req.query.term;
  res.send('<p>You searched: ' + escapeHtml(term) + '</p>');
});"""),

    ("vue_vhtml", "javascript", "Note.vue", "Vue v-html vs mustache",
     """<template>
  <div class="note" v-html="userNote"></div>
</template>""",
     """<template>
  <div class="note">{{ userNote }}</div>
</template>"""),

    ("jquery_html", "javascript", "chat.js", "jQuery .html() vs .text()",
     """$('#msg').on('submit', function() {
  var text = $('#input').val();
  $('#log').append($('<div>').html(text));
});""",
     """$('#msg').on('submit', function() {
  var text = $('#input').val();
  $('#log').append($('<div>').text(text));
});"""),

    ("jsp_out", "java", "result.jsp", "JSP <%= %> vs c:out escapeXml",
     """<body>
  <p>Hello <%= request.getParameter("user") %></p>
</body>""",
     """<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<body>
  <p>Hello <c:out value="${param.user}"/></p>
</body>"""),

    ("angular_innerhtml", "javascript", "comp.ts", "Angular bypassSecurityTrustHtml vs interpolation",
     """@Component({
  template: `<div [innerHTML]="trusted"></div>`
})
export class C {
  @Input() raw: string;
  constructor(private s: DomSanitizer) {}
  get trusted() { return this.s.bypassSecurityTrustHtml(this.raw); }
}""",
     """@Component({
  template: `<div>{{ raw }}</div>`
})
export class C {
  @Input() raw: string;
}"""),

    ("php_setcookie_reflect", "php", "welcome.php", "reflected cookie + htmlspecialchars",
     """<?php
$theme = $_COOKIE['theme'];
echo "<body class='" . $theme . "'>";""",
     """<?php
$theme = $_COOKIE['theme'];
echo "<body class='" . htmlspecialchars($theme, ENT_QUOTES, 'UTF-8') . "'>";"""),

    ("js_template_literal", "javascript", "card.js", "template literal innerHTML vs textContent",
     """function show(user) {
  card.innerHTML = `<h3>${user.displayName}</h3>`;
}""",
     """function show(user) {
  const h = document.createElement('h3');
  h.textContent = user.displayName;
  card.replaceChildren(h);
}"""),
]


def build():
    cases = []
    for pid, lang, fname, mech, vuln, safe in PAIRS:
        for variant, code, verdict in [("vuln", vuln, "TRUE_POSITIVE"),
                                        ("safe", safe, "FALSE_POSITIVE")]:
            case_id = f"ctrl79_{pid}_{variant}"
            cases.append({
                "messages": [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": USER_TMPL.format(fname=fname, code=code)},
                ],
                "metadata": {
                    "case_id": case_id, "pair_id": pid, "variant": variant,
                    "claimed_cwe": "CWE-79", "real_cwe": "CWE-79",
                    "verdict": verdict, "language": lang, "tool": "semgrep",
                    "mechanism": mech, "source": "cwe79_controlled",
                },
            })
    return cases


def main():
    cases = build()
    OUT.write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    n_tp = sum(1 for c in cases if c["metadata"]["verdict"] == "TRUE_POSITIVE")
    print(f"wrote {len(cases)} cases ({len(PAIRS)} pairs, {n_tp} TP / {len(cases)-n_tp} FP) -> {OUT}")
    from collections import Counter
    print("langs:", dict(Counter(c["metadata"]["language"] for c in cases)))


if __name__ == "__main__":
    main()
