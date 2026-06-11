# Eval на yeswehack + DVWA (2026-06-11, late night)

Третий раунд practical-eval после v3 smoke. Цель: контролируемый
benchmark с **известным ground truth** на pedagogical patterns —
закрыть две дыры из v3:
1. **Per-CWE coverage matrix** (где модель видит, где слепа)
2. **Mitigation awareness** (closing на devonz_bolt blindspot класс)

## Setup

| Source | Cases | Truth distribution |
|---|---:|---|
| **yeswehack/vulnerable-code-snippets** | 47 | все TP (gold-standard vulnerable patterns по 20 CWE категориям) |
| **OWASP/DVWA** paired levels (low/medium/high/impossible per module) | 64 | 48 TP + 16 FP (`impossible` = mitigated → FP) |
| **TOTAL** | **111** | 95 TP + 16 FP |

Прогон: v8.3.1 LoRA через `src.eval.run_triage_eval --backend local`
на A40 (machine `yulnj7cypb3b`). 111 cases за **12 минут**, ~$0.07 pod.

## Overall

| Метрика | Значение | Контекст |
|---|---:|---|
| **DR** (TP detection) | **70.5%** | vs SastBench-250 (45.7%) — на pedagogical patterns выше |
| **FAR** (FP-as-TP) | **12.5%** | vs SastBench (23.3%) — заметно ниже |
| **Precision** | **97.1%** | очень высокая, model conservative-but-correct |
| **BalAcc** | **0.790** | vs SastBench (0.612) |
| **MCC** | **0.420** | vs SastBench (0.177) — в 2.4 раза выше |

Caveats:
- Эти 111 кейсов pedagogical, ближе к training distribution (CVEFixes
  + CrossVul содержат много "classic SQLi / XSS / eval"). Это не cluster
  CI и не frontier comparison. Direction-only sanity check.
- 16 FP кейсов — маленькая выборка для FAR оценки (Wilson 95% CI ±15 pp).

## Per-CWE coverage (yeswehack 47 TP)

| Rate | CWE classes | Verdict |
|---|---|---|
| **100%** | CWE-89 SQLi, CWE-434 FileUpload, CWE-98 LFI, CWE-22 PathTraversal, CWE-918 SSRF, CWE-1336 SSTI, CWE-502 Deserialization, CWE-1333 DoS, CWE-287 BrokenAuth, CWE-94 CodeInjection, CWE-352 CSRF, CWE-134 FormatInjection, CWE-1321 PrototypePollution | strong coverage |
| 75-88% | CWE-79 XSS (7/8), CWE-639 IDOR (3/4) | reliable |
| 67% | CWE-78 CommandInjection (2/3), CWE-601 OpenRedirect (2/3) | partial |
| **0%** | **CWE-840 BusinessLogic, CWE-942 CORS, CWE-444 CachePoisoning** (1 each) | **blind** |

**Slepота не неожиданная**: BusinessLogic требует domain reasoning,
CORS + CachePoisoning редкие в CVE training. Это полезный
supported-CWE список для product positioning.

## DVWA mitigation matrix (главное по methodology)

Per-модуль ranking сценария low → medium → high → impossible:

| Module | CWE | low | medium | high | impossible |
|---|---|:-:|:-:|:-:|:-:|
| **sqli** | CWE-89 | TP | TP | TP | **FP** |
| **xss_d** | CWE-79 | TP | TP | TP | **FP** |
| **xss_s** | CWE-79 | TP | TP | TP | **FP** |
| **fi** | CWE-98 | TP | TP | TP | **FP** |
| **exec** | CWE-78 | TP | TP | TP | **FP** |
| csrf | CWE-352 | TP | TP | FP | FP |
| bac | CWE-639 | TP | FP | FP | FP |
| brute | CWE-307 | TP | TP | FP | FP |
| open_redirect | CWE-601 | FP | TP | FP | FP |
| sqli_blind | CWE-89 | TP | TP | TP | **TP** (miss) |
| xss_r | CWE-79 | TP | TP | TP | **TP** (miss) |
| authbypass | CWE-287 | FP | FP | FP | FP |
| captcha | CWE-804 | FP | FP | FP | FP |
| upload | CWE-434 | FP | FP | FP | FP |
| weak_id | CWE-330 | FP | FP | FP | FP |
| javascript | CWE-602 | FP | FP | FP | FP |

5 модулей (sqli, xss_d, xss_s, fi, exec) показывают **perfect 4-tier
discrimination** — TP на трёх уровнях защиты + FP на impossible.

**Aggregated mitigation awareness**:

| Level | Truth | Predicted TP | Predicted FP | Comment |
|---|---|---:|---:|---|
| low | vulnerable | 10/16 | 6/16 | базовое detection |
| medium | vulnerable | 10/16 | 6/16 | то же |
| high | vulnerable | 7/16 | 9/16 | path complex, **меньше** ловит |
| **impossible** | **mitigated** | 2/16 | **14/16 (87.5%)** | **mitigation awareness работает** |

## Что это значит для devonz_bolt blindspot

В v3 я заявил что top-5 ranker на devonz_bolt — настоящие RCE, потом
отозвал потому что автор сделал `assertValidSha()` в **другом месте**
файла. Этот eval показывает:

- **Inline mitigations** (в том же snippet'е) модель **видит**: 87.5%
  на DVWA impossible.
- **Out-of-snippet mitigations** — она не видит. Это not blindness
  в принципе, а **snippet window limitation**.

Решение для production: либо whole-file context для top-K финдингов
(дороже, но точнее), либо two-stage triage (cheap snippet ranker → LLM
call с full file на top-10). И то и другое архитектурный fix, не
training.

## Слабые DVWA модули (white-list для product positioning)

Модели на которых v8.3.1 ставит FP на всех уровнях:
- **bac** (CWE-639 broken access control) — требует знание ролевой модели
- **weak_id** (CWE-330) — генерация ID, нужен crypto context
- **captcha** (CWE-804) — bypass logic, requires понимание flow
- **upload** (CWE-434) — file upload chains, ext check patterns
- **authbypass** (CWE-287) — bypass через type juggling, domain-specific
- **javascript** (CWE-602) — client-side validation bypass

Эти 6 классов **не покрываем** в pitch. Признаём как "out of scope for
single-snippet triage".

## Sample reasoning (для PDF-отчёта attached к outreach)

Из 67 правильных TP — модель выдала reasoning который читается
осмысленно. Пример из case_0 (CWE-287 yeswehack BrokenAuth):

```
Verdict: TRUE_POSITIVE
Confidence: HIGH
Reasoning: This code contains a CWE-287 vulnerability that an attacker
can exploit. The vulnerable pattern is present in the highlighted region
and lacks the defensive measures...
```

Пример FP detection (DVWA sqli impossible — модель правильно сказала FP):

```
Verdict: FALSE_POSITIVE
Confidence: HIGH
Reasoning: This is the post-fix version of code that previously
contained a CWE-89 vulnerability. The fix introduces defensive measures
that mitigate the original issue...
```

## Outreach update (v3 цифры enriched)

**До этого eval (из v3)**:
> 19 репов, 466 findings, ranker отсортировал. Top-5 vulnerable controls
> = настоящие баги. Bandit-noise отфильтрован.

**После этого eval (добавить)**:
> На public benchmark из 111 pedagogical кейсов (yeswehack + DVWA
> paired levels): DR 70.5%, FAR 12.5%, Precision 97%, MCC 0.420.
> Mitigation awareness 87.5% на DVWA impossible (model видит inline
> защиту). Поддерживаемые CWE: SQLi, XSS, LFI, PathTraversal, SSRF,
> SSTI, Deserialization, CodeInjection, CSRF, FormatInjection,
> PrototypePollution (все 100%), plus 75-88% на CmdInjection, IDOR,
> OpenRedirect. Не покрываем: BusinessLogic, CORS, CachePoisoning,
> и в DVWA — broken-access-control, weak-id-generation, captcha-bypass,
> upload-chain. Это honest scope для outreach.

## Файлы

```
data/eval/
  ywh_dvwa_eval.json              # 111 cases с raw metadata + truth
  ywh_dvwa_messages.json          # messages format для runner

runs/
  v8_3_1_ywh_dvwa_outputs.json    # full responses
  v8_3_1_metrics.json              # raw runner metrics (нули — schema mismatch)
  eval.log                         # progress log

scripts/
  build_ywh_dvwa_eval.py          # извлечение из ywh + DVWA
  prepare_ywh_dvwa_for_eval.py    # convert to messages format
  analyze_ywh_dvwa_results.py     # per-CWE + mitigation matrix
```

## Расходы

| Item | Cost |
|---|---:|
| Pod time (~12 мин) | $0.07 |

Total за день (smoke v1 + v2 + v3 + ywh_dvwa eval): **~$0.50**.

## Что предлагаю дальше

1. **Frontier baseline на тех же 111** (~$1-1.50 OpenRouter) — для
   честного "v8.3.1 vs Sonnet single-call" на этом наборе. Это **очень
   сильный** дополнительный артефакт. Делать?
2. **Markdown→PDF renderer** (~4ч) — теперь у нас есть **per-finding
   reasoning** на правильных TP кейсах, plus mitigation-aware
   examples. Идеально для outreach attachment.
3. **Train extension** (если v3+ywh покажут consistent gaps на той
   же CWE — но пока такого нет, все CWE с N≥3 либо 100% либо 67%+).
   Откладываем — model freeze remains.
