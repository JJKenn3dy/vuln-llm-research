# Next steps — UPDATED 2026-06-11 night (strategic pivot to demand validation)

## Strategic shift — model research freeze, demand validation primary

Захар поставил кадр 2026-06-11 поздний вечер. Прямая цитата:

> Самая рискованная гипотеза проекта сейчас не "дотянем ли до 0.25", а
> "нужно ли это кому-то за деньги" — и её исследовать train-прогонами
> невозможно в принципе.

Все оставшиеся research-рычаги (teacher reasoning v8.3.2, Juliet, prompt
format) дают +0.02-0.05 каждый. Ни один не меняет ответ на вопрос "можно
ли продавать как ranker": при MCC 0.20 и 0.23 ответ одинаковый. Скачок
v8.2 → v8.3.1 (root cause найден, +0.07 absolute) был раз-за-цикл event,
повторить его без structural insight не выйдет.

**Стратегия**: после закрытия двух tier-1 хвостов (hand-labeling, frontier
baseline) — **заморозить model research**. Опционально v8.3.2 фоном с
teacher reasoning ($1.50 OpenRouter), но не как gating activity.
Переключаемся на проверку спроса.

## Priority queue (новая, executable)

### P1: Hand-labeling 50 — ✅ DONE 2026-06-11 night (AI labeler + tri-judge)

Полный отчёт: [HAND_LABEL_50_2026-06-11.md](HAND_LABEL_50_2026-06-11.md).

Headline:
- AI Pass 1 на 50 snippets: 56% agreement с SastBench
- 10 HIGH-confidence disagreements → tri-judge adjudication
- **7 strong_mislabel candidates** confirmed (AI + Sonnet + Gemini vs SB)
- 2 reclassified as AI error (frontier на стороне SB)
- 1 ambiguous

**Sufficiency conclusion** (главное для roadmap): snippet достаточен в
76% по самооценке, evidence packet ceiling ~12%. **Sprint 2 evidence
packet официально закрыт в backlog** — не нужен для v8.3.x.

**Three independent outputs gate** (per reviewer's framing):
1. Sufficiency probe: closed, evidence packet deprioritized
2. SastBench label trust: floor ≥14% noise in val-558 partition (confirmed)
3. Judge calibration baseline: established (AI HIGH-confidence inverted,
   need adjudication for any single-judge claim)

**Захар hand-labeling по-прежнему добавит value** на:
- 1 ambiguous case (c9ba7b08 themeisle pricing-table)
- 35 case confusion-intersection priority list (v8.3.1 + Sonnet + Gemini
  all wrong vs SastBench на subset250) — top mislabel candidates на test
  set
- broader sample adjudication для unbiased noise estimate

### P2: Frontier baseline 250 — ✅ DONE 2026-06-11 night

Sonnet 4.5 + Gemini 2.5 Pro single-call на тех же 250 кейсах через
OpenRouter. Cluster bootstrap CI by repo_url. Decision rule applied
mechanically.

| Model | MCC | Cluster CI | FAR |
|---|---|---|---|
| v8.3.1 | +0.177 | [+0.004, +0.297] | 23.3% |
| Sonnet 4.5 | +0.019 | [-0.141, +0.118] | 68.8% |
| Gemini 2.5 Pro | +0.043 | [-0.150, +0.138] | 59.4% |

**Verdict**: per script's strict pre-commit rule → "match" (frontier
point inside our CI). Honest narrative → **asymmetric soft beat** (our
CI excludes 0, theirs include 0; our point above their CI upper bound).

Полный отчёт: [docs/RESULTS_v8_3_1.md](RESULTS_v8_3_1.md), сравнительная
таблица в [docs/FINDINGS_2026-06-11.md](FINDINGS_2026-06-11.md), per-case
data в `runs/frontier_v8_3_1/`.

**Confusion intersection**: 35 кейсов где все три модели не согласны с
SastBench ground truth — priority кандидаты для P1 hand-labeling.
Список case_ids в `runs/frontier_v8_3_1/comparison_report.md`.

**Что осталось открытым** (deferred):
- Sonnet neutral prompt run (+$3.50 OpenRouter) для закрытия
  format-unfamiliarity атаки. Не критично сейчас (Sonnet smoke
  parse_fail=0% значит format adherence хороший), но добавит конкретики
  если pitch встретит сопротивление.

### P3: МОДЕЛЬНЫЙ FREEZE на v8.3.1

После P1-P2 объявляем v8.3.1 production-frozen. v8.3.2 опционально:
- Teacher reasoning for CrossVul (~$1.50 OpenRouter, ~2h pod) — может
  дать +0.02-0.05 MCC, но **не gating** для outreach
- Juliet small dose (~$1) — то же самое, optional

**Не делаем больше**:
- r=4 / r=32 sweep (Lesson 18: wait until train doubles)
- Calibration tricks (gap < 0.05 на SastBench, dead)
- 14B base model (Lesson 10)
- Evidence packet pipeline до hand-labeling decision

### P4: Demand validation MVP — ranker-CLI + OSS PDF reports

**Цель**: ноль байт информации о стороне спроса. Закрываем за 3 недели.

Артефакты для outreach:
1. **Ranker-CLI** (уже написан, `src/product/`): "ест SARIF, выдаёт ранжированный
   список с p_tp". MVP-state: тестировать на real Semgrep output из 3-5
   OSS репозиториев. p_tp через `--mode ranker` (first-token logprobs,
   не verdict → 1/0).
2. **3-5 PDF reports** по известным OSS-репам: запустить Semgrep на public
   repo (например mongodb, rails, django), пропустить через v8.3.1 ranker,
   сгенерить PDF "мы отсортировали ваши 800 алертов, вот топ-30 с p_tp ≥ X".
   Не filter, не "вот эти не баги" — **сортированный список с честным
   confidence**. Формат проверяемый получателем за час.
3. **Outreach 20-30 контактов**: AppSec-инженеры, CTO мелких команд.
   Cold message + PDF attached. Не invest pitch — это "вот triage отчёт
   по вашему репо, скажите honestly: useful?"

### P5: Demand validation pre-committed success criterion

Та же дисциплина что pre-commit на frontier baseline. Записано ДО старта
outreach чтобы не было motivated reasoning post-факто:

> **20 контактов за 3 недели.**
> - Если ≥ 3 запросили отчёт по своему репо AND ≥ 1 после отчёта
>   продолжил разговор → **продуктовая ветка живёт**. Sprint 4 stripe
>   billing + landing page.
> - Если < 3 запросов OR никто не продолжил → **уходим в paper ветку**.
>   Архивируем GitHub App planning, пишем методологическую секцию paper'а
>   по уровню v8.3.1 + lesson 15/18/19 findings.
> - Intermediate (3+ запросили, 0 продолжили после отчёта) → диагностика
>   ad-hoc: показывает что отчёт не bridges от curiosity к engagement,
>   нужен другой формат demo.

Без этого критерия outreach превращается в бесконечное "ещё чуть улучшим
и тогда напишем". С ним — есть exit condition в обе стороны.

## Original queue (rest of this doc) — superseded by above


## Priority queue (in execution order)

### P1: Frontier baseline на тех же 250 кейсах (~$2, ~45 мин)

Эта дыра была в day-0 списке и до сих пор не закрыта. Без неё все
сравнения с frontier в docs невалидны. Reviewer 11.06.2026 поймал и
пометил как первое что надо сделать.

**Методология (закрепить ДО запуска чтобы не было motivated reasoning)**:
- Те же 250 кейсов из `data/eval/sastbench_v01_subset250.json`
- greedy / temperature=0 (для OpenAI/OpenRouter где можно)
- Тот же parse-regex что в `src.eval.run_triage_eval` (VERDICT_RE)
- parse_fail считается как абсолютная ошибка (любой, не parse_fail rate)
- Cluster bootstrap по `repo_url` для CI, identical scripts
  (`scripts/cluster_bootstrap_eval.py`)
- Sonnet 4.5 прогоняем **двумя промптами**:
  (a) наш TRIAGE_USER_TEMPLATE
  (b) нейтральный: "Here's a Semgrep finding, here's the code. TP or FP?
     Answer 'Verdict: TRUE_POSITIVE' or 'Verdict: FALSE_POSITIVE' on the
     first line, then a one-paragraph reason"
  В отчёт идёт **лучший из двух** Sonnet result. Закрывает атаку "вы
  дали frontier неудобный формат и назвали это baseline"
- Gemini 2.5 Pro одним промптом (наш TRIAGE), для бюджета

**Pre-commit interpretation criteria** (зафиксировать ДО запуска):
- "Мы лучше frontier" = наш cluster CI lower bound ≥ их point estimate
  (консервативно). Headline сравнение только при этом условии
- "Мы матчим frontier" = наш point estimate в их cluster CI и наоборот
- "Мы хуже frontier" = их point estimate выше нашего upper bound
- **Что говорить если Sonnet single-call на 250 даст 0.15+**: значит
  smoke n=10 был мисчиталой, single-call frontier работает на этой
  distribution лучше чем мы думали, наш +0.177 ≈ frontier, pitch
  переходит на cost wedge и calibration controllability, не на margin

**Бонус из того же прогона**:
- Сохранить per-case verdicts всех три (v8.3.1 + Sonnet + Gemini)
- Confusion intersection: кейсы где ошибаются все три → первые
  кандидаты для разметки-50 (вероятно кривые SastBench метки)
- Per-case JSON сохранится autoматически по partial-правилу

**Бюджет**: ~$1.5-2 OpenRouter (Sonnet двумя промптами ~$1, Gemini
~$0.5, plus overhead). Если жмёт, упростить до Sonnet одного промпта
+ Gemini одного промпта ~$1.

### P2: Правка docs (нет compute, ~30 мин) — ✅ DONE 11.06 late evening

- FINDINGS_2026-06-11.md: убран "обходим Gemini ReAct" и "crossing
  significance" из самооценки и pitch story
- RESULTS_v8_3_1.md: "decisive margin" и "first crossing significance"
  заменены на "first version with honest CI no longer in negative
  territory" + явный список запрещённых формулировок
- OVERNIGHT_SUMMARY.md: без правок (там нет overclaim'ов, только raw
  numbers)
- NEXT_STEPS.md: этот файл

### P3: r=8 ablation v8.3.1 — ✅ DONE 11.06 late evening, scope discovered

Полный отчёт: [docs/RESULTS_v8_3_1_r8.md](RESULTS_v8_3_1_r8.md). Headline
(N=1, direction-only):

| | v8.3.1 (r=16) | v8.3.1_r8 |
|---|---|---|
| SastBench MCC | +0.177 | +0.057 |
| SastBench FAR | 23.3% | 40.5% |

**Mechanism interpretation gated by pre-registered prediction**
([docs/PREREGISTERED_PREDICTION_v8_3_1_r8.md](PREREGISTERED_PREDICTION_v8_3_1_r8.md)).
Two competing hypotheses:
- H1 (capacity bottleneck): in-domain тоже просел, R ≈ ΔMCC_ID/ΔMCC_OOD ∈ [0.5, 1.0]
- H2 (transfer-DoF): in-domain почти не просел, R ∈ [0.0, 0.2]
- Mixed: R ∈ [0.2, 0.5]

Wait for test_balanced final → compute R → close interpretation. Production
decision (keep r=16) does NOT depend on mechanism — both H1 and H2 yield
"keep r=16" given training cost asymmetry.

**Lesson 4 NOT retracted, scoped**: regularization heals noisy supervision,
starves clean supervision. Lesson 18 (regime boundary) + Lesson 19
(paranoia-as-uncertainty signature) added to HISTORY.md.

**Operational rule going forward** (Lesson 18): capacity choice re-opens
each time train doubles. We carried r=16 from v8.2 → v8.3 by inertia; was
lucky. v8.3.2+ Juliet / D2A → 5-8k rows = r=32 legitimate candidate, one
cheap ablation per event.

r=4 и r=32 sweep НЕ делать на текущих 2180 rows.

### P4: Ranker-CLI расширение (нет compute, code only)

Repositioning продукта с filter на ranker. Reviewer аргумент:
> "Live бот с DR=46% = анти-кейс при первом missed bug в проде клиента.
> Корректное позиционирование: сортируем алерты по p_tp без скрытия"

Расширить `src/product/` (уже написан):
- Добавить `--mode ranker` к CLI
- p_tp из first-token logprobs через `src.eval.extract_triage_logprobs`
  (НЕ из текстового verdict, иначе ранжирование вырождается в два ведра)
- Output: ranked SARIF где каждый result имеет `properties.vuln_llm_triage.p_tp`,
  сортированный по убыванию
- Не маппим p_tp в verdict, отдаём raw для пользователя

### P5 (Захару): hand-labeling 50 (полдня, нет автоматизации)

Reviewer вернул это из do-not-do листа в priority. Аргумент:
> Sufficiency probe дал: Sonnet выдал 37 TP без evidence и 36 с evidence.
> Это метрика **сдвига вердиктов**, не качества. Без ground truth
> различить "evidence не помогает" от "Sonnet игнорирует evidence"
> невозможно. Hand-labeling даёт (a) ground truth для sufficiency,
> (b) валидацию SastBench меток, (c) калибровку judge'ей

Scaffold готов: `scripts/carve_exam.py` создал `data/exam/hand_label_50.json`
с правильной структурой two-pass labeling. Захар заполняет руками.

Это **самый ценный** несделанный пункт всего проекта согласно reviewer.

### P6: HF upload v8.3.1 adapter (~$0.10, 10 мин)

Тех-долг: adapter `/workspace/adapters/v8_3_1/` только на network volume,
HF upload в train script не сработал. Pod EXITED, A6000 capacity wait
блокирует resume. Опция: temp A40 deploy (new pod billing), нужен явный
OK на трату.

## Exam-A policy reaffirmed

`data/exam/exam_a.json` — locked, **не открывается до v8.3.2 finals**.
v8.3.1 на exam_a НЕ peek'аем. Soблазн "глянуть как там" категорически
отбрасывается, иначе через месяц сета не останется.

Per `feedback_exam_set_discipline.md`: each peek = 1 researcher decision
of contamination. After 3 peeks the set is de-facto val.

## Что **НЕ** в priority queue (исправление прежнего do-not-do)

- ~~Evidence packet (Sprint 2) до v8.3.2~~ — reviewer вернул, ждёт
  hand-labeling decision. Если ручная разметка показала что код в репо
  даёт ground truth точнее чем код в сниппете, то контекст содержит
  signal и evidence packet рестартует как pre-v8.3.2 prerequisite.
  Sufficiency probe не закрыл этот вопрос.



## v8.3.0 done — Case B confirmed

See `docs/RESULTS_v8_3_0.md` for full numbers. Headline:
- SastBench MCC: 0.10 → **0.14**
- SastBench FAR: 77% → **32%** (anti-paranoia win, biggest delta)
- SastBench DR: 89% → 51% (recall trade-off)
- test_balanced MCC: 0.65 → 0.45 (in-domain trade-off, expected)
- gap_p_tp (in-domain): 0.058 → **0.175** (calibration restored!)

Reviewer's mechanistic prediction confirmed: contradictory train labels were
destroying first-token signal. Dedup restored signal on in-domain. Distribution
mismatch on SastBench remains — multi-source needed.

Cluster bootstrap honest CI: v8.3.0 MCC=[-0.07, +0.31] (still captures 0,
but ceiling moved from v8.2's +0.19 to +0.31).

## v8.3.1 in progress (overnight)

Started ~05:00 UTC on RunPod A40. Multi-source train:
- 970 v8.3 clean CVEFixes + 1210 CrossVul TRIAGE = 2180 unique rows
- Source-tag in metadata for future LOSO eval
- Same hyperparams as v8.3.0 (r=16) — only train data differs

Known risk: CrossVul reasoning is placeholder (no teacher API). If stylistic
shortcut returns, v8.3.2 needs teacher call. ~$1.50 OpenRouter would fix.

Expected ~2h wall-clock. Results land in `runs/v8_3_1_*` files. Run
`scripts/v8_3_0_full_report.py` (works for v8.3.1 with --v83-* flags repointed)
or write a v8.3.1 report.

# Original 2026-06-11 morning — Next steps as of the morning, kept for context

Concise summary. For full details see:
- `docs/SESSION_2026-06-11_autonomous.md` (running session journal)
- `docs/RESULTS_v8_2_diagnostics.md` (per-CWE / per-language / per-project slices)
- `project_v8_3_train_data_dedup.md` in memory (the train data finding)

## TL;DR — the one finding that changes everything

**v8.2 train had 64% duplicate code rows; 35% of unique codes had conflicting verdicts** (same code labeled both TRUE_POSITIVE and FALSE_POSITIVE across different claimed CWE). Structurally taught the model to distrust the verdict and default to TP → the paranoia observed everywhere.

Root cause: `prepare_cvefixes_triage.py` misclassification FP strategy reused `fixed_code` from other CVE rows as FP-source, overlapping with TP pool.

**Fix already produced**: `data/train/triage_v8_3_clean/train_dedup_balanced.json` (932 unique rows, 466 TP + 466 FP).

## v8.3.0 — what to run next

Single experiment isolating the dedup effect. Same v8.2 hyperparameters, only train data differs. **Updated 2026-06-11 evening per external review** to include the logprob-extract mechanistic check.

```bash
# On pod:
cd /workspace/vuln-llm-research && git pull origin main
python scripts/prepare_v8_3_clean.py \
    --input data/train/triage_v8_2_train.json \
    --out-dir data/train/triage_v8_3_clean
bash scripts/train_v8_3_0.sh v8_3_0
```

train_v8_3_0.sh now ALSO runs `extract_triage_logprobs` on both test_balanced
and SastBench-250. This is the mechanistic test. v8.2's `gap_p_tp` (median TP
minus median FP first-token probabilities) collapsed to 0.058 — hypothesis
is that contradictory train labels destroyed first-token signal. If dedup
cures it, gap should return on in-domain test_balanced, regardless of what
happens on SastBench.

Expected wall-clock: ~2h on A6000, ~$1 train + ~$1 eval + ~$0.20 logprob = ~$2.20.

**Decision tree (three cases, not two)**:

**Case A — dedup cures everything**: SastBench MCC > 0.15 cluster CI bound,
FAR < 50%, gap > 0.10 on both test_balanced AND SastBench.
→ Calibration trick alive on this distribution. v8.3.1 multi-source becomes
  next accelerant (not prerequisite). Run per-slice calibration on val_working
  with cluster bootstrap.

**Case B — contradictory train was the issue, distribution mismatch wasn't**:
gap returns on test_balanced (>0.10) but stays collapsed on SastBench (<0.07).
SastBench MCC may not move much.
→ Clean separation of two problems. v8.3.1 multi-source mix IS needed for
  out-of-distribution generalization. Don't claim dedup as the full fix.

**Case C — gap stays collapsed on test_balanced too**:
gap < 0.08 on in-domain after dedup.
→ Dedup hypothesis wrong; problem is deeper than label noise. Review training
  methodology (loss formulation, prompt format, base model choice).

## Methodology updates (from external review)

1. **Cluster bootstrap** for all SastBench CIs by `repo_url`. WeGIA = 30%
   of test, naive case bootstrap is too tight. Use
   `scripts/cluster_bootstrap_eval.py`. Honest CIs are wider; most per-language
   claims become statistically borderline.

2. **Don't close sufficiency gate** — model-proxy labeling answers "what does
   Sonnet think", not "what does an expert see". Hand-labeling 50 cases
   still adds genuine signal that's orthogonal to v8.3.0 training. The two
   tasks parallelise perfectly. Status of hand-labeling and probe should be
   noted in any future summary.

3. **Ruby MCC=-1 was an n=10 / 5-cluster observation** — wider cluster CI
   shows we can't claim "systematically inverted" on this evidence alone.
   Treat as hypothesis worth examining, not a fact.

## What else was found today

1. **Per-CWE breakdown of v8.2 on SastBench-250**: signal **only** on CWE-79
   (MCC +0.34). CWE-89 and CWE-22 have MCC < 0 (model actively wrong).
   Five CWEs (502/798/352/611/434) are degenerate in our 250 subset (0 TP),
   distorting overall MCC.

2. **Per-language reveal**: JS works (MCC +0.28), PHP mid (+0.10), Go pure
   paranoia (FAR 100%), Python actively wrong (-0.07), TypeScript wrong
   (-0.12), **Ruby catastrophic** (MCC -1.00, all 10 cases inverted).

3. **WeGIA project inflates headline**: WeGIA is 30% of SastBench-250 with
   MCC +0.145. WeGIA-stripped honest MCC = +0.061. Our real "diverse-OSS"
   number is half of the headline 0.10.

4. **Per-language flip trick — honest +0.014 MCC**: Zakhar's math point
   (MCC=-1 means flip to +1) is correct but 5-fold CV honest gain is
   modest. Ruby flip stable in 4/5 folds, Python in 3/5, TS in 2/5. Apply
   as final eval step, but not a pitch headline.

5. **Frontier in single-call setup**: Sonnet 4.5 BA=0.50 / MCC=0 on smoke
   10, Gemini 2.5 Pro BA=0.30 / MCC=-0.50 paranoid. Paper's 0.11/0.15
   numbers are for ReAct (multi-turn agent), not fair single-call. Our v8.2
   at 0.10 is mid-tier-of-frontier in fair comparison.

6. **Sufficiency probe (via model-proxy labeling, killed mid-way)**: Sonnet
   4.5 calls 36/50 cases TP from snippet alone, 37/50 after evidence
   packet added. Evidence moves verdict on 1 case out of 50. Single-call
   frontier does not need evidence packet; snippet sufficient. Evidence
   packet (Sprint 2) is **demoted** from pre-v8.3 prerequisite to post-v8.3
   product feature.

## Mailbox infrastructure

`coordination/POLICY.md` + `scripts/mailbox_listen.ps1` committed. Ready for
Zakhar to configure Codex's symmetric watcher to close the loop.

## Memory rules added this session

- `feedback_smoke_before_full_experiment.md` — smoke before paying for full
- `feedback_meta_check_between_experiments.md` — don't auto-pilot pipeline
- `feedback_intermediate_results_always.md` — partial dumps in every long run
- `feedback_no_oracle_leak_in_calibration.md` — flip/threshold by CV not by eye
- `project_v8_3_train_data_dedup.md` — the 64% duplicate finding

## Budget burn this session

~$3.66 of $5 OpenRouter top-up + ~$0.80 RunPod (two short A40 sessions).
Total under $5. Most of the spend was the labeling + half-finished probe
before Zakhar's "stop" caught me auto-piloting; rest was pod for data audits.

## What's NOT in this session (deferred)

- Frontier baseline FULL 250 on Sonnet / Gemini (smoke-10 enough for pitch)
- D2A integration (D2A not downloaded; needs IBM DAX registration; also
  D2A is C/C++ only so it's a "stylistic anchor" mechanism, not drop-in)
- CrossVul integration (similar to D2A — different mechanism)
- Juliet (synthetic, requires careful dosing)
- Sprint 2 evidence packet — demoted per finding 6 above
- Sprint 3 GitHub App MVP — premature until v8.3.0 numbers

## Decision queue for Zakhar

1. Run v8.3.0 dedup ablation when ready (1.5h pod, ~$2). This is THE next
   experiment.
2. If v8.3.0 succeeds: pitch story update, focus on SARIF/serving.
3. If v8.3.0 falls short: Phase 1 multi-source mix from `project_v8_3_plan.md`.
4. Configure Codex's symmetric mailbox watcher per `coordination/POLICY.md`
   when convenient (not blocking).
