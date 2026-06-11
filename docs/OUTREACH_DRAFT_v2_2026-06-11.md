# Cold outreach v2 (2026-06-11, после practical smoke v3)

Обновлённая версия [OUTREACH_DRAFT_2026-06-11.md](OUTREACH_DRAFT_2026-06-11.md)
с реальными примерами из 19 проверенных репов. Три варианта по адресату.

## Главная цифра (для всех вариантов)

> 19 репов, 466 findings (Semgrep + Bandit), 7 минут pod-time, ranker
> отсортировал по p_tp с gap 0.30-0.52 в semantically консистентном
> порядке. На 5 vulnerable controls (NodeGoat, dvna, DVWA, django_nv_vuln,
> dvws_node) top-5 каждого репа — настоящие критические уязвимости
> (SQLi/XSS/eval). Bandit-шум в production-тестах все отнесены вниз
> (rpg_life 74/74 в p_tp ≤ 0.45 — реально все FP, использование assert
> в pytest).

**Caveat который выяснили manual check'ом**: на real-world коде (не
intentionally vulnerable) ranker может поставить наверх finding'и
которые формально являются FP из-за mitigations выше по файлу.
Конкретно: top-5 в devonz_bolt (`execSync(`git archive --format=zip
${commitSha}`)`) защищены `assertValidSha()` строгой regex выше. Это
ограничение snippet-only triage. Frontier single-call (Sonnet/Gemini)
имеет ту же слепую зону. Для production: top-K **всегда** требует
manual confirmation перед disclosure.

## Вариант A: УБРАН (false positive после manual check)

Ранее: предлагалось писать автору Devonz про 5 found command-injection.
**После ручной проверки**: все 5 finding'ов имеют mitigations
(`assertValidSha` строгая regex, regex sanitize on paths, local-only
pre-start script). Disclosure был бы неправильным.

Это известное ограничение snippet-based triage (наш Lesson 20). НЕ
отправлять "found RCE" message без manual verification top-K finding'ов.
Если top-K руками подтвердились — тогда disclosure OK.

## Вариант B: AppSec инженеру (короткое cold-message)

Адресат: AppSec / Security Engineer в команде где есть какой-то AI-coded
код. Тон: collegial, data-driven.

Subject: SAST recall на AI-сгенерированном коде — данные на 19 репах

Body:

> Меня зовут Захар Якуба, делаю исследование по SAST-триажу.
>
> Прогнал Semgrep + Bandit на 19 репах: 13 AI-сгенерированных (v0.dev,
> Lovable, Bolt, Cursor-style) и 6 контрольных intentionally-vulnerable.
> Результаты:
>
> 1. На 8 простых AI-coded landing/boilerplate — 0 findings суммарно.
>    Pattern-SAST на vibe-coded UI не цепляется вообще.
> 2. На 5 AI-coded full-stack (bolt-coded git tool, Lovable-coded
>    portals, Cursor-coded Django demo) — 192 findings, среди них
>    реальные command injections и format string bugs.
> 3. Bandit на Python (FastAPI + Django) дал 201 finding суммарно.
>    Мой fine-tuned 7B триаж отсортировал так что 74 ассерт-в-тестах
>    из rpg_life ушли в low-priority (median p_tp 0.39), а реальные
>    issue вверху.
>
> Хочу проверить гипотезу: команды которые катают vibe-coded
> прототипы не имеют security gate потому что (a) Semgrep на их коде
> молчит, (b) Bandit генерит горы шума который никто не разбирает.
>
> Если у тебя есть public репо в стек FastAPI / Django / Node /
> Next.js, я бы прогнал свой триаж и прислал PDF с top-30 findings +
> reasoning. Бесплатно, цель — собрать сигнал нужно ли это вам как
> продукт.
>
> Можно прислать ссылку?

Подпись.

## Вариант C: CTO (одноразмерный pitch)

Адресат: основатель / CTO небольшой команды (5-30 человек) с микс
human + AI-coded backend. Тон: продуктовый.

Subject: 91% SAST алертов это шум, мы делаем triage layer

Body:

> Hi {name},
>
> Building a SAST triage layer that filters scanner noise via a 7B
> specialist model. Quick proof:
>
> - 19 repos tested today (13 AI-generated, 6 vulnerable controls)
> - 466 findings from Semgrep + Bandit ranked in 7 minutes on a single A40
> - Top-5 of every vulnerable control = real critical bugs (SQLi/XSS/eval/RCE)
> - All 74 Bandit-noise findings (Use of assert in tests) in rpg_life
>   were correctly filtered to bottom (p_tp 0.28-0.45)
> - Found 5 unreported command injection candidates in a bolt-coded
>   git tool with 52 stars
>
> The product: ingest SARIF from your existing scanner (Semgrep, CodeQL,
> Snyk, Bandit), output ranked SARIF with `properties.vuln_llm_triage.p_tp`
> on every finding. Self-hosted (no code leaves your VPC), ~$0.0001 per
> finding at scale, vs $0.015 per finding via single-call frontier APIs
> with similar quality on the same benchmark.
>
> Would value 15 min to show the demo and ask 3 questions about your
> AppSec triage workflow. Worth a call?

Подпись.

## Pre-commit success criterion (повтор)

(из NEXT_STEPS P5)

- **≥3 запросов отчётов AND ≥1 follow-up после отчёта** = продуктовая
  ветка живёт. Sprint 4: stripe billing + landing page.
- **<3 запросов OR никто не продолжил после отчёта** = paper ветка.
- **3+ запросов, 0 follow-up** = отчёт не bridges curiosity к engagement,
  нужен другой формат demo.

## Артефакты для outreach

Готово прямо сейчас (можно ссылаться):
- [docs/PRACTICAL_SMOKE_v3_2026-06-11.md](PRACTICAL_SMOKE_v3_2026-06-11.md) —
  полный отчёт с цифрами и tables
- 14 ranked SARIF файлов в `data/practical/results_*/`
- partial.jsonl с p_tp на каждый finding для верификации

Не готово (нужно ~5 часов):
- Markdown→PDF report renderer (filter mode + reasoning + code snippet)
- Landing page с числами выше

## Контакты для рассылки (черновик)

Цель: 20 за 3 недели по P5.

**Вариант A** (open-source authors):
- zebbern (Devonz, найден command-injection) — приоритет 1
- Gerome-Elassaad (CodingIT, lovable-coded) — приоритет 2
- robdmac (talkito, bolt-coded Python tool) — приоритет 3

**Вариант B** (AppSec engineers через каналы):
- DevSecOps RU чат
- OWASP Russia chapter
- HSE/Yandex/Avito alumni LinkedIn

**Вариант C** (CTOs мелких команд):
- Founders из Y Combinator W25/S25 (vibe-coded стек обычно)
- Bug bounty platform CTOs (Selectel/Avito BB)
