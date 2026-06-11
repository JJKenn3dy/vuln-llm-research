# Cold outreach draft (2026-06-11)

Два варианта сообщения для outreach по P4 demand validation (NEXT_STEPS).
Хук: pattern-SAST не ловит AI-сгенерированный код. Это работает в обе
стороны: либо приходишь к нашему semantic-aware детектору, либо просто
понимаешь что текущий стек у тебя пустой.

Pre-commit success criterion из NEXT_STEPS P5: 20 контактов за 3 недели,
≥3 запросили отчёт по своему репо AND ≥1 после отчёта продолжил разговор
= продуктовая ветка живёт.

## Вариант A: AppSec-инженерам (русский, для российских CTO / AppSec)

Subject (короткий): SAST на AI-сгенерированном коде даёт ноль findings

Body:

> Меня зовут Захар Якуба, я делаю исследование по SAST-триажу. Прогнал
> Semgrep на 7 AI-сгенерированных веб-приложениях (v0.dev, Lovable,
> Cursor-style), результат — **0 findings на 7 репах, 874 правила**.
>
> На контрольных intentionally-vulnerable приложениях того же стека
> (NodeGoat, DVNA, DVWA) — 123 findings, всё разнообразно.
>
> Это значит pattern-based SAST на AI-коде имеет recall ≈ 0. Я этого
> не ожидал такого размера и проверяю гипотезу: команды которые катают
> vibe-coded прототипы фактически без security gate, потому что
> существующие сканеры не цепляются за их код.
>
> Если у тебя в команде есть AI-сгенерированный код (frontend, internal
> tooling, MVP-страницы) и ты можешь дать ссылку на public repo — я бы
> прогнал свой 7B fine-tuned детектор и прислал PDF-отчёт с top-30
> findings + объяснениями. Бесплатно, без обязательств, цель — собрать
> сигнал нужно ли это вам как продукт.
>
> Можно прислать в ответ ссылку?

Подпись: ссылка на этот репо (или landing когда будет), email.

## Вариант B: западные CTO / AppSec-инженеры (english)

Subject: SAST returns 0 findings on AI-generated apps — sample of 7

Body:

> Hi {name},
>
> I'm researching SAST triage for AI-generated apps. I just ran Semgrep
> with auto-config (874 rules) against 7 AI-coded web apps (v0.dev,
> Lovable, Cursor-style). Total findings: **0**.
>
> Control runs on intentionally-vulnerable Node/PHP apps (NodeGoat,
> DVNA, DVWA) on the same scanner: 123 findings, broad CWE coverage.
>
> The implication: teams shipping vibe-coded prototypes (internal
> tools, MVP frontends, demos) likely have no security signal at all
> because pattern-based scanners do not engage with the structural
> patterns AI code generators produce.
>
> I built a 7B specialist (Qwen-Coder-7B + LoRA, fine-tuned on
> CVEFixes/CrossVul, MCC +0.18 on SastBench-250 single-call vs Sonnet
> 4.5 single-call +0.02). On NodeGoat my ranker put `eval(req.body.X)`
> RCE in the top-5 and false-positive pattern-only findings in the
> bottom-5 with no manual tuning.
>
> If you have public AI-generated repos in your stack, I can run them
> through my pipeline and send you a PDF triage report with top-30
> findings + reasoning per finding. Free, no obligations, I'm
> collecting signal on whether this is worth productizing.
>
> Interested? Reply with a repo link.

Подпись: same.

## Что готово для отчёта-приманки (delivery format)

`src/product/` уже умеет:
- SARIF input -> ranker mode -> sorted SARIF with `properties.vuln_llm_triage.p_tp`
- SARIF input -> filter mode -> SARIF with verdict + reasoning + suggested_fix

Что нужно дописать (~1 день работы):
- Markdown-render: SARIF -> человеческий отчёт с top-K findings, кодом,
  reasoning, ссылкой на line в repo (если public)
- WeasyPrint / md-to-pdf -> PDF

Минимально это 4-5 часов. Можно набросать прототип на 1 finding
сейчас.

## Список потенциальных контактов (черновик)

Цель: 20 за 3 недели. Источники:
- AppSec-чаты Telegram (DevSecOps RU, SecurityRU, Application Security)
- HSE/Yandex/Avito выпускники в LinkedIn с титулами AppSec / Security
  Engineer / Security Champion
- Founders / CTOs Bug Bounty платформ (HackerOne RU community, Avito BB,
  Selectel BB)
- AppSec community OWASP Russia chapter
- Cold LinkedIn outreach: vibe-coding twitter community (cursor,
  bolt, lovable employees) для западного варианта

## Pre-commit interpretation criterion

(из NEXT_STEPS P5, повтор для ясности здесь)

- **≥3 запросов отчётов AND ≥1 follow-up после отчёта** = продуктовая
  ветка живёт. Sprint 4: stripe billing + landing page.
- **<3 запросов OR никто не продолжил после отчёта** = уходим в paper
  ветку. Архивируем GitHub App planning, публикуем методологию.
- **3+ запросов, 0 follow-up** = диагностика формата отчёта. Возможно
  PDF не bridges от curiosity к engagement.

Без pre-committed criterion outreach превращается в бесконечное "ещё
улучшим и тогда напишем". С ним есть exit condition в обе стороны.

## Что я бы делал в ближайшие 3 дня

1. Сегодня (закрыто): практический smoke на 11 репах, обнаружил факт
   нулевого recall pattern-SAST на AI-коде. Это и есть outreach hook.
2. Завтра: написать markdown report renderer (4-5 часов). Прогнать
   filter mode на NodeGoat (29 findings) чтобы получить пример PDF
   с reasoning. Послать одному дружелюбному контакту в виде test.
3. Послезавтра: отправить вариант A 5 русским AppSec / CTO. Замерить
   open rate, reply rate, ask rate.

Если из 5 контактов есть хотя бы 1 reply — это уже сигнал.
