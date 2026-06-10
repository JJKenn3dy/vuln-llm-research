"""Quick distribution audit on local SastBench cases (258 = hand_label + working)."""
import json, collections, statistics
hl = json.load(open('data/exam/hand_label_cases.json', encoding='utf-8'))
wr = json.load(open('data/exam/val_working_remainder.json', encoding='utf-8'))
sb = hl + wr

print(f'Total local SastBench: {len(sb)}  (hand_label {len(hl)} + working {len(wr)})')
print(f'Verdict: {dict(collections.Counter(c["metadata"]["verdict"] for c in sb))}\n')

print('=== CWE distribution ===')
cwes = collections.Counter(c['metadata']['claimed_cwe'] for c in sb)
for cwe, n in cwes.most_common():
    print(f'  {cwe:>10}: {n:>3} ({100*n/len(sb):.1f}%)')

print('\n=== Language distribution ===')
langs = collections.Counter(c['metadata']['language'] for c in sb)
for l, n in langs.most_common():
    print(f'  {l:>15}: {n:>3} ({100*n/len(sb):.1f}%)')

print('\n=== Project diversity ===')
projects = collections.Counter(c['metadata']['project_id'] for c in sb)
print(f'  unique projects: {len(projects)} for {len(sb)} cases')
counts = list(projects.values())
print(f'  cases per project: median={statistics.median(counts)}, mean={statistics.mean(counts):.1f}, max={max(counts)}')
print(f'  top 10 projects by cases:')
for p, n in projects.most_common(10):
    p_short = p.replace('https://github.com/', '') if p else '?'
    print(f'    {n:>3}  {p_short}')

print('\n=== CWE x verdict (where TP/FP ratios diverge) ===')
cwe_verdict = collections.defaultdict(lambda: collections.Counter())
for c in sb:
    cwe_verdict[c['metadata']['claimed_cwe']][c['metadata']['verdict']] += 1
print(f'  {"CWE":>10}  {"TP":>4}  {"FP":>4}  {"%TP":>6}')
for cwe in sorted(cwe_verdict, key=lambda c: -sum(cwe_verdict[c].values())):
    cv = cwe_verdict[cwe]
    total = cv['TRUE_POSITIVE'] + cv['FALSE_POSITIVE']
    pct = 100 * cv['TRUE_POSITIVE'] / total if total else 0
    print(f'  {cwe:>10}  {cv["TRUE_POSITIVE"]:>4}  {cv["FALSE_POSITIVE"]:>4}  {pct:>5.1f}%')
