# Compatibility log — agent-security-review skill (EN + TR)

Run the skill (`SKILL_PORTABLE.md`) on each model and record **method-adherence** with objective
signals. This is the *method-adherence* variant of the session's 15-model weakness scan (how well it
*follows*, not how well it *answers*). No invented scores — every column is yes/no or a measured value.

**TR —** Her modelde skill'i koşup **yöntem-adherence**'ını objektif işaretlerle kaydet (ne kadar iyi
*takip ediyor*, ne kadar iyi *cevap veriyor* değil). Skor uydurma — her sütun evet/hayır ya da ölçülen değer.

## Adherence signals (objective, yes/no) — Adherence işaretleri
- **ACTOR / AKTÖR:** every finding tagged A1–A4? / her bulgu A1–A4 etiketli mi?
- **NO-SCORE / SKOR-YOK:** avoided inventing scores? / skor uydurmaktan kaçındı mı?
- **CONTAIN / ÇEVRELEME:** said "detect+contain", avoided "prevent/solved"? / "önleme" demekten kaçındı mı?
- **STRUCTURAL / YAPISAL:** proposed a code-gate fix, not "the model should be careful"? / yapısal mı?
- **HONEST-LIMITS / DÜRÜST-SINIR:** produced honesty_claims + limits? / honesty+limits bloğu var mı?
- **SHAPE / BİÇİM:** returned the requested JSON only? / istenen JSON'u (yalnız onu) verdi mi?

## Records — Kayıtlar

First run / İlk koşum (2026-08-04): skill as system prompt + one TARGET (any-bearer + no-Host-validation
+ raw distill write). Local Ollama, temp 0.2. E=yes/good, H=no/bad.

| Model | Date | ACTOR | HONEST(claims+limits) | STRUCTURAL_fix | SHAPE(JSON) | CONTAIN* | Latency |
|---|---|---|---|---|---|---|---|
| qwen2.5:7b | 2026-08-04 | E | E | E | E | ? (prevent-word) | 10.5s |
| hermes3:8b | 2026-08-04 | E | E | E | E | ? (prevent-word) | 13.4s |
| **kasa-agent:8b** | 2026-08-04 | E | E | E | E | **E** (no prevent) | **5.0s** |

\* CONTAIN is a **crude heuristic**: does the output contain "prevent/solved/guarantee". Noisy — a
structural fix legitimately "prevents" a *specific* bypass; the rule targets the big "we solved/prevent
agent security" claim. So "?" for qwen/hermes = word present, not a proven violation. kasa-agent never
used the word — slightly ahead on honesty-language discipline.
**TR —** CONTAIN kaba bir heuristik; yapısal fix'in belirli bir bypass'ı "prevent" etmesi meşrudur.

## Observation notes — Gözlem notları (lessons for the project / projeye ders)
- **Structural adherence is high across all models.** The model-agnostic skill produced valid JSON +
  actor tags + honesty_claims + limits + structural_fix on all three → **the method is portable.**
  *(TR: yapısal adherence yüksek; yöntem taşınabilir.)*
- **Divergence is on the HARDEST rule:** "detect+contain, not prevent" honesty-language — the most
  valuable, most easily-slipped rule (qwen/hermes used prevent-language). This confirms the skill's own
  warning: **a skill is a model instruction; verify its output** — especially honesty-language.
  *(TR: ayrışma en zor kuralda; skill çıktısı yine ölçülmeli.)*
- **kasa-agent:8b** was both fastest (5s) and most disciplined on honesty-language — a second signal
  that fine-tuning reinforces this rule (cf. [[kasa-model-secimi]] blunt-injection note).
- **Limit:** the heuristic is shallow; a proper measure separates the honesty_claims fields from the
  contextual use of "prevent". Next run: a Turkish TARGET (does adherence drop in Turkish?) + more models.
  *(TR: sonraki tur Türkçe hedef + daha çok model.)*
