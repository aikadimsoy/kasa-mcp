# agent-security-review — KASA structural-defense methodology (skill)

*(Türkçe: [README_TR.md](README_TR.md))*

This folder packages **KASA's defense position as a portable *skill* (a methodology bundle)**: a set
of instructions used to **review / harden** an agent / MCP / local-first system with KASA's discipline.

> **Most critical note (honesty):** this is a **review methodology**, **not a runtime security
> control.** A skill = instructions to a model → soft, bypassable. It hardens the *review process*,
> not the target. "Install this skill and your agent is defended" is WRONG. The target's safety comes
> from structural code (KASA phases), not from the model reading this file. **Always verify skill
> output with real measurement.**

## Contents
- **`SKILL_PORTABLE.md`** — model-agnostic skill text. Paste into any LLM as a **system prompt / first
  message**. It requests structured output → adherence is **measurable**.
- **`COMPATIBILITY_LOG.md`** — a template (bilingual) to record per-model observations.
- Claude Code operational version: `.claude/skills/agent-security-review/SKILL.md` at the repo root
  (invoked in a Claude session via `/agent-security-review` or the Skill tool).

## The method in brief (full text in SKILL_PORTABLE.md)
1. **Assume the model is poisoned (A1);** defense must be **structural**, not model judgment.
2. **Actor tagging is mandatory** (A1 poisoned-model, A2 malicious-tool, A3 web-page, A4 same-OS).
   An untagged finding is invalid.
3. **Deny-by-default / total-mediation** check (a broker existing is not enough; show it *cannot be
   bypassed*).
4. **Measurement / honesty:** no invented scores; positive+negative controls; **found→proved→closed**;
   claim **"detect + contain"**, not "prevent / solved"; measurement level (`CODE-STRUCTURE`/`RAN-LIVE`/`DOCUMENTED`).
5. **Hardening order:** attack-surface → cryptographic integrity → isolation → controlled processing.

## Compatibility testing on any model (your goal)
1. Give `SKILL_PORTABLE.md` to the model as a **system prompt**.
2. Then give a small **TARGET** (a code snippet, an MCP endpoint definition, or a defense claim).
3. Compare the output against the requested **structured shape** and observe these adherence signals
   (yes/no — objective):
   - Did it **tag every finding with an actor**?
   - Did it **avoid inventing scores** (objective pass/fail)?
   - Did it say **"detect + contain"** and avoid **"prevent / solved"**?
   - Did it propose a **structural** fix, or fall back to "the model should be more careful"?
   - Did it produce an **honesty_claims + limits** block?
4. Record it in **`COMPATIBILITY_LOG.md`**. (This is the method-adherence variant of the session's
   15-model weakness scan — see `docs/LOCAL_MODEL_WEAKNESS_MAP_EN_2026-08-04.md`.)

## Why this is valuable for us
KASA's real differentiator is not memory quality but **this method** ("the negative-control discipline
that makes agent-security claims falsifiable"). Packaging it as a skill makes that IP reusable and
testable; it aligns 1:1 with the NLnet thesis. **Condition:** position it as a *method*, not a
*protection*; and since a skill is itself a model instruction, do not blindly trust its output — measure.
