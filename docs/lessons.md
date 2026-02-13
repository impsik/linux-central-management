# Lessons

A running log of small engineering skills we deliberately practice and then apply to the codebase.

## 2026-02-13
- Skill focus: Define *operational semantics* precisely, then implement detection logic with a single authoritative source and a small unit test.
- What I applied: Fixed user "locked" detection to rely on `passwd -S` statuses (treat only `L` as locked), avoiding ambiguous `/etc/shadow` heuristics that mark new/no-password users as locked.
- What I learned: On Debian/Ubuntu, a leading `!` in `/etc/shadow` can also indicate "no password set" (common for newly created accounts) and shouldn’t automatically be treated as an explicit lock when the UI intends "passwd-locked" semantics.
