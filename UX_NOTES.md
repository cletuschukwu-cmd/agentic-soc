# UX / UI Notes

Observations gathered while building, to address in the final enterprise
frontend (the React rebuild). The current HTML console is the working prototype;
these are the refinements the shipping UI should incorporate.

## Deferred to the final UX/UI phase

- **Submit control.** Replace the "Investigate" button with a return/enter
  symbol (↵) or a neutral "Send". Not every request is an investigation — some
  are reports or summaries — so "Investigate" is misleading. (Requested by user.)

- **Promptbooks.** Let senior analysts author, name, save, and share reusable
  investigation prompts (like Security Copilot promptbooks). Natural-language
  freedom for everyone; saved expert prompts for consistency across the team.
  (Requested early; carried forward.)

- **Recommendation length.** The reporting agent occasionally over-elaborates a
  single recommendation into a long paragraph. Tighten via prompt ("one or two
  sentences each") and/or render with truncation + expand. (Cosmetic.)

- **Report vs verdict rendering.** Handled in the prototype (console detects and
  renders each), but the React version should formalize this as distinct
  components — VerdictCard vs ReportView — since more non-verdict agents are
  coming.

- **Live reasoning stream.** The prototype shows a single "investigating…"
  status then the result. The correlator and deep-diving specialists take 1–2+
  minutes; the final UI should stream intermediate steps (tool calls,
  consultations) so the analyst sees progress, not a spinner. Especially for the
  correlation agent, which consults other agents serially.

- **Injection findings surfacing.** When the injection guard fires, the final UI
  should make it prominent (it's a security signal, not a footnote) — a distinct
  banner, not just a section.

## Design direction (from frontend-design guidance)

- Dark SOC-console aesthetic; verdict color encodes disposition (not decoration).
- Evidence-forward, calm, trustworthy — trust is the brand.
- Enterprise React rebuild on the same authenticated API; components, routing,
  state management, promptbooks.

## Refinements found during agent build

- **Network verdict citations.** The Network/C2 specialist reaches correct
  verdicts but returns empty key_evidence / 0-0 grounding, because network
  telemetry rows lack the resolvable identifiers (SystemAlertId etc.) the
  citation check expects. Network verdicts should be able to cite a connection
  record or a Defender indicator match as evidence. Refinement, not a bug.
- **Recommendation verbosity.** Reporting agent occasionally over-elaborates a
  single recommendation into a long paragraph; tighten via prompt.
