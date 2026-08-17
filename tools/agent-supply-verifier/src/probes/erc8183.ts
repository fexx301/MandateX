import type { DetectedAgentCard } from "./a2a.js";

export type PassiveErc8183Evidence = Readonly<{
  level: "claimed" | "unknown";
  declared: boolean;
  activeProbePerformed: false;
  verified: false;
  skillIds: readonly string[];
  note: string;
}>;

export function inspectPassiveErc8183(
  card: DetectedAgentCard | null,
): PassiveErc8183Evidence {
  if (card === null) {
    return {
      level: "unknown",
      declared: false,
      activeProbePerformed: false,
      verified: false,
      skillIds: [],
      note: "No compatible Agent Card was detected.",
    };
  }

  const declaredSkills = card.skills.filter(
    (skill) =>
      skill.id === "negotiate" ||
      skill.id === "notify_funded" ||
      skill.tags.some((tag) => tag.toLowerCase() === "erc8183"),
  );

  return {
    level: declaredSkills.length > 0 ? "claimed" : "unknown",
    declared: declaredSkills.length > 0,
    activeProbePerformed: false,
    verified: false,
    skillIds: declaredSkills.map((skill) => skill.id).sort(),
    note:
      declaredSkills.length > 0
        ? "ERC-8183 is declared by Agent Card metadata only; no commerce call was sent."
        : "No ERC-8183 declaration was detected; no commerce call was sent.",
  };
}
