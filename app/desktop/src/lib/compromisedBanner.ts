export const COMPROMISED_COMPOSER_TEXT = "Sending is disabled: this session is compromised.";

export interface CompromisedNotice {
  headline: string;
  detail: string;
}

function formatSince(ms: number): string {
  return new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

/**
 * What the chat says once the core has marked a direct conversation
 * `compromised`: the contact's device key signed two conflicting updates, so
 * someone else holds it.
 *
 * There is deliberately no action. Nothing in the app can repair a session
 * keyed to a stolen device key, and the safety number cannot tell either: it
 * covers the same keys the thief now has, so comparing it would still match.
 */
export function compromisedNotice(
  state: string | undefined,
  forkedSinceMs: number | null | undefined,
  peerName: string,
  formatTime: (ms: number) => string = formatSince,
): CompromisedNotice | null {
  if (state !== "compromised") {
    return null;
  }
  const since = forkedSinceMs
    ? `Messages received since ${formatTime(forkedSinceMs)} may not be from ${peerName}.`
    : `Recent messages may not be from ${peerName}.`;
  return {
    headline: "Session compromised",
    detail:
      `${peerName}'s device key signed two conflicting updates, so someone else holds it. ` +
      `${since} Reach ${peerName} another way; comparing safety numbers won't help, they still match.`,
  };
}
