export const COMPROMISED_COMPOSER_TEXT = "Sending is disabled: this session is compromised.";

export const UNCONFIRMED_SENDER_LABEL = "Unconfirmed sender";

/**
 * Whether an inbound message in a compromised conversation arrived after the
 * commit the double sign contradicts. Both times are the host's receipt
 * stamps, so they compare; an untrusted host can move either, which only
 * moves this marker, never what was delivered.
 */
export function isUnconfirmedSender(
  direction: string,
  createdAt: number,
  forkedSinceMs: number | null | undefined,
): boolean {
  return direction === "received" && forkedSinceMs != null && createdAt >= forkedSinceMs;
}

/** What the side that lost its group is told: only its peer can fix this. */
export function awaitingResetDetail(peerName: string): string {
  return `This side lost its secure session. Ask ${peerName} to reset it from their side.`;
}

/** The confirmation the reset action asks for. */
export function resetSessionConfirmText(peerName: string): string {
  return (
    `Reset the secure session with ${peerName}?\n\n` +
    `Only do this if ${peerName}'s app says the chat needs a reset. ` +
    `If it doesn't, their app refuses the reset and the chat stops working for both of you.`
  );
}

export interface CompromisedNotice {
  headline: string;
  detail: string;
  advice: string;
}

function formatSince(ms: number): string {
  return new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

/**
 * What the chat says once the core has marked a direct conversation
 * `compromised`: the contact's device key signed two conflicting updates, so
 * someone else holds it.
 *
 * The only way forward is on the contact's side and outside this session. The
 * stolen snapshot holds their root key as well, so the current safety number
 * still matches and proves nothing, and anything this session delivers about
 * a replacement could come from the thief. They need a new identity from a
 * new recovery phrase, and its safety number compared in person.
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
    detail: `${peerName}'s device key signed two conflicting updates, so someone else holds it. ${since}`,
    advice:
      `Tell ${peerName} outside TapChat. They need a new identity with a new recovery phrase; ` +
      `verify its safety number in person. The current safety number still matches, so it can't help.`,
  };
}
