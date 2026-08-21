import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  envelopeV2SigningPayload,
  identityBundleDigest,
  mlsDeviceKeyBindingSigningPayload
} from "../src/auth/capability";
import type { EnvelopeV2, IdentityBundle, MlsDeviceKeyBinding } from "../src/types/contracts";

interface ProtocolV2Fixture {
  mlsDeviceKeyBinding: MlsDeviceKeyBinding;
  mlsDeviceKeyBindingSigningPayload: string;
  identityBundle: IdentityBundle;
  identityBundleSigningPayload: string;
  identityBundleDigest: string;
  envelope: EnvelopeV2;
  envelopeSigningPayload: string;
}

const fixture = JSON.parse(
  readFileSync(new URL("../../../test-vectors/protocol-v2.json", import.meta.url), "utf8")
) as ProtocolV2Fixture;

test("Rust and Worker share the MLS binding signing vector", () => {
  assert.equal(
    new TextDecoder().decode(mlsDeviceKeyBindingSigningPayload(fixture.mlsDeviceKeyBinding)),
    fixture.mlsDeviceKeyBindingSigningPayload
  );
});

test("Rust and Worker share the Envelope V2 signing vector", async () => {
  assert.equal(
    new TextDecoder().decode(await envelopeV2SigningPayload(fixture.envelope)),
    fixture.envelopeSigningPayload
  );
});

test("Rust and Worker share the IdentityBundle V2 digest vector", async () => {
  assert.equal(await identityBundleDigest(fixture.identityBundle), fixture.identityBundleDigest);
});

test("every security-relevant Envelope V2 class changes the signing payload", async () => {
  const baseline = new TextDecoder().decode(await envelopeV2SigningPayload(fixture.envelope));
  const mutations: EnvelopeV2[] = [
    { ...fixture.envelope, relationshipId: "rel-tampered" },
    { ...fixture.envelope, generation: fixture.envelope.generation + 1 },
    { ...fixture.envelope, proposalId: "proposal-tampered" },
    { ...fixture.envelope, claimId: "claim-tampered" },
    { ...fixture.envelope, recipientDeviceId: "device:bob:other" },
    { ...fixture.envelope, inlineCiphertext: "BAUG" },
    {
      ...fixture.envelope,
      storageRefs: fixture.envelope.storageRefs?.map((reference, index) =>
        index === 0 ? { ...reference, ref: "storage:tampered" } : reference
      )
    },
    { ...fixture.envelope, senderBundleDigest: "sha256:tampered" }
  ];
  for (const mutation of mutations) {
    assert.notEqual(
      new TextDecoder().decode(await envelopeV2SigningPayload(mutation)),
      baseline
    );
  }
});
