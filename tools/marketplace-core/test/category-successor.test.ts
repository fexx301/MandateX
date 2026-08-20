import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import test from "node:test";

import { canonicalSha256 } from "../src/canonical.js";
import {
  categoryLinkageProjectionSha256,
  type CategoryLinkageProjectionUnsigned,
} from "../src/category-linkage.js";
import {
  MARKETPLACE_GRID_ADAPTER,
  MARKETPLACE_VENUS_HEALTH_ADAPTER,
  MARKETPLACE_VENUS_HEALTH_EVIDENCE_SCHEMA,
  MARKETPLACE_YIELD_ADAPTER,
} from "../src/category-policy.js";
import {
  createMarketplaceCategoryTrustController,
  createMarketplaceCategoryTrustStateStore,
} from "../src/category-trust-controller.js";
import {
  CATEGORY_THRESHOLD_UNITS,
  MARKETPLACE_CATEGORY_CANDIDATE_IDENTITY_SCHEMA,
  MARKETPLACE_CATEGORY_ACTION_PROFILE_APPROVAL,
  MARKETPLACE_CATEGORY_ACTION_PROFILE_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA,
  MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
  MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA,
  MARKETPLACE_MANDATE_V2_SCHEMA,
  categoryReadArgumentBindingSha256,
  categoryReadCalldataSha256,
  categoryReadCommitmentsSha256,
  categoryStaticReadProfileSha256,
  type CategoryActionProfile,
  type CategoryReadProfile,
  type CategoryTargetObservation,
  type MarketplaceCategoryQuoteRequest,
  type MarketplaceMandateV2,
} from "../src/category-production.js";
import {
  MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_AUDIENCE,
  MARKETPLACE_CATEGORY_QUOTE_ISSUER,
  MARKETPLACE_CATEGORY_QUOTE_PROJECTION_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_SIDECARS_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE,
  deriveMarketplaceCategoryActiveReport,
  createMarketplaceCategoryQuoteTrustStore,
  marketplaceCategoryQuoteProjectionSchema,
  marketplaceCategoryQuoteAttestationSigningMessage,
  marketplaceCategoryQuoteAttestationUnsignedSchema,
  serializeMarketplaceCategoryQuoteAttestation,
  verifyMarketplaceCategoryQuoteAttestation,
  type MarketplaceCategoryQuoteAttestationUnsigned,
  type MarketplaceCategoryQuoteProjection,
  type MarketplaceCategoryQuoteTrustStore,
} from "../src/category-successor.js";
import {
  MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA,
  MARKETPLACE_TRUST_BUNDLE_AUDIENCE,
  MARKETPLACE_TRUST_BUNDLE_ISSUER,
  MARKETPLACE_TRUST_BUNDLE_SCHEMA,
  MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE,
  MARKETPLACE_TRUST_KEY_SCHEMA,
  MARKETPLACE_TRUST_RELEASE_SCHEMA,
  marketplaceTrustBundleSigningMessage,
  marketplaceTrustBundleUnsignedSchema,
  marketplaceTrustReleaseDefinitionSha256,
  serializeMarketplaceTrustBundle,
  type MarketplaceTrustBundleReleaseRecord,
  type MarketplaceTrustBundleUnsigned,
} from "../src/trust-bundle.js";

const REGISTRY = `0x${"11".repeat(20)}`;
const OWNER = `0x${"22".repeat(20)}`;
const POOL = `0x${"33".repeat(20)}`;
const VAULT = `0x${"34".repeat(20)}`;
const COMMERCE = `0x${"44".repeat(20)}`;
const OTHER_COMMERCE = `0x${"55".repeat(20)}`;
const BLOCK_HASH = `0x${"ab".repeat(32)}`;
const VENUS_COMPTROLLER = `0x${"66".repeat(20)}`;
const VENUS_BORROW_MARKET = `0x${"77".repeat(20)}`;
const VENUS_ACCOUNT = `0x${"88".repeat(20)}`;
const POLICY_SHA256 = "66".repeat(32);
const DEPLOYMENT_SHA256 = "77".repeat(32);
const ARTIFACT_SHA256 = "88".repeat(32);
const EVIDENCE_SHA256 = "99".repeat(32);
const RESPONSE_SHA256 = "aa".repeat(32);
const PROVIDER_CODE_SHA256 = "ee".repeat(32);

const rootKeyPair = generateKeyPairSync("ed25519");
const signerKeyPair = generateKeyPairSync("ed25519");

test("protocol-instance-verified grid evidence remains hireable", async () => {
  const fixture = makeFixture();
  const trustStore = await makeTrustStore(
    fixture.readProfile,
    fixture.actionProfile,
  );
  const wire = signedAttestationWire(fixture, trustStore);
  const verified = verifyMarketplaceCategoryQuoteAttestation({
    wire,
    mandate: fixture.mandate,
    request: fixture.request,
    identityArtifact: fixture.identity,
    targetObservations: fixture.targets,
    readProfile: fixture.readProfile,
    trustStore,
    clock: () => 1_150,
  });
  const report = deriveMarketplaceCategoryActiveReport({
    verifiedAttestation: verified,
    actionProfile: null,
    clock: () => 1_150,
  });

  assert.deepEqual(
    verified.targetObservations.map((target) => target.assurance),
    ["protocol_instance_verified"],
  );
  assert.equal(report.status, "VERIFIED_HIREABLE");
  assert.equal(report.validUntil, 1_300);
  assert.equal(report.actionCoverage, "not_applicable");
  assert.equal(report.minimumTargetAssurance, "protocol_instance_verified");
  assert.equal(report.linkage.providerAuthority.kind, "erc8004_registered_owner");
  assert.equal(Object.isFrozen(report), true);
  assert.equal(Object.isFrozen(report.linkage), true);
  const replayed = deriveMarketplaceCategoryActiveReport({
    verifiedAttestation: verifyMarketplaceCategoryQuoteAttestation({
      wire,
      mandate: fixture.mandate,
      request: fixture.request,
      identityArtifact: fixture.identity,
      targetObservations: fixture.targets,
      readProfile: fixture.readProfile,
      trustStore,
      clock: () => 1_271,
    }),
    actionProfile: null,
    clock: () => 1_271,
  });
  assert.equal(replayed.status, "UNAVAILABLE");
  assert.equal(replayed.validUntil, report.validUntil);

  assert.throws(
    () =>
      deriveMarketplaceCategoryActiveReport({
        verifiedAttestation: verified,
        actionProfile: null,
        clock: () => 1_150,
        status: "VERIFIED_HIREABLE",
      } as never),
    hasCode("INPUT_INVALID"),
  );
  assert.throws(
    () =>
      deriveMarketplaceCategoryActiveReport({
        verifiedAttestation: verified,
        actionProfile: null,
        clock: () => 1_151,
      }),
    hasCode("ATTESTATION_REVERIFY_REQUIRED"),
  );
  assert.throws(
    () =>
      serializeMarketplaceCategoryQuoteAttestation({
        ...makeUnsignedAttestation(fixture, trustStore),
        status: "VERIFIED_HIREABLE",
        signature: "00".repeat(64),
      }),
    /unrecognized_keys|Unrecognized key/,
  );
});

test("interface-only ERC-4626 is hireable only as an explicitly unendorsed observation", async () => {
  const fixture = makeInterfaceOnlyYieldFixture();
  const trustStore = await makeTrustStore(
    fixture.readProfile,
    fixture.actionProfile,
  );
  const verified = verifyMarketplaceCategoryQuoteAttestation({
    wire: signedAttestationWire(fixture, trustStore),
    mandate: fixture.mandate,
    request: fixture.request,
    identityArtifact: fixture.identity,
    targetObservations: fixture.targets,
    readProfile: fixture.readProfile,
    trustStore,
    clock: () => 1_150,
  });
  const report = deriveMarketplaceCategoryActiveReport({
    verifiedAttestation: verified,
    actionProfile: null,
    clock: () => 1_150,
  });

  assert.equal(verified.targetObservations[0]?.assurance, "interface_only_unendorsed");
  assert.equal(verified.linkage.observation.status, "pass");
  assert.equal(report.status, "VERIFIED_HIREABLE");
  assert.equal(
    report.sidecars.targetObservations[0]?.provenance.status,
    "unendorsed",
  );
  assert.equal(
    report.sidecars.targetObservations[0]?.provenance.source,
    "interface-only-unendorsed-v1",
  );
  assert.equal(report.minimumTargetAssurance, "interface_only_unendorsed");
});

test("signed release assurance policy can keep interface-only evidence inconclusive", async () => {
  const fixture = makeInterfaceOnlyYieldFixture();
  const trustStore = await makeTrustStore(
    fixture.readProfile,
    fixture.actionProfile,
    "protocol_instance_verified",
  );
  const release = marketplaceTrustBundleUnsignedSchema.parse(
    JSON.parse(
      signedTrustBundlePayload(
        fixture.readProfile,
        fixture.actionProfile,
        "protocol_instance_verified",
      ),
    ),
  ).releases[0]!;
  const verified = verifyMarketplaceCategoryQuoteAttestation({
    wire: signedAttestationWire(fixture, trustStore, {
      releaseDefinitionSha256: release.definitionSha256,
    }),
    mandate: fixture.mandate,
    request: fixture.request,
    identityArtifact: fixture.identity,
    targetObservations: fixture.targets,
    readProfile: fixture.readProfile,
    trustStore,
    clock: () => 1_150,
  });
  const report = deriveMarketplaceCategoryActiveReport({
    verifiedAttestation: verified,
    actionProfile: null,
    clock: () => 1_150,
  });

  assert.equal(report.minimumTargetAssurance, "protocol_instance_verified");
  assert.equal(report.status, "INCONCLUSIVE");
});

test("Venus successor binds the second health adapter and all three exact reads", async () => {
  const fixture = makeVenusFixture();
  const trustStore = await makeTrustStore(
    fixture.readProfile,
    fixture.actionProfile,
  );
  const verified = verifyMarketplaceCategoryQuoteAttestation({
    wire: signedAttestationWire(fixture, trustStore),
    mandate: fixture.mandate,
    request: fixture.request,
    identityArtifact: fixture.identity,
    targetObservations: fixture.targets,
    readProfile: fixture.readProfile,
    trustStore,
    clock: () => 1_150,
  });
  const report = deriveMarketplaceCategoryActiveReport({
    verifiedAttestation: verified,
    actionProfile: null,
    clock: () => 1_150,
  });

  assert.equal(verified.request.adapterId, MARKETPLACE_VENUS_HEALTH_ADAPTER);
  assert.deepEqual(
    verified.targetObservations.map((target) => [target.role, target.targetAddress]),
    [
      ["borrowMarket", VENUS_BORROW_MARKET],
      ["comptroller", VENUS_COMPTROLLER],
    ],
  );
  assert.deepEqual(
    verified.readProfile.reads.map((read) => [read.role, read.callId, read.selector]),
    [
      ["borrowMarket", "borrowBalanceStored(address)", "0x95dd9193"],
      ["comptroller", "getAccountLiquidity(address)", "0x5ec88c79"],
      ["comptroller", "getAssetsIn(address)", "0xabfceffc"],
    ],
  );
  assert.equal(report.category, "health");
  assert.equal(report.status, "VERIFIED_HIREABLE");
  assert.equal(report.minimumTargetAssurance, "protocol_instance_verified");
});

test("signed successor sidecars bind identity, targets, reads, service, and observation", async () => {
  const fixture = makeFixture();
  const trustStore = await makeTrustStore(
    fixture.readProfile,
    fixture.actionProfile,
  );
  const wire = signedAttestationWire(fixture, trustStore);
  const verified = verifyMarketplaceCategoryQuoteAttestation({
    wire,
    mandate: fixture.mandate,
    request: fixture.request,
    identityArtifact: fixture.identity,
    targetObservations: fixture.targets,
    readProfile: fixture.readProfile,
    trustStore,
    clock: () => 1_150,
  });

  assert.deepEqual(verified.sidecars.candidateIdentity, fixture.identity);
  assert.deepEqual(verified.sidecars.targetObservations, fixture.targets);
  assert.deepEqual(verified.sidecars.readProfile, fixture.readProfile);
  assert.deepEqual(
    verified.sidecars.observation,
    fixture.projection.linkage.observation,
  );
  assert.equal(Object.isFrozen(verified.sidecars), true);
  assert.equal(Object.isFrozen(verified.sidecars.targetObservations), true);
  assert.equal(Object.isFrozen(verified.sidecars.targetObservations[0]), true);

  const identityDrift = {
    ...fixture.projection,
    sidecars: {
      ...fixture.projection.sidecars,
      candidateIdentity: {
        ...fixture.identity,
        ownerAddress: OTHER_COMMERCE,
      },
    },
  };
  assert.equal(
    marketplaceCategoryQuoteProjectionSchema.safeParse(identityDrift).success,
    false,
  );

  const targetDrift = {
    ...fixture.projection,
    sidecars: {
      ...fixture.projection.sidecars,
      targetObservations: [
        {
          ...fixture.targets[0]!,
          runtimeCodeSha256: "ff".repeat(32),
        },
      ],
    },
  };
  assert.equal(
    marketplaceCategoryQuoteProjectionSchema.safeParse(targetDrift).success,
    false,
  );

  const readDrift = {
    ...fixture.projection,
    sidecars: {
      ...fixture.projection.sidecars,
      readProfile: {
        ...fixture.readProfile,
        reads: [
          {
            ...fixture.readProfile.reads[0]!,
            responseSha256: "ff".repeat(32),
          },
        ],
      },
    },
  };
  assert.equal(
    marketplaceCategoryQuoteProjectionSchema.safeParse(readDrift).success,
    false,
  );

  const serviceDrift = {
    ...fixture.projection,
    sidecars: {
      ...fixture.projection.sidecars,
      service: {
        ...fixture.projection.sidecars.service,
        permissionExpiresAt:
          fixture.projection.sidecars.service.permissionExpiresAt - 1,
      },
    },
  };
  assert.throws(
    () =>
      verifyMarketplaceCategoryQuoteAttestation({
        wire: signedAttestationWire(fixture, trustStore, {
          projection: serviceDrift,
        }),
        mandate: fixture.mandate,
        request: fixture.request,
        identityArtifact: fixture.identity,
        targetObservations: fixture.targets,
        readProfile: fixture.readProfile,
        trustStore,
        clock: () => 1_150,
      }),
    hasCode("SERVICE_SIDECAR_MISMATCH"),
  );
});

test("successor rejects fabricated trust, domain, nonce, expiry, tuple, and wire mutations", async () => {
  const fixture = makeFixture();
  const trustStore = await makeTrustStore(
    fixture.readProfile,
    fixture.actionProfile,
  );
  const wire = signedAttestationWire(fixture, trustStore);
  const baseInput = {
    mandate: fixture.mandate,
    request: fixture.request,
    identityArtifact: fixture.identity,
    targetObservations: fixture.targets,
    readProfile: fixture.readProfile,
    clock: () => 1_150,
  } as const;

  const fabricated = { ...trustStore } as MarketplaceCategoryQuoteTrustStore;
  assert.throws(
    () =>
      verifyMarketplaceCategoryQuoteAttestation({
        ...baseInput,
        wire,
        trustStore: fabricated,
      }),
    hasCode("TRUST_STORE_UNVERIFIED"),
  );

  const domainProjection = mutateLinkage(fixture.projection.linkage, {
    providerAcceptance: {
      ...fixture.projection.linkage.providerAcceptance,
      verifyingContract: OTHER_COMMERCE,
    },
  });
  assert.throws(
    () =>
      verifyMarketplaceCategoryQuoteAttestation({
        ...baseInput,
        wire: signedAttestationWire(fixture, trustStore, {
          quoteVerifyingContract: OTHER_COMMERCE,
          projection: {
            ...fixture.projection,
            linkage: domainProjection,
          },
        }),
        trustStore,
      }),
    hasCode("QUOTE_DOMAIN_MISMATCH"),
  );

  const nonceProjection = mutateLinkage(fixture.projection.linkage, {
    providerAcceptance: {
      ...fixture.projection.linkage.providerAcceptance,
      quoteNonce: "other-nonce",
    },
  });
  assert.throws(
    () =>
      verifyMarketplaceCategoryQuoteAttestation({
        ...baseInput,
        wire: signedAttestationWire(fixture, trustStore, {
          projection: { ...fixture.projection, linkage: nonceProjection },
        }),
        trustStore,
      }),
    /different quote nonce/,
  );

  assert.throws(
    () =>
      verifyMarketplaceCategoryQuoteAttestation({
        ...baseInput,
        wire: signedAttestationWire(fixture, trustStore, { expiresAt: 1_421 }),
        trustStore,
      }),
    hasCode("ATTESTATION_EXPIRY_INVALID"),
  );
  assert.throws(
    () =>
      verifyMarketplaceCategoryQuoteAttestation({
        ...baseInput,
        wire: signedAttestationWire(fixture, trustStore, { releaseId: "release-other" }),
        trustStore,
      }),
    /signed authorization edge/,
  );

  const parsed = JSON.parse(wire) as Record<string, unknown>;
  const signature = String(parsed.signature);
  const tamperedSignature = `${signature.slice(0, -1)}${signature.endsWith("0") ? "1" : "0"}`;
  assert.throws(
    () =>
      verifyMarketplaceCategoryQuoteAttestation({
        ...baseInput,
        wire: JSON.stringify({ ...parsed, signature: tamperedSignature }),
        trustStore,
      }),
    hasCode("ATTESTATION_SIGNATURE_INVALID"),
  );
  assert.throws(
    () =>
      verifyMarketplaceCategoryQuoteAttestation({
        ...baseInput,
        wire: ` ${wire}`,
        trustStore,
      }),
    hasCode("ATTESTATION_NONCANONICAL"),
  );
  assert.throws(
    () =>
      verifyMarketplaceCategoryQuoteAttestation({
        ...baseInput,
        wire,
        trustStore,
        clock: () => 1_300,
      }),
    hasCode("ATTESTATION_EXPIRED"),
  );
});

test("draft transactional profiles remain inconclusive even with a passing preview", async () => {
  const fixture = makeTransactionalFixture();
  const trustStore = await makeTrustStore(
    fixture.readProfile,
    fixture.actionProfile,
  );
  const wire = signedAttestationWire(fixture, trustStore);
  const verified = verifyMarketplaceCategoryQuoteAttestation({
    wire,
    mandate: fixture.mandate,
    request: fixture.request,
    identityArtifact: fixture.identity,
    targetObservations: fixture.targets,
    readProfile: fixture.readProfile,
    trustStore,
    clock: () => 1_150,
  });
  const report = deriveMarketplaceCategoryActiveReport({
    verifiedAttestation: verified,
    actionProfile: fixture.actionProfile,
    clock: () => 1_150,
  });

  assert.equal(report.status, "INCONCLUSIVE");
  assert.equal(report.actionCoverage, "incomplete");
  assert.equal(report.preview.status, "passed");
});

test("transactional releases cannot lower the target-assurance floor", async () => {
  const fixture = makeTransactionalFixture();
  await assert.rejects(
    () =>
      makeTrustStore(
        fixture.readProfile,
        fixture.actionProfile,
        "interface_only_unendorsed",
      ),
    /transactional adapter modes require protocol-instance assurance/,
  );
});

function makeFixture() {
  const scope = {
    adapterId: MARKETPLACE_GRID_ADAPTER,
    category: "grid" as const,
    evidenceSchema: "mandatex.category.grid-evidence.v1" as const,
    protocol: "pancakeswap-v3" as const,
    subject: { poolAddress: POOL },
    conditionPolicy: { unit: CATEGORY_THRESHOLD_UNITS.gridTick, lowerTick: -100, upperTick: 100 },
  };
  const mandate: MarketplaceMandateV2 = {
    schema: MARKETPLACE_MANDATE_V2_SCHEMA,
    mandateId: "mandate-successor-1",
    category: "grid",
    adapterId: MARKETPLACE_GRID_ADAPTER,
    chainId: 56,
    createdAt: 1_000,
    expiresAt: 1_600,
    maxClockSkewSeconds: 30,
    maxEvidenceAgeSeconds: 300,
    serviceMode: "observe_only",
    categoryScope: scope,
    actionPermissions: [],
    maxSpendUsdMicros: "0",
    permissionsExpiresAt: 1_350,
  };
  const request: MarketplaceCategoryQuoteRequest = {
    schema: MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA,
    requestId: "request-successor-1",
    mandateId: mandate.mandateId,
    mandateSha256: canonicalSha256(mandate),
    category: mandate.category,
    adapterId: mandate.adapterId,
    protocol: mandate.categoryScope.protocol,
    categoryScope: mandate.categoryScope,
    categoryScopeSha256: canonicalSha256(mandate.categoryScope),
    candidate: { chainId: 56, tokenId: "7" },
    serviceMode: "observe_only",
    actionPermissions: [],
    actionPermissionsSha256: canonicalSha256([]),
    maxSpendUsdMicros: "0",
    permissionsExpiresAt: 1_350,
    nonce: "quote-nonce-1",
    issuedAt: 1_050,
    expiresAt: 1_400,
  };
  const identityWithoutDigest = {
    schema: MARKETPLACE_CATEGORY_CANDIDATE_IDENTITY_SCHEMA,
    chainId: 56 as const,
    tokenId: "7",
    registryAddress: REGISTRY,
    ownerAddress: OWNER,
    observedBlock: 123,
    observedBlockHash: BLOCK_HASH,
    confirmationDepth: 2,
    registryCodeSha256: "11".repeat(32),
    observedAt: 1_100,
  };
  const identity = {
    ...identityWithoutDigest,
    identitySha256: canonicalSha256(identityWithoutDigest),
  };
  const targets = [
    {
      schema: MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA,
      adapterId: MARKETPLACE_GRID_ADAPTER,
      role: "pool",
      targetAddress: POOL,
      assurance: "protocol_instance_verified" as const,
      runtimeCodeSha256: "22".repeat(32),
      proxy: { kind: "none" as const },
      provenance: {
        status: "verified" as const,
        source: "pancakeswap-v3-factory-membership-v1",
        proofSha256: "33".repeat(32),
      },
      observedAt: 1_100,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
    },
  ];
  const readProfile: CategoryReadProfile = {
    schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
    profileId: "pancakeswap-v3-grid-observation-v1",
    adapterId: MARKETPLACE_GRID_ADAPTER,
    reads: [
      {
        role: "pool",
        callId: "slot0()",
        target: POOL,
        selector: "0x3850c7bd",
        argumentBindingSha256: categoryReadArgumentBindingSha256(),
        calldataSha256: categoryReadCalldataSha256("0x3850c7bd"),
        responseSha256: RESPONSE_SHA256,
      },
    ],
  };
  const linkageUnsigned: CategoryLinkageProjectionUnsigned = {
    schema: "mandatex.marketplace.category-linkage-projection.v1",
    trustStatus: "untrusted_until_successor_attestation_verified",
    relation: "candidate_accepts_service_for_subject",
    scope: "evaluation_only",
    activationAuthorization: "none",
    reservation: "none",
    subjectSelection: "mandate_declared_exact",
    anchorBinding: "same_canonical_block",
    requestId: request.requestId,
    mandateId: mandate.mandateId,
    mandateSha256: canonicalSha256(mandate),
    categoryQuoteRequestSha256: canonicalSha256(request),
    category: "grid",
    adapterId: MARKETPLACE_GRID_ADAPTER,
    protocol: "pancakeswap-v3",
    candidate: request.candidate,
    candidateIdentity: {
      proofProfile: "erc8004-owner-of-v1",
      chainId: 56,
      tokenId: "7",
      registryAddress: REGISTRY,
      registeredOwner: OWNER,
      confirmationDepth: 2,
      registryCodeSha256: identity.registryCodeSha256,
      identitySha256: identity.identitySha256,
      observedAt: 1_100,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
    },
    providerAuthority: {
      kind: "erc8004_registered_owner",
      providerAddress: OWNER,
      validatedSigner: OWNER,
      providerCodeSha256: PROVIDER_CODE_SHA256,
      candidateIdentitySha256: identity.identitySha256,
    },
    providerAcceptance: {
      relation: "candidate_accepts_service_for_subject",
      verificationProfile: "mandatex-category-quote-verification-v1",
      providerKind: "eoa",
      signatureMethod: "eip191",
      validatedSigner: OWNER,
      validatedProvider: OWNER,
      providerCodeSha256: PROVIDER_CODE_SHA256,
      chainId: 56,
      verifyingContract: COMMERCE,
      candidateIdentitySha256: identity.identitySha256,
      mandateSha256: canonicalSha256(mandate),
      categoryQuoteRequestSha256: canonicalSha256(request),
      subjectSha256: canonicalSha256(scope.subject),
      conditionPolicySha256: canonicalSha256(scope.conditionPolicy),
      actionPermissionsSha256: request.actionPermissionsSha256,
      quoteNonce: request.nonce,
      quoteRequestKeccak256: `0x${"44".repeat(32)}`,
      quoteResponseKeccak256: `0x${"55".repeat(32)}`,
      negotiationKeccak256: `0x${"66".repeat(32)}`,
      quoteEndpointSha256: "44".repeat(32),
      negotiatedAt: 1_080,
      quoteExpiresAt: 1_350,
    },
    categoryScope: scope,
    categoryScopeSha256: canonicalSha256(scope),
    subjectSha256: canonicalSha256(scope.subject),
    conditionPolicySha256: canonicalSha256(scope.conditionPolicy),
    serviceMode: "observe_only",
    actionPermissionsSha256: request.actionPermissionsSha256,
    observation: {
      status: "pass",
      categoryDeploymentSha256: DEPLOYMENT_SHA256,
      verifierPolicySha256: POLICY_SHA256,
      targetsSha256: canonicalSha256(targets),
      readProfileId: readProfile.profileId,
      readProfileSha256: categoryStaticReadProfileSha256(readProfile),
      readCommitmentsSha256: categoryReadCommitmentsSha256(readProfile),
      artifactSha256: ARTIFACT_SHA256,
      evidenceSha256: EVIDENCE_SHA256,
      observedAt: 1_100,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
    },
  };
  const linkage = {
    ...linkageUnsigned,
    linkageSha256: categoryLinkageProjectionSha256(linkageUnsigned),
  };
  const projection = {
    schema: MARKETPLACE_CATEGORY_QUOTE_PROJECTION_SCHEMA,
    linkage,
    sidecars: {
      schema: MARKETPLACE_CATEGORY_QUOTE_SIDECARS_SCHEMA,
      candidateIdentity: identity,
      targetObservations: targets,
      readProfile,
      actionProfile: null,
      service: {
        mode: "observe_only" as const,
        actionPermissionsSha256: request.actionPermissionsSha256,
        coverage: "not_applicable" as const,
        permissionExpiresAt: request.permissionsExpiresAt,
        assurance: "protocol_instance_verified" as const,
      },
      observation: linkage.observation,
    },
    preview: { status: "not_applicable" as const },
  };
  return {
    mandate,
    request,
    identity,
    targets,
    readProfile,
    projection,
    actionProfile: null,
  };
}

function makeTransactionalFixture() {
  const base = makeFixture();
  const permission = {
    actionId: "rebalance-grid",
    targetRole: "pool",
    target: POOL,
    callId: "rebalance(int24,int24)",
    selector: "0x12345678",
    maxValueWei: "100",
  } as const;
  const mandate: MarketplaceMandateV2 = {
    ...base.mandate,
    serviceMode: "transactional",
    actionPermissions: [permission],
    maxSpendUsdMicros: "1000",
  };
  const request: MarketplaceCategoryQuoteRequest = {
    ...base.request,
    mandateSha256: canonicalSha256(mandate),
    serviceMode: "transactional",
    actionPermissions: [permission],
    actionPermissionsSha256: canonicalSha256([permission]),
    maxSpendUsdMicros: "1000",
  };
  const linkageUnsigned = {
    ...base.projection.linkage,
    mandateSha256: canonicalSha256(mandate),
    categoryQuoteRequestSha256: canonicalSha256(request),
    serviceMode: "transactional" as const,
    actionPermissionsSha256: request.actionPermissionsSha256,
    providerAcceptance: {
      ...base.projection.linkage.providerAcceptance,
      mandateSha256: canonicalSha256(mandate),
      categoryQuoteRequestSha256: canonicalSha256(request),
      actionPermissionsSha256: request.actionPermissionsSha256,
    },
  };
  const { linkageSha256: _oldDigest, ...withoutDigest } = linkageUnsigned;
  const linkage = {
    ...withoutDigest,
    linkageSha256: categoryLinkageProjectionSha256(withoutDigest),
  };
  const actionProfile: CategoryActionProfile = {
    schema: MARKETPLACE_CATEGORY_ACTION_PROFILE_SCHEMA,
    approval: MARKETPLACE_CATEGORY_ACTION_PROFILE_APPROVAL,
    profileId: "pancakeswap-v3-grid-action-v1",
    adapterId: MARKETPLACE_GRID_ADAPTER,
    serviceMode: "transactional",
    actions: [
      {
        actionId: permission.actionId,
        targetRole: permission.targetRole,
        callId: permission.callId,
        selector: permission.selector,
        maxValueWei: permission.maxValueWei,
      },
    ],
  };
  return {
    ...base,
    mandate,
    request,
    actionProfile,
    projection: {
      ...base.projection,
      linkage,
      sidecars: {
        ...base.projection.sidecars,
        actionProfile,
        service: {
          mode: "transactional" as const,
          actionPermissionsSha256: request.actionPermissionsSha256,
          coverage: "incomplete" as const,
          permissionExpiresAt: request.permissionsExpiresAt,
          assurance: "protocol_instance_verified" as const,
        },
      },
      preview: {
        status: "passed" as const,
        observedAt: 1_100,
        observedBlock: 123,
        observedBlockHash: BLOCK_HASH,
      },
    },
  };
}

function makeInterfaceOnlyYieldFixture(): SuccessorFixture {
  const base = makeFixture();
  const scope = {
    adapterId: MARKETPLACE_YIELD_ADAPTER,
    category: "yield" as const,
    evidenceSchema: "mandatex.category.yield-evidence.v1" as const,
    protocol: "erc4626" as const,
    subject: { vaultAddress: VAULT },
    conditionPolicy: { unit: CATEGORY_THRESHOLD_UNITS.yieldSharePrice, minSharePriceScaled: "1000000000000000000" },
  };
  const mandate: MarketplaceMandateV2 = {
    ...base.mandate,
    mandateId: "mandate-successor-yield-1",
    category: "yield",
    adapterId: MARKETPLACE_YIELD_ADAPTER,
    categoryScope: scope,
  };
  const request: MarketplaceCategoryQuoteRequest = {
    ...base.request,
    requestId: "request-successor-yield-1",
    mandateId: mandate.mandateId,
    mandateSha256: canonicalSha256(mandate),
    category: mandate.category,
    adapterId: mandate.adapterId,
    protocol: scope.protocol,
    categoryScope: scope,
    categoryScopeSha256: canonicalSha256(scope),
  };
  const targets: readonly CategoryTargetObservation[] = [
    {
      schema: MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA,
      adapterId: MARKETPLACE_YIELD_ADAPTER,
      role: "vault",
      targetAddress: VAULT,
      assurance: "interface_only_unendorsed",
      runtimeCodeSha256: "22".repeat(32),
      proxy: { kind: "none" },
      provenance: {
        status: "unendorsed",
        source: "interface-only-unendorsed-v1",
        proofSha256: "33".repeat(32),
      },
      observedAt: 1_100,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
    },
  ];
  const readProfile: CategoryReadProfile = {
    schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
    profileId: "erc4626-yield-observation-v1",
    adapterId: MARKETPLACE_YIELD_ADAPTER,
    reads: [
      {
        role: "vault",
        callId: "totalAssets()",
        target: VAULT,
        selector: "0x01e1d114",
        argumentBindingSha256: categoryReadArgumentBindingSha256(),
        calldataSha256: categoryReadCalldataSha256("0x01e1d114"),
        responseSha256: RESPONSE_SHA256,
      },
      {
        role: "vault",
        callId: "totalSupply()",
        target: VAULT,
        selector: "0x18160ddd",
        argumentBindingSha256: categoryReadArgumentBindingSha256(),
        calldataSha256: categoryReadCalldataSha256("0x18160ddd"),
        responseSha256: RESPONSE_SHA256,
      },
    ],
  };
  const { linkageSha256: _oldDigest, ...baseLinkage } =
    base.projection.linkage;
  const linkageUnsigned: CategoryLinkageProjectionUnsigned = {
    ...baseLinkage,
    requestId: request.requestId,
    mandateId: mandate.mandateId,
    mandateSha256: canonicalSha256(mandate),
    categoryQuoteRequestSha256: canonicalSha256(request),
    category: "yield",
    adapterId: MARKETPLACE_YIELD_ADAPTER,
    protocol: "erc4626",
    candidate: request.candidate,
    providerAcceptance: {
      ...baseLinkage.providerAcceptance,
      mandateSha256: canonicalSha256(mandate),
      categoryQuoteRequestSha256: canonicalSha256(request),
      subjectSha256: canonicalSha256(scope.subject),
      conditionPolicySha256: canonicalSha256(scope.conditionPolicy),
      actionPermissionsSha256: request.actionPermissionsSha256,
    },
    categoryScope: scope,
    categoryScopeSha256: canonicalSha256(scope),
    subjectSha256: canonicalSha256(scope.subject),
    conditionPolicySha256: canonicalSha256(scope.conditionPolicy),
    observation: {
      ...baseLinkage.observation,
      targetsSha256: canonicalSha256(targets),
      readProfileId: readProfile.profileId,
      readProfileSha256: categoryStaticReadProfileSha256(readProfile),
      readCommitmentsSha256: categoryReadCommitmentsSha256(readProfile),
    },
  };
  const linkage = {
    ...linkageUnsigned,
    linkageSha256: categoryLinkageProjectionSha256(linkageUnsigned),
  };

  return {
    mandate,
    request,
    identity: base.identity,
    targets,
    readProfile,
    projection: {
      schema: MARKETPLACE_CATEGORY_QUOTE_PROJECTION_SCHEMA,
      linkage,
      sidecars: {
        schema: MARKETPLACE_CATEGORY_QUOTE_SIDECARS_SCHEMA,
        candidateIdentity: base.identity,
        targetObservations: targets,
        readProfile,
        actionProfile: null,
        service: {
          mode: "observe_only",
          actionPermissionsSha256: request.actionPermissionsSha256,
          coverage: "not_applicable",
          permissionExpiresAt: request.permissionsExpiresAt,
          assurance: "interface_only_unendorsed",
        },
        observation: linkage.observation,
      },
      preview: { status: "not_applicable" },
    },
    actionProfile: null,
  };
}

function makeVenusFixture(): SuccessorFixture {
  const base = makeFixture();
  const scope = {
    adapterId: MARKETPLACE_VENUS_HEALTH_ADAPTER,
    category: "health" as const,
    evidenceSchema: MARKETPLACE_VENUS_HEALTH_EVIDENCE_SCHEMA,
    protocol: "venus" as const,
    subject: {
      comptrollerAddress: VENUS_COMPTROLLER,
      accountAddress: VENUS_ACCOUNT,
      borrowMarketAddress: VENUS_BORROW_MARKET,
    },
    conditionPolicy: { unit: CATEGORY_THRESHOLD_UNITS.venusUsd, minLiquidityUsdScaled: "1000000" },
  };
  const mandate: MarketplaceMandateV2 = {
    ...base.mandate,
    mandateId: "mandate-successor-venus-1",
    category: "health",
    adapterId: MARKETPLACE_VENUS_HEALTH_ADAPTER,
    categoryScope: scope,
  };
  const request: MarketplaceCategoryQuoteRequest = {
    ...base.request,
    requestId: "request-successor-venus-1",
    mandateId: mandate.mandateId,
    mandateSha256: canonicalSha256(mandate),
    category: mandate.category,
    adapterId: mandate.adapterId,
    protocol: scope.protocol,
    categoryScope: scope,
    categoryScopeSha256: canonicalSha256(scope),
  };
  const targets: readonly CategoryTargetObservation[] = [
    {
      schema: MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA,
      adapterId: MARKETPLACE_VENUS_HEALTH_ADAPTER,
      role: "borrowMarket",
      targetAddress: VENUS_BORROW_MARKET,
      assurance: "protocol_instance_verified",
      runtimeCodeSha256: "22".repeat(32),
      proxy: { kind: "none" },
      provenance: {
        status: "verified",
        source: "venus-market-membership-v1",
        proofSha256: "33".repeat(32),
      },
      observedAt: 1_100,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
    },
    {
      schema: MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA,
      adapterId: MARKETPLACE_VENUS_HEALTH_ADAPTER,
      role: "comptroller",
      targetAddress: VENUS_COMPTROLLER,
      assurance: "protocol_instance_verified",
      runtimeCodeSha256: "23".repeat(32),
      proxy: { kind: "none" },
      provenance: {
        status: "verified",
        source: "venus-market-membership-v1",
        proofSha256: "34".repeat(32),
      },
      observedAt: 1_100,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
    },
  ];
  const readProfile: CategoryReadProfile = {
    schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
    profileId: "venus-health-observation-v1",
    adapterId: MARKETPLACE_VENUS_HEALTH_ADAPTER,
    reads: [
      {
        role: "borrowMarket",
        callId: "borrowBalanceStored(address)",
        target: VENUS_BORROW_MARKET,
        selector: "0x95dd9193",
        argumentBindingSha256: categoryReadArgumentBindingSha256(VENUS_ACCOUNT),
        calldataSha256: categoryReadCalldataSha256("0x95dd9193", VENUS_ACCOUNT),
        responseSha256: RESPONSE_SHA256,
      },
      {
        role: "comptroller",
        callId: "getAccountLiquidity(address)",
        target: VENUS_COMPTROLLER,
        selector: "0x5ec88c79",
        argumentBindingSha256: categoryReadArgumentBindingSha256(VENUS_ACCOUNT),
        calldataSha256: categoryReadCalldataSha256("0x5ec88c79", VENUS_ACCOUNT),
        responseSha256: "bb".repeat(32),
      },
      {
        role: "comptroller",
        callId: "getAssetsIn(address)",
        target: VENUS_COMPTROLLER,
        selector: "0xabfceffc",
        argumentBindingSha256: categoryReadArgumentBindingSha256(VENUS_ACCOUNT),
        calldataSha256: categoryReadCalldataSha256("0xabfceffc", VENUS_ACCOUNT),
        responseSha256: "cc".repeat(32),
      },
    ],
  };
  const { linkageSha256: _oldDigest, ...baseLinkage } = base.projection.linkage;
  const linkageUnsigned: CategoryLinkageProjectionUnsigned = {
    ...baseLinkage,
    requestId: request.requestId,
    mandateId: mandate.mandateId,
    mandateSha256: canonicalSha256(mandate),
    categoryQuoteRequestSha256: canonicalSha256(request),
    category: "health",
    adapterId: MARKETPLACE_VENUS_HEALTH_ADAPTER,
    protocol: "venus",
    providerAcceptance: {
      ...baseLinkage.providerAcceptance,
      mandateSha256: canonicalSha256(mandate),
      categoryQuoteRequestSha256: canonicalSha256(request),
      subjectSha256: canonicalSha256(scope.subject),
      conditionPolicySha256: canonicalSha256(scope.conditionPolicy),
      actionPermissionsSha256: request.actionPermissionsSha256,
    },
    categoryScope: scope,
    categoryScopeSha256: canonicalSha256(scope),
    subjectSha256: canonicalSha256(scope.subject),
    conditionPolicySha256: canonicalSha256(scope.conditionPolicy),
    observation: {
      ...baseLinkage.observation,
      targetsSha256: canonicalSha256(targets),
      readProfileId: readProfile.profileId,
      readProfileSha256: categoryStaticReadProfileSha256(readProfile),
      readCommitmentsSha256: categoryReadCommitmentsSha256(readProfile),
    },
  };
  const linkage = {
    ...linkageUnsigned,
    linkageSha256: categoryLinkageProjectionSha256(linkageUnsigned),
  };
  return {
    ...base,
    mandate,
    request,
    targets,
    readProfile,
    projection: {
      ...base.projection,
      linkage,
      sidecars: {
        ...base.projection.sidecars,
        candidateIdentity: base.identity,
        targetObservations: targets,
        readProfile,
        actionProfile: null,
        service: {
          mode: "observe_only",
          actionPermissionsSha256: request.actionPermissionsSha256,
          coverage: "not_applicable",
          permissionExpiresAt: request.permissionsExpiresAt,
          assurance: "protocol_instance_verified",
        },
        observation: linkage.observation,
      },
      preview: { status: "not_applicable" },
    },
    actionProfile: null,
  };
}

async function makeTrustStore(
  readProfile: CategoryReadProfile,
  actionProfile: CategoryActionProfile | null,
  minimumTargetAssurance:
    | "interface_only_unendorsed"
    | "protocol_instance_verified" =
    readProfile.adapterId === MARKETPLACE_YIELD_ADAPTER
      ? "interface_only_unendorsed"
      : "protocol_instance_verified",
) {
  const bundleWire = signedTrustBundleWire(
    readProfile,
    actionProfile,
    minimumTargetAssurance,
  );
  let state: unknown;
  let stateSha256: string | undefined;
  const stateStore = createMarketplaceCategoryTrustStateStore({
    load: async () => ({ state, stateSha256 }),
    compareAndSwap: async (input: any) => {
      if (input.expectedStateSha256 !== stateSha256) {
        return {
          status: "conflict",
          expectedStateSha256: input.expectedStateSha256,
          committedStateSha256: stateSha256,
          bundleSha256: (state as any)?.bundleSha256,
          generation: (state as any)?.generation,
          revocationEpoch: (state as any)?.revocationEpoch,
        };
      }
      state = input.nextState;
      stateSha256 = input.nextStateSha256;
      return {
        status: "committed",
        expectedStateSha256: input.expectedStateSha256,
        committedStateSha256: stateSha256,
        bundleSha256: input.bundleSha256,
        generation: input.generation,
        revocationEpoch: input.revocationEpoch,
      };
    },
    withRevision: async (expected, operation) => {
      assert.equal(stateSha256, expected);
      return operation();
    },
  });
  const controller = createMarketplaceCategoryTrustController({
    root: {
      keyId: "root-k1",
      publicKeySpkiDer: exportedSpki(rootKeyPair.publicKey),
      publicKeyFingerprintSha256: fingerprint(rootKeyPair.publicKey),
    },
    quoteVerifyingContract: COMMERCE,
    rollbackFloor: { generation: 0, revocationEpoch: 0 },
    stateStore,
    clock: () => 1_150,
  });
  const commitment = await controller.prepare({ bundleWire });
  return createMarketplaceCategoryQuoteTrustStore({
    commitment,
  });
}

function signedTrustBundleWire(
  readProfile: CategoryReadProfile,
  actionProfile: CategoryActionProfile | null,
  minimumTargetAssurance:
    | "interface_only_unendorsed"
    | "protocol_instance_verified" =
    readProfile.adapterId === MARKETPLACE_YIELD_ADAPTER
      ? "interface_only_unendorsed"
      : "protocol_instance_verified",
): string {
  const releasePartial = {
    schema: MARKETPLACE_TRUST_RELEASE_SCHEMA,
    releaseId: "release-r1",
    attestationSchema: MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA,
    signatureProfile: MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE,
    verifierPolicySha256: POLICY_SHA256,
    categoryDeploymentSha256: DEPLOYMENT_SHA256,
    enabledAdapterModes: [
      {
        adapterId: readProfile.adapterId,
        serviceMode:
          actionProfile === null ? "observe_only" as const : "transactional" as const,
        readProfileId: readProfile.profileId,
        readProfileSha256: categoryStaticReadProfileSha256(readProfile),
        actionProfileId: actionProfile?.profileId ?? null,
        actionProfileSha256:
          actionProfile === null ? null : canonicalSha256(actionProfile),
        minimumTargetAssurance,
      },
    ],
    definitionSha256: "00".repeat(32),
    lifecycle: "active" as const,
    lifecycleChangedAt: 900,
    notBefore: 800,
    notAfter: 2_000,
    revokedAt: null,
    revocationEpoch: null,
  };
  const release: MarketplaceTrustBundleReleaseRecord = {
    ...releasePartial,
    definitionSha256: marketplaceTrustReleaseDefinitionSha256(releasePartial),
  };
  const unsigned: MarketplaceTrustBundleUnsigned =
    marketplaceTrustBundleUnsignedSchema.parse({
      schema: MARKETPLACE_TRUST_BUNDLE_SCHEMA,
      signatureProfile: MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE,
      issuer: MARKETPLACE_TRUST_BUNDLE_ISSUER,
      audience: MARKETPLACE_TRUST_BUNDLE_AUDIENCE,
      rootKeyId: "root-k1",
      generation: 1,
      revocationEpoch: 0,
      issuedAt: 1_000,
      expiresAt: 1_500,
      activeSignerKeyId: "signer-k1",
      activeReleaseId: "release-r1",
      keys: [
        {
          schema: MARKETPLACE_TRUST_KEY_SCHEMA,
          keyId: "signer-k1",
          algorithm: "Ed25519",
          publicKeyEncoding: "spki-der",
          publicKeySpkiDerBase64: exportedSpki(signerKeyPair.publicKey).toString("base64"),
          publicKeyFingerprintSha256: fingerprint(signerKeyPair.publicKey),
          lifecycle: "active",
          lifecycleChangedAt: 900,
          notBefore: 800,
          notAfter: 2_000,
          revokedAt: null,
          revocationEpoch: null,
        },
      ],
      releases: [release],
      authorizations: [
        {
          schema: MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA,
          keyId: "signer-k1",
          releaseId: "release-r1",
          channel: "production",
          notBefore: 800,
          notAfter: 2_000,
        },
      ],
      keyTombstones: [],
      releaseTombstones: [],
      revokedKeyFingerprints: [],
    });
  const signature = sign(
    null,
    marketplaceTrustBundleSigningMessage(unsigned),
    rootKeyPair.privateKey,
  ).toString("hex");
  return serializeMarketplaceTrustBundle({ ...unsigned, signature });
}

function makeUnsignedAttestation(
  fixture: SuccessorFixture,
  trustStore: MarketplaceCategoryQuoteTrustStore,
  overrides: Partial<MarketplaceCategoryQuoteAttestationUnsigned> = {},
): MarketplaceCategoryQuoteAttestationUnsigned {
  const release = marketplaceTrustBundleUnsignedSchema.parse(
    JSON.parse(
      signedTrustBundlePayload(
        fixture.readProfile,
        fixture.actionProfile,
        fixture.request.serviceMode === "transactional"
          ? "protocol_instance_verified"
          : fixture.readProfile.adapterId === MARKETPLACE_YIELD_ADAPTER
            ? "interface_only_unendorsed"
            : "protocol_instance_verified",
      ),
    ),
  ).releases[0]!;
  const base = {
    schema: MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA,
    signatureProfile: MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE,
    issuer: MARKETPLACE_CATEGORY_QUOTE_ISSUER,
    audience: MARKETPLACE_CATEGORY_QUOTE_AUDIENCE,
    keyId: "signer-k1",
    releaseId: "release-r1",
    releaseDefinitionSha256: release.definitionSha256,
    publicKeyFingerprintSha256: fingerprint(signerKeyPair.publicKey),
    attestationId: "attestation-successor-1",
    scope: "evaluation_only" as const,
    activationAuthorization: "none" as const,
    reservation: "none" as const,
    replayPolicy: "reusable_until_expiry" as const,
    replayScope: "request_id" as const,
    issuedAt: 1_120,
    expiresAt: 1_300,
    mandateSha256: canonicalSha256(fixture.mandate),
    categoryQuoteRequestSha256: canonicalSha256(fixture.request),
    projectionSha256: canonicalSha256(fixture.projection),
    verifierPolicySha256: POLICY_SHA256,
    categoryDeploymentSha256: DEPLOYMENT_SHA256,
    quoteVerifyingContract: trustStore.quoteVerifyingContract,
    projection: fixture.projection,
  };
  const merged = { ...base, ...overrides };
  if (overrides.projection !== undefined) {
    merged.projectionSha256 = canonicalSha256(overrides.projection);
  }
  return marketplaceCategoryQuoteAttestationUnsignedSchema.parse(merged);
}

function signedAttestationWire(
  fixture: SuccessorFixture,
  trustStore: MarketplaceCategoryQuoteTrustStore,
  overrides: Partial<MarketplaceCategoryQuoteAttestationUnsigned> = {},
): string {
  const unsigned = makeUnsignedAttestation(fixture, trustStore, overrides);
  const signature = sign(
    null,
    marketplaceCategoryQuoteAttestationSigningMessage(unsigned),
    signerKeyPair.privateKey,
  ).toString("hex");
  return serializeMarketplaceCategoryQuoteAttestation({ ...unsigned, signature });
}

function signedTrustBundlePayload(
  readProfile: CategoryReadProfile,
  actionProfile: CategoryActionProfile | null,
  minimumTargetAssurance:
    | "interface_only_unendorsed"
    | "protocol_instance_verified" =
    readProfile.adapterId === MARKETPLACE_YIELD_ADAPTER
      ? "interface_only_unendorsed"
      : "protocol_instance_verified",
): string {
  return JSON.stringify(
    JSON.parse(
      signedTrustBundleWire(
        readProfile,
        actionProfile,
        minimumTargetAssurance,
      ),
    ),
    (_key, value) => (_key === "signature" ? undefined : value),
  );
}

function mutateLinkage(
  linkage: ReturnType<typeof makeFixture>["projection"]["linkage"],
  overrides: Partial<CategoryLinkageProjectionUnsigned>,
) {
  const { linkageSha256: _oldDigest, ...unsigned } = linkage;
  const mutated = { ...unsigned, ...overrides };
  return {
    ...mutated,
    linkageSha256: categoryLinkageProjectionSha256(mutated),
  };
}

type SuccessorFixture = Readonly<{
  mandate: MarketplaceMandateV2;
  request: MarketplaceCategoryQuoteRequest;
  identity: ReturnType<typeof makeFixture>["identity"];
  targets: readonly CategoryTargetObservation[];
  readProfile: CategoryReadProfile;
  projection: MarketplaceCategoryQuoteProjection;
  actionProfile: CategoryActionProfile | null;
}>;

function exportedSpki(publicKey: KeyObject): Buffer {
  const exported = publicKey.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(exported)) throw new Error("expected SPKI DER bytes");
  return exported;
}

function fingerprint(publicKey: KeyObject): string {
  return createHash("sha256").update(exportedSpki(publicKey)).digest("hex");
}

function hasCode(code: string) {
  return (error: unknown) =>
    error instanceof Error && "code" in error && error.code === code;
}
