import assert from "node:assert/strict";
import test from "node:test";

import { canonicalSha256 } from "../src/canonical.js";
import {
  MARKETPLACE_AAVE_HEALTH_ADAPTER,
  MARKETPLACE_GRID_ADAPTER,
  MARKETPLACE_VENUS_HEALTH_ADAPTER,
  MARKETPLACE_YIELD_ADAPTER,
} from "../src/category-policy.js";
import {
  MARKETPLACE_CATEGORY_LINKAGE_PROJECTION_SCHEMA,
  MAX_CATEGORY_IDENTITY_AGE_SECONDS,
  categoryLinkageProjectionSchema,
  categoryLinkageProjectionSha256,
  categoryLinkageProjectionUnsignedSchema,
  validateCategoryLinkageProjection,
} from "../src/category-linkage.js";
import {
  CATEGORY_THRESHOLD_UNITS,
  MARKETPLACE_CATEGORY_CANDIDATE_IDENTITY_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA,
  MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
  MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA,
  MARKETPLACE_MANDATE_V2_SCHEMA,
  categoryReadArgumentBindingSha256,
  categoryReadCalldataSha256,
  categoryReadCommitmentsSha256,
  categoryStaticReadProfileSha256,
  marketplaceCategoryQuoteRequestSchema,
  marketplaceMandateV2Schema,
  type CategoryScope,
  type MarketplaceCategoryQuoteRequest,
  type MarketplaceMandateV2,
} from "../src/category-production.js";
import * as publicApi from "../src/index.js";

const ADDRESS_A = `0x${"11".repeat(20)}`;
const ADDRESS_B = `0x${"22".repeat(20)}`;
const ADDRESS_C = `0x${"33".repeat(20)}`;
const ADDRESS_D = `0x${"44".repeat(20)}`;
const BLOCK_HASH = `0x${"ab".repeat(32)}`;
const HASH_A = "aa".repeat(32);
const HASH_B = "bb".repeat(32);
const HASH_C = "cc".repeat(32);
const HASH_D = "dd".repeat(32);
const PROVIDER_CODE_SHA256 = "ee".repeat(32);
const KECCAK_A = `0x${"01".repeat(32)}`;
const KECCAK_B = `0x${"02".repeat(32)}`;
const KECCAK_C = `0x${"03".repeat(32)}`;

const scopes = [
  {
    adapterId: MARKETPLACE_GRID_ADAPTER,
    category: "grid",
    evidenceSchema: "mandatex.category.grid-evidence.v1",
    protocol: "pancakeswap-v3",
    subject: { poolAddress: ADDRESS_A },
    conditionPolicy: { unit: CATEGORY_THRESHOLD_UNITS.gridTick, lowerTick: -100, upperTick: 100 },
  },
  {
    adapterId: MARKETPLACE_YIELD_ADAPTER,
    category: "yield",
    evidenceSchema: "mandatex.category.yield-evidence.v1",
    protocol: "erc4626",
    subject: { vaultAddress: ADDRESS_A },
    conditionPolicy: { unit: CATEGORY_THRESHOLD_UNITS.yieldSharePrice, minSharePriceScaled: "1000000000000000000" },
  },
  {
    adapterId: MARKETPLACE_AAVE_HEALTH_ADAPTER,
    category: "health",
    evidenceSchema: "mandatex.category.health-evidence.v1",
    protocol: "aave-v3",
    subject: { poolAddress: ADDRESS_A, accountAddress: ADDRESS_C },
    conditionPolicy: { unit: CATEGORY_THRESHOLD_UNITS.aaveHealthFactor, minHealthFactorScaled: "1200000000000000000" },
  },
  {
    adapterId: MARKETPLACE_VENUS_HEALTH_ADAPTER,
    category: "health",
    evidenceSchema: "mandatex.category.venus-health-evidence.v1",
    protocol: "venus",
    subject: {
      comptrollerAddress: ADDRESS_A,
      accountAddress: ADDRESS_C,
      borrowMarketAddress: ADDRESS_D,
    },
    conditionPolicy: { unit: CATEGORY_THRESHOLD_UNITS.venusUsd, minLiquidityUsdScaled: "1000000000000000000000" },
  },
] as const satisfies readonly CategoryScope[];

test("private linkage composes all four exact adapter scopes and remains untrusted", () => {
  for (const scope of scopes) {
    const fixture = makeFixture(scope);
    const validated = validateFixture(fixture);
    assert.equal(validated.schema, MARKETPLACE_CATEGORY_LINKAGE_PROJECTION_SCHEMA);
    assert.equal(validated.trustStatus, "untrusted_until_successor_attestation_verified");
    assert.equal(validated.providerAuthority.kind, "erc8004_registered_owner");
    assert.equal(validated.providerAuthority.providerAddress, ADDRESS_B);
    assert.equal(validated.candidateIdentity.registeredOwner, ADDRESS_B);
    assert.equal(Object.isFrozen(validated), true);
    assert.equal(Object.isFrozen(validated.providerAcceptance), true);
  }

  assert.equal("categoryLinkageProjectionSchema" in publicApi, false);
  assert.equal("validateCategoryLinkageProjection" in publicApi, false);
});

test("health account identity remains distinct from registered-owner provider authority", () => {
  const fixture = makeFixture(scopes[2]);
  const validated = validateFixture(fixture);
  assert.equal(validated.categoryScope.adapterId, MARKETPLACE_AAVE_HEALTH_ADAPTER);
  if (validated.categoryScope.adapterId !== MARKETPLACE_AAVE_HEALTH_ADAPTER) {
    assert.fail("expected the Aave health linkage variant");
  }
  assert.equal(validated.candidateIdentity.registeredOwner, ADDRESS_B);
  assert.equal(validated.categoryScope.subject.accountAddress, ADDRESS_C);
  assert.notEqual(
    validated.candidateIdentity.registeredOwner,
    validated.categoryScope.subject.accountAddress,
  );
});

test("registered owner, provider, and validated signer cannot diverge", () => {
  const fixture = makeFixture(scopes[0]);
  const acceptance = {
    ...fixture.projection.providerAcceptance,
    validatedSigner: ADDRESS_C,
    validatedProvider: ADDRESS_C,
  };
  const authority = {
    ...fixture.projection.providerAuthority,
    providerAddress: ADDRESS_C,
    validatedSigner: ADDRESS_C,
  };
  assert.throws(
    () =>
      rehash({
        ...fixture.projection,
        providerAcceptance: acceptance,
        providerAuthority: authority,
      }),
    /registered owner, provider, and validated signer/,
  );

  assert.equal(
    categoryLinkageProjectionSchema.safeParse({
      ...fixture.projection,
      providerAuthority: {
        kind: "verifier_observed_delegation",
        providerAddress: ADDRESS_B,
        validatedSigner: ADDRESS_B,
        candidateIdentitySha256: fixture.identity.identitySha256,
      },
    }).success,
    false,
  );
});

test("quote commitments are algorithm-qualified Keccak-256 values", () => {
  const fixture = makeFixture(scopes[0]);
  assert.equal(fixture.projection.providerAcceptance.quoteRequestKeccak256, KECCAK_A);
  assert.equal(fixture.projection.providerAcceptance.quoteResponseKeccak256, KECCAK_B);
  assert.equal(fixture.projection.providerAcceptance.negotiationKeccak256, KECCAK_C);

  for (const field of [
    "quoteRequestKeccak256",
    "quoteResponseKeccak256",
    "negotiationKeccak256",
  ] as const) {
    assert.equal(
      categoryLinkageProjectionSchema.safeParse({
        ...fixture.projection,
        providerAcceptance: {
          ...fixture.projection.providerAcceptance,
          [field]: HASH_A,
        },
      }).success,
      false,
    );
  }
});

test("provider acceptance is reusable and validation has no input side effects", () => {
  const fixture = makeFixture(scopes[0]);
  const acceptanceBefore = structuredClone(
    fixture.projection.providerAcceptance,
  );

  const first = validateFixture(fixture);
  const second = validateFixture(fixture);

  assert.deepEqual(fixture.projection.providerAcceptance, acceptanceBefore);
  assert.equal(Object.isFrozen(fixture.projection.providerAcceptance), false);
  assert.deepEqual(second.providerAcceptance, first.providerAcceptance);
  assert.equal(Object.isFrozen(first.providerAcceptance), true);
  assert.equal(Object.isFrozen(second.providerAcceptance), true);
});

test("provider authority and acceptance bind one observed runtime code hash", () => {
  const fixture = makeFixture(scopes[0]);
  const mismatched = {
    ...fixture.projection.providerAcceptance,
    providerCodeSha256: HASH_A,
  };
  assert.equal(
    categoryLinkageProjectionSchema.safeParse({
      ...fixture.projection,
      providerAcceptance: mismatched,
    }).success,
    false,
  );
  assert.throws(
    () =>
      validateFixture({
        ...fixture,
        projection: rehash({
          ...fixture.projection,
          providerAcceptance: mismatched,
        }),
      }),
    /runtime code/,
  );
});

test("fabricated candidate, subject, and release bindings fail closed", () => {
  const fixture = makeFixture(scopes[0]);
  const { identitySha256: _identitySha256, ...identityBody } = fixture.identity;
  const forgedIdentityBody = {
    ...identityBody,
    ownerAddress: ADDRESS_C,
  };
  const forgedIdentity = {
    ...forgedIdentityBody,
    identitySha256: canonicalSha256(forgedIdentityBody),
  };
  assert.throws(
    () => validateFixture({ ...fixture, identity: forgedIdentity }),
    /candidate identity|registered owner|provider authority/,
  );

  const otherMandate = makeMandate({
    ...scopes[0],
    subject: { poolAddress: ADDRESS_D },
  });
  const otherRequest = makeRequest(otherMandate);
  assert.throws(
    () =>
      validateFixture({
        ...fixture,
        mandate: otherMandate,
        request: otherRequest,
      }),
    /quote request binding|category scope|subject|mandate-selected contract targets/,
  );

  assert.throws(
    () =>
      validateFixture({
        ...fixture,
        expectedRelease: {
          ...fixture.expectedRelease,
          verifierPolicySha256: HASH_A,
        },
      }),
    /trusted release commitments/,
  );
});

test("quote domain, nonce, signature method, and expiry are mandatory", () => {
  const fixture = makeFixture(scopes[0]);
  assert.throws(
    () =>
      validateFixture({
        ...fixture,
        expectedQuoteDomain: { chainId: 56, verifyingContract: ADDRESS_A },
      }),
    /quote trust domain/,
  );

  assert.throws(
    () =>
      validateFixture({
        ...fixture,
        projection: rehash({
          ...fixture.projection,
          providerAcceptance: {
            ...fixture.projection.providerAcceptance,
            quoteNonce: "other-nonce",
          },
        }),
      }),
    /quote nonce/,
  );

  assert.equal(
    categoryLinkageProjectionSchema.safeParse({
      ...fixture.projection,
      providerAcceptance: {
        ...fixture.projection.providerAcceptance,
        signatureMethod: "erc1271",
      },
    }).success,
    false,
  );
  assert.throws(
    () => validateFixture({ ...fixture, evaluatedAt: 1_260 }),
    /expired/,
  );
});

test("target, exact-read, and shared-block mutations fail closed", () => {
  const fixture = makeFixture(scopes[0]);
  assert.throws(
    () =>
      validateFixture({
        ...fixture,
        targetObservations: [
          { ...fixture.targetObservations[0]!, targetAddress: ADDRESS_D },
        ],
      }),
    /mandate-selected contract targets/,
  );
  assert.throws(
    () =>
      validateFixture({
        ...fixture,
        readProfile: {
          ...fixture.readProfile,
          reads: [
            { ...fixture.readProfile.reads[0]!, selector: "0xdeadbeef" },
          ],
        },
      }),
    /exact scope-bound reads/,
  );
  assert.throws(
    () =>
      validateFixture({
        ...fixture,
        targetObservations: [
          { ...fixture.targetObservations[0]!, observedBlock: 124 },
        ],
      }),
    /same canonical block anchor|target digest/,
  );
});

test("linkage hash excludes itself and source binding survives rehash attempts", () => {
  const fixture = makeFixture(scopes[0]);
  const { linkageSha256, ...unsigned } = fixture.projection;
  assert.equal(linkageSha256, categoryLinkageProjectionSha256(unsigned));
  assert.equal(
    categoryLinkageProjectionSchema.safeParse({
      ...fixture.projection,
      linkageSha256: HASH_D,
    }).success,
    false,
  );

  const scopeSwap = {
    ...fixture.projection,
    observation: {
      ...fixture.projection.observation,
      readProfileSha256: HASH_D,
    },
  };
  assert.throws(
    () => validateFixture({ ...fixture, projection: rehash(scopeSwap) }),
    /read-profile commitment/,
  );
});

test("validity is evaluator-owned and re-enters the current clock", () => {
  const fixture = makeFixture(scopes[0]);
  assert.equal(MAX_CATEGORY_IDENTITY_AGE_SECONDS, 300);
  assert.doesNotThrow(() => validateFixture(fixture));
  assert.throws(
    () => validateFixture({ ...fixture, evaluatedAt: 1_260 }),
    /expired/,
  );
  assert.equal(
    categoryLinkageProjectionSchema.safeParse({
      ...fixture.projection,
      maxIdentityAgeSeconds: 3_600,
    }).success,
    false,
  );
  assert.equal(
    categoryLinkageProjectionSchema.safeParse({
      ...fixture.projection,
      validUntil: 1_400,
    }).success,
    false,
  );
});

function makeFixture(scope: CategoryScope) {
  const mandate = marketplaceMandateV2Schema.parse(makeMandate(scope));
  const request = marketplaceCategoryQuoteRequestSchema.parse(makeRequest(mandate));
  const identity = makeIdentity();
  const targetObservations = makeTargets(scope);
  const readProfile = makeReadProfile(scope);
  const expectedQuoteDomain = { chainId: 56 as const, verifyingContract: ADDRESS_D };
  const expectedRelease = {
    categoryDeploymentSha256: HASH_C,
    verifierPolicySha256: HASH_D,
  };
  const unsigned = categoryLinkageProjectionUnsignedSchema.parse({
    schema: MARKETPLACE_CATEGORY_LINKAGE_PROJECTION_SCHEMA,
    trustStatus: "untrusted_until_successor_attestation_verified",
    relation: "candidate_accepts_service_for_subject",
    scope: "evaluation_only",
    activationAuthorization: "none",
    reservation: "none",
    subjectSelection: "mandate_declared_exact",
    anchorBinding: "same_canonical_block",
    requestId: request.requestId,
    mandateId: request.mandateId,
    mandateSha256: canonicalSha256(mandate),
    categoryQuoteRequestSha256: canonicalSha256(request),
    category: request.category,
    adapterId: request.adapterId,
    protocol: request.protocol,
    candidate: request.candidate,
    candidateIdentity: {
      proofProfile: "erc8004-owner-of-v1",
      chainId: identity.chainId,
      tokenId: identity.tokenId,
      registryAddress: identity.registryAddress,
      registeredOwner: identity.ownerAddress,
      confirmationDepth: identity.confirmationDepth,
      registryCodeSha256: identity.registryCodeSha256,
      identitySha256: identity.identitySha256,
      observedAt: identity.observedAt,
      observedBlock: identity.observedBlock,
      observedBlockHash: identity.observedBlockHash,
    },
    providerAuthority: {
      kind: "erc8004_registered_owner",
      providerAddress: identity.ownerAddress,
      validatedSigner: identity.ownerAddress,
      providerCodeSha256: PROVIDER_CODE_SHA256,
      candidateIdentitySha256: identity.identitySha256,
    },
    providerAcceptance: {
      relation: "candidate_accepts_service_for_subject",
      verificationProfile: "mandatex-category-quote-verification-v1",
      providerKind: "eoa",
      signatureMethod: "eip191",
      validatedSigner: identity.ownerAddress,
      validatedProvider: identity.ownerAddress,
      providerCodeSha256: PROVIDER_CODE_SHA256,
      chainId: 56,
      verifyingContract: expectedQuoteDomain.verifyingContract,
      candidateIdentitySha256: identity.identitySha256,
      mandateSha256: canonicalSha256(mandate),
      categoryQuoteRequestSha256: canonicalSha256(request),
      subjectSha256: canonicalSha256(request.categoryScope.subject),
      conditionPolicySha256: canonicalSha256(
        request.categoryScope.conditionPolicy,
      ),
      actionPermissionsSha256: request.actionPermissionsSha256,
      quoteNonce: request.nonce,
      quoteRequestKeccak256: KECCAK_A,
      quoteResponseKeccak256: KECCAK_B,
      negotiationKeccak256: KECCAK_C,
      quoteEndpointSha256: HASH_A,
      negotiatedAt: 1_110,
      quoteExpiresAt: 1_260,
    },
    categoryScope: request.categoryScope,
    categoryScopeSha256: request.categoryScopeSha256,
    subjectSha256: canonicalSha256(request.categoryScope.subject),
    conditionPolicySha256: canonicalSha256(
      request.categoryScope.conditionPolicy,
    ),
    serviceMode: request.serviceMode,
    actionPermissionsSha256: request.actionPermissionsSha256,
    observation: {
      status: "pass",
      categoryDeploymentSha256: expectedRelease.categoryDeploymentSha256,
      verifierPolicySha256: expectedRelease.verifierPolicySha256,
      targetsSha256: canonicalSha256(targetObservations),
      readProfileId: readProfile.profileId,
      readProfileSha256: categoryStaticReadProfileSha256(readProfile),
      readCommitmentsSha256: categoryReadCommitmentsSha256(readProfile),
      artifactSha256: HASH_A,
      evidenceSha256: HASH_B,
      observedAt: 1_100,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
    },
  });
  const projection = {
    ...unsigned,
    linkageSha256: categoryLinkageProjectionSha256(unsigned),
  };
  return {
    projection,
    mandate,
    request,
    identity,
    targetObservations,
    readProfile,
    expectedQuoteDomain,
    expectedRelease,
    evaluatedAt: 1_120,
  };
}

function validateFixture(fixture: {
  projection: unknown;
  mandate: unknown;
  request: unknown;
  identity: unknown;
  targetObservations: unknown;
  readProfile: unknown;
  expectedQuoteDomain: unknown;
  expectedRelease: unknown;
  evaluatedAt: number;
}) {
  return validateCategoryLinkageProjection({
    projection: fixture.projection,
    mandate: fixture.mandate,
    request: fixture.request,
    identityArtifact: fixture.identity,
    targetObservations: fixture.targetObservations,
    readProfile: fixture.readProfile,
    expectedQuoteDomain: fixture.expectedQuoteDomain,
    expectedRelease: fixture.expectedRelease,
    evaluatedAt: fixture.evaluatedAt,
  });
}

function rehash(input: Record<string, unknown>) {
  const { linkageSha256: _discard, ...unsignedInput } = input;
  const unsigned = categoryLinkageProjectionUnsignedSchema.parse(unsignedInput);
  return {
    ...unsigned,
    linkageSha256: categoryLinkageProjectionSha256(unsigned),
  };
}

function makeMandate(scope: CategoryScope): MarketplaceMandateV2 {
  return {
    schema: MARKETPLACE_MANDATE_V2_SCHEMA,
    mandateId: "mandate-1",
    category: scope.category,
    adapterId: scope.adapterId,
    chainId: 56,
    createdAt: 1_000,
    expiresAt: 1_400,
    maxClockSkewSeconds: 30,
    maxEvidenceAgeSeconds: 300,
    serviceMode: "observe_only",
    categoryScope: scope,
    actionPermissions: [],
    maxSpendUsdMicros: "0",
    permissionsExpiresAt: 1_350,
  };
}

function makeRequest(
  mandate: MarketplaceMandateV2,
): MarketplaceCategoryQuoteRequest {
  return {
    schema: MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA,
    requestId: "request-1",
    mandateId: mandate.mandateId,
    mandateSha256: canonicalSha256(mandate),
    category: mandate.category,
    adapterId: mandate.adapterId,
    protocol: mandate.categoryScope.protocol,
    categoryScope: mandate.categoryScope,
    categoryScopeSha256: canonicalSha256(mandate.categoryScope),
    candidate: { chainId: 56, tokenId: "7" },
    serviceMode: mandate.serviceMode,
    actionPermissions: mandate.actionPermissions,
    actionPermissionsSha256: canonicalSha256(mandate.actionPermissions),
    maxSpendUsdMicros: mandate.maxSpendUsdMicros,
    permissionsExpiresAt: 1_290,
    nonce: "nonce-1",
    issuedAt: 1_100,
    expiresAt: 1_300,
  };
}

function makeIdentity() {
  const withoutDigest = {
    schema: MARKETPLACE_CATEGORY_CANDIDATE_IDENTITY_SCHEMA,
    chainId: 56 as const,
    tokenId: "7",
    registryAddress: ADDRESS_A,
    ownerAddress: ADDRESS_B,
    observedBlock: 123,
    observedBlockHash: BLOCK_HASH,
    confirmationDepth: 2,
    registryCodeSha256: HASH_A,
    observedAt: 1_100,
  };
  return {
    ...withoutDigest,
    identitySha256: canonicalSha256(withoutDigest),
  };
}

function makeTargets(scope: CategoryScope) {
  const target = (
    role: string,
    targetAddress: string,
    assurance: "protocol_instance_verified" | "interface_only_unendorsed",
    source: string,
  ) => ({
    schema: MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA,
    adapterId: scope.adapterId,
    role,
    targetAddress,
    assurance,
    runtimeCodeSha256: HASH_A,
    proxy: { kind: "none" as const },
    provenance: {
      status: assurance === "protocol_instance_verified" ? "verified" as const : "unendorsed" as const,
      source,
      proofSha256: HASH_B,
    },
    observedAt: 1_100,
    observedBlock: 123,
    observedBlockHash: BLOCK_HASH,
  });
  switch (scope.adapterId) {
    case MARKETPLACE_GRID_ADAPTER:
      return [
        target(
          "pool",
          scope.subject.poolAddress,
          "protocol_instance_verified",
          "pancakeswap-v3-factory-membership-v1",
        ),
      ];
    case MARKETPLACE_YIELD_ADAPTER:
      return [
        target(
          "vault",
          scope.subject.vaultAddress,
          "interface_only_unendorsed",
          "interface-only-unendorsed-v1",
        ),
      ];
    case MARKETPLACE_AAVE_HEALTH_ADAPTER:
      return [
        target(
          "pool",
          scope.subject.poolAddress,
          "protocol_instance_verified",
          "aave-v3-addresses-provider-v1",
        ),
      ];
    case MARKETPLACE_VENUS_HEALTH_ADAPTER:
      return [
        target(
          "borrowMarket",
          scope.subject.borrowMarketAddress,
          "protocol_instance_verified",
          "venus-market-membership-v1",
        ),
        target(
          "comptroller",
          scope.subject.comptrollerAddress,
          "protocol_instance_verified",
          "venus-market-membership-v1",
        ),
      ];
  }
}

function makeReadProfile(scope: CategoryScope) {
  const read = (input: {
    role: string;
    callId: string;
    target: string;
    selector: string;
    accountAddress?: string;
  }) => ({
    role: input.role,
    callId: input.callId,
    target: input.target,
    selector: input.selector,
    argumentBindingSha256: categoryReadArgumentBindingSha256(
      input.accountAddress,
    ),
    calldataSha256: categoryReadCalldataSha256(
      input.selector,
      input.accountAddress,
    ),
    responseSha256: HASH_C,
  });
  switch (scope.adapterId) {
    case MARKETPLACE_GRID_ADAPTER:
      return {
        schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
        profileId: "pancakeswap-v3-grid-observation-v1",
        adapterId: scope.adapterId,
        reads: [
          read({
            role: "pool",
            callId: "slot0()",
            target: scope.subject.poolAddress,
            selector: "0x3850c7bd",
          }),
        ],
      };
    case MARKETPLACE_YIELD_ADAPTER:
      return {
        schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
        profileId: "erc4626-yield-observation-v1",
        adapterId: scope.adapterId,
        reads: [
          read({
            role: "vault",
            callId: "totalAssets()",
            target: scope.subject.vaultAddress,
            selector: "0x01e1d114",
          }),
          read({
            role: "vault",
            callId: "totalSupply()",
            target: scope.subject.vaultAddress,
            selector: "0x18160ddd",
          }),
        ],
      };
    case MARKETPLACE_AAVE_HEALTH_ADAPTER:
      return {
        schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
        profileId: "aave-v3-health-observation-v1",
        adapterId: scope.adapterId,
        reads: [
          read({
            role: "pool",
            callId: "getUserAccountData(address)",
            target: scope.subject.poolAddress,
            selector: "0xbf92857c",
            accountAddress: scope.subject.accountAddress,
          }),
        ],
      };
    case MARKETPLACE_VENUS_HEALTH_ADAPTER:
      return {
        schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
        profileId: "venus-health-observation-v1",
        adapterId: scope.adapterId,
        reads: [
          read({
            role: "borrowMarket",
            callId: "borrowBalanceStored(address)",
            target: scope.subject.borrowMarketAddress,
            selector: "0x95dd9193",
            accountAddress: scope.subject.accountAddress,
          }),
          read({
            role: "comptroller",
            callId: "getAccountLiquidity(address)",
            target: scope.subject.comptrollerAddress,
            selector: "0x5ec88c79",
            accountAddress: scope.subject.accountAddress,
          }),
          read({
            role: "comptroller",
            callId: "getAssetsIn(address)",
            target: scope.subject.comptrollerAddress,
            selector: "0xabfceffc",
            accountAddress: scope.subject.accountAddress,
          }),
        ],
      };
  }
}
