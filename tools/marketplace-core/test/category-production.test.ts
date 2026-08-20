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
  CATEGORY_THRESHOLD_UNITS,
  MARKETPLACE_ACTIVE_CANDIDATE_REPORT_SCHEMA,
  MARKETPLACE_CATEGORY_ACTION_PROFILE_SCHEMA,
  MARKETPLACE_CATEGORY_CANDIDATE_IDENTITY_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA,
  MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
  MARKETPLACE_CATEGORY_RELEASE_UNIT_SCHEMA,
  MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA,
  MARKETPLACE_MANDATE_V2_SCHEMA,
  activeCandidateReportSchema,
  assertMinimumCategoryValidity,
  categoryCandidateIdentityArtifactSchema,
  categoryReadProfileSchema,
  categoryReleaseUnitSchema,
  categoryScopeSchema,
  categoryTargetObservationSchema,
  computeCategoryValidUntil,
  hasMinimumCategoryValidity,
  marketplaceMandateV2Schema,
  remainingCategoryValiditySeconds,
  validateActionCoverage,
  validateActiveCandidateReport,
  validateAdapterReadProfile,
  validateCandidateAcceptanceBinding,
  validateCandidateIdentityForSelector,
  validateCategoryQuoteRequestBinding,
  validateCategoryReleaseUnits,
  validateExactReadCommitments,
  validateTargetObservationsForScope,
  categoryReadArgumentBindingSha256,
  categoryReadCalldataSha256,
  categoryStaticReadProfileForAdapterSha256,
  type CategoryActionPermission,
  type CategoryScope,
  type MarketplaceCategoryQuoteRequest,
  type MarketplaceMandateV2,
} from "../src/category-production.js";

const ADDRESS_A = `0x${"11".repeat(20)}`;
const ADDRESS_B = `0x${"22".repeat(20)}`;
const ADDRESS_C = `0x${"33".repeat(20)}`;
const ADDRESS_D = `0x${"44".repeat(20)}`;
const BLOCK_HASH = `0x${"ab".repeat(32)}`;
const HASH_A = "aa".repeat(32);
const HASH_B = "bb".repeat(32);
const HASH_C = "cc".repeat(32);
const HASH_D = "dd".repeat(32);

const scopes = [
  {
    adapterId: MARKETPLACE_GRID_ADAPTER,
    category: "grid",
    evidenceSchema: "mandatex.category.grid-evidence.v1",
    protocol: "pancakeswap-v3",
    subject: { poolAddress: ADDRESS_A },
    conditionPolicy: {
      unit: CATEGORY_THRESHOLD_UNITS.gridTick,
      lowerTick: -100,
      upperTick: 100,
    },
  },
  {
    adapterId: MARKETPLACE_YIELD_ADAPTER,
    category: "yield",
    evidenceSchema: "mandatex.category.yield-evidence.v1",
    protocol: "erc4626",
    subject: { vaultAddress: ADDRESS_A },
    conditionPolicy: {
      unit: CATEGORY_THRESHOLD_UNITS.yieldSharePrice,
      minSharePriceScaled: "1000000000000000000",
    },
  },
  {
    adapterId: MARKETPLACE_AAVE_HEALTH_ADAPTER,
    category: "health",
    evidenceSchema: "mandatex.category.health-evidence.v1",
    protocol: "aave-v3",
    subject: { poolAddress: ADDRESS_A, accountAddress: ADDRESS_B },
    conditionPolicy: {
      unit: CATEGORY_THRESHOLD_UNITS.aaveHealthFactor,
      minHealthFactorScaled: "1200000000000000000",
    },
  },
  {
    adapterId: MARKETPLACE_VENUS_HEALTH_ADAPTER,
    category: "health",
    evidenceSchema: "mandatex.category.venus-health-evidence.v1",
    protocol: "venus",
    subject: {
      comptrollerAddress: ADDRESS_A,
      accountAddress: ADDRESS_B,
      borrowMarketAddress: ADDRESS_C,
    },
    conditionPolicy: {
      unit: CATEGORY_THRESHOLD_UNITS.venusUsd,
      minLiquidityUsdScaled: "1000000000000000000000",
    },
  },
] as const satisfies readonly CategoryScope[];

const actionPermission = {
  actionId: "rebalance-grid",
  targetRole: "pool",
  target: ADDRESS_A,
  callId: "rebalance(int24,int24)",
  selector: "0x12345678",
  maxValueWei: "100",
} as const satisfies CategoryActionPermission;

test("mandate v2 has strict, explicit category scopes for all four adapters", () => {
  for (const scope of scopes) {
    assert.deepEqual(categoryScopeSchema.parse(scope), scope);
    const mandate = makeMandate(scope, "observe_only");
    assert.equal(marketplaceMandateV2Schema.parse(mandate).adapterId, scope.adapterId);
  }

  const aave = scopes[2];
  const missingAaveFloor = {
    ...aave,
    conditionPolicy: {},
  };
  assert.equal(categoryScopeSchema.safeParse(missingAaveFloor).success, false);
  assert.equal(
    categoryScopeSchema.safeParse({
      ...scopes[1],
      conditionPolicy: {
        unit: CATEGORY_THRESHOLD_UNITS.yieldSharePrice,
        minSharePriceScaled: "0",
      },
    }).success,
    false,
  );
  assert.equal(
    categoryScopeSchema.safeParse({
      ...scopes[2],
      conditionPolicy: {
        unit: CATEGORY_THRESHOLD_UNITS.aaveHealthFactor,
        minHealthFactorScaled: "0",
      },
    }).success,
    false,
  );
  assert.equal(
    categoryScopeSchema.safeParse({
      ...scopes[3],
      conditionPolicy: {
        unit: CATEGORY_THRESHOLD_UNITS.venusUsd,
        minLiquidityUsdScaled: "0",
      },
    }).success,
    false,
  );

  for (const scope of scopes) {
    assert.equal(
      categoryScopeSchema.safeParse({
        ...scope,
        conditionPolicy: { ...scope.conditionPolicy, unit: "wrong-unit" },
      }).success,
      false,
    );
  }
  assert.equal(
    categoryScopeSchema.safeParse({
      ...scopes[1],
      conditionPolicy: {
        ...scopes[1].conditionPolicy,
        minSharePriceScaled: (10n ** 18n - 1n).toString(),
      },
    }).success,
    false,
  );
  assert.equal(
    categoryScopeSchema.safeParse({
      ...scopes[1],
      conditionPolicy: {
        ...scopes[1].conditionPolicy,
        minSharePriceScaled: (10n ** 36n + 1n).toString(),
      },
    }).success,
    false,
  );
  assert.equal(
    categoryScopeSchema.safeParse({
      ...scopes[2],
      conditionPolicy: {
        ...scopes[2].conditionPolicy,
        minHealthFactorScaled: (10n ** 18n).toString(),
      },
    }).success,
    false,
  );
  assert.equal(
    categoryScopeSchema.safeParse({
      ...scopes[2],
      conditionPolicy: {
        ...scopes[2].conditionPolicy,
        minHealthFactorScaled: (10n ** 36n + 1n).toString(),
      },
    }).success,
    false,
  );
  assert.equal(
    categoryScopeSchema.safeParse({
      ...scopes[3],
      conditionPolicy: {
        ...scopes[3].conditionPolicy,
        minLiquidityUsdScaled: (10n ** 30n + 1n).toString(),
      },
    }).success,
    false,
  );

  const venus = scopes[3];
  const missingBorrowMarket = {
    ...venus,
    subject: {
      comptrollerAddress: ADDRESS_A,
      accountAddress: ADDRESS_B,
    },
  };
  assert.equal(categoryScopeSchema.safeParse(missingBorrowMarket).success, false);

  assert.equal(
    categoryScopeSchema.safeParse({ ...scopes[0], deploymentDefault: true }).success,
    false,
  );
});

test("service modes reject implicit or over-broad authority", () => {
  assert.equal(
    marketplaceMandateV2Schema.safeParse({
      ...makeMandate(scopes[0], "observe_only"),
      actionPermissions: [actionPermission],
    }).success,
    false,
  );
  assert.equal(
    marketplaceMandateV2Schema.safeParse({
      ...makeMandate(scopes[0], "observe_only"),
      maxSpendUsdMicros: "1",
    }).success,
    false,
  );
  assert.equal(
    marketplaceMandateV2Schema.safeParse({
      ...makeMandate(scopes[0], "transactional"),
      actionPermissions: [],
    }).success,
    false,
  );

  const transactional = makeMandate(scopes[0], "transactional");
  assert.equal(transactional.actionPermissions.length, 1);
  assert.equal(marketplaceMandateV2Schema.safeParse(transactional).success, true);
});

test("quote, candidate identity, and acceptance bind the exact subject and mandate", () => {
  const mandate = marketplaceMandateV2Schema.parse(makeMandate(scopes[0], "observe_only"));
  const request = makeRequest(mandate);
  const validated = validateCategoryQuoteRequestBinding({ request, mandate });
  assert.equal(validated.requestId, "request-1");
  assert.equal(Object.isFrozen(validated), true);

  assert.throws(
    () =>
      validateCategoryQuoteRequestBinding({
        request: { ...request, categoryScopeSha256: HASH_A },
        mandate,
      }),
    /scope hash/,
  );
  assert.throws(
    () =>
      validateCategoryQuoteRequestBinding({
        request: { ...request, protocol: "venus" },
        mandate,
      }),
    /protocol/,
  );
  const transactionalMandate = marketplaceMandateV2Schema.parse(
    makeMandate(scopes[0], "transactional"),
  );
  const transactionalRequest = makeRequest(transactionalMandate);
  const narrowedActions = [{ ...actionPermission, maxValueWei: "50" }];
  assert.equal(
    validateCategoryQuoteRequestBinding({
      request: {
        ...transactionalRequest,
        actionPermissions: narrowedActions,
        actionPermissionsSha256: canonicalSha256(narrowedActions),
        maxSpendUsdMicros: "500",
        permissionsExpiresAt: 1_200,
      },
      mandate: transactionalMandate,
    }).actionPermissions[0]?.maxValueWei,
    "50",
  );

  const identityWithoutDigest = {
    schema: MARKETPLACE_CATEGORY_CANDIDATE_IDENTITY_SCHEMA,
    chainId: 56,
    tokenId: "7",
    registryAddress: ADDRESS_A,
    ownerAddress: ADDRESS_B,
    observedBlock: 123,
    observedBlockHash: BLOCK_HASH,
    confirmationDepth: 2,
    registryCodeSha256: HASH_A,
    observedAt: 1_100,
  } as const;
  const identity = {
    ...identityWithoutDigest,
    identitySha256: canonicalSha256(identityWithoutDigest),
  };
  assert.equal(categoryCandidateIdentityArtifactSchema.safeParse(identity).success, true);
  assert.equal(
    validateCandidateIdentityForSelector({
      artifact: identity,
      candidate: request.candidate,
    }).ownerAddress,
    ADDRESS_B,
  );
  assert.throws(
    () =>
      validateCandidateIdentityForSelector({
        artifact: identity,
        candidate: { chainId: 56, tokenId: "8" },
      }),
    /different candidate/,
  );

  const acceptance = makeAcceptance(request, identity.identitySha256);
  assert.equal(
    validateCandidateAcceptanceBinding({
      acceptance,
      request,
      identityArtifact: identity,
    }).relation,
    "candidate_accepts_service_for_subject",
  );
  assert.throws(
    () =>
      validateCandidateAcceptanceBinding({
        acceptance: { ...acceptance, providerAddress: ADDRESS_D },
        request,
        identityArtifact: identity,
      }),
    /provider/,
  );
  assert.throws(
    () =>
      validateCandidateAcceptanceBinding({
        acceptance: { ...acceptance, candidateIdentitySha256: HASH_D },
        request,
        identityArtifact: identity,
      }),
    /identity binding/,
  );
  assert.throws(
    () =>
      validateCandidateAcceptanceBinding({
        acceptance: { ...acceptance, subjectSha256: HASH_D },
        request,
        identityArtifact: identity,
      }),
    /subject binding/,
  );
  assert.throws(
    () =>
      validateCandidateAcceptanceBinding({
        acceptance: { ...acceptance, conditionPolicySha256: HASH_D },
        request,
        identityArtifact: identity,
      }),
    /condition policy binding/,
  );
  const swappedRequest = {
    ...request,
    categoryScope: {
      ...request.categoryScope,
      subject: { poolAddress: ADDRESS_D },
    },
    categoryScopeSha256: canonicalSha256({
      ...request.categoryScope,
      subject: { poolAddress: ADDRESS_D },
    }),
  };
  assert.throws(
    () =>
      validateCandidateAcceptanceBinding({
        acceptance,
        request: swappedRequest,
        identityArtifact: identity,
      }),
    /different quote request|subject binding/,
  );
});

test("target assurance and exact adapter reads are strict and independently bound", () => {
  const target = makeTarget("pool", "protocol_instance_verified");
  assert.equal(categoryTargetObservationSchema.parse(target).provenance.status, "verified");
  assert.equal(
    validateTargetObservationsForScope({ scope: scopes[0], targets: [target] }).length,
    1,
  );
  assert.throws(
    () =>
      validateTargetObservationsForScope({
        scope: scopes[0],
        targets: [{ ...target, targetAddress: ADDRESS_D }],
      }),
    /mandate-selected/,
  );
  assert.equal(
    categoryTargetObservationSchema.safeParse({
      ...target,
      assurance: "interface_only_unendorsed",
    }).success,
    false,
  );
  assert.equal(
    categoryTargetObservationSchema.safeParse({
      ...target,
      proxy: { kind: "eip1967" },
    }).success,
    false,
  );
  const beaconTarget = {
    ...target,
    proxy: {
      kind: "beacon" as const,
      beaconAddress: ADDRESS_B,
      beaconCodeSha256: HASH_C,
      implementationAddress: ADDRESS_C,
      implementationCodeSha256: HASH_D,
    },
  };
  assert.equal(categoryTargetObservationSchema.safeParse(beaconTarget).success, true);
  assert.equal(
    categoryTargetObservationSchema.safeParse({
      ...beaconTarget,
      proxy: {
        kind: "beacon" as const,
        implementationAddress: ADDRESS_C,
        implementationCodeSha256: HASH_D,
      },
    }).success,
    false,
  );
  assert.equal(
    categoryTargetObservationSchema.safeParse({
      ...target,
      proxy: {
        kind: "eip1967" as const,
        implementationAddress: ADDRESS_C,
        implementationCodeSha256: HASH_D,
        beaconAddress: ADDRESS_B,
        beaconCodeSha256: HASH_C,
      },
    }).success,
    false,
  );

  const gridProfile = makeGridReadProfile();
  assert.equal(categoryReadProfileSchema.safeParse(gridProfile).success, true);
  for (const scope of scopes) {
    assert.equal(
      validateAdapterReadProfile({ profile: makeReadProfile(scope), scope }).adapterId,
      scope.adapterId,
    );
  }
  assert.equal(
    validateExactReadCommitments({
      expected: gridProfile.reads,
      actual: [...gridProfile.reads].reverse(),
    }),
    true,
  );
  assert.throws(
    () =>
      validateExactReadCommitments({
        expected: gridProfile.reads,
        actual: [{ ...gridProfile.reads[0], responseSha256: HASH_D }],
      }),
    /exactly match/,
  );
  assert.throws(
    () =>
      validateAdapterReadProfile({
        profile: {
          ...gridProfile,
          reads: [{ ...gridProfile.reads[0], selector: "0xdeadbeef" }],
        },
        scope: scopes[0],
    }),
    /scope-bound reads/,
  );
  assert.throws(
    () =>
      validateAdapterReadProfile({
        profile: {
          ...gridProfile,
          reads: [{ ...gridProfile.reads[0], calldataSha256: HASH_D }],
        },
        scope: scopes[0],
      }),
    /scope-bound reads/,
  );
  assert.throws(
    () =>
      validateAdapterReadProfile({
        profile: {
          ...gridProfile,
          reads: [{ ...gridProfile.reads[0], target: ADDRESS_D }],
        },
        scope: scopes[0],
      }),
    /scope-bound reads/,
  );

  const yieldTarget = makeTarget("vault", "protocol_instance_verified");
  assert.throws(
    () => validateTargetObservationsForScope({ scope: scopes[1], targets: [yieldTarget] }),
    /ERC-4626 targets are interface-only|not approved/,
  );
});

test("mode-aware action coverage is a mandate and adapter-profile subset", () => {
  assert.equal(
    validateActionCoverage({
      adapterId: MARKETPLACE_GRID_ADAPTER,
      serviceMode: "observe_only",
      mandatePermissions: [],
      quotedPermissions: [],
      mandateSpendCapUsdMicros: "0",
      quotedSpendCapUsdMicros: "0",
    }),
    true,
  );

  const profile = {
    schema: MARKETPLACE_CATEGORY_ACTION_PROFILE_SCHEMA,
    approval: "draft_unapproved",
    profileId: "grid-actions-v1",
    adapterId: MARKETPLACE_GRID_ADAPTER,
    serviceMode: "transactional",
    actions: [
      {
        actionId: actionPermission.actionId,
        targetRole: actionPermission.targetRole,
        callId: actionPermission.callId,
        selector: actionPermission.selector,
        maxValueWei: "100",
      },
    ],
  } as const;
  assert.equal(
    validateActionCoverage({
      adapterId: MARKETPLACE_GRID_ADAPTER,
      serviceMode: "transactional",
      mandatePermissions: [actionPermission],
      quotedPermissions: [{ ...actionPermission, maxValueWei: "50" }],
      mandateSpendCapUsdMicros: "1000",
      quotedSpendCapUsdMicros: "500",
      actionProfile: profile,
    }),
    true,
  );
  assert.throws(
    () =>
      validateActionCoverage({
        adapterId: MARKETPLACE_GRID_ADAPTER,
        serviceMode: "transactional",
        mandatePermissions: [actionPermission],
        quotedPermissions: [{ ...actionPermission, maxValueWei: "101" }],
        mandateSpendCapUsdMicros: "1000",
        quotedSpendCapUsdMicros: "500",
        actionProfile: profile,
      }),
    /exceeds the mandate/,
  );
  assert.throws(
    () =>
      validateActionCoverage({
        adapterId: MARKETPLACE_GRID_ADAPTER,
        serviceMode: "transactional",
        mandatePermissions: [actionPermission],
        quotedPermissions: [actionPermission],
        mandateSpendCapUsdMicros: "1000",
        quotedSpendCapUsdMicros: "1001",
        actionProfile: profile,
      }),
    /spend cap/,
  );
});

test("raw reports cannot self-assert VERIFIED_HIREABLE before the signed evaluator", () => {
  const observe = makeActiveReport("observe_only");
  assert.equal(activeCandidateReportSchema.safeParse(observe).success, false);
  assert.throws(() => validateActiveCandidateReport(observe), /remains dormant/);

  const dormantReport = { ...observe, status: "INCONCLUSIVE" as const };
  assert.equal(activeCandidateReportSchema.safeParse(dormantReport).success, true);

  const transactional = makeActiveReport("transactional");
  assert.equal(activeCandidateReportSchema.safeParse(transactional).success, false);

  const staleWithFutureValidity = {
    ...observe,
    status: "INCONCLUSIVE" as const,
    validUntil: 1_999,
    evaluatedAt: 1_350,
  };
  assert.equal(activeCandidateReportSchema.safeParse(staleWithFutureValidity).success, false);

  const observeWithPreview = {
    ...observe,
    status: "INCONCLUSIVE" as const,
    preview: transactional.preview,
  };
  assert.equal(activeCandidateReportSchema.safeParse(observeWithPreview).success, false);
  assert.equal(MARKETPLACE_ACTIVE_CANDIDATE_REPORT_SCHEMA.includes("active"), true);
});

test("validUntil and minimum remaining validity use exclusive boundaries", () => {
  const validUntil = computeCategoryValidUntil({
    attestationExpiresAt: 1_300,
    quoteExpiresAt: 1_250,
    mandateExpiresAt: 1_400,
    permissionExpiresAt: 1_260,
    identityExpiresAt: 1_220,
    evidenceObservedAt: 1_100,
    maxEvidenceAgeSeconds: 50,
  });
  assert.equal(validUntil, 1_151);
  assert.equal(remainingCategoryValiditySeconds(validUntil, 1_120), 31);
  assert.equal(hasMinimumCategoryValidity(validUntil, 1_120, 30), true);
  assert.equal(hasMinimumCategoryValidity(validUntil, 1_120, 32), false);
  assert.equal(assertMinimumCategoryValidity({
    validUntil,
    evaluatedAt: 1_120,
    minimumRemainingSeconds: 31,
  }), true);
  assert.throws(
    () =>
      assertMinimumCategoryValidity({
        validUntil,
        evaluatedAt: 1_120,
        minimumRemainingSeconds: 32,
      }),
    /minimum remaining validity/,
  );
});

test("release metadata is keyed by adapterId x serviceMode", () => {
  const units = scopes.flatMap((scope) => [
    makeReleaseUnit(scope, "observe_only"),
    makeReleaseUnit(scope, "transactional"),
  ]);
  assert.equal(validateCategoryReleaseUnits(units, { requireCompleteMatrix: true }).length, 8);
  assert.equal(categoryReleaseUnitSchema.safeParse(units[0]).success, true);
  assert.equal(
    units.filter((unit) => unit.category === "health").length,
    4,
  );
  assert.throws(
    () => validateCategoryReleaseUnits([...units.slice(0, 7), units[0]]),
    /unique by adapterId and serviceMode/,
  );
  assert.throws(
    () => validateCategoryReleaseUnits(units.slice(0, 7), { requireCompleteMatrix: true }),
    /missing/,
  );
  assert.equal(
    categoryReleaseUnitSchema.safeParse({
      ...units[0],
      readProfileId: "wrong-profile",
    }).success,
    false,
  );
  assert.equal(
    categoryReleaseUnitSchema.safeParse({
      ...units[0],
      readProfileSha256: HASH_D,
    }).success,
    false,
  );
  assert.equal(
    categoryReleaseUnitSchema.safeParse({
      ...units[1],
      enabled: true,
      minimumTargetAssurance: "interface_only_unendorsed",
    }).success,
    false,
  );
  assert.equal(
    categoryReleaseUnitSchema.safeParse({
      ...units[1],
      enabled: true,
      actionProfileId: null,
      actionProfileSha256: null,
    }).success,
    false,
  );
});

function makeMandate(
  scope: CategoryScope,
  serviceMode: "observe_only" | "transactional",
): MarketplaceMandateV2 {
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
    serviceMode,
    categoryScope: scope,
    actionPermissions: serviceMode === "observe_only" ? [] : [actionPermission],
    maxSpendUsdMicros: serviceMode === "observe_only" ? "0" : "1000",
    permissionsExpiresAt: 1_300,
  };
}

function makeRequest(mandate: MarketplaceMandateV2): MarketplaceCategoryQuoteRequest {
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
    permissionsExpiresAt: mandate.permissionsExpiresAt,
    nonce: "nonce-1",
    issuedAt: 1_100,
    expiresAt: 1_300,
  };
}

function makeAcceptance(request: MarketplaceCategoryQuoteRequest, identitySha256: string) {
  return {
    relation: "candidate_accepts_service_for_subject" as const,
    requestId: request.requestId,
    mandateId: request.mandateId,
    category: request.category,
    adapterId: request.adapterId,
    protocol: request.protocol,
    candidate: request.candidate,
    candidateIdentitySha256: identitySha256,
    providerAddress: ADDRESS_B,
    providerKind: "eoa" as const,
    signatureMethod: "eip191" as const,
    quoteRequestSha256: canonicalSha256(request),
    quoteResponseSha256: HASH_A,
    negotiationSha256: HASH_B,
    subjectSha256: canonicalSha256(request.categoryScope.subject),
    conditionPolicySha256: canonicalSha256(request.categoryScope.conditionPolicy),
    serviceMode: request.serviceMode,
    quoteExpiresAt: request.expiresAt,
  };
}

function makeTarget(
  role: string,
  assurance: "protocol_instance_verified" | "interface_only_unendorsed",
) {
  return {
    schema: MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA,
    adapterId:
      role === "vault" ? MARKETPLACE_YIELD_ADAPTER : MARKETPLACE_GRID_ADAPTER,
    role,
    targetAddress: ADDRESS_A,
    assurance,
    runtimeCodeSha256: HASH_A,
    proxy: { kind: "none" as const },
    provenance: {
      status: assurance === "protocol_instance_verified" ? "verified" as const : "unendorsed" as const,
      source:
        assurance === "protocol_instance_verified"
          ? role === "vault"
            ? "erc4626-interface-only"
            : "pancakeswap-v3-factory-membership-v1"
          : "interface-only-unendorsed-v1",
      proofSha256: HASH_B,
    },
    observedAt: 1_100,
    observedBlock: 123,
    observedBlockHash: BLOCK_HASH,
  };
}

function makeGridReadProfile() {
  return makeReadProfile(scopes[0]);
}

function makeReadProfile(scope: CategoryScope) {
  const responseSha256 = HASH_B;
  switch (scope.adapterId) {
    case MARKETPLACE_GRID_ADAPTER:
      return {
        schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
        profileId: "pancakeswap-v3-grid-observation-v1",
        adapterId: scope.adapterId,
        reads: [
          makeRead({
            role: "pool",
            callId: "slot0()",
            target: scope.subject.poolAddress,
            selector: "0x3850c7bd",
            responseSha256,
          }),
        ],
      } as const;
    case MARKETPLACE_YIELD_ADAPTER:
      return {
        schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
        profileId: "erc4626-yield-observation-v1",
        adapterId: scope.adapterId,
        reads: [
          makeRead({
            role: "vault",
            callId: "totalAssets()",
            target: scope.subject.vaultAddress,
            selector: "0x01e1d114",
            responseSha256,
          }),
          makeRead({
            role: "vault",
            callId: "totalSupply()",
            target: scope.subject.vaultAddress,
            selector: "0x18160ddd",
            responseSha256,
          }),
        ],
      } as const;
    case MARKETPLACE_AAVE_HEALTH_ADAPTER:
      return {
        schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
        profileId: "aave-v3-health-observation-v1",
        adapterId: scope.adapterId,
        reads: [
          makeRead({
            role: "pool",
            callId: "getUserAccountData(address)",
            target: scope.subject.poolAddress,
            selector: "0xbf92857c",
            accountAddress: scope.subject.accountAddress,
            responseSha256,
          }),
        ],
      } as const;
    case MARKETPLACE_VENUS_HEALTH_ADAPTER:
      return {
        schema: MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA,
        profileId: "venus-health-observation-v1",
        adapterId: scope.adapterId,
        reads: [
          makeRead({
            role: "borrowMarket",
            callId: "borrowBalanceStored(address)",
            target: scope.subject.borrowMarketAddress,
            selector: "0x95dd9193",
            accountAddress: scope.subject.accountAddress,
            responseSha256,
          }),
          makeRead({
            role: "comptroller",
            callId: "getAccountLiquidity(address)",
            target: scope.subject.comptrollerAddress,
            selector: "0x5ec88c79",
            accountAddress: scope.subject.accountAddress,
            responseSha256,
          }),
          makeRead({
            role: "comptroller",
            callId: "getAssetsIn(address)",
            target: scope.subject.comptrollerAddress,
            selector: "0xabfceffc",
            accountAddress: scope.subject.accountAddress,
            responseSha256,
          }),
        ],
      } as const;
  }
}

function makeRead(input: {
  role: string;
  callId: string;
  target: string;
  selector: string;
  accountAddress?: string;
  responseSha256: string;
}) {
  return {
    role: input.role,
    callId: input.callId,
    target: input.target,
    selector: input.selector,
    argumentBindingSha256: categoryReadArgumentBindingSha256(input.accountAddress),
    calldataSha256: categoryReadCalldataSha256(input.selector, input.accountAddress),
    responseSha256: input.responseSha256,
  };
}

function makeActiveReport(serviceMode: "observe_only" | "transactional") {
  const mandate = marketplaceMandateV2Schema.parse(makeMandate(scopes[0], serviceMode));
  const request = makeRequest(mandate);
  const identity = makeIdentity();
  const identityHash = identity.identitySha256;
  const target = makeTarget("pool", "protocol_instance_verified");
  return {
    schema: MARKETPLACE_ACTIVE_CANDIDATE_REPORT_SCHEMA,
    status: "VERIFIED_HIREABLE" as const,
    scope: "evaluation_only" as const,
    activationAuthorization: "none" as const,
    reservation: "none" as const,
    replayPolicy: "reusable_until_expiry" as const,
    verifierPolicySha256: HASH_C,
    categoryDeploymentSha256: HASH_D,
    requestId: request.requestId,
    mandateId: request.mandateId,
    category: request.category,
    adapterId: request.adapterId,
    protocol: request.protocol,
    categoryScope: request.categoryScope,
    categoryScopeSha256: request.categoryScopeSha256,
    candidate: request.candidate,
    mandate,
    quoteRequest: request,
    candidateIdentity: identity,
    candidateIdentitySha256: identityHash,
    acceptance: makeAcceptance(request, identityHash),
    serviceMode,
    targets: [target],
    observation: {
      status: "pass" as const,
      targetsSha256: canonicalSha256([target]),
      readProfile: makeGridReadProfile(),
      artifactSha256: HASH_A,
      evidenceSha256: HASH_B,
      observedAt: 1_100,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
    },
    actionCoverage: serviceMode === "observe_only" ? "not_applicable" as const : "complete" as const,
    preview:
      serviceMode === "observe_only"
        ? { status: "not_applicable" as const }
        : {
            status: "passed" as const,
            observedAt: 1_100,
            observedBlock: 123,
            observedBlockHash: BLOCK_HASH,
          },
    attestationExpiresAt: 1_300,
    maxIdentityAgeSeconds: 300,
    validUntil: 1_300,
    evaluatedAt: 1_120,
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

function makeReleaseUnit(
  scope: CategoryScope,
  serviceMode: "observe_only" | "transactional",
) {
  return {
    schema: MARKETPLACE_CATEGORY_RELEASE_UNIT_SCHEMA,
    adapterId: scope.adapterId,
    category: scope.category,
    serviceMode,
    enabled: false,
    verifierPolicySha256: HASH_A,
    categoryDeploymentSha256: HASH_B,
    quoteSchema: MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA,
    readProfileId:
      scope.adapterId === MARKETPLACE_GRID_ADAPTER
        ? "pancakeswap-v3-grid-observation-v1"
        : scope.adapterId === MARKETPLACE_YIELD_ADAPTER
          ? "erc4626-yield-observation-v1"
          : scope.adapterId === MARKETPLACE_AAVE_HEALTH_ADAPTER
            ? "aave-v3-health-observation-v1"
            : "venus-health-observation-v1",
    readProfileSha256: categoryStaticReadProfileForAdapterSha256(
      scope.adapterId,
    ),
    actionProfileId: serviceMode === "observe_only" ? null : `${scope.adapterId}-actions`,
    actionProfileSha256: serviceMode === "observe_only" ? null : HASH_C,
    minimumTargetAssurance:
      scope.adapterId === MARKETPLACE_YIELD_ADAPTER
        ? "interface_only_unendorsed"
        : "protocol_instance_verified",
  } as const;
}
