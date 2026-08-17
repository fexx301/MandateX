import assert from "node:assert/strict";
import test from "node:test";

import { marketplaceEvaluationRequestSchema } from "../src/schema.js";
import { fixtureRequest } from "./fixture.js";

test("evaluation requests bind one candidate and contain no activation acknowledgement", () => {
  const request = fixtureRequest();
  assert.deepEqual(marketplaceEvaluationRequestSchema.parse(request), request);
  assert.deepEqual(Object.keys(request).sort(), ["candidate", "mandate", "policy"]);

  const obsolete = {
    mandate: request.mandate,
    policy: request.policy,
    candidates: [request.candidate],
    acknowledgements: {
      actionableQuoteRequests: "I_ACKNOWLEDGE_ACTIONABLE_QUOTE_REQUESTS",
      operatorSuppliedSimulations:
        "I_ACKNOWLEDGE_OPERATOR_SUPPLIED_SIMULATIONS_ONLY",
    },
  };
  assert.equal(marketplaceEvaluationRequestSchema.safeParse(obsolete).success, false);
});

test("the service request fails closed on non-BSC mandates", () => {
  const request = fixtureRequest();
  const invalid = {
    ...request,
    mandate: { ...request.mandate, chain_id: 1 },
  };
  assert.equal(marketplaceEvaluationRequestSchema.safeParse(invalid).success, false);
});
