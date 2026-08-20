/**
 * Internal successor trust-state boundary.
 *
 * Durable CAS state and issuance permits are service concerns. They remain
 * available to the private issuer, but are intentionally absent from the
 * public Marketplace Core package entry point. The factory-branded root
 * resolver is likewise an internal provenance check, not a public trust API.
 */
export {
  createMarketplaceCategoryTrustController,
  createMarketplaceCategoryTrustStateStore,
  resolveMarketplaceCategoryTrustCommitment,
  resolveMarketplaceCategoryTrustControllerRoot,
  type MarketplaceCategoryIssuancePermit,
  type MarketplaceCategoryTrustCommitment,
  type MarketplaceCategoryTrustController,
  type MarketplaceCategoryTrustRootIdentity,
  type MarketplaceCategoryTrustStateStore,
} from "../category-trust-controller.js";
