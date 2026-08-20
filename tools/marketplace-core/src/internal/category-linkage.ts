/**
 * Internal successor-orchestration boundary.
 *
 * Category linkage is intentionally not part of the public Core package
 * surface: its projection is untrusted until the successor trust path has
 * validated it. Consumers that own that path must import this explicit
 * internal entrypoint instead of relying on the package root.
 */
export {
  buildCategoryLinkageProjection,
  categoryLinkageProjectionSha256,
  validateCategoryLinkageProjection,
  MARKETPLACE_CATEGORY_LINKAGE_PROJECTION_SCHEMA,
  type CategoryLinkageObservation,
  type CategoryLinkageProviderAcceptance,
  type CategoryLinkageProviderAuthority,
  type CategoryLinkageProjectionUnsigned,
  type UntrustedCategoryLinkageProjection,
} from "../category-linkage.js";
