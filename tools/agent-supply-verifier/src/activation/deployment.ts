export const ACTIVATION_SCHEMA_VERSION = 1 as const;

export const BSC_ACTIVATION_DEPLOYMENT = Object.freeze({
  chainId: 56,
  registry: "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432",
  commerceProxy: "0xea4daa3100a767e86fded867729ae7446476eba6",
  commerceImplementation: "0xd5f9b570c96b5d67702d508c0bfb8b3b09209787",
  commerceProxyCodeHash:
    "0x1f1858db4825be798342d4c094630bf5ddc685bd802a083d8d88f15a6cdb2a89",
  commerceImplementationCodeHash:
    "0x795596ea32b0d4e651cdd8d10e52c18ad759406172f5780ef867d968d9389c39",
  routerProxy: "0x51895229e12f9876011789b04f8698af06ccd6da",
  routerImplementation: "0xf0cf8f47e5c035f16247ff16e9f367e477ee5007",
  routerProxyCodeHash:
    "0x1f1858db4825be798342d4c094630bf5ddc685bd802a083d8d88f15a6cdb2a89",
  routerImplementationCodeHash:
    "0x5f95706fdeae0bf3ac092ee86998dde7b9ce3fdcb2c8082d40f0c7847122df6a",
  policy: "0x9c01845705b3078aa2e8cff7520a6376fd766de5",
  policyCodeHash:
    "0x79a469cc624bdb3a85350a6bd220c8368ebdc8c5a8e9cf9a431422db68419b1c",
  paymentToken: "0xce24439f2d9c6a2289f741120fe202248b666666",
  paymentTokenCodeHash:
    "0xae12b1d61f7ed4febf649ccf319cb49a0e921cca3739dcb01b47d316049d46ff",
  eip1967ImplementationSlot:
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
  observedForkBlock: "116370940",
} as const);

export const ACTIVATION_CONFIRMATION_DEPTH = 2 as const;
export const ACTIVATION_ASSUMED_BLOCK_SECONDS = 3 as const;
export const ACTIVATION_STEP_BUDGET_SECONDS = 45 as const;
export const ACTIVATION_CLOCK_SKEW_SECONDS = 30 as const;
export const ACTIVATION_FUNDING_PREVIEW_BUFFER_SECONDS = 30 as const;

export const ACTIVATION_PHASE_ORDER = [
  "PREPARED_CREATE",
  "CREATE_CONFIRMED",
  "PREPARED_REGISTER",
  "REGISTER_CONFIRMED",
  "PREPARED_SET_BUDGET",
  "BUDGET_CONFIRMED",
  "PREPARED_FUND",
  "FUNDED_CONFIRMED",
] as const;

export type ActivationPhase = (typeof ACTIVATION_PHASE_ORDER)[number];

export function minimumQuoteRemainingSeconds(phase: ActivationPhase): number {
  const preparedIndex = Math.floor(ACTIVATION_PHASE_ORDER.indexOf(phase) / 2);
  const remainingWrites = Math.max(1, 4 - preparedIndex);
  return (
    remainingWrites * ACTIVATION_STEP_BUDGET_SECONDS +
    ACTIVATION_CLOCK_SKEW_SECONDS +
    (phase === "PREPARED_FUND"
      ? ACTIVATION_FUNDING_PREVIEW_BUFFER_SECONDS
      : 0)
  );
}
