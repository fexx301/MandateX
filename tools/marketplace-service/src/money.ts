const USD_MICROS_SCALE = 6;
const MAX_SAFE_MICROS = BigInt(Number.MAX_SAFE_INTEGER);

export class UsdMicrosConversionError extends RangeError {
  constructor(message: string) {
    super(message);
    this.name = "UsdMicrosConversionError";
  }
}

export function usdNumberToMicros(value: number): string {
  if (!Number.isFinite(value) || value < 0) {
    throw new UsdMicrosConversionError(
      "USD values must be finite and non-negative",
    );
  }
  if (Object.is(value, -0) || value === 0) return "0";

  const match = /^(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/i.exec(
    value.toString(),
  );
  if (match === null) {
    throw new UsdMicrosConversionError("USD value is not a canonical number");
  }

  const integer = match[1]!;
  const fraction = match[2] ?? "";
  const exponent = Number(match[3] ?? "0");
  if (!Number.isSafeInteger(exponent)) {
    throw new UsdMicrosConversionError("USD exponent is outside the safe range");
  }

  const decimalPlaces = fraction.length - exponent;
  const zerosToAppend = USD_MICROS_SCALE - decimalPlaces;
  if (zerosToAppend < 0) {
    throw new UsdMicrosConversionError(
      "USD values may contain at most six decimal places",
    );
  }

  const digits = `${integer}${fraction}`.replace(/^0+(?=\d)/, "");
  const micros = BigInt(`${digits}${"0".repeat(zerosToAppend)}`);
  if (micros > MAX_SAFE_MICROS) {
    throw new UsdMicrosConversionError(
      "USD value cannot be converted to micros without unsafe numeric input",
    );
  }
  return micros.toString();
}
