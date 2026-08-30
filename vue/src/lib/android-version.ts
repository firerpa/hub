export function androidVersionFromSdk(sdk?: string | number) {
  const api = Number(sdk);
  if (!Number.isFinite(api) || api <= 0) return "-";

  const map: Record<number, string> = {
    16: "4.1",
    17: "4.2",
    18: "4.3",
    19: "4.4",
    20: "4.4W",
    21: "5.0",
    22: "5.1",
    23: "6.0",
    24: "7.0",
    25: "7.1",
    26: "8.0",
    27: "8.1",
    28: "9",
    29: "10",
    30: "11",
    31: "12",
    32: "12L",
    33: "13",
    34: "14",
    35: "15",
    36: "16",
  };

  const version = map[api];
  return version ? `Android ${version}` : `Android (API ${api})`;
}
