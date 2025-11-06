/**
 * Trims a string value and returns undefined if empty
 */
export const trimOrUndefined = (value?: string): string | undefined => {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

/**
 * Normalizes resource URI by removing trailing slashes (except for root)
 */
export const normalizeResourceValue = (value: string): string => {
  return value.endsWith("/") && value.length > 1
    ? value.replace(/\/+$/, "")
    : value;
};

