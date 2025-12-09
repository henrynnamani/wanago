export function recursivelyStripNullValues(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value
      .map(recursivelyStripNullValues)
      .filter((v) => v !== null && v !== undefined);
  }

  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .map(([key, val]) => [key, recursivelyStripNullValues(val)])
        .filter(([, val]) => val !== null && val !== undefined),
    );
  }

  return value === null ? undefined : value;
}
