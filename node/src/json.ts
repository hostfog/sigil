export type JSONObject = Record<string, unknown>;

export function isObject(value: unknown): value is JSONObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
