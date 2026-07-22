function hasAccessToken(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0 && value.every(hasAccessToken)
  if (!value || typeof value !== 'object') return false
  const record = value as Record<string, unknown>
  const tokens = record.tokens as Record<string, unknown> | undefined
  const token = record.accessToken ?? record.access_token ?? tokens?.accessToken ?? tokens?.access_token
  return typeof token === 'string' && token.trim().length > 0
}

export function isOpenAISessionJSONContent(content: string): boolean {
  try {
    return hasAccessToken(JSON.parse(content))
  } catch {
    const lines = content.split('\n').map((line) => line.trim()).filter(Boolean)
    if (lines.length === 0) return false
    try {
      return lines.every((line) => hasAccessToken(JSON.parse(line)))
    } catch {
      return false
    }
  }
}
