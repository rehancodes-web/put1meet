// Session tokens are bearer credentials. Store only a SHA-256 digest in the
// database so a database read cannot immediately become account takeover.
export async function hashSessionToken(token: string): Promise<string> {
  const bytes = new TextEncoder().encode(token)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest)).map((value) => value.toString(16).padStart(2, '0')).join('')
}

export async function tokenCandidates(token: string): Promise<string[]> {
  if (!token) return []
  return [await hashSessionToken(token)]
}
