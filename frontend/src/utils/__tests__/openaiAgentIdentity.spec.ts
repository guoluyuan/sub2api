import { describe, expect, it } from 'vitest'
import { isOpenAISessionJSONContent } from '../openaiAgentIdentity'

describe('isOpenAISessionJSONContent', () => {
  it.each([
    ['camel case', { accessToken: 'header.payload.signature' }],
    ['snake case', { access_token: 'header.payload.signature' }],
    ['nested tokens', { tokens: { accessToken: 'header.payload.signature' } }]
  ])('accepts %s Session JSON', (_name, session) => {
    expect(isOpenAISessionJSONContent(JSON.stringify(session))).toBe(true)
  })

  it('accepts a batch of Session JSON objects', () => {
    const content = '{"accessToken":"one"}\n{"access_token":"two"}'
    expect(isOpenAISessionJSONContent(content)).toBe(true)
  })

  it.each([
    ['raw token', 'header.payload.signature'],
    ['missing token', '{"user":{"email":"test@example.com"}}'],
    ['invalid JSON', '{"accessToken":']
  ])('rejects %s', (_name, content) => {
    expect(isOpenAISessionJSONContent(content)).toBe(false)
  })
})
