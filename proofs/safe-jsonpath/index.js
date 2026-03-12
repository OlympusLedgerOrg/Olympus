'use strict'

/**
 * Minimal, non-eval JSONPath parser that supports the subset used by bfj:
 *   - Absolute paths starting with "$"
 *   - Child access via dot notation (e.g., $.a.b)
 *   - Subscript access for string, numeric, or wildcard entries (e.g., $['a'][0][*])
 *
 * The shape of the returned nodes mirrors jsonpath@1.x parse output for the
 * supported subset so downstream consumers (bfj) continue to function while
 * avoiding the insecure jsonpath dependency that relies on static-eval.
 */
function parse (path) {
  if (typeof path !== 'string') {
    throw new TypeError('JSONPath must be a string')
  }

  const trimmed = path.trim()
  if (/[()]/.test(trimmed) || /script\s*:/i.test(trimmed)) {
    throw new Error('Unsafe JSONPath syntax')
  }
  if (!trimmed.startsWith('$')) {
    throw new Error('Only absolute JSONPath expressions starting with "$" are supported')
  }

  const tokens = [{ expression: { type: 'root', value: '$' } }]
  let index = 1

  // allow an optional separator after the root symbol
  if (trimmed[index] === '.') {
    index += 1
  }

  while (index < trimmed.length) {
    if (trimmed[index] === '[') {
      const close = trimmed.indexOf(']', index)
      if (close === -1) {
        throw new Error('Unterminated subscript segment in JSONPath')
      }
      const content = trimmed.slice(index + 1, close)
      tokens.push(buildSegment(content, 'subscript'))
      index = close + 1
      if (trimmed[index] === '.') {
        index += 1
      }
      continue
    }

    // member access via dot notation
    const nextSep = nextSeparator(trimmed, index)
    const segment = trimmed.slice(index, nextSep === -1 ? trimmed.length : nextSep)
    tokens.push(buildSegment(segment, 'member'))
    if (nextSep === -1) {
      break
    }

    // Revisit the separator so bracket access is handled in the next iteration;
    // skip over dots immediately.
    index = trimmed[nextSep] === '.' ? nextSep + 1 : nextSep
  }

  return tokens
}

function nextSeparator (input, start) {
  for (let i = start; i < input.length; i++) {
    const ch = input[i]
    if (ch === '.' || ch === '[') {
      return i
    }
  }
  return -1
}

function buildSegment (raw, operation) {
  if (raw === '*') {
    return {
      expression: {
        type: 'wildcard',
        value: '*'
      },
      scope: 'child',
      operation
    }
  }

  // bracketed string literal: "foo" or 'foo'
  const stringLiteral = raw.match(/^(['"])(.*)\1$/)
  if (stringLiteral) {
    return {
      expression: {
        type: 'string_literal',
        value: stringLiteral[2]
      },
      scope: 'child',
      operation
    }
  }

  // numeric literal (only non-negative integers are expected in our use)
  if (/^\d+$/.test(raw)) {
    return {
      expression: {
        type: 'numeric_literal',
        value: Number.parseInt(raw, 10)
      },
      scope: 'child',
      operation
    }
  }

  // identifier (dot notation or bracket without quotes)
  if (/^[a-zA-Z_$][\w$]*$/.test(raw)) {
    return {
      expression: {
        type: 'identifier',
        value: raw
      },
      scope: 'child',
      operation
    }
  }

  throw new Error(`Unsupported or unsafe JSONPath segment: ${raw}`)
}

module.exports = {
  parse
}
