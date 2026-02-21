const assert = require('node:assert/strict')
const { test } = require('node:test')

const { parse } = require('../safe-jsonpath')

test('parses simple member paths', () => {
  const result = parse('$.foo.bar')
  assert.deepEqual(result, [
    { expression: { type: 'root', value: '$' } },
    {
      expression: { type: 'identifier', value: 'foo' },
      scope: 'child',
      operation: 'member'
    },
    {
      expression: { type: 'identifier', value: 'bar' },
      scope: 'child',
      operation: 'member'
    }
  ])
})

test('parses array access with wildcard', () => {
  const result = parse("$.items[0].*")
  assert.deepEqual(result, [
    { expression: { type: 'root', value: '$' } },
    {
      expression: { type: 'identifier', value: 'items' },
      scope: 'child',
      operation: 'member'
    },
    {
      expression: { type: 'numeric_literal', value: 0 },
      scope: 'child',
      operation: 'subscript'
    },
    {
      expression: { type: 'wildcard', value: '*' },
      scope: 'child',
      operation: 'member'
    }
  ])
})

test('rejects unsupported selectors', () => {
  assert.throws(() => parse('foo'), /absolute JSONPath/)
  assert.throws(() => parse('$..foo'), /Unsupported/)
  assert.throws(() => parse('$[?(@.a>1)]'), /Unsupported/)
})
