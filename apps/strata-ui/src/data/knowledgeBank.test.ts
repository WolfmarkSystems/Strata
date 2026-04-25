import assert from 'node:assert/strict'
import { lookupKnowledge } from './knowledgeBank.ts'

const exact = lookupKnowledge('NTUSER.DAT', 'dat')
assert.equal(exact?.matchType, 'filename')
assert.equal(exact?.entry.title, 'Windows Registry — User Hive')

const generic = lookupKnowledge('FlagMailboxes.plist', '.plist')
assert.equal(generic?.matchType, 'extension')
assert.equal(generic?.extension, 'plist')
assert.equal(generic?.entry.title, 'macOS Property List')

const missing = lookupKnowledge('unknown.nope', 'nope')
assert.equal(missing, null)
