import test from 'node:test';
import assert from 'node:assert/strict';
import { formatLocalTimestamp, formatRelativeTime, formatUtcIsoSeconds } from '../src/lib/timeFormat.js';

test('formatLocalTimestamp handles empty and invalid values safely', () => {
  assert.equal(formatLocalTimestamp(null), 'N/A');
  assert.equal(formatLocalTimestamp('not-a-date'), 'not-a-date');
});

test('formatRelativeTime returns stable relative labels', () => {
  const now = new Date('2026-03-09T12:00:00Z');
  assert.equal(formatRelativeTime('2026-03-09T12:00:00Z', now), 'just now');
  assert.equal(formatRelativeTime('2026-03-09T11:59:00Z', now), '1 minute ago');
  assert.equal(formatRelativeTime('2026-03-09T10:00:00Z', now), '2 hours ago');
  assert.equal(formatRelativeTime('2026-03-10T12:00:00Z', now), 'in 1 day');
});

test('formatUtcIsoSeconds trims milliseconds for query controls', () => {
  assert.equal(formatUtcIsoSeconds('2026-03-09T12:34:56.789Z'), '2026-03-09T12:34:56Z');
  assert.equal(formatUtcIsoSeconds('invalid-date'), '');
});
