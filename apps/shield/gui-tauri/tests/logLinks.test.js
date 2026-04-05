import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildLogSelectionState,
  buildLogSelectionStateForCommand,
  findJobByFilename,
  findLatestJobFilename,
  normalizeJobFilename,
  resolveTimelineEntryJobFilename,
} from '../src/lib/logLinks.js';

function makeJob({
  filename,
  command,
  timestamp,
  sortEpochMs,
}) {
  return {
    filename,
    command,
    timestamp,
    sort_epoch_ms: sortEpochMs,
  };
}

test('normalizes filenames and builds log selection state', () => {
  assert.equal(normalizeJobFilename('  /2026-03-08T14-00-00_verify.json  '), '2026-03-08T14-00-00_verify.json');
  assert.deepEqual(buildLogSelectionState(''), {});
  assert.deepEqual(buildLogSelectionState('2026-03-08T14-00-00_verify.json'), {
    selectJobFilename: '2026-03-08T14-00-00_verify.json',
  });
});

test('findJobByFilename and findLatestJobFilename return expected jobs', () => {
  const jobs = [
    makeJob({ filename: '2026-03-08T15-00-00_verify.json', command: 'verify', timestamp: '2026-03-08T15:00:00Z', sortEpochMs: 2000 }),
    makeJob({ filename: '2026-03-08T14-00-00_verify.json', command: 'verify', timestamp: '2026-03-08T14:00:00Z', sortEpochMs: 1000 }),
  ];
  assert.equal(findJobByFilename(jobs, '/2026-03-08T15-00-00_verify.json')?.filename, '2026-03-08T15-00-00_verify.json');
  assert.equal(findLatestJobFilename(jobs, 'verify'), '2026-03-08T15-00-00_verify.json');
  assert.deepEqual(buildLogSelectionStateForCommand(jobs, 'verify'), {
    selectJobFilename: '2026-03-08T15-00-00_verify.json',
  });
  assert.deepEqual(buildLogSelectionStateForCommand(jobs, 'doctor'), {});
});

test('timeline resolver uses direct source filename when present', () => {
  const jobs = [
    makeJob({ filename: '2026-03-08T14-00-00_timeline.json', command: 'timeline', timestamp: '2026-03-08T14:00:00Z', sortEpochMs: 1000 }),
  ];
  const resolved = resolveTimelineEntryJobFilename(
    {
      source: 'activity',
      timestamp: '2026-03-08T14:00:05Z',
      sourceJobFilename: '2026-03-08T14-00-00_timeline.json',
    },
    jobs,
  );
  assert.equal(resolved, '2026-03-08T14-00-00_timeline.json');
});

test('timeline resolver falls back by source/type and timestamp proximity', () => {
  const jobs = [
    makeJob({ filename: '2026-03-08T12-00-00_timeline.json', command: 'timeline', timestamp: '2026-03-08T12:00:00Z', sortEpochMs: 1000 }),
    makeJob({ filename: '2026-03-08T12-05-00_violations.json', command: 'violations', timestamp: '2026-03-08T12:05:00Z', sortEpochMs: 2000 }),
  ];

  const activityResolved = resolveTimelineEntryJobFilename(
    {
      source: 'activity',
      type: 'activity',
      timestamp: '2026-03-08T12:00:30Z',
      sourceJobFilename: null,
    },
    jobs,
  );
  assert.equal(activityResolved, '2026-03-08T12-00-00_timeline.json');

  const violationResolved = resolveTimelineEntryJobFilename(
    {
      source: 'violations',
      type: 'violation',
      timestamp: '2026-03-08T12:05:10Z',
      sourceJobFilename: null,
    },
    jobs,
  );
  assert.equal(violationResolved, '2026-03-08T12-05-00_violations.json');
});
