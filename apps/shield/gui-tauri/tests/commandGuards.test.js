import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getCaseContextGuardReason,
  getCommandDisabledReason,
  getEvidenceGuardReason,
  getRunningGuardReason,
} from '../src/lib/commandGuards.js';

test('running guard reason includes active command when available', () => {
  assert.equal(
    getRunningGuardReason(true, 'verify'),
    "Command 'verify' is currently running.",
  );
  assert.equal(getRunningGuardReason(true, ''), 'A command is currently running.');
  assert.equal(getRunningGuardReason(false, 'verify'), '');
});

test('case and evidence guard helpers return expected reasons', () => {
  assert.equal(getCaseContextGuardReason('', ''), 'Requires both Case ID and DB path.');
  assert.equal(getCaseContextGuardReason('CASE-1', ''), 'Requires both Case ID and DB path.');
  assert.equal(getCaseContextGuardReason('CASE-1', 'exports/cases/main.db'), '');

  assert.equal(getEvidenceGuardReason(''), 'Requires a selected evidence path.');
  assert.equal(getEvidenceGuardReason('D:\\evidence\\disk.E01'), '');
});

test('combined command guard prioritizes running, then context requirements', () => {
  assert.equal(
    getCommandDisabledReason({
      isRunning: true,
      activeCommand: 'triage-session',
      requiresCaseContext: true,
      caseId: '',
      caseDbPath: '',
      requiresEvidence: true,
      evidencePath: '',
    }),
    "Command 'triage-session' is currently running.",
  );

  assert.equal(
    getCommandDisabledReason({
      isRunning: false,
      requiresCaseContext: true,
      caseId: '',
      caseDbPath: '',
      requiresEvidence: true,
      evidencePath: '',
    }),
    'Requires both Case ID and DB path.',
  );

  assert.equal(
    getCommandDisabledReason({
      isRunning: false,
      requiresEvidence: true,
      evidencePath: '',
    }),
    'Requires a selected evidence path.',
  );
});
