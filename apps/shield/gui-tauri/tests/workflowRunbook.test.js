import test from 'node:test';
import assert from 'node:assert/strict';
import { buildWorkflowRunbookSteps, deriveWorkflowState } from '../src/lib/workflowRunbook.js';

function job(command, status = 'ok', data = {}) {
  return {
    command,
    status,
    data: { data },
  };
}

test('runbook recommends evidence selection first when no context is set', () => {
  const state = deriveWorkflowState({
    caseId: '',
    caseDbPath: '',
    evidencePath: '',
    jobs: [],
  });
  const runbook = buildWorkflowRunbookSteps(state);
  assert.equal(runbook.nextAction.id, 'go-evidence');
  assert.equal(runbook.steps.find((step) => step.id === 'evidence')?.state, 'pending');
});

test('runbook recommends verify when smoke and examine exist but verify is missing', () => {
  const state = deriveWorkflowState({
    caseId: 'CASE-100',
    caseDbPath: 'exports/cases/main.db',
    evidencePath: 'D:\\evidence\\disk.E01',
    jobs: [
      job('examine', 'ok', { result: { status: 'ok' } }),
      job('smoke-test', 'ok', { analysis_mode: 'full' }),
    ],
  });
  const runbook = buildWorkflowRunbookSteps(state);
  assert.equal(runbook.nextAction.id, 'run-verify');
  assert.equal(runbook.steps.find((step) => step.id === 'examine')?.state, 'complete');
});

test('runbook recommends violations review when workflow is complete and violations exist', () => {
  const state = deriveWorkflowState({
    caseId: 'CASE-100',
    caseDbPath: 'exports/cases/main.db',
    evidencePath: 'D:\\evidence\\disk.E01',
    jobs: [
      job('triage-session', 'ok', { result: { status: 'ok' } }),
      job('verify', 'ok', { status: 'ok' }),
      job('examine', 'ok', { result: { status: 'ok' } }),
      job('smoke-test', 'ok', { analysis_mode: 'full' }),
      job('violations', 'warn', { total_returned: 3, violations: [{ id: 'v1' }] }),
    ],
  });
  const runbook = buildWorkflowRunbookSteps(state);
  assert.equal(runbook.nextAction.id, 'review-violations');
  assert.equal(state.violationsCount, 3);
});
