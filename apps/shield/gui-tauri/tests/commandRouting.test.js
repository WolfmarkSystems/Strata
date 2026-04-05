import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getCommandRoute,
  getCommandNavigationTarget,
  getRouteLabel,
  getTimelineEntryRoute,
} from '../src/lib/commandRouting.js';

test('maps known commands to expected routes', () => {
  assert.equal(getCommandRoute('capabilities'), '/dashboard');
  assert.equal(getCommandRoute('open-evidence'), '/evidence');
  assert.equal(getCommandRoute('verify'), '/case');
  assert.equal(getCommandRoute('filetable'), '/files');
  assert.equal(getCommandRoute('timeline'), '/timeline');
});

test('unknown command falls back to logs route', () => {
  assert.equal(getCommandRoute('unknown-command'), '/logs');
});

test('command navigation target includes case tab state where relevant', () => {
  assert.deepEqual(getCommandNavigationTarget('verify'), { route: '/case', state: { focusTab: 'verify' } });
  assert.deepEqual(getCommandNavigationTarget('triage-session'), { route: '/case', state: { focusTab: 'triage' } });
  assert.deepEqual(getCommandNavigationTarget('doctor'), { route: '/dashboard', state: null });
});

test('timeline entry route mapping is type/source aware', () => {
  assert.equal(getTimelineEntryRoute({ type: 'evidence-check' }), '/evidence');
  assert.equal(getTimelineEntryRoute({ type: 'verification' }), '/case');
  assert.equal(getTimelineEntryRoute({ type: 'examination' }), '/artifacts');
  assert.equal(getTimelineEntryRoute({ source: 'activity' }), '/timeline');
  assert.equal(getTimelineEntryRoute({ source: 'violations' }), '/case');
});

test('route labels are stable for known app pages', () => {
  assert.equal(getRouteLabel('/dashboard'), 'Dashboard');
  assert.equal(getRouteLabel('/timeline'), 'Timeline');
  assert.equal(getRouteLabel('/unknown'), 'Related Page');
});
