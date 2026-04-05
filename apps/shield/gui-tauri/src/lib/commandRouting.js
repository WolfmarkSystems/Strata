const COMMAND_ROUTE_MAP = Object.freeze({
  capabilities: '/dashboard',
  doctor: '/dashboard',
  'smoke-test': '/evidence',
  'open-evidence': '/evidence',
  verify: '/case',
  'triage-session': '/case',
  examine: '/artifacts',
  watchpoints: '/case',
  violations: '/case',
  filetable: '/files',
  search: '/files',
  strings: '/artifacts',
  timeline: '/timeline',
});

const ROUTE_LABEL_MAP = Object.freeze({
  '/dashboard': 'Dashboard',
  '/evidence': 'Evidence Sources',
  '/case': 'Case Overview',
  '/artifacts': 'Artifacts',
  '/files': 'File Explorer',
  '/timeline': 'Timeline',
  '/logs': 'Logs',
  '/hashes': 'Hash Sets',
  '/settings': 'Settings',
});
const COMMAND_ROUTE_STATE_MAP = Object.freeze({
  verify: { focusTab: 'verify' },
  'triage-session': { focusTab: 'triage' },
  examine: { focusTab: 'examine' },
  watchpoints: { focusTab: 'watchpoints' },
  violations: { focusTab: 'violations' },
});

function normalize(value) {
  return String(value || '').trim().toLowerCase();
}

export function getCommandRoute(command) {
  const normalized = normalize(command);
  return COMMAND_ROUTE_MAP[normalized] || '/logs';
}

export function getRouteLabel(route) {
  const normalized = String(route || '').trim();
  return ROUTE_LABEL_MAP[normalized] || 'Related Page';
}

export function getCommandNavigationTarget(command) {
  const route = getCommandRoute(command);
  const normalized = normalize(command);
  const state = COMMAND_ROUTE_STATE_MAP[normalized] || null;
  return { route, state };
}

export function getTimelineEntryRoute(entry) {
  const source = normalize(entry?.source);
  const type = normalize(entry?.type);

  if (type === 'evidence-check' || type === 'evidence-detection') return '/evidence';
  if (type === 'verification' || type === 'triage') return '/case';
  if (type === 'examination') return '/artifacts';
  if (source === 'activity' || source === 'evidence' || source === 'timeline') return '/timeline';
  if (source === 'violations' || source === 'violation' || type === 'violation') return '/case';

  return '/logs';
}
