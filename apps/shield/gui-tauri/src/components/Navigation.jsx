import { NavLink } from 'react-router-dom';

const navItems = [
  { path: '/', label: 'Dashboard' },
  { path: '/case', label: 'Case Overview' },
  { path: '/evidence', label: 'Evidence Sources' },
  { path: '/files', label: 'File Explorer' },
  { path: '/timeline', label: 'Timeline' },
  { path: '/artifacts', label: 'Artifacts' },
  { path: '/hashes', label: 'Hash Sets' },
  { path: '/logs', label: 'Logs' },
  { path: '/settings', label: 'Settings' },
];

function Navigation({ caseId }) {
  return (
    <nav className="navigation">
      <div className="nav-brand">
        <span className="brand-text">Forensic Suite</span>
      </div>

      {caseId && (
        <div className="nav-case-info">
          <span className="case-label">Case:</span>
          <span className="case-id">{caseId}</span>
        </div>
      )}

      <ul className="nav-list">
        {navItems.map((item) => (
          <li key={item.path}>
            <NavLink
              to={item.path}
              className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
              end={item.path === '/'}
            >
              <span className="nav-label">{item.label}</span>
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="nav-footer">
        <span className="version">v0.1.0</span>
      </div>
    </nav>
  );
}

export default Navigation;
