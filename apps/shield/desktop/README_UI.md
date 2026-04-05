# Forensic Suite UI

## Running the UI

### Prerequisites
- Node.js 18+
- Rust (for Tauri backend)

### Setup

```bash
cd desktop
npm install
```

### Development

```bash
npm run dev
```

This starts:
- Vite dev server on http://localhost:5173
- Tauri backend

Or use Tauri CLI:
```bash
npm run tauri dev
```

### Build

```bash
npm run build
npm run tauri build
```

## Commands Used

The UI uses these Tauri commands:

### Case Management
- `open_case(casePath)` - Open a case
- `list_cases()` - List all cases

### Evidence
- `open_evidence(caseId, evidencePath)` - Open evidence file

### File Table
- `file_table_query(query)` - Query file table with filters, sorting, cursor paging
- `file_table_preview(caseId, sourceType, sourceId, mode)` - Get preview (text/hex/metadata)

### Notes
- `add_to_notes(req)` - Add selection to notes (no typing)

### Events
- `get_event_buffer(caseId?, limit?)` - Get recent events

### System
- `get_capabilities()` - Get capability registry
- `run_preflight()` - Run preflight checks
- `get_preflight_report()` - Get latest preflight report

### Scoring
- `rebuild_scores(caseId)` - Rebuild suspiciousness scores
- `explain_score(caseId, rowId)` - Explain score for a row

## Troubleshooting

### Events not showing
- Ensure backend is running
- Check browser console for errors
- Verify Tauri event emission is working

### File table empty
- Verify case is opened with correct path
- Check that evidence has been processed

### Preview not loading
- Some files may not have extractable content
- Check file permissions

### Build errors
- Ensure all dependencies installed: `npm install`
- Try cleaning: `rm -rf node_modules && npm install`
