import { useState } from 'react';
import { Group, Panel, Separator } from 'react-resizable-panels';
import { Menu, Search, Folder, FileText, Eye, Clipboard, Settings, Shield, HardDrive, BookmarkPlus, RotateCcw } from 'lucide-react';

const menubarItems = [
  { title: 'File', items: ['Open Image', 'Add to Case', 'Save Case', 'Export Report', 'Exit'] },
  { title: 'Edit', items: ['Copy', 'Select All', 'Find', 'Find Next'] },
  { title: 'Search', items: ['Keyword Search', 'Index Search', 'Regex Search', 'File Header Signature Search', 'Hash Database'] },
  { title: 'Position', items: ['Go to Sector', 'Go to Offset', 'Go to File'] },
  { title: 'View', items: ['Case Data', 'Directory Browser', 'Hex Editor', 'Gallery View', 'Details View'] },
  { title: 'Specialist', items: ['Refine Volume Snapshot', 'Recover Deleted Files', 'File Type Verification', 'Entropy Test', 'Hash Calculation'] },
  { title: 'Window', items: ['Reset Layout', 'Tile Horizontal', 'Tile Vertical'] },
  { title: 'Help', items: ['Documentation', 'Keyboard Shortcuts', 'About'] },
];

const sampleTree = [
  {
    name: 'case.dd',
    icon: 'case',
    expanded: true,
    children: [
      { name: 'C:', icon: 'drive', expanded: true, children: [
        { name: 'Windows', icon: 'folder', children: [
          { name: 'system32', icon: 'folder' },
          { name: 'Users', icon: 'folder' },
        ]},
        { name: 'Program Files', icon: 'folder' },
      ]},
    ],
  },
];

function TreeNode({ node, depth, selectedPath, onSelect }) {
  const [expanded, setExpanded] = useState(node.expanded || false);
  const hasChildren = node.children?.length > 0;
  const isSelected = selectedPath === node.name;
  const iconColor = node.icon === 'case' || node.icon === 'drive' ? 'text-primary' : 'text-muted-foreground';

  return (
    <div>
      <div
        className={`flex items-center gap-1 py-0.5 px-1 cursor-pointer rounded-md text-xs ${isSelected ? 'bg-accent text-accent-foreground' : 'hover:bg-muted'} `}
        style={{ paddingLeft: depth * 14 + 4 }}
        onClick={() => {
          if (hasChildren) setExpanded(!expanded);
          onSelect(node.name);
        }}
      >
        {hasChildren ? (
          <span className="w-4 h-4 flex items-center justify-center text-muted-foreground">
            {expanded ? '▾' : '▸'}
          </span>
        ) : (
          <span className="w-3" />
        )}
        <span className={`${iconColor} mr-1`}>
          {node.icon === 'case' ? <Shield size={12} /> : node.icon === 'drive' ? <HardDrive size={12} /> : node.icon === 'folder' ? <Folder size={12} /> : <FileText size={12} />}
        </span>
        <span className="truncate">{node.name}</span>
      </div>
      {hasChildren && expanded && node.children.map((child) => (
        <TreeNode key={`${node.name}-${child.name}`} node={child} depth={depth + 1} selectedPath={selectedPath} onSelect={onSelect} />
      ))}
    </div>
  );
}

function FileTreePanel({ data, selectedPath, onSelect }) {
  return (
    <div className="h-full min-h-0 flex flex-col bg-card rounded-lg border border-border overflow-hidden">
      <div className="px-3 py-2 border-b bg-muted/50 text-xs font-semibold uppercase tracking-wider">CASE DATA</div>
      <div className="flex-1 overflow-auto p-1.5">
        {data.map((node) => (
          <TreeNode key={node.name} node={node} depth={0} selectedPath={selectedPath} onSelect={onSelect} />
        ))}
      </div>
    </div>
  );
}

import DataTable from './DataTable';
import HexView from './HexView';
import GalleryView from './GalleryView';
import DetailsView from './DetailsView';

function DataViewerPanel({ activeTab, onTab = () => {} }) {
  // Demo data
  const columns = [
    { key: 'name', label: 'Name' },
    { key: 'size', label: 'Size' },
    { key: 'mtime', label: 'Modified' },
  ];
  const rows = [
    { name: 'file1.txt', size: '1 KB', mtime: '2026-03-25' },
    { name: 'file2.jpg', size: '2 MB', mtime: '2026-03-24' },
  ];
  const hexData = 'Hello, ForensicView!';
  const details = { Name: 'file1.txt', Size: '1 KB', Modified: '2026-03-25', Hash: 'abc123...' };
  const images = [
    { src: 'https://placehold.co/80x80', alt: 'Demo 1' },
    { src: 'https://placehold.co/80x80', alt: 'Demo 2' },
  ];

  return (
    <div className="h-full min-h-0 flex flex-col bg-card rounded-lg border border-border overflow-hidden">
      <div className="border-b border-border bg-muted/50 px-1">
        <div className="flex gap-1">
          {['File List', 'Hex View', 'Details', 'Gallery'].map((tab) => (
            <button
              key={tab}
              className={`text-[11px] px-3 py-2 ${activeTab === tab ? 'border-b-2 border-primary text-foreground' : 'border-b-2 border-transparent text-muted-foreground'} rounded-none`}
              onClick={() => onTab(tab)}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>
      <div className="flex-1 min-h-0 overflow-hidden">
        {activeTab === 'File List' && <DataTable columns={columns} rows={rows} />}
        {activeTab === 'Hex View' && <HexView data={hexData} />}
        {activeTab === 'Details' && <DetailsView details={details} />}
        {activeTab === 'Gallery' && <GalleryView images={images} />}
      </div>
    </div>
  );
}

import NotesPanel from './NotesPanel';
import PreviewPanel from './PreviewPanel';

function NotesPreviewPanel({ activeTab, onTab, notes, onNotesChange, previewContent }) {
  return (
    <div className="h-full min-h-0 flex flex-col bg-card rounded-lg border border-border overflow-hidden">
      <div className="border-b border-border bg-muted/50 px-1">
        <div className="flex gap-1">
          {['Notes', 'Preview'].map((tab) => (
            <button
              key={tab}
              className={`text-[11px] px-3 py-2 ${activeTab === tab ? 'border-b-2 border-primary text-foreground' : 'border-b-2 border-transparent text-muted-foreground'} rounded-none`}
              onClick={() => onTab(tab)}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>
      <div className="flex-1 min-h-0 overflow-hidden">
        {activeTab === 'Notes' ? (
          <NotesPanel notes={notes} onChange={onNotesChange} />
        ) : (
          <PreviewPanel content={previewContent} />
        )}
      </div>
    </div>
  );
}

function StatusBar({ summary }) {
  return (
    <div className="bg-card border-t border-border px-3 py-1 flex items-center justify-between text-[10px] text-muted-foreground">
      <div className="flex gap-4 items-center">{summary}</div>
      <div className="flex gap-3 items-center"><span className="text-primary">Read-Only</span></div>
    </div>
  );
}

export default function App() {
  const [selectedTree, setSelectedTree] = useState('case.dd');
  const [activeDataTab, setActiveDataTab] = useState('File List');
  const [activeRightTab, setActiveRightTab] = useState('Notes');
  const [notes, setNotes] = useState('');
  const [previewContent, setPreviewContent] = useState('No preview loaded.');

  return (
    <div className="h-screen flex flex-col overflow-hidden bg-background text-foreground">
      <header className="bg-card border-b border-border flex items-center justify-between px-3 py-2">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-primary" />
          <span className="font-bold text-sm">ForensicView</span>
          <span className="text-[10px] font-mono bg-accent text-accent-foreground rounded px-1.5 py-0.5">PRO</span>
        </div>
        <div className="flex gap-1 text-xs text-muted-foreground">
          {menubarItems.map((m) => (
            <button key={m.title} className="px-2 py-1 rounded-md hover:bg-accent hover:text-foreground">{m.title}</button>
          ))}
        </div>
      </header>

      <div className="bg-card border-b border-border px-3 py-1.5 flex items-center gap-1">
        {[
          { icon: Folder, label: 'Open Image' },
          { icon: Clipboard, label: 'Add Case' },
          { icon: FileText, label: 'Save Case' },
          { icon: Search, label: 'Search' },
          { icon: Settings, label: 'Settings' },
          { icon: RotateCcw, label: 'Refresh' },
        ].map((item) => (
          <button
            key={item.label}
            className="h-8 w-8 flex items-center justify-center rounded-md text-muted-foreground hover:text-primary hover:bg-accent"
            title={item.label}
            aria-label={item.label}
          >
            <item.icon size={16} />
          </button>
        ))}
      </div>

      <div className="flex-1 flex p-1.5 overflow-hidden">
        <Group direction="horizontal" autoSaveId="forensic-panels">
          <Panel minSize={12} maxSize={35} defaultSize={20}>
            <FileTreePanel data={sampleTree} selectedPath={selectedTree} onSelect={setSelectedTree} />
          </Panel>
          <Separator className="w-1 cursor-col-resize bg-transparent hover:bg-primary/20" />
          <Panel minSize={30} defaultSize={55}>
            <DataViewerPanel activeTab={activeDataTab} onTab={setActiveDataTab} />
          </Panel>
          <Separator className="w-1 cursor-col-resize bg-transparent hover:bg-primary/20" />
          <Panel minSize={15} maxSize={40} defaultSize={25}>
            <NotesPreviewPanel
              activeTab={activeRightTab}
              onTab={setActiveRightTab}
              notes={notes}
              onNotesChange={setNotes}
              previewContent={previewContent}
            />
          </Panel>
        </Group>
      </div>

      <StatusBar summary={<><HardDrive className="w-3 h-3" /> {selectedTree}</>} />
    </div>
  );
}
