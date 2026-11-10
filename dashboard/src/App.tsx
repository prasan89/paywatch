import { useState, useEffect, useCallback, useRef } from 'react'
import { AgGridReact } from 'ag-grid-react'
import type { ColDef, GridReadyEvent } from 'ag-grid-community'
import 'ag-grid-community/styles/ag-grid.css'
import 'ag-grid-community/styles/ag-theme-quartz.css'
import {
  Shield, AlertTriangle, AlertCircle, CheckCircle2, Activity,
  Search, X, Package, RefreshCw, Clock, MessageSquareWarning,
  ChevronRight, Loader2
} from 'lucide-react'
import './App.css'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

interface Verdict {
  ts: number
  package: string
  version: string
  label: 'suspicious' | 'malicious'
  confidence: number
  summary: string
  persuasion: boolean
  hash: string
}

interface Stats {
  total_flagged: number
  malicious: number
  suspicious: number
}

type Filter = 'all' | 'malicious' | 'suspicious'

// ── Cell renderers ──────────────────────────────────────────────────────────

const LabelCell = (params: { value: string }) => {
  const v = params.value as 'malicious' | 'suspicious' | 'safe'
  const icon = v === 'malicious'
    ? <AlertCircle size={11} />
    : v === 'suspicious'
    ? <AlertTriangle size={11} />
    : <CheckCircle2 size={11} />
  return <span className={`badge ${v}`}>{icon}{v}</span>
}

const ConfidenceCell = (params: { value: number }) => {
  const pct = Math.round(params.value * 100)
  const tier = pct >= 80 ? 'high' : pct >= 55 ? 'medium' : 'low'
  return (
    <div className="confidence-cell">
      <div className="confidence-bar-wrap">
        <div className={`confidence-bar ${tier}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`confidence-pct ${tier}`}>{pct}%</span>
    </div>
  )
}

const PersuasionCell = (params: { value: boolean }) =>
  params.value
    ? (
      <span className="persuasion-icon" title="Package contained persuasion attempts — argued it was safe">
        <MessageSquareWarning size={15} />
      </span>
    )
    : null

const TimeCell = (params: { value: number }) => {
  const date = new Date(params.value * 1000)
  const now = Date.now()
  const diff = now - date.getTime()
  let rel: string
  if (diff < 60000) rel = 'just now'
  else if (diff < 3600000) rel = `${Math.floor(diff / 60000)}m ago`
  else if (diff < 86400000) rel = `${Math.floor(diff / 3600000)}h ago`
  else rel = `${Math.floor(diff / 86400000)}d ago`

  return (
    <span className="time-cell" title={date.toLocaleString()}>
      {rel}
    </span>
  )
}

const PackageCell = (params: { value: string }) => {
  const name = params.value
  if (name.startsWith('@')) {
    const slash = name.indexOf('/')
    if (slash > 0) {
      return (
        <span className="pkg-name">
          <span className="pkg-scope">{name.slice(0, slash + 1)}</span>
          {name.slice(slash + 1)}
        </span>
      )
    }
  }
  return <span className="pkg-name">{name}</span>
}

const SummaryCell = (params: { value: string }) => (
  <div className="summary-cell" title={params.value}>{params.value}</div>
)

const HashCell = (params: { value: string }) =>
  params.value
    ? <span className="hash-cell">{params.value.slice(0, 10)}…</span>
    : null

// ── Column defs ─────────────────────────────────────────────────────────────

const COL_DEFS: ColDef<Verdict>[] = [
  {
    field: 'ts', headerName: 'Time', width: 96,
    cellRenderer: TimeCell, sort: 'desc',
    comparator: (a: number, b: number) => a - b,
  },
  {
    field: 'package', headerName: 'Package', flex: 1, minWidth: 180,
    cellRenderer: PackageCell,
  },
  { field: 'version', headerName: 'Version', width: 90 },
  {
    field: 'label', headerName: 'Verdict', width: 128,
    cellRenderer: LabelCell,
  },
  {
    field: 'confidence', headerName: 'Confidence', width: 148,
    cellRenderer: ConfidenceCell,
    comparator: (a: number, b: number) => a - b,
  },
  {
    field: 'persuasion', headerName: '', width: 42,
    cellRenderer: PersuasionCell, sortable: false, filter: false,
  },
  {
    field: 'summary', headerName: 'Summary', flex: 2, minWidth: 260,
    cellRenderer: SummaryCell,
    sortable: false,
  },
  {
    field: 'hash', headerName: 'OTS', width: 104,
    cellRenderer: HashCell, sortable: false,
  },
]

// ── Detail Drawer ───────────────────────────────────────────────────────────

function DetailDrawer({ row, onClose }: { row: Verdict; onClose: () => void }) {
  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div className="drawer-overlay" onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <div className="drawer" role="dialog" aria-modal="true" aria-label="Package details">
        <div className="drawer-header">
          <Package size={16} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
          <span className="drawer-title">{row.package}@{row.version}</span>
          <span className={`badge ${row.label}`}>{row.label}</span>
          <button className="drawer-close" onClick={onClose} aria-label="Close details">
            <X size={14} />
          </button>
        </div>

        <div className="drawer-body">
          <div className="detail-row">
            <span className="detail-label">Verdict</span>
            <span className="detail-value">
              <LabelCell value={row.label} />
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label">Confidence</span>
            <span className="detail-value">
              <ConfidenceCell value={row.confidence} />
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label">Detected</span>
            <span className="detail-value" title={new Date(row.ts * 1000).toLocaleString()}>
              <TimeCell value={row.ts} />
              <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 8 }}>
                ({new Date(row.ts * 1000).toLocaleString()})
              </span>
            </span>
          </div>

          {row.persuasion && (
            <div className="detail-row">
              <span className="detail-label">Persuasion</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--amber-600)', fontSize: 13 }}>
                <MessageSquareWarning size={15} />
                Package attempted to argue it was safe during analysis
              </div>
            </div>
          )}

          <div className="drawer-section-title">Analysis Summary</div>

          <div className={`detail-summary ${row.label}`}>
            {row.summary || 'No summary available.'}
          </div>

          {row.hash && (
            <>
              <div className="drawer-section-title">Integrity Anchor</div>
              <div className="detail-row">
                <span className="detail-label">OpenTimestamps SHA-256</span>
                <div className="detail-value mono">{row.hash}</div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Toast ───────────────────────────────────────────────────────────────────

interface Toast { id: number; message: string; type: 'info' | 'success' | 'error' | 'warn' }

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div className="toast-container" aria-live="polite">
      {toasts.map(t => (
        <div key={t.id} className={`toast ${t.type}`} role="status">
          {t.type === 'success' && <CheckCircle2 size={15} />}
          {t.type === 'error' && <AlertCircle size={15} />}
          {t.type === 'warn' && <AlertTriangle size={15} />}
          <span style={{ flex: 1 }}>{t.message}</span>
          <button
            onClick={() => onDismiss(t.id)}
            style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: '0 0 0 4px', opacity: 0.7 }}
            aria-label="Dismiss"
          >
            <X size={13} />
          </button>
        </div>
      ))}
    </div>
  )
}

// ── Main App ────────────────────────────────────────────────────────────────

export default function App() {
  const [rows, setRows] = useState<Verdict[]>([])
  const [stats, setStats] = useState<Stats>({ total_flagged: 0, malicious: 0, suspicious: 0 })
  const [live, setLive] = useState(false)
  const [loading, setLoading] = useState(true)
  const [lastScan, setLastScan] = useState<Date | null>(null)

  const [scanInput, setScanInput] = useState('')
  const [scanLoading, setScanLoading] = useState(false)
  const [scanFeedback, setScanFeedback] = useState<{ msg: string; type: 'info' | 'success' | 'error' } | null>(null)
  const [scanError, setScanError] = useState(false)

  const [filter, setFilter] = useState<Filter>('all')
  const [search, setSearch] = useState('')
  const [selectedRow, setSelectedRow] = useState<Verdict | null>(null)

  const [toasts, setToasts] = useState<Toast[]>([])
  const toastIdRef = useRef(0)

  const addToast = useCallback((message: string, type: Toast['type'] = 'info') => {
    const id = ++toastIdRef.current
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const loadData = useCallback(async () => {
    try {
      const [verdictRes, statsRes] = await Promise.all([
        fetch(`${API}/api/verdicts`),
        fetch(`${API}/api/stats`),
      ])
      const [verdictData, statsData] = await Promise.all([
        verdictRes.json(),
        statsRes.json(),
      ])
      setRows(verdictData)
      setStats(statsData)
      setLastScan(new Date())
    } catch {
      // backend might not be reachable on initial load
    } finally {
      setLoading(false)
    }
  }, [])

  // Load history on mount
  useEffect(() => { loadData() }, [loadData])

  // SSE live stream
  useEffect(() => {
    const es = new EventSource(`${API}/api/stream`)
    es.onmessage = (e) => {
      const data = JSON.parse(e.data)
      if (data.ping) return
      setLive(true)
      setTimeout(() => setLive(false), 2500)
      setLastScan(new Date())
      setRows(prev => [data, ...prev].slice(0, 200))
      setStats(prev => ({
        total_flagged: prev.total_flagged + 1,
        malicious: prev.malicious + (data.label === 'malicious' ? 1 : 0),
        suspicious: prev.suspicious + (data.label === 'suspicious' ? 1 : 0),
      }))
      addToast(
        `${data.label === 'malicious' ? '🚨' : '⚠️'} ${data.package}@${data.version} flagged as ${data.label}`,
        data.label === 'malicious' ? 'error' : 'warn'
      )
    }
    return () => es.close()
  }, [addToast])

  const handleScan = useCallback(async () => {
    const pkg = scanInput.trim()
    if (!pkg) {
      setScanError(true)
      setScanFeedback({ msg: 'Enter a package name', type: 'error' })
      return
    }
    setScanError(false)
    setScanLoading(true)
    setScanFeedback({ msg: `Scanning ${pkg}…`, type: 'info' })
    try {
      const r = await fetch(`${API}/api/scan/${encodeURIComponent(pkg)}`, { method: 'POST' })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const data = await r.json()
      setScanFeedback({
        msg: `Scanning ${data.package}@${data.version} — result will appear in the table`,
        type: 'success',
      })
      setTimeout(() => setScanFeedback(null), 8000)
    } catch {
      setScanFeedback({ msg: 'Scan failed — is the backend running?', type: 'error' })
    } finally {
      setScanLoading(false)
    }
  }, [scanInput])

  const handleScanKey = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleScan()
  }, [handleScan])

  const handleScanChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setScanInput(e.target.value)
    if (scanError) { setScanError(false); setScanFeedback(null) }
  }, [scanError])

  const handleGridReady = useCallback((_e: GridReadyEvent) => {}, [])

  const handleRowClick = useCallback((e: { data?: Verdict }) => {
    if (e.data) setSelectedRow(e.data)
  }, [])

  const handleRefresh = useCallback(() => {
    setLoading(true)
    loadData().then(() => addToast('Data refreshed', 'success'))
  }, [loadData, addToast])

  // Filtered rows
  const filteredRows = rows
    .filter(r => filter === 'all' || r.label === filter)
    .filter(r => !search || r.package.toLowerCase().includes(search.toLowerCase()))

  const lastScanStr = lastScan
    ? lastScan.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '—'

  return (
    <div className="app">
      {/* Nav */}
      <nav className="nav">
        <div className="nav-inner">
          <div className="logo">
            <div className="logo-icon" aria-hidden="true">
              <Shield size={18} />
            </div>
            <div>
              <div className="logo-name">PayWatch</div>
              <div className="logo-subtitle">Real-time npm threat intelligence</div>
            </div>
          </div>

          <div className="nav-spacer" />

          {lastScan && (
            <span style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 5 }}>
              <Clock size={13} />
              Last: {lastScanStr}
            </span>
          )}

          <div className={`nav-status ${live ? 'live' : ''}`}>
            <span className={`status-dot ${live ? 'live' : ''}`} />
            {live ? 'Live event' : 'Monitoring'}
          </div>

          <button className="nav-btn" onClick={handleRefresh} aria-label="Refresh data">
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            Refresh
          </button>
        </div>
      </nav>

      {/* Main */}
      <main className="main">
        {/* Stats */}
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon blue"><Activity size={20} /></div>
            <div className="stat-body">
              <div className="stat-value">{stats.total_flagged}</div>
              <div className="stat-label">Total Flagged</div>
            </div>
          </div>

          <div className="stat-card danger">
            <div className="stat-icon red"><AlertCircle size={20} /></div>
            <div className="stat-body">
              <div className="stat-value">{stats.malicious}</div>
              <div className="stat-label">Malicious</div>
            </div>
          </div>

          <div className="stat-card warn">
            <div className="stat-icon amber"><AlertTriangle size={20} /></div>
            <div className="stat-body">
              <div className="stat-value">{stats.suspicious}</div>
              <div className="stat-label">Suspicious</div>
            </div>
          </div>
        </div>

        {/* Scan */}
        <div className="scan-section">
          <div className="scan-header">
            <Search size={15} />
            <span className="scan-header-title">Scan a Package</span>
          </div>
          <div className="scan-row">
            <div className="scan-input-wrap">
              <Package size={15} className="scan-input-icon" />
              <input
                className={`scan-input${scanError ? ' error' : ''}`}
                value={scanInput}
                onChange={handleScanChange}
                onKeyDown={handleScanKey}
                placeholder="@paypal/react-paypal-js@8.1.0"
                aria-label="Package name to scan"
                disabled={scanLoading}
              />
            </div>
            <button
              className="scan-btn"
              onClick={handleScan}
              disabled={scanLoading}
              aria-label="Start scan"
            >
              {scanLoading ? <Loader2 size={15} className="spin" /> : <Search size={15} />}
              {scanLoading ? 'Scanning…' : 'Scan'}
            </button>
            {scanFeedback && (
              <div className={`scan-feedback ${scanFeedback.type}`}>
                {scanFeedback.type === 'success' && <CheckCircle2 size={14} />}
                {scanFeedback.type === 'error' && <AlertCircle size={14} />}
                {scanFeedback.type === 'info' && <Loader2 size={14} className="spin" />}
                <span>{scanFeedback.msg}</span>
                <button
                  onClick={() => setScanFeedback(null)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: 0, display: 'flex', alignItems: 'center' }}
                  aria-label="Dismiss"
                >
                  <X size={13} />
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Threat table */}
        <div className="table-section">
          <div className="table-toolbar">
            <span className="table-title">
              <AlertTriangle size={15} style={{ color: 'var(--amber-600)' }} />
              Threat Intelligence
            </span>
            <span className="row-count">{filteredRows.length}</span>

            <div className="filter-group">
              <button
                className={`filter-btn${filter === 'all' ? ' active' : ''}`}
                onClick={() => setFilter('all')}
              >All</button>
              <button
                className={`filter-btn${filter === 'malicious' ? ' active danger' : ''}`}
                onClick={() => setFilter('malicious')}
              >Malicious</button>
              <button
                className={`filter-btn${filter === 'suspicious' ? ' active warn' : ''}`}
                onClick={() => setFilter('suspicious')}
              >Suspicious</button>
            </div>

            <div className="toolbar-spacer" />

            <div className="search-wrap">
              <Search size={14} className="search-icon" />
              <input
                className="search-input"
                placeholder="Filter by package…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                aria-label="Filter packages"
              />
            </div>
          </div>

          <div className="grid-wrap">
            {loading ? (
              <div className="empty-state">
                <div className="empty-state-icon">
                  <Loader2 size={22} className="spin" />
                </div>
                <span className="empty-state-text">Loading threat data…</span>
              </div>
            ) : filteredRows.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-icon">
                  <Shield size={22} />
                </div>
                <span className="empty-state-text">
                  {search || filter !== 'all' ? 'No matching results' : 'No threats detected yet'}
                </span>
                <span className="empty-state-sub">
                  {search || filter !== 'all'
                    ? 'Try adjusting your filter or search'
                    : 'The monitor is watching npm for suspicious activity'}
                </span>
              </div>
            ) : (
              <div className="ag-theme-quartz" style={{ width: '100%' }}>
                <AgGridReact<Verdict>
                  rowData={filteredRows}
                  columnDefs={COL_DEFS}
                  defaultColDef={{ resizable: true, sortable: true, filter: false }}
                  rowHeight={52}
                  headerHeight={40}
                  domLayout="autoHeight"
                  suppressColumnVirtualisation
                  suppressHorizontalScroll={false}
                  tooltipShowDelay={400}
                  onGridReady={handleGridReady}
                  onRowClicked={handleRowClick}
                  getRowId={r => `${r.data.package}@${r.data.version}@${r.data.ts}`}
                  animateRows
                />
              </div>
            )}
          </div>

          {/* Table row hint */}
          {filteredRows.length > 0 && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '9px 18px',
              borderTop: '1px solid var(--border-subtle)',
              fontSize: 12, color: 'var(--text-muted)',
            }}>
              <ChevronRight size={13} />
              Click any row to view investigation details
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="footer">
        Verdicts anchored with salted SHA-256 + Bitcoin via OpenTimestamps · Powered by Meta AI · PayPal Sandbox verified
      </footer>

      {/* Detail Drawer */}
      {selectedRow && (
        <DetailDrawer row={selectedRow} onClose={() => setSelectedRow(null)} />
      )}

      {/* Toast container */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Spin keyframe for inline use */}
      <style>{`
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
