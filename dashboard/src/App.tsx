import { useState, useEffect, useCallback } from 'react'
import { AgGridReact } from 'ag-grid-react'
import type { ColDef } from 'ag-grid-community'
import 'ag-grid-community/styles/ag-grid.css'
import 'ag-grid-community/styles/ag-theme-quartz.css'
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

const labelCell = (params: { value: string }) => {
  const color = params.value === 'malicious' ? '#ef4444' : '#f59e0b'
  return <span style={{ color, fontWeight: 700, textTransform: 'uppercase', fontSize: 12 }}>{params.value}</span>
}

const confidenceCell = (params: { value: number }) => {
  const pct = Math.round(params.value * 100)
  const color = pct >= 80 ? '#ef4444' : pct >= 60 ? '#f59e0b' : '#6b7280'
  return <span style={{ color, fontWeight: 600 }}>{pct}%</span>
}

const persuasionCell = (params: { value: boolean }) =>
  params.value ? <span title="Package argued it was safe">⚠️</span> : null

const timeCell = (params: { value: number }) =>
  new Date(params.value * 1000).toLocaleTimeString()

const COL_DEFS: ColDef<Verdict>[] = [
  { field: 'ts', headerName: 'Time', width: 100, cellRenderer: timeCell, sort: 'desc' },
  { field: 'package', headerName: 'Package', flex: 1, minWidth: 180 },
  { field: 'version', headerName: 'Version', width: 100 },
  { field: 'label', headerName: 'Label', width: 110, cellRenderer: labelCell },
  { field: 'confidence', headerName: 'Confidence', width: 120, cellRenderer: confidenceCell },
  { field: 'persuasion', headerName: '⚠', width: 60, cellRenderer: persuasionCell },
  { field: 'summary', headerName: 'Summary', flex: 2, minWidth: 280, wrapText: true, autoHeight: true },
  {
    field: 'hash', headerName: 'OTS Hash', width: 130,
    cellRenderer: (p: { value: string }) =>
      p.value ? <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#6b7280' }}>{p.value.slice(0, 12)}…</span> : null
  },
]

export default function App() {
  const [rows, setRows] = useState<Verdict[]>([])
  const [stats, setStats] = useState<Stats>({ total_flagged: 0, malicious: 0, suspicious: 0 })
  const [scanInput, setScanInput] = useState('')
  const [scanStatus, setScanStatus] = useState('')
  const [live, setLive] = useState(false)

  // Load history
  useEffect(() => {
    fetch(`${API}/api/verdicts`)
      .then(r => r.json())
      .then(setRows)
      .catch(() => {})

    fetch(`${API}/api/stats`)
      .then(r => r.json())
      .then(setStats)
      .catch(() => {})
  }, [])

  // SSE live stream
  useEffect(() => {
    const es = new EventSource(`${API}/api/stream`)
    es.onmessage = (e) => {
      const data = JSON.parse(e.data)
      if (data.ping) return
      setLive(true)
      setTimeout(() => setLive(false), 2000)
      setRows(prev => [data, ...prev].slice(0, 200))
      setStats(prev => ({
        total_flagged: prev.total_flagged + 1,
        malicious: prev.malicious + (data.label === 'malicious' ? 1 : 0),
        suspicious: prev.suspicious + (data.label === 'suspicious' ? 1 : 0),
      }))
    }
    return () => es.close()
  }, [])

  const handleScan = useCallback(async () => {
    if (!scanInput.trim()) return
    setScanStatus('Scanning…')
    try {
      const r = await fetch(`${API}/api/scan/${encodeURIComponent(scanInput.trim())}`, { method: 'POST' })
      const data = await r.json()
      setScanStatus(`Scanning ${data.package}@${data.version} — result will appear below`)
    } catch {
      setScanStatus('Error — is the backend running?')
    }
  }, [scanInput])

  return (
    <div className="app">
      <header>
        <div className="logo">
          <span className="logo-icon">🛡</span>
          <span className="logo-text">PayWatch</span>
        </div>
        <p className="tagline">Live npm monitor for PayPal payment fraud</p>
        <div className={`live-dot ${live ? 'live' : ''}`}>{live ? '● LIVE' : '○ watching'}</div>
      </header>

      <div className="stats">
        <div className="stat-card">
          <div className="stat-value">{stats.total_flagged}</div>
          <div className="stat-label">Total Flagged</div>
        </div>
        <div className="stat-card danger">
          <div className="stat-value">{stats.malicious}</div>
          <div className="stat-label">Malicious</div>
        </div>
        <div className="stat-card warn">
          <div className="stat-value">{stats.suspicious}</div>
          <div className="stat-label">Suspicious</div>
        </div>
      </div>

      <div className="scan-bar">
        <input
          value={scanInput}
          onChange={e => setScanInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleScan()}
          placeholder="Scan a package  e.g. paypa1-checkout or @paypal/react-paypal-js@8.1.0"
        />
        <button onClick={handleScan}>Scan</button>
        {scanStatus && <span className="scan-status">{scanStatus}</span>}
      </div>

      <div className="grid-wrapper ag-theme-quartz-dark">
        <AgGridReact<Verdict>
          rowData={rows}
          columnDefs={COL_DEFS}
          defaultColDef={{ resizable: true, sortable: true, filter: true }}
          pagination
          paginationPageSize={20}
          domLayout="autoHeight"
          getRowId={r => `${r.data.package}@${r.data.version}@${r.data.ts}`}
        />
      </div>

      <footer>
        Verdicts timestamped with salted SHA-256 + Bitcoin anchoring via OpenTimestamps · Powered by Claude AI · PayPal Sandbox verified
      </footer>
    </div>
  )
}
