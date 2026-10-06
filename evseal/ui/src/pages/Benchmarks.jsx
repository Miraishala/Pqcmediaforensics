import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Benchmarks() {
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [quick, setQuick] = useState(true)

  useEffect(() => {
    api.get('/api/bench/results').then((d) => setResults(d.results || [])).catch(() => {})
  }, [])

  const runBench = async () => {
    setLoading(true)
    try {
      const res = await api.post('/api/bench/run', { quick })
      setResults(res.results || [])
    } catch (err) {
      alert(`Benchmark failed: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Benchmarks</h1>
          <p className="text-sm text-slate-500">
            Parameter sweeps over throughput, RAM overhead, and RS parity (SPEC §6 item 8, SPEC §7F).
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-400">
            <input
              type="checkbox"
              checked={quick}
              onChange={(e) => setQuick(e.target.checked)}
              className="rounded"
            />
            Quick Preset Sweep (Fast)
          </label>
          <button
            onClick={runBench}
            disabled={loading}
            className="rounded bg-accent-600 px-4 py-1.5 text-xs font-medium text-white shadow hover:bg-accent-700 disabled:opacity-50"
          >
            {loading ? 'Running Benchmarks...' : 'Run Benchmark Sweep'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="text-xs text-slate-500">SPEC Reference: ML-DSA-44 Overhead</div>
          <div className="mt-1 text-2xl font-bold text-accent-600">~1.0%</div>
          <div className="mt-1 text-[11px] text-slate-400">
            At 2 Mbps video, per-second signing adds ~2.5 KB/s
          </div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="text-xs text-slate-500">SPEC Reference: Low-Storage Profile</div>
          <div className="mt-1 text-2xl font-bold text-emerald-600">~0.07%</div>
          <div className="mt-1 text-[11px] text-slate-400">
            Per-minute signing with block_segments=60
          </div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="text-xs text-slate-500">SPEC Reference: RS 10+2 Overhead</div>
          <div className="mt-1 text-2xl font-bold text-indigo-600">+20%</div>
          <div className="mt-1 text-[11px] text-slate-400">
            Parity shards; 20+2 yields +10% overhead
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <h2 className="mb-3 text-sm font-semibold">Sweep Results ({results.length})</h2>
        {results.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-400">
            No benchmark runs yet. Click "Run Benchmark Sweep" to measure live throughput and overhead.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 text-slate-400 dark:border-slate-800">
                  <th className="py-2">Configuration</th>
                  <th className="py-2">Algorithm</th>
                  <th className="py-2">Parity (k+m)</th>
                  <th className="py-2">Overhead %</th>
                  <th className="py-2">Throughput</th>
                  <th className="py-2">Real-time Factor</th>
                  <th className="py-2">RAM (Peak)</th>
                  <th className="py-2">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {results.map((r, idx) => (
                  <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="py-2.5 font-medium">{r.label}</td>
                    <td className="py-2.5 font-mono text-[11px]">{r.alg}</td>
                    <td className="py-2.5">{r.ec}</td>
                    <td className="py-2.5 font-semibold text-accent-600">{r.overhead_pct}%</td>
                    <td className="py-2.5">{r.throughput_mb_s} MB/s</td>
                    <td className="py-2.5 text-emerald-600">{r.realtime_x}x</td>
                    <td className="py-2.5 text-slate-500">{r.peak_ram_mb} MB</td>
                    <td className="py-2.5">
                      <span className="rounded bg-emerald-50 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-400">
                        {r.verified ? 'VERIFIED' : 'FAILED'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
