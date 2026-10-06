import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function StressLab() {
  const [scenarios, setScenarios] = useState([])
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [seed, setSeed] = useState(1)
  const [full, setFull] = useState(false)
  const [selectedScenario, setSelectedScenario] = useState('')
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    api.get('/api/stress/scenarios').then((d) => setScenarios(d.scenarios || [])).catch(() => {})
  }, [])

  const runMatrix = async (ids = null) => {
    setLoading(true)
    try {
      const res = await api.post('/api/stress/run', {
        ids: ids ? [ids] : (selectedScenario ? [selectedScenario] : null),
        seed: Number(seed) || 1,
        full,
      })
      setResults(res)
    } catch (err) {
      alert(`Stress run failed: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const filtered = scenarios.filter((s) => {
    if (filter === 'fast') return !s.slow
    if (filter === 'slow') return s.slow
    if (filter === 'compare') return s.kind === 'compare'
    if (filter === 'crash') return s.kind === 'crash'
    return true
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Stress Lab</h1>
          <p className="text-sm text-slate-500">
            Fault injection, attacks, and verification matrix against expected verdicts (SPEC §7).
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
            Seed:
            <input
              type="number"
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
              className="w-16 rounded border border-slate-300 px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-800"
            />
          </label>
          <label className="flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-400">
            <input
              type="checkbox"
              checked={full}
              onChange={(e) => setFull(e.target.checked)}
              className="rounded"
            />
            Include Slow Scenarios
          </label>
          <button
            onClick={() => runMatrix(null)}
            disabled={loading}
            className="rounded bg-accent-600 px-4 py-1.5 text-xs font-medium text-white shadow hover:bg-accent-700 disabled:opacity-50"
          >
            {loading ? 'Running...' : 'Run Selected Matrix'}
          </button>
        </div>
      </div>

      {results && (
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between pb-3">
            <h2 className="text-sm font-semibold">
              Matrix Run Results (Seed: {results.seed})
            </h2>
            <div className="flex items-center gap-3 text-xs">
              <span className="font-semibold text-emerald-600">
                ✓ {results.passed} Passed
              </span>
              {results.failed > 0 && (
                <span className="font-semibold text-rose-600">
                  ✗ {results.failed} Failed
                </span>
              )}
              <span className="text-slate-500">
                Total: {results.total}
              </span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 text-slate-400 dark:border-slate-800">
                  <th className="py-2">Status</th>
                  <th className="py-2">Scenario</th>
                  <th className="py-2">Expected</th>
                  <th className="py-2">Actual</th>
                  <th className="py-2">Time</th>
                  <th className="py-2">Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {results.results.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="py-2.5">
                      {r.pass ? (
                        <span className="inline-flex items-center rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-400">
                          PASS
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded-full bg-rose-50 px-2 py-0.5 text-[11px] font-medium text-rose-700 dark:bg-rose-950/60 dark:text-rose-400">
                          MISMATCH
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 font-medium">{r.id}</td>
                    <td className="py-2.5 text-slate-500 font-mono text-[11px]">
                      {JSON.stringify(r.expected)}
                    </td>
                    <td className="py-2.5 font-mono text-[11px]">
                      {r.actual.overall || r.actual.verdict || (r.actual.error ? 'CRASH' : '-')}
                    </td>
                    <td className="py-2.5 text-slate-500">{r.seconds}s</td>
                    <td className="py-2.5 text-rose-600 dark:text-rose-400">
                      {r.mismatches?.length ? r.mismatches.join('; ') : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Available Scenarios ({filtered.length})</h2>
          <div className="flex gap-2 text-xs">
            {['all', 'fast', 'slow', 'compare', 'crash'].map((k) => (
              <button
                key={k}
                onClick={() => setFilter(k)}
                className={`rounded px-2.5 py-1 ${
                  filter === k
                    ? 'bg-slate-200 font-semibold text-slate-900 dark:bg-slate-700 dark:text-white'
                    : 'text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                {k.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-100 text-slate-400 dark:border-slate-800">
                <th className="py-2">Scenario ID</th>
                <th className="py-2">Title</th>
                <th className="py-2">Type</th>
                <th className="py-2">Media</th>
                <th className="py-2">Attack / Fault</th>
                <th className="py-2">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {filtered.map((s) => (
                <tr key={s.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <td className="py-2.5 font-medium">{s.id}</td>
                  <td className="py-2.5 text-slate-600 dark:text-slate-300">{s.title || '-'}</td>
                  <td className="py-2.5">
                    <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                      {s.slow ? 'SLOW' : 'FAST'} · {s.kind}
                    </span>
                  </td>
                  <td className="py-2.5 text-slate-500">{s.media}</td>
                  <td className="py-2.5 text-slate-500">{s.attack || '-'}</td>
                  <td className="py-2.5">
                    <button
                      onClick={() => runMatrix(s.id)}
                      disabled={loading}
                      className="rounded border border-slate-300 px-2 py-0.5 text-[11px] hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:hover:bg-slate-800"
                    >
                      Run
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
