import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Doctor() {
  const [d, setD] = useState(null)
  useEffect(() => { api.get('/api/doctor').then(setD) }, [])
  if (!d) return <div className="text-sm">Checking environment…</div>
  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <h1 className="h1">Environment <span className="text-sm font-normal text-slate-500">(evseal doctor)</span></h1>
      <div className={`card text-sm ${d.ok ? 'text-emerald-700' : 'text-red-700'}`}>{d.ok ? '✓ Ready' : '✕ Not ready'} · Python {d.python_version} · {d.os}</div>
      <div className="grid gap-3 md:grid-cols-3">
        {['ffmpeg', 'ffprobe', 'zfec'].map((k) => (
          <div key={k} className="card text-sm"><div className="font-semibold">{d[k].ok ? '✓' : '✕'} {k}</div><div className="mono text-slate-500">{d[k].detail}</div></div>
        ))}
      </div>
      <div className="card">
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-1">Algorithm</th><th>Family</th><th>Backend</th><th>Note</th></tr></thead>
          <tbody>{d.algorithms.map((a) => (
            <tr key={a.name} className="border-t border-slate-200 dark:border-slate-800">
              <td className="py-1">{a.name}</td><td>{a.family}</td>
              <td>{a.backend === 'liboqs' ? '✓ liboqs' : a.backend === 'pure-python' ? '⚠ pure-python' : a.backend || '✕ none'}</td>
              <td className={`text-xs ${a.backend === 'pure-python' ? 'text-amber-700 dark:text-amber-400' : 'text-slate-500'}`}>{a.note}</td>
            </tr>))}</tbody>
        </table>
      </div>
    </div>
  )
}
