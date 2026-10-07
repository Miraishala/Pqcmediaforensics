import { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Audit() {
  const [users, setUsers] = useState([])
  const [log, setLog] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    api.get('/api/audit/users').then((d) => setUsers(d.users)).catch((e) => setErr(e.message))
    api.get('/api/audit/log?limit=100').then(setLog).catch((e) => setErr(e.message))
  }, [])
  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <h1 className="h1">Access &amp; audit</h1>
      {err && <div className="card text-sm text-red-700">{err}</div>}
      {log && <div className={`card text-sm ${log.intact ? 'text-emerald-700' : 'text-red-700'}`}>
        {log.intact ? '✓ Access log intact' : '✕ Access log damaged'}: {log.entries} signed, hash-chained entries
      </div>}
      <div className="card">
        <div className="mb-2 font-semibold">Users</div>
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-1">User</th><th>Role</th><th>Status</th><th>Key</th></tr></thead>
          <tbody>{users.map((u) => (
            <tr key={u.id} className="border-t border-slate-200 dark:border-slate-800">
              <td className="py-1">{u.id}</td><td>{u.role}</td><td>{u.active ? 'active' : 'revoked'}</td>
              <td className="mono text-xs text-slate-500">{u.alg} {u.fp.slice(0, 16)}…</td>
            </tr>))}</tbody>
        </table>
      </div>
      <div className="card">
        <div className="mb-2 font-semibold">Recent signed entries</div>
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-1">#</th><th>Who</th><th>Action</th><th>Detail</th></tr></thead>
          <tbody>{(log?.tail || []).slice().reverse().map((r) => (
            <tr key={r.seq} className="border-t border-slate-200 dark:border-slate-800">
              <td className="py-1">{r.seq}</td><td>{r.actor_id}</td><td>{r.action}</td>
              <td className="mono text-xs text-slate-500">{JSON.stringify(r.detail).slice(0, 90)}</td>
            </tr>))}</tbody>
        </table>
      </div>
    </div>
  )
}
