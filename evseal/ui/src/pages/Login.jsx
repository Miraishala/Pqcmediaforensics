import { useState } from 'react'
import { api } from '../api.js'

export default function Login({ setupNeeded, onDone }) {
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (e) => {
    e.preventDefault()
    setBusy(true); setErr('')
    try { await api.post('/api/auth/login', { user, passphrase: pass }); onDone() }
    catch (ex) { setErr(ex.status === 429 ? 'Too many failed attempts. Wait a few minutes.' : 'Login failed.') }
    setBusy(false)
  }
  return (
    <div className="flex h-full items-center justify-center p-6">
      <form onSubmit={submit} className="card w-full max-w-sm space-y-3">
        <div className="flex items-center gap-2">
          <img src="/favicon.svg" alt="" className="h-7 w-7" />
          <div className="font-semibold">EviSeal sign-in</div>
        </div>
        {setupNeeded && <div className="rounded-lg bg-amber-50 p-2 text-sm text-amber-800 dark:bg-amber-950/50 dark:text-amber-300">No users exist yet. Run <span className="mono">evseal user-init ADMIN</span> first.</div>}
        <p className="text-xs text-slate-500">You sign in with your own signing key. Everything you do is signed with it and recorded in a tamper-evident access log.</p>
        <label className="block text-sm">User id
          <input className="input mt-1 w-full" value={user} onChange={(e) => setUser(e.target.value)} autoFocus autoComplete="username" />
        </label>
        <label className="block text-sm">Key passphrase
          <input className="input mt-1 w-full" type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="current-password" />
        </label>
        {err && <div className="text-sm text-red-700">{err}</div>}
        <button className="btn-primary w-full justify-center" disabled={busy || !user}>Sign in</button>
      </form>
    </div>
  )
}
