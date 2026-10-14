import { useState } from "react";
import { useAuth } from "./AuthContext";

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try { await login(username, password); } catch (err) { setError(err.message); } finally { setSubmitting(false); }
  };

  return <main className="min-h-screen flex items-center justify-center bg-void p-6">
    <form onSubmit={submit} className="w-full max-w-sm bg-panel border border-hairline rounded-lg p-6 space-y-4">
      <h1 className="text-xl font-semibold text-ink">AI-TIP Sign In</h1>
      <input className="w-full bg-void border border-hairline rounded p-2 text-ink" placeholder="Email or username" value={username} onChange={(e) => setUsername(e.target.value)} required />
      <input className="w-full bg-void border border-hairline rounded p-2 text-ink" type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      {error && <p className="text-sm text-ember-bright">{error}</p>}
      <button className="w-full bg-ember-bright text-white rounded p-2 disabled:opacity-50" disabled={submitting}>{submitting ? "Signing in..." : "Sign in"}</button>
    </form>
  </main>;
}
