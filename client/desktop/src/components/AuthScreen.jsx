import { useState } from 'react';
import { api } from '../api';

export default function AuthScreen({ onLogin }) {
  const [mode, setMode] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (mode === 'register') {
        // TODO: generate real keypair for E2E encryption and pass real public key
        await api.register(username, password, 'placeholder-public-key');
      }
      const { token } = await api.login(username, password);
      onLogin(token, username);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-logo">
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2C6.48 2 2 6.48 2 12C2 17.52 6.48 22 12 22C17.52 22 22 17.52 22 12C22 6.48 17.52 2 12 2ZM17 8H15C15 6.34 13.66 5 12 5C10.34 5 9 6.34 9 8H7C6.45 8 6 8.45 6 9V19C6 19.55 6.45 20 7 20H17C17.55 20 18 19.55 18 19V9C18 8.45 17.55 8 17 8ZM12 17C10.9 17 10 16.1 10 15C10 13.9 10.9 13 12 13C13.1 13 14 13.9 14 15C14 16.1 13.1 17 12 17ZM13.1 8H10.9C10.9 7.4 11.4 6.9 12 6.9C12.6 6.9 13.1 7.4 13.1 8Z" fill="currentColor"/>
          </svg>
        </div>
        <h1>E2E Messenger</h1>
        <div className="auth-tabs">
          <button className={mode === 'login' ? 'active' : ''} onClick={() => { setMode('login'); setError(''); }}>
            Sign in
          </button>
          <button className={mode === 'register' ? 'active' : ''} onClick={() => { setMode('register'); setError(''); }}>
            Register
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="field">
            <label>Username</label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="Enter your username"
              required
              autoFocus
              autoComplete="username"
            />
          </div>
          <div className="field">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Enter your password"
              required
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            />
          </div>
          {error && <p className="auth-error">{error}</p>}
          <button type="submit" className="submit-btn" disabled={loading}>
            {loading ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
          </button>
        </form>
      </div>
    </div>
  );
}
