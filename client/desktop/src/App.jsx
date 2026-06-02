import { useState } from 'react';
import AuthScreen from './components/AuthScreen';
import ChatApp from './components/ChatApp';

export default function App() {
  const [session, setSession] = useState(() => {
    const token = localStorage.getItem('authToken');
    const username = localStorage.getItem('username');
    return token && username ? { token, username } : null;
  });

  function handleLogin(token, username) {
    localStorage.setItem('authToken', token);
    localStorage.setItem('username', username);
    setSession({ token, username });
  }

  function handleLogout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    setSession(null);
  }

  if (!session) return <AuthScreen onLogin={handleLogin} />;
  return <ChatApp username={session.username} onLogout={handleLogout} />;
}
