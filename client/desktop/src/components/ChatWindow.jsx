import { useState, useEffect, useRef } from 'react';
import { api } from '../api';

export default function ChatWindow({ recipient, displayName, messages, username, onSentMessage, onRefresh }) {
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    inputRef.current?.focus();
  }, [recipient]);

  if (!recipient) {
    return (
      <div className="chat-window empty">
        <div className="empty-state">
          <svg viewBox="0 0 24 24" fill="none"><path d="M20 2H4C2.9 2 2 2.9 2 4V22L6 18H20C21.1 18 22 17.1 22 16V4C22 2.9 21.1 2 20 2ZM20 16H6L4 18V4H20V16Z" fill="currentColor"/></svg>
          <p>Select a conversation or search for someone to message</p>
        </div>
      </div>
    );
  }

  async function handleSend(e) {
    e.preventDefault();
    const trimmed = text.trim();
    if (!trimmed || sending) return;
    setSending(true);
    setError('');
    try {
      // TODO: replace ciphertext with real E2E-encrypted payload once crypto layer is integrated
      await api.sendMessage(recipient, trimmed, '', '');
      onSentMessage({
        message_id: crypto.randomUUID(),
        recipient,
        sender_id: username,
        ciphertext: trimmed,
        created_at: new Date().toISOString(),
      });
      setText('');
      onRefresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="chat-window">
      <header className="chat-header">
        <div className="avatar">{(displayName[0] ?? '?').toUpperCase()}</div>
        <div className="chat-header-info">
          <span className="chat-header-name">{displayName}</span>
        </div>
      </header>

      <div className="messages">
        {messages.length === 0 && (
          <div className="no-messages">No messages yet — say hello!</div>
        )}
        {messages.map(msg => {
          const mine = msg.direction === 'sent' || msg.sender_id === username;
          return (
            <div key={msg.message_id} className={`bubble ${mine ? 'mine' : 'theirs'}`}>
              <span className="bubble-text">{msg.ciphertext}</span>
              <time className="bubble-time">
                {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </time>
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>

      {error && <div className="send-error">{error}</div>}

      <form className="message-form" onSubmit={handleSend}>
        <input
          ref={inputRef}
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder={`Message ${displayName}…`}
          disabled={sending}
        />
        <button type="submit" disabled={sending || !text.trim()}>
          <svg viewBox="0 0 24 24" fill="none"><path d="M2.01 21L23 12L2.01 3L2 10L17 12L2 14L2.01 21Z" fill="currentColor"/></svg>
        </button>
      </form>
    </div>
  );
}
