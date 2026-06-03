import { useState, useEffect, useRef } from 'react';

export default function ChatWindow({ recipient, displayName, messages, username, onSentMessage, onRefresh, onDelete, onRevoke }) {
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [forwardMsg, setForwardMsg] = useState(null);
  const [forwardTo, setForwardTo] = useState('');
  const [forwardError, setForwardError] = useState('');
  const [forwarding, setForwarding] = useState(false);
  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    inputRef.current?.focus();
  }, [recipient]);

  async function handleForward(e) {
    e.preventDefault();
    const to = forwardTo.trim();
    if (!to || forwarding) return;
    setForwarding(true);
    setForwardError('');
    try {
      await window.messagingAPI.sendMessage({ recipient: to, plaintext: forwardMsg.plaintext });
      onSentMessage({
        message_id: crypto.randomUUID(),
        recipient: to,
        sender_id: username,
        plaintext: forwardMsg.plaintext,
        created_at: new Date().toISOString(),
      });
      setForwardMsg(null);
      setForwardTo('');
    } catch (err) {
      setForwardError(err.message);
    } finally {
      setForwarding(false);
    }
  }

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
      await window.messagingAPI.sendMessage({ recipient, plaintext: trimmed });
      onSentMessage({
        message_id: crypto.randomUUID(),
        recipient,
        sender_id: username,
        plaintext: trimmed,
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
              <span className="bubble-text">{msg.plaintext}</span>
              <div className="bubble-meta">
                <time className="bubble-time">
                  {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </time>
                <div className="bubble-actions">
                  <button
                    className="bubble-action-btn"
                    onClick={() => window.messagingAPI.downloadMessage({
                      senderName: mine ? username : (displayName ?? msg.sender_id),
                      plaintext: msg.plaintext,
                      createdAt: msg.created_at,
                    })}
                  >
                    Save
                  </button>
                  <button className="bubble-action-btn" onClick={() => { setForwardMsg(msg); setForwardTo(''); setForwardError(''); }}>
                    Forward
                  </button>
                  {!mine && onDelete && (
                    <button className="bubble-action-btn" onClick={() => onDelete(msg.message_id)}>
                      Delete
                    </button>
                  )}
                  {mine && onRevoke && (
                    <button className="bubble-action-btn" onClick={() => onRevoke(msg.message_id)}>
                      Revoke
                    </button>
                  )}
                </div>
              </div>
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

      {forwardMsg && (
        <div className="modal-overlay" onClick={() => setForwardMsg(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <h3>Forward message</h3>
            <p className="modal-preview">"{forwardMsg.plaintext}"</p>
            <form onSubmit={handleForward}>
              <input
                autoFocus
                value={forwardTo}
                onChange={e => setForwardTo(e.target.value)}
                placeholder="Recipient username"
                disabled={forwarding}
              />
              {forwardError && <p className="modal-error">{forwardError}</p>}
              <div className="modal-actions">
                <button type="button" className="modal-btn secondary" onClick={() => setForwardMsg(null)}>
                  Cancel
                </button>
                <button type="submit" className="modal-btn primary" disabled={forwarding || !forwardTo.trim()}>
                  {forwarding ? 'Sending…' : 'Forward'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
