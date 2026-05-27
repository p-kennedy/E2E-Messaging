import { useState } from 'react';

export default function ConversationList({
  conversations, selected, onSelect, username, onLogout, onStartConvo,
}) {
  const [search, setSearch] = useState('');

  function handleSearchKey(e) {
    if (e.key === 'Enter' && search.trim()) {
      onStartConvo(search.trim());
      setSearch('');
    }
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <span className="sidebar-title">Messages</span>
        <button className="icon-btn" onClick={onLogout} title="Sign out">
          <svg viewBox="0 0 24 24" fill="none"><path d="M17 7L15.59 8.41L18.17 11H8V13H18.17L15.59 15.58L17 17L22 12L17 7ZM4 5H12V3H4C2.9 3 2 3.9 2 5V19C2 20.1 2.9 21 4 21H12V19H4V5Z" fill="currentColor"/></svg>
        </button>
      </div>

      <div className="search-bar">
        <svg viewBox="0 0 24 24" fill="none"><path d="M15.5 14H14.71L14.43 13.73C15.41 12.59 16 11.11 16 9.5C16 5.91 13.09 3 9.5 3C5.91 3 3 5.91 3 9.5C3 13.09 5.91 16 9.5 16C11.11 16 12.59 15.41 13.73 14.43L14 14.71V15.5L19 20.49L20.49 19L15.5 14ZM9.5 14C7.01 14 5 11.99 5 9.5C5 7.01 7.01 5 9.5 5C11.99 5 14 7.01 14 9.5C14 11.99 11.99 14 9.5 14Z" fill="currentColor"/></svg>
        <input
          placeholder="Search or start new chat…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={handleSearchKey}
        />
      </div>

      <ul className="convo-list">
        {conversations.length === 0 && (
          <li className="convo-empty">
            Type a username above and press Enter to start a conversation
          </li>
        )}
        {conversations.map(c => {
          const last = c.messages.at(-1);
          return (
            <li
              key={c.key}
              className={`convo-item${selected === c.key ? ' active' : ''}`}
              onClick={() => onSelect(c.key)}
            >
              <div className="avatar">{(c.displayName[0] ?? '?').toUpperCase()}</div>
              <div className="convo-info">
                <span className="convo-name">{c.displayName}</span>
                {last && (
                  <span className="convo-preview">
                    {last.direction === 'sent' ? 'You: ' : ''}{last.ciphertext?.slice(0, 45)}
                  </span>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      <div className="sidebar-footer">
        <div className="avatar sm">{(username[0] ?? '?').toUpperCase()}</div>
        <span>{username}</span>
      </div>
    </aside>
  );
}
