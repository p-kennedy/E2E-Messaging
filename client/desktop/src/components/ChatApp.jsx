import { useState, useEffect, useCallback } from 'react';
import { getMyUserId } from '../api';
import ConversationList from './ConversationList';
import ChatWindow from './ChatWindow';

// Group all messages into conversations keyed by the other party.
// Received messages use sender_id (UUID); sent messages use recipient username.
// TODO: add GET /api/users/{id} to the server to resolve UUIDs to usernames.
function buildConversations(received, sent, myUserId) {
  const convos = {};

  for (const msg of received) {
    const key = msg.sender_username ?? msg.sender_id;
    const displayName = msg.sender_username ?? shortId(msg.sender_id);
    if (!convos[key]) convos[key] = { key, displayName, messages: [] };
    convos[key].messages.push({ ...msg, direction: 'received' });
  }

  for (const msg of sent) {
    const key = msg.recipient;
    if (!convos[key]) convos[key] = { key, displayName: msg.recipient, messages: [] };
    convos[key].messages.push({ ...msg, direction: 'sent' });
  }

  // Sort each conversation's messages chronologically
  for (const c of Object.values(convos)) {
    c.messages.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  }

  return convos;
}

function shortId(uuid) {
  return `User ${uuid?.slice(0, 8) ?? '?'}`;
}

export default function ChatApp({ username, onLogout }) {
  const [received, setReceived] = useState([]);
  const [sent, setSent] = useState([]);
  const [selected, setSelected] = useState(null);
  const myUserId = getMyUserId();

  const loadMessages = useCallback(async () => {
    try {
      const messages = await window.messagingAPI.fetchMessages();
      if (messages.length > 0) {
        setReceived(prev => {
          const existingIds = new Set(prev.map(m => m.message_id));
          const fresh = messages.filter(m => !existingIds.has(m.message_id));
          return fresh.length > 0 ? [...prev, ...fresh] : prev;
        });
      }
    } catch (err) {
      console.error('Failed to poll messages:', err);
    }
  }, []);

  useEffect(() => {
    async function init() {
      try {
        const history = await window.messagingAPI.fetchReceivedMessages();
        if (history.length > 0) {
          const seen = new Set();
          setReceived(history.filter(m => seen.has(m.message_id) ? false : seen.add(m.message_id)));
        }
      } catch (err) {
        console.error('Failed to load received history:', err);
      }
      await loadMessages();
      try {
        const history = await window.messagingAPI.fetchSentMessages();
        setSent(history);
      } catch (err) {
        console.error('Failed to load sent history:', err);
      }
    }
    init();
    const id = setInterval(loadMessages, 5000);
    return () => clearInterval(id);
  }, [loadMessages]);

  const conversations = buildConversations(received, sent, myUserId);
  const selectedMessages = selected ? (conversations[selected]?.messages ?? []) : [];

  async function handleDelete(messageId) {
    await window.messagingAPI.deleteMessage({ messageId });
    setReceived(prev => prev.filter(m => m.message_id !== messageId));
  }

  async function handleRevoke(messageId) {
    await window.messagingAPI.revokeMessage({ messageId });
    setSent(prev => prev.filter(m => m.message_id !== messageId));
  }

  function handleSentMessage(msg) {
    setSent(prev => [...prev, msg]);
    setSelected(msg.recipient);
  }

  return (
    <div className="chat-app">
      <ConversationList
        conversations={Object.values(conversations)}
        selected={selected}
        onSelect={setSelected}
        username={username}
        onLogout={onLogout}
        onStartConvo={name => setSelected(name)}
      />
      <ChatWindow
        recipient={selected}
        displayName={conversations[selected]?.displayName ?? selected}
        messages={selectedMessages}
        username={username}
        onSentMessage={handleSentMessage}
        onRefresh={loadMessages}
        onDelete={handleDelete}
        onRevoke={handleRevoke}
      />
    </div>
  );
}
