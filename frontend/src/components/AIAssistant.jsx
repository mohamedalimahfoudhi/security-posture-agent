import { useEffect, useMemo, useRef, useState } from 'react';
import { Bot, Building, LoaderCircle, Send } from 'lucide-react';
import { chatWithAI, clearChatHistory, getAllCustomers, getChatConversations, getChatHistory } from '../api/client';

const formatInlineMarkdown = (text = '') =>
  text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((part, index) => {
    if (!part) return null;
    if (part.startsWith('**') && part.endsWith('**')) {
      return (
        <strong key={index} className="font-semibold text-ink">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code key={index} className="rounded-md bg-void px-1 py-0.5 text-[11px] text-ember-bright font-mono">
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });

const renderMarkdownBlock = (block, index) => {
  const trimmed = block.trim();

  if (/^```[\s\S]*```$/m.test(trimmed)) {
    const code = trimmed.replace(/^```.*\n?/, '').replace(/```$/, '');
    return (
      <pre key={index} className="rounded-lg bg-void px-4 py-3 text-xs text-mist font-mono overflow-x-auto border border-hairline">
        {code}
      </pre>
    );
  }

  if (/^#{1,3}\s+/.test(trimmed)) {
    const level = trimmed.match(/^#{1,3}/)[0].length;
    const content = trimmed.replace(/^#{1,3}\s+/, '');
    const sizes = ['text-lg', 'text-base', 'text-sm'];
    return (
      <p key={index} className={`font-semibold ${sizes[level - 1]} text-ink`}>
        {formatInlineMarkdown(content)}
      </p>
    );
  }

  const lines = trimmed.split('\n');
  if (lines.every((line) => /^\s*[-*]\s+/.test(line))) {
    return (
      <ul key={index} className="list-disc space-y-1 pl-5 text-sm text-ink font-body">
        {lines.map((line, idx) => (
          <li key={idx}>{formatInlineMarkdown(line.replace(/^\s*[-*]\s+/, ''))}</li>
        ))}
      </ul>
    );
  }

  if (lines.every((line) => /^\s*\d+\.\s+/.test(line))) {
    return (
      <ol key={index} className="list-decimal space-y-1 pl-5 text-sm text-ink font-body">
        {lines.map((line, idx) => (
          <li key={idx}>{formatInlineMarkdown(line.replace(/^\s*\d+\.\s+/, ''))}</li>
        ))}
      </ol>
    );
  }

  if (lines.length > 1 && lines[0].includes('|') && /^\s*[|:-]+\s*$/.test(lines[1])) {
    const headers = lines[0].split('|').map((cell) => cell.trim()).filter(Boolean);
    const rows = lines.slice(2).map((row) => row.split('|').map((cell) => cell.trim()).filter(Boolean));
    return (
      <div key={index} className="overflow-x-auto">
        <table className="w-full border-collapse text-sm text-ink font-body">
          <thead>
            <tr>
              {headers.map((header, idx) => (
                <th key={idx} className="border-b border-hairline px-3 py-2 text-left font-semibold text-ink">
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, rowIndex) => (
              <tr key={rowIndex} className={rowIndex % 2 === 0 ? 'bg-void/50' : ''}>
                {row.map((cell, idx) => (
                  <td key={idx} className="border-b border-hairline px-3 py-2">
                    {formatInlineMarkdown(cell)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <p key={index} className="whitespace-pre-wrap break-words text-sm text-ink font-body">
      {formatInlineMarkdown(trimmed)}
    </p>
  );
};

const renderMarkdown = (text) => {
  if (!text) return null;
  return text.split(/\n{2,}/g).map(renderMarkdownBlock);
};

const renderAIResponse = (response) => {
  if (!response) return null;

  if (typeof response === 'string') {
    return (
      <div className="space-y-3">
        {renderMarkdown(response)}
      </div>
    );
  }

  if (typeof response === 'object') {
    const recommendations = Array.isArray(response.recommendations)
      ? response.recommendations
      : response.recommendations
      ? [response.recommendations]
      : [];

    const affectedProducts = Array.isArray(response.affected_products)
      ? response.affected_products
      : response.affected_products
      ? [response.affected_products]
      : [];

    const renderedSections = [];

    if (response.threat_summary) {
      renderedSections.push(
        <div key="threat-summary">
          <p className="font-semibold text-ink">Threat Summary</p>
          <div className="mt-1">{renderMarkdown(response.threat_summary)}</div>
        </div>
      );
    }

    if (response.notes) {
      renderedSections.push(
        <div key="notes">
          <p className="font-semibold text-ink">Summary</p>
          <div className="mt-1">{renderMarkdown(response.notes)}</div>
        </div>
      );
    }

    if (response.severity) {
      renderedSections.push(
        <div key="severity">
          <p className="font-semibold text-ink">Severity</p>
          <p className="text-sm text-ink font-body">{response.severity}</p>
        </div>
      );
    }

    if (response.risk_score !== undefined && response.risk_score !== null) {
      renderedSections.push(
        <div key="risk-score">
          <p className="font-semibold text-ink">Risk Score</p>
          <p className="text-sm text-ink font-body">{response.risk_score}</p>
        </div>
      );
    }

    if (response.exploitation_risk) {
      renderedSections.push(
        <div key="exploitation-risk">
          <p className="font-semibold text-ink">Exploitation Risk</p>
          <div className="mt-1">{renderMarkdown(response.exploitation_risk)}</div>
        </div>
      );
    }

    if (affectedProducts.length > 0) {
      renderedSections.push(
        <div key="affected-products">
          <p className="font-semibold text-ink">Affected Products</p>
          <ul className="list-disc list-inside text-sm text-ink font-body">
            {affectedProducts.map((product, idx) => (
              <li key={idx}>{product}</li>
            ))}
          </ul>
        </div>
      );
    }

    if (recommendations.length > 0) {
      renderedSections.push(
        <div key="recommendations">
          <p className="font-semibold text-ink">Recommendations</p>
          <ul className="list-disc list-inside text-sm text-ink font-body">
            {recommendations.map((item, idx) => (
              <li key={idx}>{item}</li>
            ))}
          </ul>
        </div>
      );
    }

    if (response.error) {
      renderedSections.push(
        <div key="error">
          <p className="font-semibold text-ink">Error</p>
          <p className="text-sm text-ink font-body">{response.error}</p>
        </div>
      );
    }

    if (renderedSections.length === 0) {
      renderedSections.push(
        <div key="fallback">
          <p className="font-semibold text-ink">AI analysis returned no structured fields.</p>
          <p className="text-sm text-mist font-body">Raw response is shown below.</p>
        </div>
      );
    }

    return (
      <div className="space-y-3 text-sm text-ink font-body">
        {renderedSections}
        {response.raw_response && (
          <div>
            <p className="font-semibold text-ink">Raw AI Response</p>
            <pre className="whitespace-pre-wrap overflow-x-auto text-xs bg-void p-3 rounded-md border border-hairline font-mono">
              {typeof response.raw_response === 'string'
                ? response.raw_response
                : JSON.stringify(response.raw_response, null, 2)}
            </pre>
          </div>
        )}
      </div>
    );
  }

  return <p className="text-sm text-ink font-body">Unsupported AI response format.</p>;
};

const suggestionPrompts = [
  'Explain CVE-2026-XXXX',
  'Analyze IOC activity',
  'Summarize the latest threat feed',
  'Map an incident to MITRE ATT&CK',
  'Review vendor risk exposure',
  'Generate detection rules for suspicious behavior'
];

export default function AIAssistant({ selectedCustomerId = null, role = null }) {
  const [prompt, setPrompt] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [selectedConversationId, setSelectedConversationId] = useState(null);
  const [pendingMessage, setPendingMessage] = useState(null);
  // Resolved name of the active customer context (for display)
  const [activeCustomerName, setActiveCustomerName] = useState(null);
  const chatEndRef = useRef(null);
  const inputRef = useRef(null);

  // Resolve customer name for the context banner (Admin only)
  useEffect(() => {
    if (role !== 'Admin' || !selectedCustomerId) {
      setActiveCustomerName(null);
      return;
    }
    getAllCustomers()
      .then(customers => {
        const found = customers.find(c => c.id === selectedCustomerId);
        setActiveCustomerName(found?.name || `Customer #${selectedCustomerId}`);
      })
      .catch(() => setActiveCustomerName(`Customer #${selectedCustomerId}`));
  }, [selectedCustomerId, role]);

  const loadConversations = async () => {
    try {
      const convResult = await getChatConversations();
      setConversations(convResult.conversations || []);
      return convResult.conversations || [];
    } catch (err) {
      console.error('Failed to load AI chat conversations:', err);
      return [];
    }
  };

  const loadConversationHistory = async (conversationId) => {
    try {
      const result = await getChatHistory(conversationId);
      setSelectedConversationId(result.conversation_id || null);
      setHistory(
        result.history.map((entry) => ({
          id: entry.id,
          prompt: entry.message,
          response: entry.response,
          timestamp: entry.created_at ? new Date(entry.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
        }))
      );
    } catch (err) {
      console.error('Failed to load AI chat history:', err);
      setHistory([]);
    }
  };

  useEffect(() => {
    const initializeChat = async () => {
      await loadConversations();
      await loadConversationHistory();
    };

    initializeChat();
  }, []);

  useEffect(() => {
    if (!inputRef.current) return;
    inputRef.current.style.height = 'auto';
    inputRef.current.style.height = `${Math.min(inputRef.current.scrollHeight, 170)}px`;
  }, [prompt]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [history, pendingMessage, loading]);

  const startNewConversation = () => {
    setSelectedConversationId(null);
    setHistory([]);
    setPendingMessage(null);
    setError(null);
    setPrompt('');
  };

  const handleSelectConversation = async (conversationId) => {
    if (conversationId === selectedConversationId) return;
    setPendingMessage(null);
    await loadConversationHistory(conversationId);
  };

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    const trimmedPrompt = prompt.trim();
    if (!trimmedPrompt || loading) return;

    setError(null);
    setPendingMessage(trimmedPrompt);
    setPrompt('');
    setLoading(true);

    try {
      // Forward selectedCustomerId so the backend uses the correct RAG context.
      // Backend enforces authorization — non-admins will get 403 if mismatch.
      const result = await chatWithAI(trimmedPrompt, selectedConversationId, selectedCustomerId);
      const newConversationId = result.conversation_id;
      // Clear optimistic message BEFORE loading server state to prevent
      // the pending message and the server-fetched version from coexisting
      // in displayedMessages, which caused garbled double-rendering.
      setPendingMessage(null);
      await loadConversations();
      await loadConversationHistory(newConversationId);
    } catch (err) {
      console.error('AI analysis failed:', err);
      setError('Failed to get AI response');
      setPendingMessage(null);
    } finally {
      setLoading(false);
    }
  };

  const clearConversation = async () => {
    if (!selectedConversationId) return;

    try {
      await clearChatHistory(selectedConversationId);
      const convs = await loadConversations();
      const nextConversationId = convs[0]?.conversation_id || convs[0]?.id || null;
      if (nextConversationId) {
        await loadConversationHistory(nextConversationId);
      } else {
        setSelectedConversationId(null);
        setHistory([]);
      }
    } catch (err) {
      console.error('Failed to clear AI chat history:', err);
      setError('Failed to clear history');
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const displayedMessages = [...history];
  if (pendingMessage) {
    displayedMessages.push({
      id: 'pending-user-message',
      prompt: pendingMessage,
      response: null,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      pending: true
    });
  }

  const hasMessages = displayedMessages.length > 0;
  const activeConversation = conversations.find((conv) => (conv.conversation_id || conv.id) === selectedConversationId);
  const currentTitle = activeConversation?.title || 'New conversation';
  const currentSummary = activeConversation
    ? `${activeConversation.message_count} message${activeConversation.message_count === 1 ? '' : 's'}`
    : 'Start a new chat with AI-TIP.';

  return (
    <div className="flex h-full overflow-hidden">
      {/* Sidebar */}
      <aside className="w-[280px] min-w-[260px] border-r border-hairline bg-panel flex flex-col">
        <div className="p-4 border-b border-hairline">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold font-display text-ink">AI-TIP Chat</h2>
              <p className="text-xs text-mist font-body mt-1">Conversations</p>
            </div>
            <button
              onClick={startNewConversation}
              className="flex items-center justify-center w-8 h-8 rounded-lg border border-hairline bg-void text-mist hover:border-ember-bright hover:text-ember-bright transition-colors"
              aria-label="New conversation"
            >
              +
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-3">
          <div className="space-y-2">
            {conversations.length === 0 ? (
              <div className="bg-void border border-hairline rounded-lg p-3 text-xs text-mist font-body">
                No conversations yet. Start a new chat.
              </div>
            ) : (
              conversations.map((conv) => {
                const conversationId = conv.conversation_id || conv.id;
                const isActive = conversationId === selectedConversationId;
                return (
                  <button
                    key={conversationId}
                    onClick={() => handleSelectConversation(conversationId)}
                    className={`w-full rounded-lg border px-3 py-3 text-left transition-colors ${isActive ? 'border-ember-bright bg-ember-bright/10 text-ink' : 'border-hairline bg-void text-mist hover:border-ember-dim hover:text-ink'}`}
                  >
                    <p className="text-sm font-semibold font-body leading-5 line-clamp-2">{conv.title}</p>
                    <p className="mt-1 text-xs text-mist font-body">{conv.message_count} message{conv.message_count === 1 ? '' : 's'}</p>
                    {conv.last_updated && <p className="mt-0.5 text-xs text-mist/70 font-body">{new Date(conv.last_updated).toLocaleString()}</p>}
                  </button>
                );
              })
            )}
          </div>
        </div>

        <div className="p-3 border-t border-hairline">
          <button
            onClick={clearConversation}
            disabled={!selectedConversationId}
            className="w-full rounded-lg border border-hairline bg-void px-3 py-2 text-left text-xs text-mist font-body transition-colors hover:border-ember-bright disabled:cursor-not-allowed disabled:opacity-50"
          >
            Clear current conversation
          </button>
        </div>
      </aside>

      {/* Main Chat Area */}
      <div className="flex flex-1 min-w-0 flex-col">
        {/* Header */}
        <div className="bg-panel border-b border-hairline p-4 flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold font-display text-ink">{currentTitle}</h1>
            <p className="text-xs text-mist font-body mt-1">{currentSummary}</p>
          </div>
          <div className="flex items-center gap-2">
            {/* Admin AI Context indicator */}
            {role === 'Admin' && activeCustomerName && (
              <span className="inline-flex items-center gap-1.5 text-xs bg-void border border-hairline rounded-md px-2 py-1 text-mist">
                <Building className="w-3 h-3 text-ember-bright" />
                <span className="font-body">AI Context: <span className="text-ink font-medium">{activeCustomerName}</span></span>
              </span>
            )}
            {loading && (
              <span className="inline-flex items-center gap-2 text-xs font-mono text-ember-bright">
                <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> Analyzing…
              </span>
            )}
            <button
              type="button"
              onClick={startNewConversation}
              className="text-xs text-mist hover:text-ink font-body transition-colors"
            >
              New Chat
            </button>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {hasMessages || loading ? (
            <>
              {displayedMessages.map((entry) => (
                <div key={entry.id} className="space-y-2">
                  {/* User message */}
                  <div className="bg-void rounded-lg p-3 border border-hairline">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-mist">{entry.timestamp}</span>
                    </div>
                    <p className="text-sm text-ink font-body">{entry.prompt}</p>
                  </div>
                  {/* AI response */}
                  {entry.response !== null && (
                    <div className="bg-panel rounded-lg p-3 border-l-2 border-ember-bright">
                      <div className="flex items-center gap-2 mb-2">
                        <Bot className="w-4 h-4 text-ember-bright" />
                        <span className="text-xs font-mono text-ember-bright">AI-TIP Response</span>
                      </div>
                      {renderAIResponse(entry.response)}
                    </div>
                  )}
                </div>
              ))}
              {loading && (
                <div className="bg-panel rounded-lg p-3 border-l-2 border-ember-bright">
                  <div className="flex items-center gap-2">
                    <LoaderCircle className="h-4 w-4 animate-spin text-ember-bright" />
                    <span className="text-sm text-mist font-body">AI-TIP is analyzing…</span>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <Bot className="w-12 h-12 text-mist mb-4" />
              <p className="text-sm text-mist font-body mb-2">
                Ask about vulnerabilities and receive structured analysis results.
              </p>
              <p className="text-xs text-mist font-body mb-6">
                Example: "Analyze the critical vulnerabilities for customer BIAT"
              </p>
              <div className="grid gap-2 sm:grid-cols-2 max-w-lg">
                {suggestionPrompts.map((suggestion) => (
                  <button
                    key={suggestion}
                    type="button"
                    onClick={() => setPrompt(suggestion)}
                    className="rounded-lg border border-hairline bg-void px-3 py-2 text-left text-xs text-mist font-body transition-colors hover:border-ember-bright hover:text-ink"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            </div>
          )}

          {error && (
            <div className="bg-void rounded-lg p-3 border-l-2 border-ember-bright">
              <p className="text-sm text-ember-bright font-body">{error}</p>
            </div>
          )}

          <div ref={chatEndRef} />
        </div>

        {/* Input Area */}
        <div className="bg-panel border-t border-hairline p-4">
          <form onSubmit={handleSubmit} className="flex gap-2">
            <textarea
              ref={inputRef}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about security posture, vulnerabilities, or risk..."
              rows={1}
              disabled={loading}
              className="flex-1 bg-void border border-hairline rounded-lg px-4 py-2 text-sm text-ink font-body placeholder-mist focus:outline-none focus:border-ember-bright disabled:opacity-50 resize-none min-h-[40px]"
            />
            <button
              type="submit"
              disabled={loading || !prompt.trim()}
              className="bg-ember-bright hover:bg-ember-bright/80 text-void rounded-lg px-4 py-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <span className="text-sm font-body">Analyzing...</span>
              ) : (
                <Send className="w-4 h-4" />
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
