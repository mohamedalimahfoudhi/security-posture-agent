import { useState } from "react";
import { Send, Bot, User, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import {
  chatConversations,
  suggestedPrompts,
  aiPlaceholderResponses,
} from "@/data/mock";
import type { ChatMessage } from "@/types";

export function AIAssistantPage() {
  const [activeConversationId, setActiveConversationId] = useState(
    chatConversations[0].id
  );
  const [messages, setMessages] = useState<ChatMessage[]>(
    chatConversations[0].messages
  );
  const [input, setInput] = useState("");

  const handleSend = (text: string) => {
    if (!text.trim()) return;

    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: "user",
      content: text.trim(),
      timestamp: new Date().toISOString(),
    };

    const responseText =
      aiPlaceholderResponses[text.trim()] ??
      "Based on my analysis of your current threat landscape, I recommend reviewing the latest alerts for affected vendors and prioritizing remediation based on CVSS scores and customer exposure. Would you like me to generate a detailed report?";

    const assistantMessage: ChatMessage = {
      id: `msg-${Date.now() + 1}`,
      role: "assistant",
      content: responseText,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMessage, assistantMessage]);
    setInput("");
  };

  const handleNewChat = () => {
    setActiveConversationId("new");
    setMessages([]);
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">AI Assistant</h1>
        <p className="text-sm text-muted-foreground">
          AI-powered threat analysis, CVE summaries, and remediation guidance.
        </p>
      </div>

      <div className="flex h-[calc(100vh-12rem)] flex-col overflow-hidden rounded-lg border border-border lg:flex-row">
        {/* Conversation history sidebar */}
        <div className="hidden w-64 shrink-0 flex-col border-r border-border bg-card lg:flex">
          <div className="border-b border-border p-3">
            <Button
              variant="outline"
              size="sm"
              className="w-full"
              onClick={handleNewChat}
            >
              <Plus className="h-4 w-4" />
              New Chat
            </Button>
          </div>
          <ScrollArea className="flex-1">
            <div className="space-y-1 p-2">
              {chatConversations.map((conv) => (
                <button
                  key={conv.id}
                  onClick={() => {
                    setActiveConversationId(conv.id);
                    setMessages(conv.messages);
                  }}
                  className={cn(
                    "w-full rounded-md px-3 py-2.5 text-left text-sm transition-colors",
                    activeConversationId === conv.id
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-muted/30 hover:text-foreground"
                  )}
                >
                  <p className="truncate font-medium">{conv.title}</p>
                  <p className="truncate text-xs opacity-70">
                    {conv.messages[conv.messages.length - 1]?.content.slice(
                      0,
                      50
                    )}
                    ...
                  </p>
                </button>
              ))}
            </div>
          </ScrollArea>
        </div>

        {/* Chat area */}
        <div className="flex flex-1 flex-col">
          <ScrollArea className="flex-1 p-4">
            {messages.length === 0 ? (
              <div className="flex h-full flex-col items-center justify-center space-y-6 py-12">
                <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/10">
                  <Bot className="h-7 w-7 text-primary" />
                </div>
                <div className="text-center">
                  <h3 className="text-lg font-semibold">
                    How can I help you today?
                  </h3>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Ask about vulnerabilities, threats, or mitigation steps.
                  </p>
                </div>
                <div className="grid w-full max-w-lg grid-cols-1 gap-2 sm:grid-cols-2">
                  {suggestedPrompts.map((prompt) => (
                    <button
                      key={prompt}
                      onClick={() => handleSend(prompt)}
                      className="rounded-lg border border-border bg-card px-4 py-3 text-left text-sm transition-colors hover:border-primary/50 hover:bg-primary/5"
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="mx-auto max-w-3xl space-y-4">
                {messages.map((message) => (
                  <div
                    key={message.id}
                    className={cn(
                      "flex gap-3",
                      message.role === "user" ? "justify-end" : "justify-start"
                    )}
                  >
                    {message.role === "assistant" && (
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/10">
                        <Bot className="h-4 w-4 text-primary" />
                      </div>
                    )}
                    <Card
                      className={cn(
                        "max-w-[80%] px-4 py-3",
                        message.role === "user"
                          ? "bg-primary text-primary-foreground border-primary"
                          : "bg-card"
                      )}
                    >
                      <p className="whitespace-pre-wrap text-sm leading-relaxed">
                        {message.content}
                      </p>
                    </Card>
                    {message.role === "user" && (
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
                        <User className="h-4 w-4" />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>

          <div className="border-t border-border p-4">
            <div className="mx-auto flex max-w-3xl gap-2">
              <Input
                placeholder="Ask about threats, CVEs, or mitigation..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSend(input);
                }}
                className="flex-1"
              />
              <Button onClick={() => handleSend(input)}>
                <Send className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
