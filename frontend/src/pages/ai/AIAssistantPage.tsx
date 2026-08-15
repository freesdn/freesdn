// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - AI Assistant Page
 *
 * Chat interface for the AI assistant module.
 * Features: conversation list sidebar, message thread, tool call visualization,
 * provider/model selector, markdown rendering.
 */

import { useState, useRef, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Brain,
  Plus,
  Send,
  Trash2,
  ChevronDown,
  ChevronRight,
  Wrench,
  AlertCircle,
  Loader2,
  MessageSquare,
  Settings,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { cn } from '@/lib/utils';


// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface ConversationSummary {
  id: string;
  title: string | null;
  provider: string;
  model: string;
  total_tokens: number;
  created_at: string;
  message_count: number;
}

interface Message {
  id: string;
  role: 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls: ToolCallRecord[] | null;
  tool_call_id: string | null;
  tool_name: string | null;
  created_at: string;
}

interface ToolCallRecord {
  id: string;
  // Persisted shape is the OpenAI-style envelope: { id, type, function: { name, arguments } }
  // where `arguments` is a JSON-encoded string. Older/normalized rows may use flat name/arguments.
  type?: string;
  function?: {
    name?: string;
    arguments?: string;
  };
  name?: string;
  arguments?: Record<string, unknown>;
}

interface ConversationDetail extends ConversationSummary {
  messages: Message[];
}

interface ChatResponse {
  conversation_id: string;
  message: string;
  tool_calls_executed: string[];
  provider: string;
  model: string;
}


// ─────────────────────────────────────────────────────────────────────────────
// Tool call visualization
// ─────────────────────────────────────────────────────────────────────────────

function ToolCallPanel({ message }: { message: Message }) {
  const { t } = useTranslation('ai');
  const [expanded, setExpanded] = useState(false);

  if (message.role === 'assistant' && message.tool_calls && message.tool_calls.length > 0) {
    const toolCount = message.tool_calls.length;
    return (
      <div className="mt-2 rounded border border-violet-200 bg-violet-50 dark:border-violet-800 dark:bg-violet-950/30">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex w-full items-center gap-2 px-3 py-2 text-xs text-violet-700 hover:bg-violet-100 dark:text-violet-300 dark:hover:bg-violet-900/30"
        >
          {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          <Wrench className="h-3 w-3" />
          <span>
            {toolCount > 1
              ? t('AIAssistantPage.toolCall.calledToolsPlural', { count: toolCount })
              : t('AIAssistantPage.toolCall.calledTools', { count: toolCount })}
          </span>
        </button>
        {expanded && (
          <div className="border-t border-violet-200 px-3 pb-3 pt-2 dark:border-violet-800">
            {message.tool_calls.map((tc) => {
              const name = tc.function?.name ?? tc.name ?? '';
              let args: unknown = tc.arguments;
              if (tc.function?.arguments !== undefined) {
                try {
                  args = JSON.parse(tc.function.arguments || '{}');
                } catch {
                  // Leave raw string if it isn't valid JSON
                  args = tc.function.arguments;
                }
              }
              return (
                <div key={tc.id} className="mt-2 text-xs">
                  <span className="font-mono font-semibold text-violet-700 dark:text-violet-300">{name}</span>
                  <pre className="mt-1 overflow-x-auto rounded bg-violet-100 p-2 text-xs text-violet-800 dark:bg-violet-900/50 dark:text-violet-200">
                    {JSON.stringify(args, null, 2)}
                  </pre>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  if (message.role === 'tool') {
    return (
      <div className="mt-2 rounded border border-green-200 bg-green-50 px-3 py-2 dark:border-green-800 dark:bg-green-950/30">
        <div className="flex items-center gap-2 text-xs text-green-700 dark:text-green-300">
          <Wrench className="h-3 w-3" />
          <span className="font-mono font-semibold">{message.tool_name}</span>
          <span className="text-muted-foreground">{t('AIAssistantPage.toolCall.result')}</span>
        </div>
        {message.content && (
          <pre className="mt-1 overflow-x-auto text-xs text-green-800 dark:text-green-200">
            {message.content.length > 300
              ? message.content.slice(0, 300) + '...'
              : message.content}
          </pre>
        )}
      </div>
    );
  }

  return null;
}


// ─────────────────────────────────────────────────────────────────────────────
// Message bubble
// ─────────────────────────────────────────────────────────────────────────────

function MessageBubble({ message }: { message: Message }) {
  const { t } = useTranslation('ai');
  const isUser = message.role === 'user';
  const isAssistant = message.role === 'assistant';
  const isTool = message.role === 'tool';

  if (isTool) {
    return <ToolCallPanel message={message} />;
  }

  return (
    <div className={cn('flex gap-3', isUser && 'flex-row-reverse')}>
      <div
        className={cn(
          'flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full text-xs font-semibold',
          isUser
            ? 'bg-primary text-primary-foreground'
            : 'bg-violet-100 text-violet-700 dark:bg-violet-900 dark:text-violet-300'
        )}
      >
        {isUser ? 'U' : <Brain className="h-4 w-4" />}
      </div>
      <div className={cn('flex max-w-[80%] flex-col', isUser && 'items-end')}>
        <div
          className={cn(
            'rounded-lg px-4 py-2.5 text-sm',
            isUser
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted text-foreground'
          )}
        >
          {isAssistant && !message.content && message.tool_calls ? (
            <span className="text-muted-foreground italic">{t('AIAssistantPage.message.usingTools')}</span>
          ) : (
            <p className="whitespace-pre-wrap break-words">{message.content}</p>
          )}
        </div>
        {isAssistant && <ToolCallPanel message={message} />}
        <span className="mt-1 text-xs text-muted-foreground">
          {new Date(message.created_at).toLocaleTimeString()}
        </span>
      </div>
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Conversation sidebar item
// ─────────────────────────────────────────────────────────────────────────────

function ConversationItem({
  conv,
  isActive,
  onSelect,
  onDelete,
}: {
  conv: ConversationSummary;
  isActive: boolean;
  onSelect: () => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation('ai');
  const [showDelete, setShowDelete] = useState(false);

  return (
    <div
      className={cn(
        'group flex cursor-pointer items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors',
        isActive
          ? 'bg-violet-100 text-violet-900 dark:bg-violet-900/40 dark:text-violet-100'
          : 'hover:bg-muted'
      )}
      onClick={onSelect}
      onMouseEnter={() => setShowDelete(true)}
      onMouseLeave={() => setShowDelete(false)}
    >
      <MessageSquare className="h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" />
      <span className="flex-1 truncate">
        {conv.title || t('AIAssistantPage.conversation.untitled')}
      </span>
      {showDelete && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete();
          }}
          className="flex-shrink-0 rounded p-0.5 text-muted-foreground hover:text-destructive"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────────────────────────────────────

export default function AIAssistantPage() {
  const { t } = useTranslation('ai');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeConvId, setActiveConvId] = useState<string | null>(null);
  const [inputValue, setInputValue] = useState('');
  const [provider, setProvider] = useState('openai');
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Load conversations list
  const { data: conversations = [], isLoading: isLoadingConversations } = useQuery<ConversationSummary[]>({
    queryKey: ['ai-conversations'],
    queryFn: () => api.get('/ai/conversations').then((r) => r.data),
  });

  // Load active conversation messages
  const {
    data: activeConv,
    isLoading: isLoadingConv,
    isError: isConvError,
    error: convError,
    refetch: refetchConv,
  } = useQuery<ConversationDetail>({
    queryKey: ['ai-conversation', activeConvId],
    queryFn: () => api.get(`/ai/conversations/${activeConvId}`).then((r) => r.data),
    enabled: !!activeConvId,
  });

  // Send message mutation
  const sendMutation = useMutation<ChatResponse, Error, string>({
    mutationFn: (message: string) =>
      api
        .post('/ai/chat', {
          message,
          conversation_id: activeConvId,
          provider,
        })
        .then((r) => r.data),
    onSuccess: (data) => {
      setActiveConvId(data.conversation_id);
      queryClient.invalidateQueries({ queryKey: ['ai-conversations'] });
      queryClient.invalidateQueries({ queryKey: ['ai-conversation', data.conversation_id] });
    },
  });

  // Delete conversation mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/ai/conversations/${id}`),
    onSuccess: (_, id) => {
      if (activeConvId === id) setActiveConvId(null);
      queryClient.invalidateQueries({ queryKey: ['ai-conversations'] });
    },
    onError: (err) => {
      toast({
        title: t('common:error'),
        description: getApiErrorMessage(err, t('errors:internalServer')),
        variant: 'destructive',
      });
    },
  });

  // Auto-scroll to latest message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeConv?.messages]);

  // Keep the provider dropdown in sync with the active conversation's real
  // provider. An existing conversation is pinned to the provider it was
  // created with; if the dropdown showed a stale value, a follow-up message
  // would route to the wrong provider and 503. Backend defends against this
  // too, but reflecting the truth in the UI avoids confusing the operator.
  useEffect(() => {
    if (activeConv?.provider) {
      setProvider(activeConv.provider);
    }
  }, [activeConv?.id, activeConv?.provider]);

  const handleSend = useCallback(() => {
    const msg = inputValue.trim();
    if (!msg || sendMutation.isPending) return;
    setInputValue('');
    sendMutation.mutate(msg);
  }, [inputValue, sendMutation]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleNewConversation = () => {
    setActiveConvId(null);
    inputRef.current?.focus();
  };

  const messages = activeConv?.messages ?? [];

  return (
    <div className="flex h-[calc(100vh-4rem)] overflow-hidden">
      {/* ── Sidebar ── */}
      <div className="flex w-64 flex-shrink-0 flex-col border-r bg-background">
        <div className="flex items-center justify-between border-b px-4 py-3">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Brain className="h-4 w-4 text-violet-600" />
            {t('AIAssistantPage.title')}
          </div>
          <Button size="sm" variant="ghost" onClick={handleNewConversation}>
            <Plus className="h-4 w-4" />
          </Button>
        </div>

        <ScrollArea className="flex-1 p-2">
          {isLoadingConversations ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : conversations.length === 0 ? (
            <p className="px-2 py-4 text-center text-xs text-muted-foreground">
              {t('AIAssistantPage.conversation.empty')}
            </p>
          ) : (
            conversations.map((conv) => (
              <ConversationItem
                key={conv.id}
                conv={conv}
                isActive={conv.id === activeConvId}
                onSelect={() => setActiveConvId(conv.id)}
                onDelete={() => setDeleteTarget(conv.id)}
              />
            ))
          )}
        </ScrollArea>

        {/* Provider selector at bottom of sidebar */}
        <div className="border-t p-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">{t('AIAssistantPage.provider.label')}</span>
            <Link to="/settings/ai">
              <Button size="icon" variant="ghost" className="h-6 w-6">
                <Settings className="h-3.5 w-3.5" />
              </Button>
            </Link>
          </div>
          <Select value={provider} onValueChange={setProvider}>
            <SelectTrigger className="mt-1 h-7 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="openai">OpenAI</SelectItem>
              <SelectItem value="anthropic">Anthropic</SelectItem>
              <SelectItem value="ollama">{t('AIAssistantPage.provider.ollamaLocal')}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* ── Main chat area ── */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center border-b px-6 py-3">
          <div className="flex items-center gap-3">
            <Brain className="h-5 w-5 text-primary" />
            <div>
              <h1 className="text-sm font-semibold">
                {activeConv?.title || t('AIAssistantPage.title')}
              </h1>
              {activeConv && (
                <p className="text-xs text-muted-foreground">
                  {activeConv.provider} · {activeConv.model} ·{' '}
                  {t('AIAssistantPage.header.tokens', {
                    count: activeConv.total_tokens,
                    value: activeConv.total_tokens.toLocaleString(),
                  })}
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Messages */}
        <ScrollArea className="flex-1 px-6 py-4">
          {isLoadingConv && activeConvId && (
            <div className="flex items-center justify-center h-64">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          )}
          {!isLoadingConv && isConvError && activeConvId && (
            <div className="flex h-full flex-col items-center justify-center py-16 text-center">
              <AlertCircle className="mb-4 h-10 w-10 text-destructive" />
              <h2 className="text-base font-semibold">{t('AIAssistantPage.conversation.loadError')}</h2>
              <p className="mt-2 max-w-sm text-sm text-muted-foreground">
                {getApiErrorMessage(convError, t('errors:internalServer'))}
              </p>
              <Button variant="outline" size="sm" className="mt-4" onClick={() => refetchConv()}>
                {t('AIAssistantPage.conversation.retry')}
              </Button>
            </div>
          )}
          {!isLoadingConv && !isConvError && messages.length === 0 && (
            <div className="flex h-full flex-col items-center justify-center py-16 text-center">
              <Brain className="mb-4 h-12 w-12 text-violet-200 dark:text-violet-800" />
              <h2 className="text-lg font-semibold">{t('AIAssistantPage.hero.title')}</h2>
              <p className="mt-2 max-w-sm text-sm text-muted-foreground">
                {t('AIAssistantPage.hero.description')}
              </p>
              <div className="mt-6 grid grid-cols-2 gap-2 text-left">
                {[
                  t('AIAssistantPage.suggestions.offlineDevices'),
                  t('AIAssistantPage.suggestions.activeAlerts'),
                  t('AIAssistantPage.suggestions.vlansOnSite'),
                  t('AIAssistantPage.suggestions.switchHealth'),
                ].map((suggestion) => (
                  <button
                    key={suggestion}
                    onClick={() => setInputValue(suggestion)}
                    className="rounded-lg border px-3 py-2 text-xs text-muted-foreground hover:border-violet-300 hover:text-violet-700 transition-colors"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="space-y-4">
            {messages.map((msg) => (
              <MessageBubble key={msg.id} message={msg} />
            ))}

            {sendMutation.isPending && (
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-violet-100 dark:bg-violet-900">
                  <Brain className="h-4 w-4 text-violet-600" />
                </div>
                <div className="flex items-center gap-2 rounded-lg bg-muted px-4 py-2.5 text-sm">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
                  <span className="text-muted-foreground">{t('AIAssistantPage.status.thinking')}</span>
                </div>
              </div>
            )}

            {sendMutation.isError && (
              <div className="flex items-center gap-2 rounded-lg border border-destructive/20 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                {getApiErrorMessage(sendMutation.error, t('AIAssistantPage.status.sendFailed'))}
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>
        </ScrollArea>

        {/* Input area */}
        <div className="border-t px-6 py-4">
          <div className="flex gap-2">
            <Input
              ref={inputRef}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={t('AIAssistantPage.input.placeholder')}
              disabled={sendMutation.isPending}
              className="flex-1"
            />
            <Button
              onClick={handleSend}
              disabled={!inputValue.trim() || sendMutation.isPending}
              className="bg-violet-600 hover:bg-violet-700"
            >
              {sendMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Send className="h-4 w-4" />
              )}
            </Button>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            {t('AIAssistantPage.input.hint')}
          </p>
        </div>
      </div>

      {/* Delete confirmation dialog */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('AIAssistantPage.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('AIAssistantPage.deleteDialog.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('AIAssistantPage.deleteDialog.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (deleteTarget) deleteMutation.mutate(deleteTarget);
                setDeleteTarget(null);
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {t('AIAssistantPage.deleteDialog.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
