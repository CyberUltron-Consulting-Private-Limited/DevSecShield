'use client';
import {
  Conversation,
  ConversationContent,
  ConversationScrollButton,
} from '@/components/ai/conversation';
import { Loader } from '@/components/ai/loader';
import { Message, MessageAvatar, MessageContent } from '@/components/ai/message';
import {
  PromptInput,
  PromptInputButton,
  PromptInputModelSelect,
  PromptInputModelSelectContent,
  PromptInputModelSelectItem,
  PromptInputModelSelectTrigger,
  PromptInputModelSelectValue,
  PromptInputSubmit,
  PromptInputTextarea,
  PromptInputToolbar,
  PromptInputTools,
} from '@/components/ai/prompt-input';
import {
  Reasoning,
  ReasoningContent,
  ReasoningTrigger,
} from '@/components/ai/reasoning';
import { Source, Sources, SourcesContent, SourcesTrigger } from '@/components/ai/source';
import { DisplaySuggestions } from '@/components/ai/DisplaySuggestions';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { MicIcon, PaperclipIcon, RotateCcwIcon, ScanIcon } from 'lucide-react';
import { nanoid } from 'nanoid';
import { type FormEventHandler, useCallback, useEffect, useState } from 'react';
import streamChatbotResponse from '@/hooks/use-sse';
import { usePathname } from 'next/navigation';
import { toast } from 'sonner';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getSastConversationMessages } from '@/utils/backend_api';
import { showErrorToast } from '@/utils/error-handler';
import ScanStatusIndicator from '@/components/ai/ScanStatusIndicator';
export type ChatMessage = {
  id: number;
  content: string;
  role: 'user' | 'assistant';
  timestamp: string;
  reasoning?: string;
  sources?: Array<{ title: string; url: string }>;
  isStreaming?: boolean;
};

const Example = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 0,
      content: "Hello! I'm your SAST AI assistant. I can help you analyze your SAST Scan results . Please run a scan first to get started.",
      role: 'assistant',
      timestamp: new Date().toISOString(),
    }
  ]);
  
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [streamingMessageId, setStreamingMessageId] = useState<number | null>(null);
  const [showSuggestions, setShowSuggestions] = useState(true);
  
  const conversation_id = parseInt(usePathname().split('/').pop() || '0');
  if (!conversation_id) {
    toast.error("Conversation id not found");
    return
  } 

  const queryClient = useQueryClient();
  const query = useQuery({queryKey: ['sast-conversation-data', conversation_id] , queryFn : getSastConversationMessages});


  const handleSuggestionClick = useCallback((suggestion: string) => {
    setInputValue(suggestion);
    setShowSuggestions(false);
  }, []);

  useEffect(() => {
    if (inputValue.trim() =="") {
      setShowSuggestions(true);
    }
  }, [inputValue]);

  useEffect(() => {
    if (query.data) {
      setMessages(query.data.messages);
    }
    if (query.error) {
      showErrorToast(query.error);
    }
  }, [query.data , query.error]);

  const handleSubmit: FormEventHandler<HTMLFormElement> = useCallback( async (event) => {
    event.preventDefault();
    
    if (!inputValue.trim() || isTyping) return;
    // Add user message
    const userMessage: ChatMessage = {
      id: messages.length + 1,
      content: inputValue.trim(),
      role: 'user',
      timestamp: new Date().toISOString(),
    };
    setMessages(prev => [...prev, userMessage]);
    setInputValue('');
    setShowSuggestions(false);
    setIsTyping(true);

    const assistantMessageId = messages.length + 2;
    
    const assistantMessage: ChatMessage = {
    id: assistantMessageId,
    content: '',
    role: 'assistant',
    timestamp: new Date().toISOString(),
    isStreaming: true,
    };
    console.log(`assistantMessage id ${assistantMessageId}`);
    setMessages(prev => [...prev, assistantMessage]);
    setStreamingMessageId(assistantMessageId);
    
    // Start streaming response from the chatbot
    await streamChatbotResponse(assistantMessageId, inputValue.trim(), messages, setMessages, conversation_id );

    setIsTyping(false);
    setStreamingMessageId(null);

  }, [inputValue, isTyping]);

  const run_scan = useCallback(() => {
    console.log("Running scan");
  }, []);

 
  return (
    <div className="flex h-screen w-full flex-col overflow-hidden rounded-xl border bg-background shadow-sm ">
      {/* Header */}
      <div className="flex items-center justify-between border-b bg-muted/50 px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm">SAST Scan Assistant</span>
          </div>
          <div className="h-4 w-px bg-border" />
          <ScanStatusIndicator scan_status={query.data?.scan_status || "unknown"} />
        </div>
        <Button 
          variant="ghost" 
          size="sm"
          onClick={run_scan}
          className="h-8 px-2 bg-teal-600 hover:bg-teal-700 text-white cursor-pointer hover:text-white"
        >
          <ScanIcon className="size-4" />
          <span className="ml-1">Run Scan</span>
        </Button>
      </div>
      {/* Conversation Area */}
      <Conversation className="flex-1">
        <ConversationContent className="space-y-4">
          {messages.map((message) => (
            <div key={message.id} className="space-y-3">
              <Message from={message.role}>
                <MessageContent>
                  {message.isStreaming && message.content === '' ? (
                    <div className="flex items-center gap-2">
                      <Loader size={14} />
                      <span className="text-muted-foreground text-sm">Thinking...</span>
                    </div>
                  ) : (
                    message.content
                  )}
                </MessageContent>
                <MessageAvatar  
                  src="" 
                  name={message.role === 'user' ? 'Me' : 'AI'} 
                />
              </Message>
              {/* Reasoning */}
              {message.reasoning && (
                <div className="ml-10">
                  <Reasoning isStreaming={message.isStreaming} defaultOpen={false}>
                    <ReasoningTrigger />
                    <ReasoningContent>{message.reasoning}</ReasoningContent>
                  </Reasoning>
                </div>
              )}
            </div>
          ))}
        </ConversationContent>
        <ConversationScrollButton />
      </Conversation>
      {/* Input Area */}
      <div className="border-t p-4 relative">
        {showSuggestions && !inputValue.trim() && !isTyping && messages.length <= 1 && (
          <div className="absolute bottom-full left-0 right-0 mb-2 z-10">
            <DisplaySuggestions onSuggestionClick={handleSuggestionClick} />
          </div>
        )}
        <PromptInput onSubmit={handleSubmit}>
          <PromptInputTextarea
            value={inputValue}
            onChange={(e: any) => {
              setInputValue(e.target.value);
              setShowSuggestions(false);
            }}
            onFocus={() => {
              if (!inputValue.trim() && messages.length <= 1) {
                setShowSuggestions(true);
              }
            }}
            placeholder="Ask me anything about development, coding, or technology..."
            disabled={isTyping}
          />
          <PromptInputToolbar>
            <PromptInputSubmit 
            className='ml-auto'
              disabled={!inputValue.trim() || isTyping}
              status={isTyping ? 'streaming' : 'ready'}
            />
          </PromptInputToolbar>
        </PromptInput>
      </div>
    </div>
  );
};
export default Example;