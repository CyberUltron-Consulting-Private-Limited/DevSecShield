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
import { ChevronRightIcon, EyeIcon, MicIcon, PaperclipIcon, RefreshCcwIcon, RotateCcwIcon, ScanIcon } from 'lucide-react';
import { nanoid } from 'nanoid';
import { type FormEventHandler, useCallback, useEffect, useState } from 'react';
import streamChatbotResponse from '@/hooks/use-sse';
import { usePathname, useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { DASTConversationResponse, getSastConversationMessages, IACConversationResponse, LLMConversationResponse } from '@/utils/backend_api';
import { showErrorToast } from '@/utils/error-handler';
import ScanStatusIndicator from '@/components/ai/ScanStatusIndicator';
import { SastConversationResponse } from '@/utils/backend_api';
import { UseQueryResult } from '@tanstack/react-query';
import { MCPConversationResponse } from '@/utils/backend_api';
import ReactMarkdown from 'react-markdown';
import api, { apiBaseURL } from '@/utils/interceptors';

export type ChatMessage = {
  id: number;
  content: string;
  role: 'user' | 'assistant';
  timestamp: string;
  reasoning?: string;
  sources?: Array<{ title: string; url: string }>;
  isStreaming?: boolean;
};

const ChatWindow = ({ 
  query }: { 
    query: UseQueryResult<SastConversationResponse> | UseQueryResult<LLMConversationResponse> | UseQueryResult<MCPConversationResponse> | UseQueryResult<IACConversationResponse> | UseQueryResult<DASTConversationResponse> }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const router = useRouter();
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [streamingMessageId, setStreamingMessageId] = useState<number | null>(null);
  const [showSuggestions, setShowSuggestions] = useState(true);
  
  


  const conversation_id = parseInt(usePathname().split('/').pop() || '0');
  if (!conversation_id) {
    toast.error("Conversation id not found");
    return
  } 

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

  // check type of conversation
  let type: 'sast' | 'llm' | 'mcp' | 'iac' | 'leakage' | 'sbom_sca' | 'agent_discovery' | 'dast' | undefined;
  const paths = usePathname().split('/');
  // console.log(paths);
  if (paths[2] === 'sast') {
      type = 'sast';
  }
  else if (paths[2] === 'llm') {
      type = 'llm';
  }
  else if (paths[2] === 'mcp') {
      type = 'mcp';
  }
  else if (paths[2] === 'iac') {
      type = 'iac';
  }
  else if (paths[2] === 'leakage') {
      type = 'leakage';
  }
  else if (paths[2] === 'sbom_sca') {
      type = 'sbom_sca';
  }
  else if (paths[2] === 'agent_discovery') {
      type = 'agent_discovery';
  }
  else if (paths[2] === 'dast') {
      type = 'dast';
  }
  else {
      toast.error('Invalid conversation type');
  }

  const handleSubmit: FormEventHandler<HTMLFormElement> = useCallback( async (event) => {
    event.preventDefault();

    if (!type) {
      toast.error('Invalid conversation type');
      return;
    }
    
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

    
    // add getting response and set it to the assistant message id  ( TEST IT )
    try { 
      const response = await api.post(`${apiBaseURL}/${type}/conversation/${conversation_id}/message`, {
        message_id: assistantMessageId,
        user_message: inputValue.trim(),
      });
      const data = await response.data;
      setMessages((prev)=>{
        return prev.map(msg => {
          if (msg.id === assistantMessageId) {
            return {
              ...msg,
              content:  data.content,
              isStreaming: false,
            };
          }
          return msg;
        });
      });
    } catch(error) { 
      showErrorToast(error);
    }

    // Start streaming response from the chatbot ( removed )
    // await streamChatbotResponse(assistantMessageId, inputValue.trim(), messages, setMessages, conversation_id, type );

    setIsTyping(false);
    setStreamingMessageId(null);

  }, [inputValue, isTyping]);

  const queryClient = useQueryClient();
  const refreshQuery = useCallback(() => {
    if (type === 'sast') {
      queryClient.invalidateQueries({ queryKey: ['sast-conversation-data', conversation_id] });
    }
    else if (type === 'llm') {
      queryClient.invalidateQueries({ queryKey: ['llm-conversation-data', conversation_id] });
    }
    else if (type === 'mcp') {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversation-data', conversation_id] });
    }
    else if (type === 'iac') {
      queryClient.invalidateQueries({ queryKey: ['iac-conversation-data', conversation_id] });
    }
    else if (type === 'leakage') {
      queryClient.invalidateQueries({ queryKey: ['leakage-conversation-data', conversation_id] });
    }
    else if (type === 'sbom_sca') {
      queryClient.invalidateQueries({ queryKey: ['sbom_sca-conversation-data', conversation_id] });
    }
    else if (type === 'agent_discovery') {
      queryClient.invalidateQueries({ queryKey: ['agent_discovery-conversation-data', conversation_id] });
    }
    else if (type === 'dast') {
      queryClient.invalidateQueries({ queryKey: ['dast-conversation-data', conversation_id] });
    }
    else {
      toast.error('Invalid conversation type');
    }
  }, [queryClient, conversation_id]);

 
  const valid_types = ['sast', 'llm', 'mcp', 'iac', 'leakage', 'sbom_sca', 'agent_discovery', 'dast'];
  let Heading: string = '';
  switch (type) {
    case 'sast':
      Heading = 'SAST';
      break;
    case 'llm':
      Heading = 'LLM';
      break;
    case 'mcp':
      Heading = 'MCP';
      break;
    case 'iac':
      Heading = 'IAC';
      break;
    case 'leakage':
      Heading = 'Data Leakage';
      break;
    case 'sbom_sca':
      Heading = 'SCA + SBOM';
      break;
    case 'agent_discovery':
      Heading = 'AI Agent Discovery';
      break;
    case 'dast':
      Heading = 'DAST';
      break;
    default:
      Heading = 'Unknown';
      break;
  }

  return (
    <div className="flex h-screen w-full flex-col overflow-hidden rounded-xl border bg-background shadow-sm ">
      {/* Header */}
      <div className="flex items-center justify-between border-b bg-muted/50 px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm cursor-pointer" onClick={() => router.push(`/home/${type}`)}>{Heading}</span>
            <ChevronRightIcon className="size-4 text-zinc-500" />
            <span className="text-teal-700 font-medium">{query.data?.title}</span>
          </div>
          <div className="h-4 w-px bg-border" />
          <ScanStatusIndicator scan_status={query.data?.scan_status || "unknown"} />
        </div>

        <div className="flex flex-row justify-end items-center gap-3">
            {/* Refresh Button */}
            <Button onClick={refreshQuery} className='bg-teal-600 hover:bg-teal-700 text-white cursor-pointer'>
              <RefreshCcwIcon className="size-4" />
              Refresh
            </Button>
        </div>
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
                    <ReactMarkdown >{message.content}</ReactMarkdown>
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
            placeholder="Ask me anything about your scan ..."
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
export default ChatWindow;