import { fetchEventSource } from '@microsoft/fetch-event-source';
import { Dispatch, SetStateAction, useEffect, useRef } from 'react';
import { apiBaseURL, getAccessToken } from '@/utils/interceptors';
import type { ChatMessage } from '@/components/ai/ChatWindow';
import { toast } from 'sonner';
import { showErrorToast } from '@/utils/error-handler';
import { usePathname } from 'next/navigation';

/**
 * Stream a chatbot response using Server-Sent Events.
 * Returns an AbortController to allow cancellation on unmount.
 */
const streamChatbotResponse = async ( 
    assistant_message_id: number, 
    user_message: string , 
    messages: ChatMessage[], 
    setMessages: Dispatch<SetStateAction<ChatMessage[]>>,
    conversation_id: number ,
    type: string,
    abortController?: AbortController
): Promise<AbortController> => {

    const valid_types = ['sast', 'llm', 'mcp', 'iac', 'leakage', 'sbom_sca', 'agent_discovery', 'dast', 'cbom'];
    if (!valid_types.includes(type)) {
        throw new Error('Invalid conversation type');
    }

    // Create new AbortController if not provided
    const controller = abortController || new AbortController();

    await fetchEventSource(`${apiBaseURL}/${type}/conversation/${conversation_id}/message`, {
            method: "POST",
            headers: { 
                Authorization: `Bearer ${getAccessToken()}`,
                "Content-Type": "application/json" ,
                "Accept": "text/event-stream"
            },
            body: JSON.stringify({
                message_id: assistant_message_id,
                user_message: user_message,
            }),
            signal: controller.signal,
            onopen: async (res: Response) =>{
                if (res.ok && res.status === 200) {
                console.log("Connection made ", res);
                } else if (res.status >= 400 && res.status < 500 && res.status !== 429) {
                console.log("Client-side error ", res);
                }
            },
            onmessage(event) {
                console.log(event.data);
                const parsedData = JSON.parse(event.data);
                const { messageId, content, reasoning, sources } = parsedData;
                setMessages((prev: ChatMessage[]): ChatMessage[] =>{
                        return prev.map(msg => {
                            if (msg.id === assistant_message_id) {
                                return {
                                    ...msg,
                                    role: "assistant",
                                    content: msg.content + content,
                                };
                            }
                            else return msg;

                        });
                    
                });
            },
            onclose() {
                setMessages(prev => {
                    const last_id = prev[prev.length - 1].id;
                    return prev.map(msg => {
                        if (msg.id === last_id) {
                            return {
                                ...msg,
                                isStreaming: false,
                            };
                        }
                        return msg;
                    });
                });

                console.log("Connection closed by the server");
            },
            onerror(err) {
                // Ignore abort errors (expected on unmount)
                if (err.name === 'AbortError') {
                    console.log("SSE connection aborted");
                    return;
                }
                showErrorToast(err, "There was an error from server");
            },
          });
    
    return controller;
};



export default streamChatbotResponse;