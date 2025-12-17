import { fetchEventSource } from '@microsoft/fetch-event-source';
import { Dispatch, SetStateAction, useEffect } from 'react';
import { apiBaseURL, getAccessToken } from '@/utils/interceptors';
import type { ChatMessage } from '@/components/ai/ChatWindow';
import { toast } from 'sonner';
import { showErrorToast } from '@/utils/error-handler';
import { usePathname } from 'next/navigation';

const streamChatbotResponse = async ( 
    assistant_message_id: number, 
    user_message: string , 
    messages: ChatMessage[], 
    setMessages: Dispatch<SetStateAction<ChatMessage[]>>,
    conversation_id: number ,
    type: string
) => {
    
    if (type !== 'sast' && type !== 'llm' && type !== 'mcp') {
        throw new Error('Invalid conversation type');
    }

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
                showErrorToast(err, "There was an error from server");
            },
          });
        };



export default streamChatbotResponse;