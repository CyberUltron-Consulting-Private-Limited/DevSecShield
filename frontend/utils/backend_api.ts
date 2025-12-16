import api from "@/utils/interceptors"
import { showErrorToast } from "./error-handler"
import { toast } from "sonner"


// -------------------------------------------------------------- SAST API Routes --------------------------------------------------------------

export interface SastConversation {
    id: number
    repo_url: string | null
    mode: string
    title: string
    created_at: string
    last_updated: string
    scan_status: string
}

const getSastConversations = async (): Promise<SastConversation[]> => {
    try {
        const response = await api.get("/sast/conversations")
        toast.success("Sast conversations fetched successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const deleteSastConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/sast/conversation/${conversation_id}`)
        toast.success("Sast conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameSastConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/sast/conversation/${conversation_id}`, { title: title })
        toast.success("Sast conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createSastConversation = async (title: string) => {
    try {
        const response = await api.post("/sast/conversation", { title: title })
        toast.success("Sast conversation created successfully")
        return response.data.conversation_id as number  
    } catch (error) {
        throw error
    }
}

export interface SastConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}   
export interface SastConversationResponse {
    title: string
    repo_url: string | null 
    scan_status: string
    data: any
    messages: SastConversationMessage[]
}

const getSastConversationMessages = async ({queryKey}: {queryKey: ['sast-conversation-data', number]}): Promise<SastConversationResponse> => {
    const conversation_id = queryKey[1]
    try {
        const response = await api.get(`/sast/conversation/${conversation_id}`)
        toast.success("Sast conversation messages fetched successfully")
        return response.data as SastConversationResponse
    } catch (error) {
        throw error
    }
}

const startSastScan = async (
    {
        conversation_id, 
        repo_url, 
        PAT, 
        app_lang,
        mode
    }: {
            conversation_id: number, 
            repo_url: string, 
            PAT: string, 
            app_lang: "python" | "javascript" | "java" | "php" | "c" | "ruby" | "rust" | "swift" | "csharp" | "kotlin" , 
            mode: "github" | "gitlab" | "bitbucket"
    }) => {
    try {
        const response = await api.post(`/sast/conversation/${conversation_id}/scan`, 
            { 
                sast_data : { repo_url: repo_url, PAT: PAT, app_lang: app_lang, mode: mode }, 
                llm_data : null 
            } , 
        )
        toast.success("Sast scan started successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

export interface ExportResults {
    vulnerabilities: Array<{
        name: string;
        description: string;
        code_snippet_or_location?: string | null;
        cves: Array<{
            cve_id: string;
            description: string;
            severity: "Low" | "Medium" | "High" | "Critical";
        }>;
        severity: "Low" | "Medium" | "High" | "Critical";
        fix: string;
    }>;
}

const getExportResults = async (conversation_id: number): Promise<ExportResults> => {
    try {   
        const response = await api.get(`/sast/conversation/${conversation_id}/export`)
        toast.success("Sast export results fetched successfully")
        console.log("response.data", response.data.data);
        return response.data.data as ExportResults
    } catch (error) {
        throw error
    }
}

export { getSastConversations, deleteSastConversation, renameSastConversation, createSastConversation, getSastConversationMessages, startSastScan, getExportResults }

// -------------------------------------------------------------- LLM API Routes --------------------------------------------------------------

export interface LLMConversation {
    id: number
    model_type: string | null
    model_name: string | null
    title: string
    created_at: string
    last_updated: string
    scan_status: string
}

const getLLMConversations = async (): Promise<LLMConversation[]> => {
    try {
        const response = await api.get("/llm/conversations")
        toast.success("LLM conversations fetched successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const deleteLLMConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/llm/conversation/${conversation_id}`)
        toast.success("LLM conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameLLMConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/llm/conversation/${conversation_id}`, { title: title })
        toast.success("LLM conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createLLMConversation = async (title: string) => {
    try {
        const response = await api.post("/llm/conversation", { title: title })
        toast.success("LLM conversation created successfully")
        return response.data.conversation_id as number  
    } catch (error) {
        throw error
    }
}

export interface LLMConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}   
export interface LLMConversationResponse {
    title: string
    model_type: string | null
    model_name: string | null
    scan_status: string
    data: any
    messages: LLMConversationMessage[]
}

const getLLMConversationMessages = async ({queryKey}: {queryKey: ['llm-conversation-data', number]}): Promise<LLMConversationResponse> => {
    const conversation_id = queryKey[1]
    try {
        const response = await api.get(`/llm/conversation/${conversation_id}`)
        toast.success("LLM conversation messages fetched successfully")
        return response.data as LLMConversationResponse
    } catch (error) {
        throw error
    }
}

const startLLMScan = async (
    {
        conversation_id, 
        model_type,
        model_name,
        generations,
        probes,
        api_key,
        headers,
        request_template,
        response_json_field,
        model_uri
    }: {
            conversation_id: number, 
            model_type: "openai" | "anthropic" | "gemini" | "custom",
            model_name: string,
            generations?: number,
            probes: string[],
            api_key?: string | null,
            headers?: Record<string, any> | null,
            request_template?: Record<string, any> | null,
            response_json_field?: string | null,
            model_uri?: string | null
    }) => {
    try {
        const response = await api.post(`/llm/conversation/${conversation_id}/scan`, 
        {
        llm_data :   { 
            model_type,
            model_name,
            generations,
            probes,
            api_key,
            headers,
            request_template,
            response_json_field,
            model_uri
        },
        sast_data : null
        }
    )
        toast.success("LLM scan started successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const getLLMExportResults = async (conversation_id: number): Promise<ExportResults> => {
    try {   
        const response = await api.get(`/llm/conversation/${conversation_id}/export`)
        toast.success("LLM export results fetched successfully")
        return response.data.data as ExportResults
    } catch (error) {
        throw error
    }
}

export { getLLMConversations, deleteLLMConversation, renameLLMConversation, createLLMConversation, getLLMConversationMessages, startLLMScan, getLLMExportResults }