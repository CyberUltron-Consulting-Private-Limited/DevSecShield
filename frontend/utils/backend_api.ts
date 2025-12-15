import api from "@/utils/interceptors"
import { showErrorToast } from "./error-handler"
import { toast } from "sonner"


// ------------------------------  SAST API Routes ------------------------------

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
        const response = await api.post(`/sast/conversation/${conversation_id}/scan`, { repo_url: repo_url, PAT: PAT, app_lang: app_lang, mode: mode })
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