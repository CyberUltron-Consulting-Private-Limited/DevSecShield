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
        showErrorToast(error,"Error fetching sast conversations")
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
        showErrorToast(error,"Error fetching sast conversation messages")
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
        showErrorToast(error,"Error fetching sast export results")
        throw error
    }
}

export { 
    getSastConversations, 
    deleteSastConversation, 
    renameSastConversation, 
    createSastConversation, 
    getSastConversationMessages, 
    startSastScan, 
    getExportResults }

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
        showErrorToast(error,"Error fetching sast export results")
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
        showErrorToast(error,"Error fetching llm conversation messages")
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
        showErrorToast(error,"Error fetching llm export results")
        throw error
    }
}

export { 
    getLLMConversations, 
    deleteLLMConversation, 
    renameLLMConversation, 
    createLLMConversation, 
    getLLMConversationMessages, 
    startLLMScan, 
    getLLMExportResults }

// -------------------------------------------------------------- MCP API Routes --------------------------------------------------------------

interface MCPConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}

export interface MCPConversationResponse {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
    messages: MCPConversationMessage[]
}

const getMCPConversationMessages = async ({queryKey}: {queryKey: ['mcp-conversation-data', number]}): Promise<MCPConversationResponse> => {
    const conversation_id = queryKey[1]
    try {
        const response = await api.get(`/mcp/conversation/${conversation_id}`)
        toast.success("MCP conversation messages fetched successfully")
        return response.data as MCPConversationResponse
    } catch (error) {
        showErrorToast(error,"Error fetching mcp conversation messages")
        throw error
    }
}

export interface MCPConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
}

const getMCPConversations = async (): Promise<MCPConversation[]> => {
    try {
        const response = await api.get("/mcp/conversations")
        toast.success("MCP conversations fetched successfully")
        return response.data as MCPConversation[]
    } catch (error) {
        showErrorToast(error,"Error fetching mcp conversations")
        throw error
    }
}

const deleteMCPConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/mcp/conversation/${conversation_id}`)
        toast.success("MCP conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameMCPConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/mcp/conversation/${conversation_id}`, { title: title })
        toast.success("MCP conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createMCPConversation = async (title: string) => {
    try {
        const response = await api.post("/mcp/conversation", { title: title })
        toast.success("MCP conversation created successfully")
        return response.data.conversation_id as number  
    } catch (error) {
        throw error
    }
}

const startMCPScan = async (
    {
        conversation_id,
        server_config
    }: {
        conversation_id: number,
        server_config: string
    }
) => {

    try {
        const response = await api.post(`/mcp/conversation/${conversation_id}/scan`, 
            { 
            mcp_data: { server_config: server_config } 
            }
        )
        toast.success("MCP scan started successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const getMCPExportResults = async (conversation_id: number): Promise<ExportResults> => {
    try {   
        const response = await api.get(`/mcp/conversation/${conversation_id}/export`)
        toast.success("MCP export results fetched successfully")
        return response.data.data as ExportResults
    } catch (error) {
        showErrorToast(error,"Error fetching mcp export results")
        throw error
    }
}
export { 
    getMCPConversationMessages,
    getMCPConversations,
    deleteMCPConversation,
    renameMCPConversation,
    createMCPConversation,
    getMCPExportResults,
    startMCPScan
}

// -------------------------------------------------------------- Auth API Routes --------------------------------------------------------------

export interface UserProfile {
    email: string
    first_name: string
    last_name: string
    profile_photo: string | null
}

const getUserProfile = async (): Promise<UserProfile> => {
    try {
        const response = await api.get("/get_user")
        return response.data as UserProfile
    } catch (error) {
        showErrorToast(error,"Error fetching user profile")
        throw error
    }
}

const logout = async () => {
    try {
        const response = await api.get("/logout")
        toast.success("Logged out successfully")
        // Clear tokens from localStorage
        localStorage.removeItem("access_token")
        localStorage.removeItem("refresh_token")
        return response.data
    } catch (error) {
        // Clear tokens even if API call fails
        localStorage.removeItem("access_token")
        localStorage.removeItem("refresh_token")
        throw error
    }
}

export {
    getUserProfile,
    logout
}

// -------------------------------------------------------------- IAC API Routes --------------------------------------------------------------

export interface IACConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
}

const getIACConversations = async (): Promise<IACConversation[]> => {
    try {
        const response = await api.get("/iac/conversations")
        toast.success("IAC conversations fetched successfully")
        return response.data as IACConversation[]
    } catch (error) {
        showErrorToast(error,"Error fetching iac conversations")
        throw error
    }
}

const deleteIACConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/iac/conversation/${conversation_id}`)
        toast.success("IAC conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameIACConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/iac/conversation/${conversation_id}`, { title: title })
        toast.success("IAC conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createIACConversation = async (title: string) => {
    try {
        const response = await api.post("/iac/conversation", { title: title })
        toast.success("IAC conversation created successfully")
        return response.data.conversation_id as number  
    } catch (error) {
        throw error
    }
}

export interface IACConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}

export interface IACConversationResponse {
    title: string
    repo_url: string | null
    scan_status: string
    data: any
    messages: IACConversationMessage[]
}

const getIACConversationMessages = async ({queryKey}: {queryKey: ['iac-conversation-data', number]}): Promise<IACConversationResponse> => {
    const conversation_id = queryKey[1]
    try {
        const response = await api.get(`/iac/conversation/${conversation_id}`)
        toast.success("IAC conversation messages fetched successfully")
        return response.data as IACConversationResponse
    } catch (error) {
        showErrorToast(error,"Error fetching iac conversation messages")
        throw error
    }
}

const startIACScan = async (
    {
        conversation_id,
        repo_url, 
        PAT, 
        mode
    }: {   
        conversation_id: number,
        repo_url: string, 
        PAT: string, 
        mode: "github" | "gitlab" | "bitbucket"
    }) => {
    try {
        const response = await api.post(`/iac/conversation/${conversation_id}/scan`, { iac_data: { repo_url: repo_url, PAT: PAT, mode: mode } })
        toast.success("IAC scan started successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const getIACExportResults = async (conversation_id: number): Promise<ExportResults> => {
    try {   
        const response = await api.get(`/iac/conversation/${conversation_id}/export`)
        toast.success("IAC export results fetched successfully")
        return response.data.data as ExportResults
    } catch (error) {
        showErrorToast(error,"Error fetching iac export results")
        throw error
    }
}

export { 
    getIACConversations, 
    deleteIACConversation, 
    renameIACConversation, 
    createIACConversation, 
    getIACConversationMessages,
    startIACScan,
    getIACExportResults
}

// -------------------------------------------------------------- SCA + SBOM API Routes --------------------------------------------------------------

export interface SCASBOMConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
}

const getSCASBOMConversations = async (): Promise<SCASBOMConversation[]> => {
    try {
        const response = await api.get("/sbom_sca/conversations")
        toast.success("SCA + SBOM conversations fetched successfully")
        return response.data as SCASBOMConversation[]
    } catch (error) {
        showErrorToast(error,"Error fetching sbom_sca conversations")
        throw error
    }
}

const deleteSCASBOMConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/sbom_sca/conversation/${conversation_id}`)
        toast.success("SCA + SBOM conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameSCASBOMConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/sbom_sca/conversation/${conversation_id}`, { title: title })
        toast.success("SCA + SBOM conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createSCASBOMConversation = async (title: string) => {
    try {
        const response = await api.post("/sbom_sca/conversation", { title: title })
        toast.success("SCA + SBOM conversation created successfully")
        return response.data.conversation_id as number  
    } catch (error) {
        throw error
    }
}

export interface SCASBOMConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}

export interface SCASBOMConversationResponse {
    title: string
    repo_url: string | null
    scan_status: string
    data: any
    messages: SCASBOMConversationMessage[]
}

const getSCASBOMConversationMessages = async ({queryKey}: {queryKey: ['sbom_sca-conversation-data', number]}): Promise<SCASBOMConversationResponse> => {
    const conversation_id = queryKey[1]
    try {
        const response = await api.get(`/sbom_sca/conversation/${conversation_id}`)
        toast.success("SCA + SBOM conversation messages fetched successfully")
        return response.data as SCASBOMConversationResponse
    } catch (error) {
        showErrorToast(error,"Error fetching sbom_sca conversation messages")
        throw error
    }
}

const startSCASBOMScan = async (
    {
        conversation_id,
        repo_url, 
        PAT, 
        mode
    }: {
        conversation_id: number,
        repo_url: string, 
        PAT: string, 
        mode: "github" | "gitlab" | "bitbucket"
    }) => {
    try {
        const response = await api.post(`/sbom_sca/conversation/${conversation_id}/scan`, { sbom_sca_data: { repo_url: repo_url, PAT: PAT, mode: mode } })
        toast.success("SCA + SBOM scan started successfully")
        return response.data
    } catch (error) {
        // console.log(error)
        throw error
    }
}

const getSCASBOMExportResults = async (conversation_id: number): Promise<ExportResults> => {
    try {   
        const response = await api.get(`/sbom_sca/conversation/${conversation_id}/export`)
        toast.success("SCA + SBOM export results fetched successfully")
        return response.data.data as ExportResults
    } catch (error) {
        showErrorToast(error,"Error fetching sbom_sca export results")
        throw error
    }
}

export { 
    getSCASBOMConversations, 
    deleteSCASBOMConversation, 
    renameSCASBOMConversation, 
    createSCASBOMConversation,
    getSCASBOMConversationMessages,
    startSCASBOMScan,
    getSCASBOMExportResults
}

// -------------------------------------------------------------- Discovery API Routes --------------------------------------------------------------

export interface DiscoveryConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
}

const getDiscoveryConversations = async (): Promise<DiscoveryConversation[]> => {
    try {
        const response = await api.get("/agent_discovery/conversations")
        toast.success("Discovery conversations fetched successfully")
        return response.data as DiscoveryConversation[]
    } catch (error) {
        showErrorToast(error,"Error fetching discovery conversations")
        throw error
    }
}

const deleteDiscoveryConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/agent_discovery/conversation/${conversation_id}`)
        toast.success("Discovery conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameDiscoveryConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/agent_discovery/conversation/${conversation_id}`, { title: title })
        toast.success("Discovery conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createDiscoveryConversation = async (title: string) => {
    try {
        const response = await api.post("/agent_discovery/conversation", { title: title })
        toast.success("Discovery conversation created successfully")
        return response.data.conversation_id as number  
    } catch (error) {
        throw error
    }
}

export interface DiscoveryConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}

export interface DiscoveryConversationResponse {
    title: string
    repo_url: string | null
    scan_status: string
    data: any
    messages: DiscoveryConversationMessage[]
}

const getDiscoveryConversationMessages = async ({queryKey}: {queryKey: ['discovery-conversation-data', number]}): Promise<DiscoveryConversationResponse> => {
    const conversation_id = queryKey[1]
    try {
        const response = await api.get(`/agent_discovery/conversation/${conversation_id}`)
        toast.success("Discovery conversation messages fetched successfully")
        return response.data as DiscoveryConversationResponse
    } catch (error) {
        showErrorToast(error,"Error fetching discovery conversation messages")
        throw error
    }
}

const startDiscoveryScan = async (
    {
        conversation_id,
        repo_url, 
        PAT, 
        mode
    }: {
        conversation_id: number,
        repo_url: string, 
        PAT: string, 
        mode: "github" | "gitlab" | "bitbucket"
    }) => {
    try {
        const response = await api.post(`/agent_discovery/conversation/${conversation_id}/scan`, { agent_discovery_data: { repo_url: repo_url, PAT: PAT, mode: mode } })
        toast.success("Discovery scan started successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const getDiscoveryExportResults = async (conversation_id: number): Promise<ExportResults> => {
    try {   
        const response = await api.get(`/agent_discovery/conversation/${conversation_id}/export`)
        toast.success("Discovery export results fetched successfully")
        return response.data.data as ExportResults
    } catch (error) {
        showErrorToast(error,"Error fetching discovery export results")
        throw error
    }
}

export { 
    getDiscoveryConversations, 
    deleteDiscoveryConversation, 
    renameDiscoveryConversation, 
    createDiscoveryConversation,
    getDiscoveryConversationMessages,
    startDiscoveryScan,
    getDiscoveryExportResults
}

// -------------------------------------------------------------- Leakage API Routes --------------------------------------------------------------

export interface LeakageConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
}

const getLeakageConversations = async (): Promise<LeakageConversation[]> => {
    try {
        const response = await api.get("/leakage/conversations")
        toast.success("Leakage conversations fetched successfully")
        return response.data as LeakageConversation[]
    } catch (error) {
        showErrorToast(error,"Error fetching leakage conversations")
        throw error
    }
}

const deleteLeakageConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/leakage/conversation/${conversation_id}`)
        toast.success("Leakage conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameLeakageConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/leakage/conversation/${conversation_id}`, { title: title })
        toast.success("Leakage conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createLeakageConversation = async (title: string) => {
    try {
        const response = await api.post("/leakage/conversation", { title: title })
        toast.success("Leakage conversation created successfully")
        return response.data.conversation_id as number  
    } catch (error) {
        throw error
    }
}

export interface LeakageConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}

export interface LeakageConversationResponse {
    title: string
    repo_url: string | null
    scan_status: string
    data: any
    messages: LeakageConversationMessage[]
}

const getLeakageConversationMessages = async ({queryKey}: {queryKey: ['leakage-conversation-data', number]}): Promise<LeakageConversationResponse> => {
    const conversation_id = queryKey[1]
    try {
        const response = await api.get(`/leakage/conversation/${conversation_id}`)
        toast.success("Leakage conversation messages fetched successfully")
        return response.data as LeakageConversationResponse
    } catch (error) {
        showErrorToast(error,"Error fetching leakage conversation messages")
        throw error
    }
}

const startLeakageScan = async (
    {
        conversation_id,
        repo_url, 
        PAT, 
        mode
    }: {
        conversation_id: number,
        repo_url: string, 
        PAT: string, 
        mode: "github" | "gitlab" | "bitbucket"
    }) => {
    try {
        const response = await api.post(`/leakage/conversation/${conversation_id}/scan`, { leakage_data: { repo_url: repo_url, PAT: PAT, mode: mode } })
        toast.success("Leakage scan started successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const getLeakageExportResults = async (conversation_id: number): Promise<ExportResults> => {
    try {   
        const response = await api.get(`/leakage/conversation/${conversation_id}/export`)
        toast.success("Leakage export results fetched successfully")
        return response.data.data as ExportResults
    } catch (error) {
        showErrorToast(error,"Error fetching leakage export results")
        throw error
    }
}

export { 
    getLeakageConversations, 
    deleteLeakageConversation, 
    renameLeakageConversation, 
    createLeakageConversation,
    getLeakageConversationMessages,
    startLeakageScan,
    getLeakageExportResults
}

// -------------------------------------------------------------- Guardrails API Routes --------------------------------------------------------------

export interface GuardrailsIntegration {
    id: number
    title: string
    created_at: string
    last_updated: string
    api_key: string
}

// Mock data for development
const mockGuardrailsIntegrations: GuardrailsIntegration[] = [
    {
        id: 1,
        title: "Production API Guardrails",
        created_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days ago
        last_updated: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), // 2 days ago
        api_key: "gr_sk_live_1234567890abcdefghijklmnopqrstuvwxyz"
    },
    {
        id: 2,
        title: "Staging Environment",
        created_at: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(), // 14 days ago
        last_updated: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(), // 1 day ago
        api_key: "gr_sk_test_abcdefghijklmnopqrstuvwxyz1234567890"
    },
    {
        id: 3,
        title: "Development Guardrails",
        created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days ago
        last_updated: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(), // 5 hours ago
        api_key: "gr_sk_dev_9876543210zyxwvutsrqponmlkjihgfedcba"
    }
];

const getGuardrailsIntegrations = async (): Promise<GuardrailsIntegration[]> => {
    try {
        // Mock API call - simulate network delay
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Return mock data
        toast.success("Guardrails integrations fetched successfully")
        return [...mockGuardrailsIntegrations]
    } catch (error) {
        showErrorToast(error,"Error fetching guardrails integrations")
        throw error
    }
}

const deleteGuardrailsIntegration = async (integration_id: number) => {
    try {
        // Mock API call - simulate network delay
        await new Promise(resolve => setTimeout(resolve, 300));
        
        // Remove from mock data
        const index = mockGuardrailsIntegrations.findIndex(integration => integration.id === integration_id);
        if (index !== -1) {
            mockGuardrailsIntegrations.splice(index, 1);
        }
        
        toast.success("Guardrails integration deleted successfully")
        return { success: true, message: "Integration deleted" }
    } catch (error) {
        throw error
    }
}

const renameGuardrailsIntegration = async ({integration_id, title}: {integration_id: number, title: string}) => {
    try {
        // Mock API call - simulate network delay
        await new Promise(resolve => setTimeout(resolve, 300));
        
        // Update mock data
        const integration = mockGuardrailsIntegrations.find(integration => integration.id === integration_id);
        if (integration) {
            integration.title = title;
            integration.last_updated = new Date().toISOString();
        }
        
        toast.success("Guardrails integration renamed successfully")
        return { success: true, message: "Integration renamed" }
    } catch (error) {
        throw error
    }
}

export { 
    getGuardrailsIntegrations, 
    deleteGuardrailsIntegration, 
    renameGuardrailsIntegration
}