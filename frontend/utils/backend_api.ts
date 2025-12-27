import api from "@/utils/interceptors"
import { showErrorToast } from "./error-handler"
import { toast } from "sonner"


// -------------------------------------------------------------- SAST API Routes --------------------------------------------------------------

export interface SastConversation {
    id: number
    repo_url: string | null
    mode: string
    app_lang: string
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



const getExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/sast/conversation/${conversation_id}/export`)
        toast.success("Sast export results fetched successfully")
        return response.data
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

const getLLMExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/llm/conversation/${conversation_id}/export`)
        toast.success("LLM export results fetched successfully")
        return response.data
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

const getMCPExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/mcp/conversation/${conversation_id}/export`)
        toast.success("MCP export results fetched successfully")
        return response.data
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
        toast.success("User profile fetched successfully")
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

const getIACExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/iac/conversation/${conversation_id}/export`)
        toast.success("IAC export results fetched successfully")
        return response.data
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
        throw error
    }
}

const getSCASBOMExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/sbom_sca/conversation/${conversation_id}/export`)
        toast.success("SCA + SBOM export results fetched successfully")
        return response.data
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

const getDiscoveryExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/agent_discovery/conversation/${conversation_id}/export`)
        toast.success("Discovery export results fetched successfully")
        return response.data
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

const getLeakageExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/leakage/conversation/${conversation_id}/export`)
        toast.success("Leakage export results fetched successfully")
        return response.data
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
    scanners_enabled?: string[]
}

const getGuardrailsIntegrations = async (): Promise<GuardrailsIntegration[]> => {
    try {
        const response = await api.get("/guardrails/integrations")
        toast.success("Guardrails integrations fetched successfully")
        return response.data as GuardrailsIntegration[]
    } catch (error) {
        showErrorToast(error,"Error fetching guardrails integrations")
        throw error
    }
}

const deleteGuardrailsIntegration = async (integration_id: number) => {
    try {
        const response = await api.delete(`/guardrails/integration/${integration_id}`)
        toast.success("Guardrails integration deleted successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error deleting guardrails integration")
        throw error
    }
}

const renameGuardrailsIntegration = async ({integration_id, title}: {integration_id: number, title: string}) => {
    try {
        const response = await api.put(`/guardrails/integration/${integration_id}`, { title: title })
        toast.success("Guardrails integration renamed successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error renaming guardrails integration")
        throw error
    }
}

export interface GuardrailsIntegrationLog {
    id: string
    status: "success" | "failure" | "pending" | "started" | "NOT_STARTED" | "retry"
    created_at: string
    input_prompt: string
    results: {
        sanitized_prompt: string
        anonymize?: {
            valid: boolean , 
            score : number
        } | null , 
        toxicity?: {
            valid: boolean , 
            score : number
        } | null 
        tokenlimit?: {
            valid: boolean , 
            score : number
        } | null 
        promptinjection?: {
            valid: boolean , 
            score : number
        } | null 
        regex?: {
            valid: boolean , 
            score : number
        } | null 
        code? : {
            valid: boolean , 
            score : number
        } | null 
        secrets?: {
            valid: boolean , 
            score : number
        } | null 
    } | null
}

export interface AnonymizeContext {
    preamble?: string
    threshold?: number
    allowed_names?: string[]
}

export interface ToxicityContext {
    threshold?: number
}

export interface TokenLimitContext {
    max_tokens?: number
}

export interface PromptInjectionContext {
    threshold?: number
}

export interface RegexContext {
    regex_patterns?: string[]
    redact?: boolean
}

export interface CodeContext {
    languages?: string[]
    is_blocked?: boolean
}

export interface SecretsContext {
    redact_mode?: "REDACT_PARTIAL" | "REDACT_ALL" | "REDACT_HASH"
}

export interface SettingsData {
    anonymize_context?: AnonymizeContext
    toxicity_context?: ToxicityContext
    tokenlimit_context?: TokenLimitContext
    promptinjection_context?: PromptInjectionContext
    regex_context?: RegexContext
    code_context?: CodeContext
    secrets_context?: SecretsContext
}
export interface GuardrailsIntegrationDashboard {
    total_logs: number
    successful_logs: number
    failed_logs: number
    pending_logs: number
    started_logs: number
    not_started_logs: number
    api_key: string
    log_data: GuardrailsIntegrationLog[]
    settings: SettingsData
}

const getGuardrailsIntegrationDashboard = async ({queryKey}: {queryKey: ['guardrails-integration-dashboard', string]}): Promise<GuardrailsIntegrationDashboard> => {
    const integration_id = queryKey[1]
    try {
        const response = await api.get(`/guardrails/integration/${integration_id}`)
        toast.success("Guardrails integration dashboard fetched successfully")
        return response.data as GuardrailsIntegrationDashboard
    } catch (error) {
        showErrorToast(error,"Error fetching guardrails integration dashboard")
        throw error
    }
}

export interface CreateGuardrailsIntegrationData {
    title: string
}

const createGuardrailsIntegration = async (data: CreateGuardrailsIntegrationData) => {
    try {
        const response = await api.post("/guardrails/integration", data)
        toast.success("Guardrails integration created successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error creating guardrails integration")
        throw error
    }
}

export interface UpdateGuardrailsIntegrationData {
    title?: string
    settings?: SettingsData
}

const updateGuardrailsIntegration = async (integration_id: number, data: UpdateGuardrailsIntegrationData) => {
    try {
        const response = await api.put(`/guardrails/integration/${integration_id}`, data)
        toast.success("Guardrails integration updated successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error updating guardrails integration")
        throw error
    }
}

export { 
    getGuardrailsIntegrations, 
    deleteGuardrailsIntegration, 
    renameGuardrailsIntegration,
    getGuardrailsIntegrationDashboard,
    createGuardrailsIntegration,
    updateGuardrailsIntegration
}

// -------------------------------------------------------------- DAST API Routes --------------------------------------------------------------

export interface DASTConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
    target_url: string | null
    attack_modules: string[] | null
    scan_force: string | null
}

const getDASTConversations = async (): Promise<DASTConversation[]> => {
    try {
        const response = await api.get("/dast/conversations")
        toast.success("DAST conversations fetched successfully")
        return response.data as DASTConversation[]
    } catch (error) {
        showErrorToast(error,"Error fetching dast conversations")
        throw error
    }
}

const deleteDASTConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/dast/conversation/${conversation_id}`)
        toast.success("DAST conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameDASTConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/dast/conversation/${conversation_id}`, { title: title })
        toast.success("DAST conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createDASTConversation = async (title: string) => {
    try {
        const response = await api.post("/dast/conversation", { title: title })
        toast.success("DAST conversation created successfully")
        return response.data.conversation_id as number  
    } catch (error) {
        throw error
    }
}

export interface DASTConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}

export interface DASTConversationResponse {
    title: string
    target_url: string | null
    auth_mode: "form_based" | "header_cookie_based" | null
    attack_modules: string[] | null
    scan_force: string | null
    exclude_url_patterns: string[] | null
    scan_status: string
    data: any
    messages: DASTConversationMessage[]
}

const getDASTConversationMessages = async ({queryKey}: {queryKey: ['dast-conversation-data', number]}): Promise<DASTConversationResponse> => {
    const conversation_id = queryKey[1]
    try {
        const response = await api.get(`/dast/conversation/${conversation_id}`)
        toast.success("DAST conversation messages fetched successfully")
        return response.data as DASTConversationResponse
    } catch (error) {
        showErrorToast(error,"Error fetching dast conversation messages")
        throw error
    }
}

export interface FormBasedDASTScanData {
    target_url: string
    login_url: string
    include_urls?: string[]
    exclude_urls?: string[]
    mode?: "St-Low-Th-High" | "API" | "API-Minimal" | "Pen Test" | "QA Standard"
    timeout_durations_mins?: number
    poll_durations_seconds?: number
    username_value: string
    password_value: string
    username_key: string
    password_key: string
    logged_in_regex: string
    logged_out_regex: string
}

export interface HeaderCookieDASTScanData {
    target_url: string
    attack_modules?: string[]
    max_scan_time?: number
    user_agent?: string
    headers?: { name: string; value: string }[]
    cookies?: { name: string; value: string }[]
    scan_force?: "paranoid" | "sneaky" | "polite" | "normal" | "aggressive" | "insane"
    exclude_url_patterns?: string[]
}

const startDASTScan = async (
    {
        conversation_id,
        auth_mode,
        form_based,
        header_cookie_based
    }: {   
        conversation_id: number,
        auth_mode: "form_based" | "header_cookie_based",
        form_based?: FormBasedDASTScanData,
        header_cookie_based?: HeaderCookieDASTScanData
    }) => {
    try {
        const response = await api.post(`/dast/conversation/${conversation_id}/scan`, { 
            dast_data: {
                auth_mode,
                form_based: form_based || null,
                header_cookie_based: header_cookie_based || null
            }
        })
        toast.success("DAST scan started successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const getDASTExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/dast/conversation/${conversation_id}/export`)
        toast.success("DAST export results fetched successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error fetching dast export results")
        throw error
    }
}

export { 
    getDASTConversations, 
    deleteDASTConversation, 
    renameDASTConversation, 
    createDASTConversation, 
    getDASTConversationMessages,
    startDASTScan,
    getDASTExportResults
}

// -------------------------------------------------------------- CI/CD API Routes --------------------------------------------------------------

export interface CicdIntegration {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_type: "sast" | "llm" | "mcp" | "iac" | "leakage" | "sbom_sca" | "agent_discovery"
    api_key: string
}

const getCicdIntegrations = async (): Promise<CicdIntegration[]> => {
    try {
        const response = await api.get("/cicd/integrations")
        toast.success("CI/CD integrations fetched successfully")
        return response.data as CicdIntegration[]
    } catch (error) {
        showErrorToast(error,"Error fetching CI/CD integrations")
        throw error
    }
}

export interface CreateCicdIntegrationData {
    title: string
    scan_type: "sast"
}

const createCicdIntegration = async (data: CreateCicdIntegrationData) => {
    try {
        const response = await api.post("/cicd/integration", data)
        toast.success("CI/CD integration created successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error creating CI/CD integration")
        throw error
    }
}

export interface CicdLog {
    id: string
    created_at: string
    last_updated: string
    status: "pending" | "started" | "NOT_STARTED" | "success" | "failure" | "retry"
    results: any | null
}

export interface CicdIntegrationDashboard {
    cicd_integration_id: number
    title: string
    created_at: string
    last_updated: string
    scan_type: "sast" | "llm" | "mcp" | "iac" | "leakage" | "sbom_sca" | "agent_discovery"
    api_key: string
    logs: CicdLog[]
}

const getCicdIntegrationDashboard = async ({queryKey}: {queryKey: ['cicd-integration-dashboard', string]}): Promise<CicdIntegrationDashboard> => {
    const integration_id = queryKey[1]
    try {
        const response = await api.get(`/cicd/integration/${integration_id}`)
        toast.success("CI/CD integration dashboard fetched successfully")
        return response.data as CicdIntegrationDashboard
    } catch (error) {
        showErrorToast(error,"Error fetching CI/CD integration dashboard")
        throw error
    }
}

const deleteCicdIntegration = async (integration_id: number) => {
    try {
        const response = await api.delete(`/cicd/integration/${integration_id}`)
        toast.success("CI/CD integration deleted successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error deleting CI/CD integration")
        throw error
    }
}

export interface UpdateCicdIntegrationData {
    title: string
}

const renameCicdIntegration = async ({integration_id, title}: {integration_id: number, title: string}) => {
    try {
        const response = await api.put(`/cicd/integration/${integration_id}`, { title: title })
        toast.success("CI/CD integration renamed successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error renaming CI/CD integration")
        throw error
    }
}

export { 
    getCicdIntegrations,
    createCicdIntegration,
    getCicdIntegrationDashboard,
    deleteCicdIntegration,
    renameCicdIntegration
}