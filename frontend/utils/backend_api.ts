import api from "@/utils/interceptors"
import { showErrorToast } from "./error-handler"
import { toast } from "sonner"


// -------------------------------------------------------------- Start scan payload types (matches backend schemas) --------------------------------------------------------------

export type RepoMode = "github" | "gitlab" | "bitbucket";
export type Mode = RepoMode | "unknown";
export type SastAppLang = "python" | "javascript" | "java" | "php" | "c" | "ruby" | "rust" | "swift" | "csharp" | "kotlin";

export interface GithubContextSchema {
  mode: "github";
  repo_url: string;
  PAT: string;
  branch?: string;
}
export interface GitlabContextSchema {
  mode: "gitlab";
  repo_url: string;
  PAT: string;
  branch?: string;
}
export interface BitbucketContextSchema {
  mode: "bitbucket";
  repo_url: string;
  PAT: string;
  branch?: string;
}

export type RepoContextSchema = GithubContextSchema | GitlabContextSchema | BitbucketContextSchema;

export interface StartSastScanData {
  repo_context: RepoContextSchema | null;
  zip_file_used: boolean;
  exclude_path_arrays?: string[][] | null;
  app_lang: SastAppLang;
}

/** IAC context mode (matches backend IACContextSchema) */
export type IACContextMode = "terraform" | "k8s" | "pulumi" | "ansible" | "helm" | "aws_cloudformation" | "aws_cdk";

export interface IACContextSchema {
  mode: IACContextMode;
  include_path_arrays: string[][];
}

export type IACEnvironment = "production" | "staging" | "development";

export interface StartIACScanData {
  repo_context: RepoContextSchema | null;
  zip_file_used: boolean;
  iac_contexts: IACContextSchema[];
  environment?: IACEnvironment;
}

/** SBOM/SCA scan input: exactly one of repo_context, zip_file_used, or sbom_file_used (matches backend StartSBOMScanData) */
export interface StartSBOMScanData {
  repo_context: RepoContextSchema | null;
  zip_file_used: boolean;
  sbom_file_used: boolean;
}

export interface StartScanPayload {
  sast?: StartSastScanData | null;
  iac?: StartIACScanData | null;
  sbom_sca?: StartSBOMScanData | null;
}

// -------------------------------------------------------------- SAST API Routes --------------------------------------------------------------

export interface ScanInfoField {
    current?: number
}

export interface ScanRiskData {
    total_critical: number
    total_high: number
    total_medium: number
    total_low: number
}

export interface SastConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
    scan_metadata?: Record<string, unknown> | null
    estimated_credits?: number | null
    owner_user_email?: string
    owner_user_full_name?: string
    info?: ScanInfoField | null
    risk_data?: ScanRiskData | null
    raw_scan_data?: unknown
    /** From backend return_sast_list_item */
    repo_url?: string | null
    zip_file_used?: boolean | null
    branch?: string | null
    app_lang?: string | null
    /** Weighted sum (critical*4 + high*3 + medium*2 + low*1); use with risk_data for 0–10 score */
    risk_score?: number | null
    code_coverage?: number | null
    /** github, gitlab, bitbucket, zip_file */
    scan_type?: string | null
    duration?: number | string | null
    top_vulnerabilities?: Array<{ title?: string; impact?: string; description?: string; policy_violation?: number }> | null
}

/** Card counts returned by list SAST scans (card_data) */
export interface SastListCardData {
    pending_scans: number
    started_scans: number
    success_scans: number
    failure_scans: number
    not_started_scans: number
    scans_created_today: number
    scans_updated_today: number
}

/** Top repo item from backend (snake_case) */
export interface TopRepoByRiskItem {
    name: string
    repo_url: string | null
    zip_file_used: boolean
    issues: number
    risk_score: number
    trend: string
    language: string
}

export interface ScanListDashboardData {
    card_data: SastListCardData
    repos_scanned: { repo_url: string }[]
    zip_files_scanned: number
    scans_per_day: Record<string, number>
    risks_per_day: Record<string, { critical: number; high: number; medium: number; low: number }>
    /** Pre-computed by backend when available */
    risk_totals?: { severity: string; count: number }[]
    average_risk_score?: number
    total_issues?: number
    critical_count?: number
    owasp_by_category?: { category: string; count: number }[]
    policy_compliance?: { name: string; violations: number; compliance: number }[]
    overall_compliance_score?: number
    by_language?: { language: string; count: number }[]
    top_repos_by_risk?: TopRepoByRiskItem[]
    /** From get_remediation_metrics: mean time [d,h,m], counts, velocity (past 7 days) */
    remediation_metrics?: {
        mean_time_to_remediate: [number, number, number]
        critical_issues_fixed: number
        remediation_velocity: number
        high_priority_backlog: number
    }
}

export interface SastListResponse {
    scans_list_data: SastConversation[]
    dashboard_data: ScanListDashboardData
}

const getSastConversations = async (team_id: number): Promise<SastListResponse> => {
    try {
        const response = await api.get(`/${team_id}/sast/scans`)
        toast.success("Sast conversations fetched successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error fetching sast conversations")
        throw error
    }
}

const deleteSastConversation = async (team_id: number, scan_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/sast/scan/${scan_id}`)
        toast.success("Sast conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameSastConversation = async ({ team_id, scan_id, title }: { team_id: number; scan_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/sast/scan/${scan_id}`, { title })
        toast.success("Sast conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createSastConversation = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/sast/scan`, { title })
        toast.success("Sast conversation created successfully")
        return response.data.scan_id as number
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
/** Remediation metrics from backend get_remediation_metrics */
export interface SastRemediationMetrics {
  mean_time_to_remediate: [number, number, number]; // [days, hours, minutes]
  critical_issues_fixed: number;
  remediation_velocity: number;
  high_priority_backlog: number;
}

/** SAST scan dashboard from backend generate_sast_dashboard */
export interface SastDashboardData {
  risk_metrics?: Record<string, number>;
  owasp_top_10_metrics?: Record<string, number>;
  compliance_controls_metrics?: Record<string, number>;
  cves_per_vulnerability?: Record<string, number>;
  remediation_metrics?: SastRemediationMetrics;
  policy_violations?: Record<string, number>;
  risk_scores_per_finding?: Record<string, number>;
}

/** SAST scan metadata from backend get_scan_metadata (SAST branch) */
export interface SastScanMetadata {
  repo_url?: string;
  branch?: string;
  zip_file_used?: boolean;
  files_scanned?: number;
  total_files?: number;
  code_coverage?: number;
}

/** IAC scan metadata from backend get_scan_metadata (IAC branch) */
export interface IACScanMetadata {
  repo_url?: string | null;
  branch?: string | null;
  zip_file_used?: boolean;
  dependency_diagram?: string | null;
}

/** SAST finding from backend get_findings_for_scan_type (for table + toggle status) */
export interface SastFinding {
  id: string
  title: string
  description: string
  impact: string
  risk_score: number
  status: string
  compliance_controls: unknown
  owasp_top_10: unknown
  cves: unknown
  suggested_fix?: string | null
  location?: string | null
  snippet?: string | null
}

/** IAC finding from backend get_findings_for_scan_type (IAC branch: includes category, resource) */
export interface IACFinding {
  id: string
  title: string
  description: string
  impact: string
  risk_score: number
  status: string
  compliance_controls: unknown
  owasp_top_10: unknown
  cves: unknown
  suggested_fix?: string | null
  location?: string | null
  snippet?: string | null
  category?: string | null
  resource?: string | null
}

/** SBOM/SCA finding from backend get_findings_for_scan_type (sbom_sca branch) */
export interface SbomFinding {
  id: string
  title: string
  description: string
  impact: string
  risk_score: number
  status: string
  compliance_controls: unknown
  owasp_top_10: unknown
  suggested_fix?: string | null
  cves: unknown
  dependency?: string | null
  reachability?: string | null
  dependency_type?: string | null
  license_type?: string | null
}

/** SBOM/SCA scan metadata from backend get_scan_metadata (sbom_sca branch) */
export interface SbomScanMetadata {
  repo_url?: string | null
  branch?: string | null
  zip_file_used?: boolean
}

/** SBOM/SCA single-scan dashboard from backend generate_scan_dashboard (scan.py sbom_sca branch) */
export interface SbomScanDashboardData {
  card_data: {
    total_vulnerabilities: number
    total_critical_vulnerabilities: number
    total_policy_violations: number
    total_license_risks: number
    total_high_risk_licenses: number
    average_risk_score: number
    total_reachable_issues: number
  }
  remediation_actions_required: {
    total_findings: number
    total_fixed: number
    total_in_progress: number
    total_not_started: number
    total_ignored: number
  }
  severity_distribution: { critical: number; high: number; medium: number; low: number }
  reachability_distribution: {
    not_reachable: number
    potentially_reachable: number
    reachable: number
    unknown: number
  }
  vulnerability_trends_over_time: Record<string, { critical: number; high: number; medium: number; low: number }>
  licenses_distribution: Record<string, number>
  top_vulnerabilities_by_risk_score: Array<{
    dependency: string
    reachability: string
    dependency_type: string
    license_type: string
    impact: string
  }>
  average_risk_score_per_reachability: Record<string, number>
}

/** IAC single-scan dashboard from backend generate_scan_dashboard (scan.py IAC branch) */
export interface IACScanDashboardData {
  risk_metrics?: Record<string, number>
  owasp_top_10_metrics?: Record<string, number>
  compliance_controls_metrics?: Record<string, number>
  cves_per_vulnerability?: Record<string, number>
  policy_violations?: Record<string, number>
  compliance_framework_coverage?: Record<string, number>
  issue_status_metrics?: Record<string, number>
  /** finding_title -> [days, hours, minutes] */
  issue_address_metrics?: Record<string, number[]>
  issues_by_category?: Record<string, number>
  issues_by_severity?: Record<string, number>
  average_risk_score_per_category?: Record<string, number>
  risk_scores_per_finding?: Record<string, number>
  /** finding_title -> total number of compliance controls violated */
  compliance_failure_trends?: Record<string, number>
  /** finding_title -> average resolution time in seconds */
  average_resolution_time?: Record<string, number>
}

export interface SastConversationResponse {
    title: string
    scan_status: string
    estimated_credits: number | null
    scan_metadata?: SastScanMetadata | Record<string, unknown> | null
    data: any
    messages: SastConversationMessage[]
    dashboard?: SastDashboardData | null
    findings?: SastFinding[] | null
    integration_settings?: Record<string, unknown> | null
    info?: ScanInfoField | null
}

const getSastConversationMessages = async ({ queryKey }: { queryKey: ['sast-conversation-data', number, number] }): Promise<SastConversationResponse> => {
    const [, team_id, scan_id] = queryKey
    try {
        const response = await api.get(`/${team_id}/sast/scan/${scan_id}`)
        toast.success("Sast conversation messages fetched successfully")
        return response.data as SastConversationResponse
    } catch (error) {
        showErrorToast(error,"Error fetching sast conversation messages")
        throw error
    }
}

const startSastScan = async (params: {
    team_id: number
    scan_id: number
    repo_url: string
    PAT: string
    app_lang: SastAppLang
    mode: RepoMode
    branch?: string
}) => {
    const payload: StartScanPayload = {
        sast: {
            repo_context: { mode: params.mode, repo_url: params.repo_url, PAT: params.PAT, branch: params.branch ?? "main" },
            zip_file_used: false,
            exclude_path_arrays: null,
            app_lang: params.app_lang,
        },
    }
    return startScan(params.team_id, "sast", params.scan_id, JSON.stringify(payload), null)
}



const getExportResults = async (team_id: number, scan_id: number): Promise<any> => {
    try {
        const response = await api.get(`/${team_id}/sast/scan/${scan_id}/export`, { responseType: "blob" })
        toast.success("Sast export results fetched successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error fetching sast export results")
        throw error
    }
}

const reinitializeSastScan = async (params: {
    team_id: number
    scan_id: number
    repo_url: string
    PAT: string
    app_lang: "python" | "javascript" | "java" | "php" | "c" | "ruby" | "rust" | "swift" | "csharp" | "kotlin"
    mode: "github" | "gitlab" | "bitbucket"
    branch?: string
}) => {
    const payload: StartScanPayload = {
        sast: {
            repo_context: { mode: params.mode, repo_url: params.repo_url, PAT: params.PAT, branch: params.branch ?? "main" },
            zip_file_used: false,
            exclude_path_arrays: null,
            app_lang: params.app_lang,
        },
    }
    const form = buildScanFormData(JSON.stringify(payload), null)
    const response = await api.post(`/${params.team_id}/sast/scan/${params.scan_id}/reinitialize`, form, {
        headers: { "Content-Type": "multipart/form-data" },
    })
    toast.success("Sast scan reinitialized successfully")
    return response.data
}

/** Send a message to a scan. POST /{team_id}/{type}/scan/{scan_id}/message */
const sendMessageToScan = async (
    team_id: number,
    type: "sast" | "iac" | "sbom_sca" | "llm" | "mcp" | "leakage" | "agent_discovery" | "dast",
    scan_id: number,
    user_message: string
): Promise<{ content: string }> => {
    const response = await api.post<{ content: string }>(`/${team_id}/${type}/scan/${scan_id}/message`, { user_message })
    return response.data
}

/** Build FormData for scan estimate/start: start_scan_payload_string (JSON) and optional file. */
const buildScanFormData = (start_scan_payload_string: string, uploaded_file?: File | null): FormData => {
  const form = new FormData();
  form.append("start_scan_payload_string", start_scan_payload_string);
  if (uploaded_file) form.append("uploaded_file", uploaded_file);
  return form;
};

/** Estimate credits for a scan. POST FormData to /{team_id}/{type}/scan/{scan_id}/estimate_credits */
const estimateCreditsForScan = async (
  team_id: number,
  type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast",
  scan_id: number,
  start_scan_payload_string: string,
  uploaded_file?: File | null
): Promise<{ credits_required: number }> => {
  const form = buildScanFormData(start_scan_payload_string, uploaded_file);
  const response = await api.post<{ credits_required: number }>(
    `/${team_id}/${type}/scan/${scan_id}/estimate_credits`,
    form,
    { headers: { "Content-Type": "multipart/form-data" } }
  );
  return response.data;
};

/** Start a scan. POST FormData to /{team_id}/{type}/scan/{scan_id}/start */
const startScan = async (
  team_id: number,
  type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast",
  scan_id: number,
  start_scan_payload_string: string,
  uploaded_file?: File | null
): Promise<{ message: string }> => {
  const form = buildScanFormData(start_scan_payload_string, uploaded_file);
  const response = await api.post<{ message: string }>(
    `/${team_id}/${type}/scan/${scan_id}/start`,
    form,
    { headers: { "Content-Type": "multipart/form-data" } }
  );
  toast.success("Scan started successfully");
  return response.data;
}

/** Create ticket payload (matches backend CreateTicketData) */
export interface CreateTicketData {
  ticket_type: "jira";
  summary: string;
  description: string;
}

/** Create a ticket for a scan. POST /{team_id}/{type}/scan/{scan_id}/create_ticket */
const createTicket = async (
  team_id: number,
  type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast",
  scan_id: number,
  data: CreateTicketData
): Promise<{ message: string }> => {
  const response = await api.post<{ message: string }>(
    `/${team_id}/${type}/scan/${scan_id}/create_ticket`,
    data
  );
  return response.data;
};

export {
    getSastConversations,
    deleteSastConversation,
    renameSastConversation,
    createSastConversation,
    getSastConversationMessages,
    startSastScan,
    getExportResults,
    reinitializeSastScan,
    estimateCreditsForScan,
    startScan,
    sendMessageToScan,
    createTicket }

// -------------------------------------------------------------- LLM API Routes --------------------------------------------------------------

/** LLM-specific card data from generate_llm_dashboard_data */
export interface LLMCardData {
    total_scans: number
    average_risk_score: number
    total_critical_vulnerabilities: number
    total_vulnerabilities: number
    owasp_compliance_score: number
    passed_rate: number
    pending_scans?: number
    started_scans?: number
    success_scans?: number
    failure_scans?: number
    not_started_scans?: number
    scans_created_today?: number
    scans_updated_today?: number
}

/** LLM scan list dashboard data from generate_llm_dashboard_data (list page) */
export interface LLMListDashboardData {
    card_data: LLMCardData
    risk_level_distribution: Record<"critical" | "high" | "medium" | "low", number>
    attack_vector_test_results: Record<string, { passed: number; failed: number }>
    model_risk_comparison: Record<string, number>
    ai_security_posture_overview: Record<string, number>
    owasp_top_10_llm_metrics: Record<string, number>
    scans_per_day?: Record<string, number>
}

export interface LLMConversation {
    id: number
    model_type: string | null
    model_name: string | null
    title: string
    created_at: string
    last_updated: string
    scan_status: string
}

/** Response from GET /{team_id}/llm/scans (backend scans router) */
/** List item shape from GET /{team_id}/llm/scans (return_llm_list_item) */
export interface LLMScanListItem {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
    scan_metadata?: Record<string, unknown> | null
    estimated_credits?: number | null
    owner_user_email?: string | null
    owner_user_full_name?: string | null
    info?: ScanInfoField | null
    risk_data?: ScanRiskData | null
    average_risk_score?: number | null
    model_type?: string | null
    model_name?: string | null
    attack_iterations?: number | null
    total_attacks_performed?: number | null
    model_vulnerabilities?: Record<string, number> | null
    total_mitre_atlas_tactics?: number | null
}

export interface LLMScansListResponse {
    scans_list_data: LLMScanListItem[]
    dashboard_data: LLMListDashboardData
}

const getLLMConversations = async (team_id: number): Promise<LLMScansListResponse> => {
    try {
        const response = await api.get(`/${team_id}/llm/scans`)
        toast.success("LLM conversations fetched successfully")
        return response.data as LLMScansListResponse
    } catch (error) {
        showErrorToast(error, "Error fetching LLM conversations")
        throw error
    }
}

const deleteLLMConversation = async (team_id: number, conversation_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/llm/scan/${conversation_id}`)
        toast.success("LLM conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameLLMConversation = async ({ team_id, conversation_id, title }: { team_id: number; conversation_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/llm/scan/${conversation_id}`, { title })
        toast.success("LLM conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createLLMConversation = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/llm/scan`, { title })
        toast.success("LLM conversation created successfully")
        return response.data.scan_id as number
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
    scan_metadata?: LLMScanMetadata | Record<string, unknown> | null
    dashboard?: LLMDashboardData | null
    findings?: LLMFinding[] | null
    integration_settings?: Record<string, unknown> | null
    info?: ScanInfoField | null
}

const getLLMConversationMessages = async ({ queryKey }: { queryKey: ['llm-conversation-data', number, number] }): Promise<LLMConversationResponse> => {
    const [, team_id, scan_id] = queryKey
    try {
        const response = await api.get(`/${team_id}/llm/scan/${scan_id}`)
        const raw = response.data as {
            title: string
            scan_metadata?: LLMScanMetadata | Record<string, unknown> | null
            scan_status: string
            data: any
            dashboard?: LLMDashboardData | null
            messages: LLMConversationMessage[]
            findings?: LLMFinding[] | null
            integration_settings?: Record<string, unknown> | null
            info?: ScanInfoField | null
        }
        toast.success("LLM conversation messages fetched successfully")
        return {
            title: raw.title,
            model_type: (raw.scan_metadata?.model_type as string) ?? null,
            model_name: (raw.scan_metadata?.model_name as string) ?? null,
            scan_status: raw.scan_status,
            data: raw.data,
            messages: raw.messages ?? [],
            scan_metadata: raw.scan_metadata,
            dashboard: raw.dashboard ?? null,
            findings: raw.findings ?? null,
            integration_settings: raw.integration_settings,
            info: raw.info,
        }
    } catch (error) {
        showErrorToast(error, "Error fetching LLM conversation messages")
        throw error
    }
}

const startLLMScan = async (
    {
        team_id,
        scan_id,
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
        team_id: number
        scan_id: number
        model_type: "openai" | "anthropic" | "gemini" | "custom"
        model_name: string
        generations?: number
        probes: string[]
        api_key?: string | null
        headers?: Record<string, any> | null
        request_template?: Record<string, any> | null
        response_json_field?: string | null
        model_uri?: string | null
    }) => {
    try {
        const payload = { llm: { model_type, model_name, generations, probes, api_key, headers, request_template, response_json_field, model_uri } }
        const form = buildScanFormData(JSON.stringify(payload), null)
        const response = await api.post(`/${team_id}/llm/scan/${scan_id}/start`, form, {
            headers: { "Content-Type": "multipart/form-data" },
        })
        toast.success("LLM scan started successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const getLLMExportResults = async (team_id: number, scan_id: number): Promise<Blob> => {
    try {
        const response = await api.get(`/${team_id}/llm/scan/${scan_id}/export`, { responseType: "blob" })
        toast.success("LLM export results fetched successfully")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error fetching LLM export results")
        throw error
    }
}

const reinitializeLLMScan = async (
    { team_id, scan_id, start_scan_payload_string }: { team_id: number; scan_id: number; start_scan_payload_string: string }
) => {
    try {
        const form = buildScanFormData(start_scan_payload_string, null)
        const response = await api.post(`/${team_id}/llm/scan/${scan_id}/reinitialize`, form, {
            headers: { "Content-Type": "multipart/form-data" },
        })
        toast.success("LLM scan reinitialized successfully")
        return response.data
    } catch (error) {
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
    getLLMExportResults,
    reinitializeLLMScan }

// -------------------------------------------------------------- MCP API Routes --------------------------------------------------------------

interface MCPConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}

/** MCP finding from backend get_findings_for_scan_type (MCP branch) */
export interface MCPFinding {
    id: string
    title: string
    description: string
    impact: string
    risk_score: number
    status: string
    owasp_top_10?: unknown
    owasp_top_10_llm?: unknown
    compliance_controls?: unknown
    suggested_fix?: string | null
    type?: "tool" | "prompt" | "resource"
}

/** MCP scan metadata from backend get_scan_metadata (MCP branch) */
export interface MCPScanMetadata {
    server_url?: string
    server_mode?: string
    headers?: Record<string, string>
    environment?: string
}

/** MCP scan dashboard (from generate_scan_dashboard for type "mcp") */
export interface MCPDashboardData {
    owasp_top_10_metrics?: Record<string, number>
    compliance_controls_metrics?: Record<string, number>
    risk_metrics?: Record<string, number>
    tools_detected?: number
    tools_vulnerability_metrics?: Record<string, number>
    tools_impact_metrics?: Record<string, { critical: number; high: number; medium: number; low: number }>
    tools_compliance_controls_metrics?: Record<string, number>
    /** Summary cards */
    card_data?: {
        overall_risk_score?: number
        total_findings?: number
        exploitability_index?: number
        attack_surface?: number
        mttr?: number | [number, number, number]
        active_vulnerabilities?: number
        compliance_score?: number
        category_coverage?: number
    }
    severity_distribution?: { critical: number; high: number; medium: number; low: number }
    category_coverage?: Record<string, number>
    category_threat_landscape?: Record<string, { avg_risk_score: number; total_issues: number }>
    compliance_framework_scores?: Record<string, number>
    compliance_failure_trends?: Record<string, number>
    asset_attack_surface?: Record<string, string>
    tool_impact_analysis?: Record<string, { critical: number; high: number; medium: number; low: number }>
    asset_compliance_violations?: Record<string, number>
    owasp_top_10_llm_metrics?: Record<string, number>
}

/** LLM finding from backend get_findings_for_scan_type (llm branch) */
export interface LLMFinding {
    id: string
    title: string
    description: string
    impact: string
    status?: string | null
    vulnerability_predictions?: unknown
    owasp_top_10_llm: unknown
    compliance_controls: unknown
    suggested_fix?: string | null
}

/** LLM scan metadata from backend get_scan_metadata (llm branch) */
export interface LLMScanMetadata {
    model_type?: string | null
    model_name?: string | null
    probes?: unknown
}

/** LLM scan dashboard (from generate_scan_dashboard for type "llm") */
export interface LLMDashboardData {
    card_data?: {
        attacks_run: number
        total_vulnerabilities_found: number
        pass_rate: number
        risk_score: number
        scan_duration: number
        policy_violations: number
    }
    security_posture?: {
        jailbreak_resistance_score: number
        injection_resistance_score: number
        hallucination_resistance_score: number
        bias_resistance_score: number
        content_safety_score: number
        data_privacy_score: number
    }
    owasp_top_10_llm_metrics?: Record<string, number>
    compliance_controls_metrics?: Record<string, number>
    risk_metrics?: { Low?: number; Medium?: number; High?: number; Critical?: number }
    mitre_atlas_metrics?: Record<string, number>
    vulnerability_breakdown?: { critical: number; high: number; medium: number; low: number }
    adversarial_attack_outcomes?: Record<string, { passed: number; total: number }>
    attack_details?: Record<string, { passed: number; total: number; hit_rate: number; description: string }>
}

export interface MCPConversationResponse {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
    data: any
    messages: MCPConversationMessage[]
    dashboard?: MCPDashboardData | null
    findings?: MCPFinding[] | null
    scan_metadata?: MCPScanMetadata | Record<string, unknown> | null
    integration_settings?: Record<string, unknown> | null
    info?: ScanInfoField | null
}

const getMCPConversationMessages = async ({ queryKey }: { queryKey: ['mcp-conversation-data', number, number] }): Promise<MCPConversationResponse> => {
    const [, team_id, scan_id] = queryKey
    try {
        const response = await api.get(`/${team_id}/mcp/scan/${scan_id}`)
        const raw = response.data as {
            title: string
            scan_metadata?: MCPScanMetadata | Record<string, unknown> | null
            scan_status: string
            data: any
            dashboard?: unknown
            messages: MCPConversationMessage[]
            findings?: MCPFinding[] | null
            integration_settings?: Record<string, unknown> | null
            info?: ScanInfoField | null
        }
        toast.success("MCP conversation messages fetched successfully")
        return {
            id: scan_id,
            title: raw.title,
            created_at: "",
            last_updated: "",
            scan_status: raw.scan_status,
            data: raw.data,
            messages: raw.messages ?? [],
            dashboard: raw.dashboard ?? null,
            findings: raw.findings ?? null,
            scan_metadata: raw.scan_metadata ?? null,
            integration_settings: raw.integration_settings ?? null,
            info: raw.info ?? null,
        }
    } catch (error) {
        showErrorToast(error, "Error fetching MCP conversation messages")
        throw error
    }
}

export interface MCPConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
    owner_user_email?: string | null
    owner_user_full_name?: string | null
    scan_metadata?: Record<string, unknown> | null
    info?: ScanInfoField | null
    risk_data?: ScanRiskData | null
    server?: string | null
    average_risk_score?: number | null
    discovery_metrics?: { total_tools: number; total_prompts: number; total_resources: number } | null
    risky_assets?: number | null
    estimated_credits?: number | null
}

/** MCP list dashboard card_data from backend generate_mcp_dashboard_data */
export interface MCPListCardData {
    total_scans: number
    total_critical_issues: number
    average_risk_score: number
    total_active_scans: number
    total_resolved_issues: number
}

/** MCP list dashboard from backend generate_mcp_dashboard_data (GET /{team_id}/mcp/scans) */
export interface MCPListDashboardData {
    card_data: MCPListCardData
    scan_status_distribution: { not_started: number; started: number; success: number; failure: number }
    risk_score_trend: Record<string, number>
    risks_over_time: Record<string, { critical: number; high: number; medium: number; low: number }>
    severity_distribution: { critical: number; high: number; medium: number; low: number }
    environment_risk_analysis: { development: number; production: number; staging: number }
    compliance_framework_distribution: Record<string, number>
    remediation_status_tracking: { not_started: number; in_progress: number; fixed: number; ignored: number }
    asset_category_vulnerabilities: Record<string, number>
    scan_duration_trends: Record<string, number>
    security_posture_overview: Record<string, number>
    mttr_per_day: Record<string, [number, number, number]>
    scan_effectiveness_trend: Record<string, { false_positive: number; total_findings: number }>
    compliance_framework_score_trend: Record<string, Record<string, number>>
    vulnerability_age_distribution: Record<string, number>
}

/** Response from GET /{team_id}/mcp/scans (backend scans router) */
export interface MCPScansListResponse {
    scans_list_data: MCPConversation[]
    dashboard_data: MCPListDashboardData
}

const getMCPConversations = async (team_id: number): Promise<MCPScansListResponse> => {
    try {
        const response = await api.get(`/${team_id}/mcp/scans`)
        toast.success("MCP conversations fetched successfully")
        return response.data as MCPScansListResponse
    } catch (error) {
        showErrorToast(error, "Error fetching MCP conversations")
        throw error
    }
}

const deleteMCPConversation = async (team_id: number, conversation_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/mcp/scan/${conversation_id}`)
        toast.success("MCP conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameMCPConversation = async ({ team_id, conversation_id, title }: { team_id: number; conversation_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/mcp/scan/${conversation_id}`, { title })
        toast.success("MCP conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createMCPConversation = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/mcp/scan`, { title })
        toast.success("MCP conversation created successfully")
        return response.data.scan_id as number
    } catch (error) {
        throw error
    }
}

/** Start MCP scan using generic start with type "mcp" and payload { mcp: { server_url, server_mode, headers } }. Prefer startScan(team_id, "mcp", scan_id, payloadString) after estimating. */
const startMCPScan = async (
    { team_id, scan_id, start_scan_payload_string }: { team_id: number; scan_id: number; start_scan_payload_string: string }
) => {
    try {
        const form = buildScanFormData(start_scan_payload_string, null)
        const response = await api.post(`/${team_id}/mcp/scan/${scan_id}/start`, form, {
            headers: { "Content-Type": "multipart/form-data" },
        })
        toast.success("MCP scan started successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const getMCPExportResults = async (team_id: number, scan_id: number): Promise<Blob> => {
    try {
        const response = await api.get(`/${team_id}/mcp/scan/${scan_id}/export`, { responseType: "blob" })
        toast.success("MCP export results fetched successfully")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error fetching MCP export results")
        throw error
    }
}

const reinitializeMCPScan = async (
    { team_id, scan_id, start_scan_payload_string }: { team_id: number; scan_id: number; start_scan_payload_string: string }
) => {
    try {
        const form = buildScanFormData(start_scan_payload_string, null)
        const response = await api.post(`/${team_id}/mcp/scan/${scan_id}/reinitialize`, form, {
            headers: { "Content-Type": "multipart/form-data" },
        })
        toast.success("MCP scan reinitialized successfully")
        return response.data
    } catch (error) {
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
    startMCPScan,
    reinitializeMCPScan
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

// -------------------------------------------------------------- Teams API Routes --------------------------------------------------------------

export interface TeamListItem {
    team_id: number
    team_name: string
    team_description: string | null
    team_members: string[]
    team_created_at: string
    team_updated_at: string
    team_credit_balance: number
}

export interface TeamMember {
    email: string
    role: string
}

/** Jira settings for team ticketing integration (matches backend JiraTeamSettingsData) */
export interface JiraTeamSettingsData {
    email: string
    api_token: string
    url: string
}

/** Team ticketing integration settings (matches backend TicketingIntegrationSettingsData) */
export interface TicketingIntegrationSettingsData {
    jira?: JiraTeamSettingsData | null
}

export interface TeamDetails {
    team_id: number
    team_name: string
    team_description: string | null
    is_team_admin: boolean
    team_members: TeamMember[]
    team_created_at: string
    team_credit_balance: number
    team_integration_settings: TicketingIntegrationSettingsData | Record<string, unknown> | null
    team_settings: Record<string, unknown> | null
}

export interface UpdateTeamData {
    name?: string
    description?: string | null
    integration_settings?: TicketingIntegrationSettingsData | null
}

export interface RemoveOrAddMembersToTeamData {
    intent: "remove" | "add"
    email_ids: string[]
}

export interface CreateTeamData {
    name: string
    description?: string | null
}

/** Per-date remediation counts (daily deltas: new/fixed/ignored that day) */
export interface RemediationsStatusDistribution {
    not_started: number
    in_progress: number
    fixed: number
    ignored: number
}

/** Summary card data for team dashboard (top of page) */
export interface TeamDashboardCardData {
    total_findings: number
    total_started_scans: number
    total_completed_scans: number
    total_not_started_scans: number
    total_fixed_findings: number
    remediation_percentage: number
}

export interface TeamDashboardData {
    scans_created_at_data: { date: string; count: number }[]
    guardrails_integrations_created_at_data: { date: string; count: number }[]
    cicd_integrations_created_at_data: { date: string; count: number }[]
    scan_type_count: Record<string, number>
    high_and_critical_vuln_in_past_month: Record<string, number>
    /** Scan status distribution for radial chart */
    scan_status_distribution?: { not_started: number; running: number; completed: number; failed: number }
    /** Remediations per day for area/line chart: date -> { not_started, in_progress, fixed, ignored } */
    remediations_status_distribution?: Record<string, RemediationsStatusDistribution>
    /** Findings created per day (date -> count) */
    findings_per_day?: Record<string, number>
    /** Fixed findings per day (date -> count) */
    fixes_per_day?: Record<string, number>
    /** Ignored findings per day (date -> count) */
    false_positive_trends?: Record<string, number>
    /** Summary card data (totals) */
    card_data?: TeamDashboardCardData
}

/** Utilization item per team (key is string representation of team) */
export interface TeamsDashboardUtilizationItem {
    sast_scans: number
    iac_scans: number
    sbom_sca_scans: number
    guardrails_integrations: number
    cicd_integrations: number
}

/** Credit balance item per team */
export interface TeamsDashboardCreditItem {
    credit_balance: number
}

/** GET /teams/dashboard - matches backend generate_team_list_dashboard_data */
export interface TeamsDashboardData {
    team_utilization_data: Record<string, TeamsDashboardUtilizationItem>
    credit_balance_data: Record<string, TeamsDashboardCreditItem>
}

const getTeamDashboard = async (team_id: number): Promise<TeamDashboardData> => {
    try {
        const response = await api.get(`/team/${team_id}/dashboard`)
        return response.data as TeamDashboardData
    } catch (error) {
        showErrorToast(error, "Error fetching team dashboard")
        throw error
    }
}

const getTeamsDashboard = async (): Promise<TeamsDashboardData> => {
    try {
        const response = await api.get("/teams/dashboard")
        return response.data as TeamsDashboardData
    } catch (error) {
        showErrorToast(error, "Error fetching teams dashboard")
        throw error
    }
}

const getTeams = async (): Promise<TeamListItem[]> => {
    try {
        const response = await api.get("/teams")
        return response.data as TeamListItem[]
    } catch (error) {
        showErrorToast(error, "Error fetching teams")
        throw error
    }
}

const createTeam = async (data: CreateTeamData) => {
    try {
        const response = await api.post("/team", data)
        toast.success("Team created successfully")
        return response.data as { team_id: number; team_name: string; team_description: string | null; team_members: string[] }
    } catch (error) {
        showErrorToast(error, "Error creating team")
        throw error
    }
}

const getTeam = async (team_id: number): Promise<TeamDetails> => {
    try {
        const response = await api.get(`/team/${team_id}`)
        return response.data as TeamDetails
    } catch (error) {
        showErrorToast(error, "Error fetching team details")
        throw error
    }
}

const updateTeam = async (team_id: number, data: UpdateTeamData) => {
    try {
        const response = await api.put(`/team/${team_id}`, data)
        toast.success("Team updated successfully")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error updating team")
        throw error
    }
}

const removeOrAddTeamMembers = async (team_id: number, data: RemoveOrAddMembersToTeamData) => {
    try {
        const response = await api.patch(`/team/${team_id}`, data)
        toast.success(`Members ${data.intent === "add" ? "added" : "removed"} successfully`)
        return response.data
    } catch (error) {
        showErrorToast(error, `Error ${data.intent === "add" ? "adding" : "removing"} members`)
        throw error
    }
}

const deleteTeam = async (team_id: number) => {
    try {
        await api.delete(`/team/${team_id}`)
        toast.success("Team deleted successfully")
    } catch (error) {
        showErrorToast(error, "Error deleting team")
        throw error
    }
}

export {
    getUserProfile,
    logout,
    getTeams,
    createTeam,
    getTeam,
    getTeamDashboard,
    getTeamsDashboard,
    updateTeam,
    removeOrAddTeamMembers,
    deleteTeam
}

// -------------------------------------------------------------- Admin API Routes --------------------------------------------------------------

export interface AdminCheckSuperuserResponse {
    message: string
    user_id: number
    email: string
}

export interface AdminUser {
    user_id: number
    user_email: string
    user_first_name: string
    user_last_name: string
    user_team_memberships: [number, string][]
    user_is_superuser: boolean
    user_default_team_id: number | null
}

export interface AdminTeam {
    team_id: number
    team_name: string
    team_description: string | null
    team_members: string[]
    team_created_at: string
    team_credit_balance: number
    scans_count: number
    guardrails_integrations_count: number
    cicd_integrations_count: number
    sast_scans_count: number
    iac_scans_count: number
    sbom_sca_scans_count: number
}

const checkSuperuser = async (): Promise<AdminCheckSuperuserResponse> => {
    const response = await api.get<AdminCheckSuperuserResponse>("/admin/check_superuser")
    return response.data
}

const getAdminUsers = async (): Promise<AdminUser[]> => {
    const response = await api.get<AdminUser[]>("/admin/users")
    return response.data
}

const getAdminTeams = async (): Promise<AdminTeam[]> => {
    const response = await api.get<AdminTeam[]>("/admin/teams")
    return response.data
}

const toggleAdminAccess = async (user_id: number) => {
    const response = await api.post("/admin/toggle_admin_access", { user_id })
    toast.success(response.data?.message || "Admin access updated successfully")
    return response.data
}

const updateTeamCreditBalance = async (team_id: number, credit_balance: number) => {
    const response = await api.post("/admin/update", { team_id, credit_balance })
    toast.success(response.data?.message || "Team credit balance updated successfully")
    return response.data
}

export interface CreateAdminUserData {
    email: string
    password: string
    first_name: string
    last_name: string
}

const createAdminUser = async (data: CreateAdminUserData) => {
    const response = await api.post("/admin/create_admin_user", data)
    toast.success(response.data?.message || "Admin user created successfully")
    return response.data
}

const deleteUser = async (user_id: number) => {
    const response = await api.delete("/admin/delete_user", { data: { user_id } })
    toast.success(response.data?.message || "User deleted successfully")
    return response.data
}

export {
    checkSuperuser,
    getAdminUsers,
    getAdminTeams,
    toggleAdminAccess,
    updateTeamCreditBalance,
    createAdminUser,
    deleteUser,
}

// -------------------------------------------------------------- IAC API Routes --------------------------------------------------------------

/** List item from GET /{team_id}/iac/scans (same shape as SAST list) */
export interface IACConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
    scan_metadata?: Record<string, unknown> | null
    estimated_credits?: number | null
    owner_user_email?: string | null
    owner_user_full_name?: string | null
    info?: ScanInfoField | null
    risk_data?: ScanRiskData | null
    /** From return_iac_list_item */
    repo_url?: string | null
    zip_file_used?: boolean | null
    branch?: string | null
    cloud_provider?: string[]
    average_risk_score?: number | null
    coverage_percentage?: number | null
    environment?: string | null
}

/** IAC list dashboard card_data from backend generate_iac_dashboard_data */
export interface IACListCardData {
    total_scans: number
    total_issues: number
    total_critical_issues: number
    avg_mttr_days: number
    coverage_percentage: number
    total_policy_violations: number
    average_risk_score: number
}

/** IAC list dashboard from backend generate_iac_dashboard_data (GET /{team_id}/iac/scans) */
export interface IACListDashboardData {
    card_data: IACListCardData
    severity_distribution: { critical: number; high: number; medium: number; low: number }
    issues_over_time: Record<string, { critical: number; high: number; medium: number; low: number }>
    security_posture_overview: Record<string, number>
    compliance_framework_coverage?: Record<string, number>
    compliance_framework_counts?: Record<string, number>
    remediation_pipeline: { total_issues: number; fixed: number; in_progress: number; not_started: number; ignored: number }
    mttr_per_day: Record<string, [number, number, number]>
    resources_by_provider: Record<string, number>
    environment: Record<string, number>
    environment_cloud_resource_heatmap: Record<string, Record<string, number>>
    remediation_metrics?: {
        mean_time_to_remediate: [number, number, number]
        critical_issues_fixed: number
        remediation_velocity: number
        high_priority_backlog: number
    }
}

export interface IACListResponse {
    scans_list_data: IACConversation[]
    dashboard_data: IACListDashboardData
}

const getIACConversations = async (team_id: number): Promise<IACListResponse> => {
    try {
        const response = await api.get(`/${team_id}/iac/scans`)
        toast.success("IAC conversations fetched successfully")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error fetching iac conversations")
        throw error
    }
}

const deleteIACConversation = async (team_id: number, scan_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/iac/scan/${scan_id}`)
        toast.success("IAC conversation deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameIACConversation = async ({ team_id, scan_id, title }: { team_id: number; scan_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/iac/scan/${scan_id}`, { title })
        toast.success("IAC conversation renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createIACConversation = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/iac/scan`, { title })
        toast.success("IAC conversation created successfully")
        return response.data.scan_id as number
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
  repo_url?: string | null
  scan_status: string
  scan_metadata?: IACScanMetadata | Record<string, unknown> | null
  data: any
  messages: IACConversationMessage[]
  dashboard?: IACScanDashboardData | SastDashboardData | null
  findings?: IACFinding[] | null
  integration_settings?: Record<string, unknown> | null
  info?: ScanInfoField | null
}

/** Team-scoped: GET /{team_id}/iac/scan/{scan_id} */
const getIACConversationMessages = async ({ queryKey }: { queryKey: ['iac-conversation-data', number, number] }): Promise<IACConversationResponse> => {
    const [, team_id, scan_id] = queryKey;
    try {
        const response = await api.get(`/${team_id}/iac/scan/${scan_id}`);
        toast.success("IAC conversation messages fetched successfully");
        return response.data as IACConversationResponse;
    } catch (error) {
        showErrorToast(error, "Error fetching iac conversation messages");
        throw error;
    }
};

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
        const response = await api.post(`/iac/conversation/${conversation_id}/scan`, { iac_data: { repo_url: repo_url, PAT: PAT, mode: mode } });
        toast.success("IAC scan started successfully");
        return response.data;
    } catch (error) {
        throw error;
    }
};

/** Team-scoped: GET /{team_id}/iac/scan/{scan_id}/export */
const getIACExportResults = async (team_id: number, scan_id: number): Promise<Blob | ArrayBuffer> => {
    try {
        const response = await api.get(`/${team_id}/iac/scan/${scan_id}/export`, { responseType: "blob" });
        toast.success("IAC export results fetched successfully");
        return response.data;
    } catch (error) {
        showErrorToast(error, "Error fetching iac export results");
        throw error;
    }
};

const reinitializeIACScan = async (
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
        const response = await api.post(`/iac/conversation/${conversation_id}/reinitialize`, { iac_data: { repo_url, PAT, mode } });
        toast.success("IAC scan reinitialized successfully");
        return response.data;
    } catch (error) {
        throw error;
    }
};

/** Team-scoped: POST /{team_id}/iac/scan/{scan_id}/reinitialize with FormData (start_scan_payload_string, optional uploaded_file) */
const reinitializeIACScanWithPayload = async (
    team_id: number,
    scan_id: number,
    start_scan_payload_string: string,
    uploaded_file?: File | null
) => {
    const form = buildScanFormData(start_scan_payload_string, uploaded_file);
    const response = await api.post<{ message: string }>(
        `/${team_id}/iac/scan/${scan_id}/reinitialize`,
        form,
        { headers: { "Content-Type": "multipart/form-data" } }
    );
    toast.success("IAC scan reinitialized successfully");
    return response.data;
};

export {
    getIACConversations,
    deleteIACConversation,
    renameIACConversation,
    createIACConversation,
    getIACConversationMessages,
    startIACScan,
    getIACExportResults,
    reinitializeIACScan,
    reinitializeIACScanWithPayload
}

// -------------------------------------------------------------- SCA + SBOM API Routes --------------------------------------------------------------

export interface SCASBOMConversation {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
    scan_metadata?: Record<string, unknown> | null
    estimated_credits?: number | null
    owner_user_email?: string
    owner_user_full_name?: string
    info?: ScanInfoField | null
    risk_data?: ScanRiskData | null
    repo_url?: string | null
    zip_file_used?: boolean | null
    branch?: string | null
    average_risk_score?: number | null
}

/** Card counts returned by list SBOM/SCA scans (same shape as SastListCardData) */
export interface SBOMSCAListCardData {
    pending_scans: number
    started_scans: number
    success_scans: number
    failure_scans: number
    not_started_scans: number
    scans_created_today: number
    scans_updated_today: number
}

/** SBOM/SCA list dashboard from backend generate_sbom_sca_dashboard_data (GET /{team_id}/sbom_sca/scans) */
export interface SBOMSCADashboardData {
    remediation_actions_required: {
        total_findings: number
        total_fixed: number
        total_in_progress: number
        total_not_started: number
        total_ignored: number
    }
    severity_distribution: { critical: number; high: number; medium: number; low: number }
    reachability_distribution: {
        not_reachable: number
        potentially_reachable: number
        reachable: number
        unknown: number
    }
    vulnerability_trends_over_time: Record<string, { critical: number; high: number; medium: number; low: number }>
    licenses_distribution: Record<string, number>
    top_vulnerabilities_by_risk_score: Array<{
        dependency: string
        reachability: string
        dependency_type: string
        license_type: string
        impact: string
    }>
    card_data: {
        total_vulnerabilities: number
        total_critical_vulnerabilities: number
        total_policy_violations: number
        total_license_risks: number
        total_high_risk_licenses: number
        average_risk_score: number
        total_reachable_issues: number
    }
    average_risk_score_per_reachability_level: Record<string, number>
    policy_compliance_data: Record<string, number>
}

export interface SBOMSCAListResponse {
    scans_list_data: SCASBOMConversation[]
    dashboard_data: SBOMSCADashboardData
}

/** Team-scoped: GET /{team_id}/sbom_sca/scans */
const getSBOMSCAScans = async (team_id: number): Promise<SBOMSCAListResponse> => {
    try {
        const response = await api.get(`/${team_id}/sbom_sca/scans`);
        toast.success("SCA + SBOM scans fetched successfully");
        return response.data as SBOMSCAListResponse;
    } catch (error) {
        showErrorToast(error, "Error fetching sbom_sca scans");
        throw error;
    }
};

const deleteSBOMSCAScan = async (team_id: number, scan_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/sbom_sca/scan/${scan_id}`);
        toast.success("SCA + SBOM scan deleted successfully");
        return response.data;
    } catch (error) {
        throw error;
    }
};

const renameSBOMSCAScan = async ({
    team_id,
    scan_id,
    title,
}: {
    team_id: number;
    scan_id: number;
    title: string;
}) => {
    try {
        const response = await api.put(`/${team_id}/sbom_sca/scan/${scan_id}`, { title });
        toast.success("SCA + SBOM scan renamed successfully");
        return response.data;
    } catch (error) {
        throw error;
    }
};

/** Update scan (title and/or integration_settings). PUT /{team_id}/{type}/scan/{scan_id} */
const updateScan = async ({
    team_id,
    type,
    scan_id,
    data,
}: {
    team_id: number;
    type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast";
    scan_id: number;
    data: UpdateScanPayload;
}) => {
    const response = await api.put(`/${team_id}/${type}/scan/${scan_id}`, data);
    return response.data;
};

/** Toggle finding state: fixed | ignored | in_progress | not_started. POST /{team_id}/{type}/scan/{scan_id}/finding */
const toggleFindingState = async ({
    team_id,
    type,
    scan_id,
    finding_id,
    state,
}: {
    team_id: number;
    type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast";
    scan_id: number;
    finding_id: string;
    state: "fixed" | "ignored" | "in_progress" | "not_started";
}): Promise<{ message: string }> => {
    const response = await api.post<{ message: string }>(
        `/${team_id}/${type}/scan/${scan_id}/finding`,
        { finding_id, state }
    );
    return response.data;
};

const createSBOMSCAScan = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/sbom_sca/scan`, { title });
        toast.success("SCA + SBOM scan created successfully");
        return response.data.scan_id as number;
    } catch (error) {
        throw error;
    }
};

/** Legacy: non–team-scoped list. Prefer getSBOMSCAScans(team_id) for [team_id]/sbom_sca page. */
const getSCASBOMConversations = async (): Promise<SCASBOMConversation[]> => {
    try {
        const response = await api.get("/sbom_sca/conversations");
        toast.success("SCA + SBOM conversations fetched successfully");
        return response.data as SCASBOMConversation[];
    } catch (error) {
        showErrorToast(error, "Error fetching sbom_sca conversations");
        throw error;
    }
};

/** Legacy: conversation-scoped delete. Prefer deleteSBOMSCAScan(team_id, scan_id). */
const deleteSCASBOMConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/sbom_sca/conversation/${conversation_id}`);
        toast.success("SCA + SBOM conversation deleted successfully");
        return response.data;
    } catch (error) {
        throw error;
    }
};

/** Legacy: conversation-scoped rename. Prefer renameSBOMSCAScan({ team_id, scan_id, title }). */
const renameSCASBOMConversation = async ({
    conversation_id,
    title,
}: {
    conversation_id: number;
    title: string;
}) => {
    try {
        const response = await api.put(`/sbom_sca/conversation/${conversation_id}`, { title });
        toast.success("SCA + SBOM conversation renamed successfully");
        return response.data;
    } catch (error) {
        throw error;
    }
};

/** Legacy: non–team-scoped create. Prefer createSBOMSCAScan(team_id, title). */
const createSCASBOMConversation = async (title: string) => {
    try {
        const response = await api.post("/sbom_sca/conversation", { title });
        toast.success("SCA + SBOM conversation created successfully");
        return response.data.conversation_id as number;
    } catch (error) {
        throw error;
    }
};

export interface SCASBOMConversationMessage {
    id: number
    content: string
    role: "user" | "assistant"
    timestamp: string
    is_streaming: boolean
}

/** Matches backend JiraTeamSettingsData for scans (db/schemas.py). Only jira_project_id is sent for scan integration_settings. */
export interface ScanJiraSettings {
    jira_project_id: string | null;
}
/** Matches backend ScanTicketingIntegrationSettingsData. */
export interface ScanTicketingIntegrationSettings {
    jira: ScanJiraSettings | null;
}
/** Payload for PUT /{team_id}/{type}/scan/{scan_id}. Matches backend UpdateScanData. */
export interface UpdateScanPayload {
    title?: string | null;
    integration_settings?: ScanTicketingIntegrationSettings | null;
}

export interface SCASBOMConversationResponse {
    title: string
    repo_url?: string | null
    scan_status: string
    scan_metadata?: SbomScanMetadata | Record<string, unknown> | null
    data: any
    dashboard?: SbomScanDashboardData | null
    findings?: SbomFinding[] | null
    messages: SCASBOMConversationMessage[]
    integration_settings?: Record<string, unknown> | null
    info?: ScanInfoField | null
}

/** Team-scoped: GET /{team_id}/sbom_sca/scan/{scan_id} — use with queryKey ['sbom_sca-conversation-data', team_id, scan_id] */
const getSBOMSCAScanData = async ({
    queryKey,
}: {
    queryKey: ["sbom_sca-conversation-data", number, number];
}): Promise<SCASBOMConversationResponse> => {
    const [, team_id, scan_id] = queryKey;
    try {
        const response = await api.get(`/${team_id}/sbom_sca/scan/${scan_id}`);
        toast.success("SCA + SBOM scan data fetched successfully");
        return response.data as SCASBOMConversationResponse;
    } catch (error) {
        showErrorToast(error, "Error fetching sbom_sca scan data");
        throw error;
    }
};

/** Legacy: conversation-scoped get (no team_id). Prefer getSBOMSCAScanData for [team_id]/sbom_sca/[scan_id] pages. */
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

/** Team-scoped: GET /{team_id}/sbom_sca/scan/{scan_id}/export */
const getSBOMExportResults = async (team_id: number, scan_id: number): Promise<Blob | ArrayBuffer> => {
    try {
        const response = await api.get(`/${team_id}/sbom_sca/scan/${scan_id}/export`, { responseType: "blob" });
        toast.success("SCA + SBOM export results fetched successfully");
        return response.data;
    } catch (error) {
        showErrorToast(error, "Error fetching sbom_sca export results");
        throw error;
    }
};

/** Team-scoped: POST /{team_id}/sbom_sca/scan/{scan_id}/reinitialize with FormData (start_scan_payload_string, optional uploaded_file) */
const reinitializeSBOMScanWithPayload = async (
    team_id: number,
    scan_id: number,
    start_scan_payload_string: string,
    uploaded_file?: File | null
) => {
    const form = buildScanFormData(start_scan_payload_string, uploaded_file);
    const response = await api.post<{ message: string }>(
        `/${team_id}/sbom_sca/scan/${scan_id}/reinitialize`,
        form,
        { headers: { "Content-Type": "multipart/form-data" } }
    );
    toast.success("SCA + SBOM scan reinitialized successfully");
    return response.data;
};

const reinitializeSCASBOMScan = async (
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
        const response = await api.post(`/sbom_sca/conversation/${conversation_id}/reinitialize`, { sbom_sca_data: { repo_url: repo_url, PAT: PAT, mode: mode } })
        toast.success("SCA + SBOM scan reinitialized successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

export {
    getSCASBOMConversations,
    getSBOMSCAScans,
    deleteSCASBOMConversation,
    deleteSBOMSCAScan,
    renameSCASBOMConversation,
    renameSBOMSCAScan,
    createSCASBOMConversation,
    createSBOMSCAScan,
    getSCASBOMConversationMessages,
    getSBOMSCAScanData,
    startSCASBOMScan,
    getSCASBOMExportResults,
    getSBOMExportResults,
    reinitializeSCASBOMScan,
    reinitializeSBOMScanWithPayload,
    updateScan,
    toggleFindingState,
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

const reinitializeDiscoveryScan = async (
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
        const response = await api.post(`/agent_discovery/conversation/${conversation_id}/reinitialize`, { agent_discovery_data: { repo_url: repo_url, PAT: PAT, mode: mode } })
        toast.success("Discovery scan reinitialized successfully")
        return response.data
    } catch (error) {
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
    getDiscoveryExportResults,
    reinitializeDiscoveryScan
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

const reinitializeLeakageScan = async (
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
        const response = await api.post(`/leakage/conversation/${conversation_id}/reinitialize`, { leakage_data: { repo_url: repo_url, PAT: PAT, mode: mode } })
        toast.success("Leakage scan reinitialized successfully")
        return response.data
    } catch (error) {
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
    getLeakageExportResults,
    reinitializeLeakageScan
}

// -------------------------------------------------------------- Guardrails API Routes --------------------------------------------------------------

export interface GuardrailsIntegration {
    id: number
    title: string
    created_at: string
    last_updated: string
    api_key: string
    scanners_enabled?: string[]
    owner_user_email?: string
    owner_user_full_name?: string
}

/** Dashboard for guardrails list page: card_data (log counts), risk score counts, daily high/critical usage */
export interface GuardrailsListDashboardData {
    card_data: {
        total_logs: number
        pending_logs: number
        started_logs: number
        not_started_logs: number
        success_logs: number
        failure_logs: number
    }
    past_30_days_risk_score_data: {
        critical: number
        high: number
        medium: number
        low: number
    }
    /** Date string (YYYY-MM-DD) -> count of high/critical risks that day */
    high_or_critical_risks_daily_usage: Record<string, number>
}

const getGuardrailsListDashboard = async (team_id: number): Promise<GuardrailsListDashboardData> => {
    try {
        const response = await api.get(`/guardrails/${team_id}/integrations/dashboard`)
        return response.data as GuardrailsListDashboardData
    } catch (error) {
        showErrorToast(error, "Error fetching guardrails list dashboard")
        throw error
    }
}

/** Response from GET /guardrails/{team_id}/integrations (includes dashboard_data) */
export interface GuardrailsIntegrationsResponse {
    integrations: GuardrailsIntegration[]
    dashboard_data: GuardrailsListDashboardData
}

const getGuardrailsIntegrations = async (team_id: number): Promise<GuardrailsIntegrationsResponse> => {
    try {
        const response = await api.get(`/guardrails/${team_id}/integrations`)
        toast.success("Guardrails integrations fetched successfully")
        const data = response.data as { integrations: GuardrailsIntegration[]; dashboard_data: GuardrailsListDashboardData }
        return data
    } catch (error) {
        showErrorToast(error,"Error fetching guardrails integrations")
        throw error
    }
}

const deleteGuardrailsIntegration = async (team_id: number, integration_id: number) => {
    try {
        const response = await api.delete(`/guardrails/${team_id}/integration/${integration_id}`)
        toast.success("Guardrails integration deleted successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error deleting guardrails integration")
        throw error
    }
}

const renameGuardrailsIntegration = async ({ team_id, integration_id, title }: { team_id: number; integration_id: number; title: string }) => {
    return updateGuardrailsIntegration({ team_id, integration_id, data: { title } })
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
/** Dashboard card metrics (total logs, today, trend, month, active scanners) */
export interface GuardrailsDashboardCardData {
    total_logs: number
    total_logs_today: number
    percentage_increase_or_decrease_in_total_logs_compared_to_yesterday: number
    total_logs_this_month: number
    total_active_scanners: number
}

/** Log status counts for radial chart (successful/failed/pending/started/not_started) */
export interface GuardrailsRadialChartData {
    total_logs: number
    successful_logs: number
    failed_logs: number
    pending_logs: number
    started_logs: number
    not_started_logs: number
}

/** Risk score counts by severity (critical/high/medium/low) */
export interface GuardrailsRiskScoreData {
    critical: number
    high: number
    medium: number
    low: number
}

/** Dashboard data returned by get_guardrails_integration_dashboard_data */
export interface GuardrailsDashboardData {
    card_data: GuardrailsDashboardCardData
    radial_chart_data: GuardrailsRadialChartData
    /** Date string (YYYY-MM-DD) -> count */
    recent_daily_detections_usage: Record<string, number>
    /** Date string (YYYY-MM-DD) -> count of high or critical risks that day */
    high_or_critical_risks_daily_usage: Record<string, number>
    past_30_days_risk_score_data: GuardrailsRiskScoreData
    past_60_days_risk_score_data: GuardrailsRiskScoreData
}

export interface GuardrailsIntegrationDashboard {
    dashboard_data: GuardrailsDashboardData
    api_key: string
    log_data: GuardrailsIntegrationLog[]
    settings: SettingsData
    integration_settings?: IntegrationSettingsData | Record<string, unknown> | null
}

const getGuardrailsIntegrationDashboard = async ({queryKey}: {queryKey: ['guardrails-integration-dashboard', string, string, number, number]}): Promise<GuardrailsIntegrationDashboard> => {
    const [, team_id, integration_id, limit, offset] = queryKey
    try {
        const response = await api.get(`/guardrails/${team_id}/integration/${integration_id}`, {
            params: { limit, offset },
        })
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

const createGuardrailsIntegration = async (team_id: number, data: CreateGuardrailsIntegrationData) => {
    try {
        const response = await api.post(`/guardrails/${team_id}/integration`, data)
        toast.success("Guardrails integration created successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error creating guardrails integration")
        throw error
    }
}

/** Jira settings for guardrails integration (matches backend JiraTeamSettingsData in guardrails schemas) */
export interface GuardrailsJiraSettingsData {
    jira_project_id?: string | null
}

export interface IntegrationSettingsData {
    jira?: GuardrailsJiraSettingsData | null
}

export interface UpdateGuardrailsIntegrationData {
    title?: string
    settings?: SettingsData
    integration_settings?: IntegrationSettingsData
}

const updateGuardrailsIntegration = async ({ team_id, integration_id, data }: { team_id: number; integration_id: number; data: UpdateGuardrailsIntegrationData }) => {
    try {
        const response = await api.put(`/guardrails/${team_id}/integration/${integration_id}`, data)
        toast.success("Guardrails integration updated successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error updating guardrails integration")
        throw error
    }
}

const getGuardrailsIntegrationSettings = async (team_id: number, integration_id: number) => {
    try {
        const response = await api.get(`/guardrails/${team_id}/integration/${integration_id}/settings`)
        return response.data as { settings: SettingsData }
    } catch (error) {
        showErrorToast(error,"Error fetching guardrails integration settings")
        throw error
    }
}

export { 
    getGuardrailsIntegrations, 
    getGuardrailsListDashboard,
    deleteGuardrailsIntegration, 
    renameGuardrailsIntegration,
    getGuardrailsIntegrationDashboard,
    createGuardrailsIntegration,
    updateGuardrailsIntegration,
    getGuardrailsIntegrationSettings
}

// -------------------------------------------------------------- DAST API Routes --------------------------------------------------------------

/** List item from return_dast_list_item (GET /{team_id}/dast/scans) */
export interface DASTListItem {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_status: string
    estimated_credits: number | null
    owner_user_email: string | null
    owner_user_full_name: string | null
    info: { current?: number } | null
    risk_data: { total_critical: number; total_high: number; total_medium: number; total_low: number }
    target_url: string | null
    average_risk_score: number
    urls_scanned: number
    coverage_percentage: number
}

/** List dashboard from generate_dast_dashboard_data */
export interface DASTListDashboardData {
    card_data: {
        total_scans: number
        total_critical_issues: number
        total_high_issues: number
        total_medium_issues: number
        total_low_issues: number
        average_risk_score: number
    }
    severity_distribution: { critical: number; high: number; medium: number; low: number }
    issues_over_time: Record<string, { critical: number; high: number; medium: number; low: number }>
    security_posture_overview: Record<string, number>
    owasp_top_10_issues: Record<string, number>
    average_risk_score_per_category: Record<string, number>
    average_risk_score_per_confidence: { high: number; medium: number; low: number }
    compliance_violations: Record<string, number>
}

export interface DASTListResponse {
    scans_list_data: DASTListItem[]
    dashboard_data: DASTListDashboardData
}

/** Single-scan dashboard from generate_scan_dashboard(scan_type="dast") */
export interface DASTSingleScanDashboard {
    card_data: {
        total_critical_issues: number
        total_high_issues: number
        total_medium_issues: number
        total_low_issues: number
        average_risk_score: number
        urls_scanned: number
        coverage_percentage: number
    }
    severity_distribution: { critical: number; high: number; medium: number; low: number }
    compliance_status: Record<string, number>
    owasp_top_10_issues: Record<string, number>
    vulnerability_category_issues_distribution: Record<string, number>
    risk_scores_per_category: Record<string, { critical: number; high: number; medium: number; low: number }>
    confidence_distribution: { high: number; medium: number; low: number }
    security_category_assessment: Record<string, number>
    compliance_risk_assessment: Record<string, number>
    remediation_metrics: {
        total_findings: number
        total_fixed: number
        total_in_progress: number
        total_not_started: number
        total_ignored: number
    }
}

/** Response from GET /{team_id}/dast/scan/{scan_id} (get_scan) */
export interface DASTScanResponse {
    title: string
    scan_metadata: Record<string, unknown> | null
    scan_status: string
    findings: unknown[]
    dashboard: DASTSingleScanDashboard | null
    messages: unknown[]
    integration_settings: Record<string, unknown> | null
    info: { current?: number } | null
    data: unknown
}

const getDASTScans = async (team_id: number): Promise<DASTListResponse> => {
    try {
        const response = await api.get(`/${team_id}/dast/scans`)
        toast.success("Refreshed successfully")
        return response.data as DASTListResponse
    } catch (error) {
        showErrorToast(error, "Error fetching DAST scans")
        throw error
    }
}

const getDASTScan = async (team_id: number, scan_id: number): Promise<DASTScanResponse> => {
    try {
        const response = await api.get(`/${team_id}/dast/scan/${scan_id}`)
        return response.data as DASTScanResponse
    } catch (error) {
        showErrorToast(error, "Error fetching DAST scan")
        throw error
    }
}

const deleteDASTScan = async (team_id: number, scan_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/dast/scan/${scan_id}`)
        toast.success("DAST scan deleted successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameDASTScan = async ({ team_id, scan_id, title }: { team_id: number; scan_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/dast/scan/${scan_id}`, { title })
        toast.success("DAST scan renamed successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

const createDASTScan = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/dast/scan`, { title })
        toast.success("DAST scan created successfully")
        return (response.data as { scan_id: number }).scan_id
    } catch (error) {
        throw error
    }
}

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

/** Auth fields for DAST (matches backend AuthRequirements). All required when starting a DAST scan. */
export interface AuthRequirements {
    login_url: string
    xpath_of_username_field: string
    xpath_of_password_field: string
    username: string
    password: string
    xpath_of_submit_button: string
}

/** DAST start payload (matches backend StartDASTScanData). Include and exclude URL patterns are not used together. Auth is required. */
export interface StartDASTScanData {
    target_url: string
    auth: AuthRequirements
    scan_speed?: "fast" | "medium" | "slow"
    max_urls?: number
    additional_urls_to_scan?: string[] | null
    exclude_url_patterns?: string[] | null
    include_url_patterns?: string[] | null
}

/** Start DAST scan via team-scoped route POST /{team_id}/dast/scan/{scan_id}/start */
const startDASTScan = async (
    { team_id, scan_id, dast }: { team_id: number; scan_id: number; dast: StartDASTScanData }
) => {
    const dastPayload = { ...dast, max_urls: dast.max_urls ?? 100 }
    const payloadString = JSON.stringify({ dast: dastPayload })
    return startScan(team_id, "dast", scan_id, payloadString, null)
}

/** Export DAST scan results via GET /{team_id}/dast/scan/{scan_id}/export */
const getDASTExportResults = async (team_id: number, scan_id: number): Promise<Blob> => {
    try {
        const response = await api.get(`/${team_id}/dast/scan/${scan_id}/export`, {
            responseType: "blob",
        })
        toast.success("DAST export results fetched successfully")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error fetching DAST export results")
        throw error
    }
}

/** Reinitialize DAST scan via POST /{team_id}/dast/scan/{scan_id}/reinitialize */
const reinitializeDASTScan = async (
    { team_id, scan_id, dast }: { team_id: number; scan_id: number; dast: StartDASTScanData }
) => {
    try {
        const dastPayload = { ...dast, max_urls: dast.max_urls ?? 100 }
        const payloadString = JSON.stringify({ dast: dastPayload })
        const form = buildScanFormData(payloadString, null)
        const response = await api.post(
            `/${team_id}/dast/scan/${scan_id}/reinitialize`,
            form,
            { headers: { "Content-Type": "multipart/form-data" } }
        )
        toast.success("DAST scan reinitialized successfully")
        return response.data
    } catch (error) {
        throw error
    }
}

export { 
    getDASTScans,
    getDASTScan,
    deleteDASTScan,
    renameDASTScan,
    createDASTScan,
    getDASTConversations,
    deleteDASTConversation,
    renameDASTConversation,
    createDASTConversation,
    getDASTConversationMessages,
    startDASTScan,
    getDASTExportResults,
    reinitializeDASTScan
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

/** Vulns-over-time chart data: date string -> counts by severity (from get_cicd_list_dashboard_data) */
export type CicdListDashboardData = Record<string, { Critical: number; High: number; Medium: number; Low: number }>

/** Response from GET /{team_id}/cicd/integrations */
export interface CicdIntegrationsResponse {
    integrations: CicdIntegration[]
    dashboard_data: CicdListDashboardData
}

const getCicdIntegrations = async (team_id: number): Promise<CicdIntegrationsResponse> => {
    try {
        const response = await api.get(`/${team_id}/cicd/integrations`)
        toast.success("CI/CD integrations fetched successfully")
        return response.data as CicdIntegrationsResponse
    } catch (error) {
        showErrorToast(error,"Error fetching CI/CD integrations")
        throw error
    }
}

export interface CreateCicdIntegrationData {
    title: string
    scan_type: "sast"
}

const createCicdIntegration = async (team_id: number, data: CreateCicdIntegrationData) => {
    try {
        const response = await api.post(`/${team_id}/cicd/integration`, data)
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
    last_updated?: string
    status: "pending" | "started" | "NOT_STARTED" | "success" | "failure" | "retry"
    results: any | null
    /** SAST (and similar) dashboard metrics; generated per log from results */
    dashboard?: SastDashboardData | null
    /** Credits consumed by this scan; may be null for older logs */
    credits_consumed?: number | null
    /** Error message when scan failed; may be null */
    error?: string | null
}

/** Per-date counts by impact (Critical, High, Medium, Low). Keys are date strings YYYY-MM-DD. */
export type VulnsOverTimeChartData = Record<string, { Critical?: number; High?: number; Medium?: number; Low?: number }>

export interface CicdIntegrationDashboard {
    cicd_integration_id: number
    title: string
    created_at: string
    last_updated: string
    scan_type: "sast" | "llm" | "mcp" | "iac" | "leakage" | "sbom_sca" | "agent_discovery"
    api_key: string
    integration_active?: boolean
    integration_settings?: Record<string, { jira_project_id?: string | null } | null> | null
    scan_settings?: Record<string, { app_lang?: SastAppLang; exclude_path_arrays?: string[][] | null } | null> | null
    logs: CicdLog[]
    /** Vulns-over-time chart data (date -> severity counts); from get_cicd_vuln_chart_data */
    dashboard_data?: VulnsOverTimeChartData | null
}

const getCicdIntegrationDashboard = async ({queryKey}: {queryKey: ['cicd-integration-dashboard', string, string, number, number]}): Promise<CicdIntegrationDashboard> => {
    const [, team_id, integration_id, limit, offset] = queryKey
    try {
        const response = await api.get(`/${team_id}/cicd/integration/${integration_id}`, {
            params: { limit, offset },
        })
        toast.success("CI/CD integration dashboard fetched successfully")
        return response.data as CicdIntegrationDashboard
    } catch (error) {
        showErrorToast(error,"Error fetching CI/CD integration dashboard")
        throw error
    }
}

const deleteCicdIntegration = async (team_id: number, integration_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/cicd/integration/${integration_id}`)
        toast.success("CI/CD integration deleted successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error deleting CI/CD integration")
        throw error
    }
}

export interface CicdIntegrationSettingsData {
    jira?: { jira_project_id?: string | null } | null
}

export interface CicdScanSettingsData {
    sast?: {
        app_lang: SastAppLang
        exclude_path_arrays?: string[][] | null
    } | null
}

export interface UpdateCicdIntegrationData {
    title?: string
    integration_settings?: CicdIntegrationSettingsData | null
    scan_settings?: CicdScanSettingsData | null
}

const updateCicdIntegration = async ({ team_id, integration_id, data }: { team_id: number; integration_id: number; data: UpdateCicdIntegrationData }) => {
    try {
        const response = await api.put(`/${team_id}/cicd/integration/${integration_id}`, data)
        toast.success("CI/CD integration updated successfully")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error updating CI/CD integration")
        throw error
    }
}

/** @deprecated Use updateCicdIntegration with { team_id, integration_id, data: { title } } */
const renameCicdIntegration = async ({ team_id, integration_id, title }: { team_id: number; integration_id: number; title: string }) => {
    return updateCicdIntegration({ team_id, integration_id, data: { title } })
}

export { 
    getCicdIntegrations,
    createCicdIntegration,
    getCicdIntegrationDashboard,
    deleteCicdIntegration,
    updateCicdIntegration,
    renameCicdIntegration
}