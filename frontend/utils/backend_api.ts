import api from "@/utils/interceptors"
import type { CbomResultOrigin, CbomSourcesRun } from "@/components/cbom/resultOrigin"
import { showErrorToast } from "./error-handler"
import { toast } from "@/utils/toast";


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

/** CBOM scan input: exactly one of repo_context, zip_file_used, or cbom_file_used (matches backend StartCBOMScanData) */
export interface StartCBOMScanData {
  repo_context: RepoContextSchema | null;
  zip_file_used: boolean;
  cbom_file_used: boolean;
  scan_binaries: boolean;
  /** code scans: also read vendor/, dist/, build/ and node_modules/ (default false) */
  include_vendored?: boolean;
  /** repository scans: clone with history (capped) and read key files found only in it (default false) */
  scan_history?: boolean;
}

/** AI BOM scan input: exactly one of repo_context, zip_file_used, or ai_bom_file_used (matches backend StartAiBomScanData) */
export interface StartAiBomScanData {
  repo_context: RepoContextSchema | null;
  zip_file_used: boolean;
  ai_bom_file_used: boolean;
}

export interface StartScanPayload {
  sast?: StartSastScanData | null;
  iac?: StartIACScanData | null;
  sbom_sca?: StartSBOMScanData | null;
  cbom?: StartCBOMScanData | null;
  ai_bom?: StartAiBomScanData | null;
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
        return response.data
    } catch (error) {
        showErrorToast(error,"Error fetching sast conversations")
        throw error
    }
}

const deleteSastConversation = async (team_id: number, scan_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/sast/scan/${scan_id}`)
        return response.data
    } catch (error) {
        throw error
    }
}

const renameSastConversation = async ({ team_id, scan_id, title }: { team_id: number; scan_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/sast/scan/${scan_id}`, { title })
        return response.data
    } catch (error) {
        throw error
    }
}

const createSastConversation = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/sast/scan`, { title })
        toast.success("SAST scan created")
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
  remediation?: RemediationData | null
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
  remediation?: RemediationData | null
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
  remediation?: RemediationData | null
}

/** SBOM/SCA scan metadata from backend get_scan_metadata (sbom_sca branch) */
export interface SbomScanMetadata {
  repo_url?: string | null
  branch?: string | null
  zip_file_used?: boolean
  sbom_compliance?: Record<string, unknown> | null
  rbi_csf_rollup?: Record<string, unknown> | null
  certin_posture?: Record<string, unknown> | null
  // CERT-In Phase 4 additive keys
  attestations?: Record<string, unknown> | null
  bom_signature?: Record<string, unknown> | null
  vex_json?: Record<string, unknown> | null
  /** CycloneDX 1.6 SBOM (real package names + advisory compliance properties) */
  sbom_json?: Record<string, unknown> | null
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
    not_assessed: number
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
        // no success toast: the scan page polls this every 6 s while a scan runs (a toast per poll, u2 round 5)
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
        toast.success("SAST report downloaded")
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
    toast.success("SAST scan restarted")
    return response.data
}

/** Cancel a pending or running code scan; its charge is refunded in full. POST /{team_id}/{type}/scan/{scan_id}/cancel.
 * A finished, failed or already-cancelled scan answers 409 { detail, code } (utils/scanCancel.ts). */
export const cancelScan = async (
    team_id: number,
    type: "sast" | "iac" | "sbom_sca" | "cbom" | "ai_bom",
    scan_id: number,
): Promise<{ scan_status: "cancelled"; refunded_credits: number; message: string }> => {
    const response = await api.post(`/${team_id}/${type}/scan/${scan_id}/cancel`)
    return response.data
}

/** Send a message to a scan. POST /{team_id}/{type}/scan/{scan_id}/message */
const sendMessageToScan = async (
    team_id: number,
    type: "sast" | "iac" | "sbom_sca" | "llm" | "mcp" | "leakage" | "agent_discovery" | "dast" | "cbom" | "ai_bom",
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
  type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast" | "cbom" | "ai_bom",
  scan_id: number,
  start_scan_payload_string: string,
  uploaded_file?: File | null
): Promise<{ credits_required: number; minimum_credits?: number }> => {
  const form = buildScanFormData(start_scan_payload_string, uploaded_file);
  const response = await api.post<{ credits_required: number; minimum_credits?: number }>(
    `/${team_id}/${type}/scan/${scan_id}/estimate_credits`,
    form,
    { headers: { "Content-Type": "multipart/form-data" } }
  );
  return response.data;
};

/** Start a scan. POST FormData to /{team_id}/{type}/scan/{scan_id}/start */
const startScan = async (
  team_id: number,
  type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast" | "cbom" | "ai_bom",
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
  toast.success("Scan started");
  return response.data;
}

/** Create ticket payload (matches backend CreateTicketData) */
export interface CreateTicketData {
  ticket_type: "jira";
  summary: string;
  description: string;
  finding_ids?: string[];
}

/** Create a ticket for a scan. POST /{team_id}/{type}/scan/{scan_id}/create_ticket */
const createTicket = async (
  team_id: number,
  type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast" | "cbom" | "ai_bom",
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
        return response.data as LLMScansListResponse
    } catch (error) {
        showErrorToast(error, "Error fetching LLM conversations")
        throw error
    }
}

const deleteLLMConversation = async (team_id: number, conversation_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/llm/scan/${conversation_id}`)
        return response.data
    } catch (error) {
        throw error
    }
}

const renameLLMConversation = async ({ team_id, conversation_id, title }: { team_id: number; conversation_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/llm/scan/${conversation_id}`, { title })
        return response.data
    } catch (error) {
        throw error
    }
}

const createLLMConversation = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/llm/scan`, { title })
        toast.success("LLM scan created")
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
        toast.success("LLM scan started")
        return response.data
    } catch (error) {
        throw error
    }
}

const getLLMExportResults = async (team_id: number, scan_id: number): Promise<Blob> => {
    try {
        const response = await api.get(`/${team_id}/llm/scan/${scan_id}/export`, { responseType: "blob" })
        toast.success("LLM report downloaded")
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
        toast.success("LLM scan restarted")
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
    remediation?: RemediationData | null
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
    remediation?: RemediationData | null
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
        return response.data as MCPScansListResponse
    } catch (error) {
        showErrorToast(error, "Error fetching MCP conversations")
        throw error
    }
}

const deleteMCPConversation = async (team_id: number, conversation_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/mcp/scan/${conversation_id}`)
        return response.data
    } catch (error) {
        throw error
    }
}

const renameMCPConversation = async ({ team_id, conversation_id, title }: { team_id: number; conversation_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/mcp/scan/${conversation_id}`, { title })
        return response.data
    } catch (error) {
        throw error
    }
}

const createMCPConversation = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/mcp/scan`, { title })
        toast.success("MCP scan created")
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
        toast.success("MCP scan started")
        return response.data
    } catch (error) {
        throw error
    }
}

const getMCPExportResults = async (team_id: number, scan_id: number): Promise<Blob> => {
    try {
        const response = await api.get(`/${team_id}/mcp/scan/${scan_id}/export`, { responseType: "blob" })
        toast.success("MCP report downloaded")
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
        toast.success("MCP scan restarted")
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
        return response.data as UserProfile
    } catch (error) {
        showErrorToast(error,"Error fetching user profile")
        throw error
    }
}

/** Account page: change the password while signed in. Every other session is signed out (the server bumps the
 * token version); the answer carries new tokens for this tab, stored here so this session goes on. */
const changePassword = async (current_password: string, new_password: string): Promise<{ message: string }> => {
    const response = await api.post("/account/password", { current_password, new_password })
    const data = response.data as { message: string; access_token: string; refresh_token: string }
    localStorage.setItem("access_token", data.access_token)
    localStorage.setItem("refresh_token", data.refresh_token)
    return { message: data.message }
}

const logout = async () => {
    try {
        const response = await api.get("/logout")
        toast.success("Signed out")
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

/** Jira settings for team ticketing integration (matches backend JiraTeamSettingsData).
 * GET /team never returns the token: only `api_token_set`. A save sends `api_token` only when one was typed
 * (empty keeps the stored token while the URL and email stay the same). */
export interface JiraTeamSettingsData {
    email: string
    api_token?: string
    api_token_set?: boolean
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

/** RBI CSF pillar rollup (team or per-scan metadata) */
export interface RbiCsfRollupPayload {
    rbi_csf_rollup?: Record<string, {
        pass?: number
        pass_with_evidence?: number
        fail?: number
        out_of_scope?: number
        not_bom_evidenceable?: number
        na?: number
        coverage?: number | null
        requirements?: Array<{
            id: string
            framework: string
            verdict: string
            title: string
            source?: string
            evidence?: string
            refs?: string[]
            attestable?: boolean
            resolve_hint?: string
            _scanner?: string
        }>
    }>
    disclaimer?: string
}

/** CERT-In TG v2.0 posture rollup (team or per-scan metadata) — Phase 5 */
export interface CertInPosturePayload {
    certin_posture?: Record<string, {
        pass?: number
        pass_with_evidence?: number
        fail?: number
        out_of_scope?: number
        not_bom_evidenceable?: number
        na?: number
        coverage?: number | null
        requirements?: Array<{ id: string; framework: string; verdict: string; title: string }>
    }>
    disclaimer?: string
    hbom_note?: string
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
    /** Aggregated RBI CSF posture from latest BOM scans */
    rbi_csf_rollup?: RbiCsfRollupPayload | null
    /** Aggregated CERT-In TG posture from latest BOM scans (Phase 5) */
    certin_posture?: CertInPosturePayload | null
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
        toast.success("Team created")
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
        toast.success("Team updated")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error updating team")
        throw error
    }
}

const removeOrAddTeamMembers = async (team_id: number, data: RemoveOrAddMembersToTeamData) => {
    try {
        const response = await api.patch(`/team/${team_id}`, data)
        // "add" invites: nobody joins until they accept the mailed link
        toast.success(data.intent === "add"
            ? (response.data?.message ?? "Invitation sent")
            : "Members removed successfully")
        return response.data
    } catch (error) {
        showErrorToast(error, data.intent === "add" ? "Error sending the invitation" : "Error removing members")
        throw error
    }
}

/** An open invitation to the team, as its admins see it (backend utilities/team/invitations.py). */
export interface TeamInvitationItem {
    id: number
    email: string
    status: "pending" | "expired" | "declined"
    invited_by: string
    created_at: string | null
    expires_at: string | null
    responded_at: string | null
}

const listTeamInvitations = async (team_id: number): Promise<TeamInvitationItem[]> => {
    const response = await api.get(`/team/${team_id}/invitations`)
    return (response.data?.invitations ?? []) as TeamInvitationItem[]
}

const resendTeamInvitation = async (team_id: number, invitation_id: number) => {
    try {
        const response = await api.post(`/team/${team_id}/invitations/${invitation_id}/resend`)
        toast.success("A new invitation link was sent; the previous link no longer works")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error resending the invitation")
        throw error
    }
}

const revokeTeamInvitation = async (team_id: number, invitation_id: number) => {
    try {
        const response = await api.delete(`/team/${team_id}/invitations/${invitation_id}`)
        toast.success("Invitation revoked")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error revoking the invitation")
        throw error
    }
}

const deleteTeam = async (team_id: number) => {
    try {
        await api.delete(`/team/${team_id}`)
        toast.success("Team deleted")
    } catch (error) {
        showErrorToast(error, "Error deleting team")
        throw error
    }
}

export {
    getUserProfile,
    logout,
    changePassword,
    getTeams,
    createTeam,
    getTeam,
    getTeamDashboard,
    getTeamsDashboard,
    updateTeam,
    removeOrAddTeamMembers,
    deleteTeam,
    listTeamInvitations,
    resendTeamInvitation,
    revokeTeamInvitation,
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
        return response.data
    } catch (error) {
        showErrorToast(error, "Error fetching iac conversations")
        throw error
    }
}

const deleteIACConversation = async (team_id: number, scan_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/iac/scan/${scan_id}`)
        return response.data
    } catch (error) {
        throw error
    }
}

const renameIACConversation = async ({ team_id, scan_id, title }: { team_id: number; scan_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/iac/scan/${scan_id}`, { title })
        return response.data
    } catch (error) {
        throw error
    }
}

const createIACConversation = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/iac/scan`, { title })
        toast.success("IAC scan created")
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
        // no success toast: the scan page polls this every 6 s while a scan runs (a toast per poll, u2 round 5)
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
        toast.success("IAC scan started");
        return response.data;
    } catch (error) {
        throw error;
    }
};

/** Team-scoped: GET /{team_id}/iac/scan/{scan_id}/export */
const getIACExportResults = async (team_id: number, scan_id: number): Promise<Blob | ArrayBuffer> => {
    try {
        const response = await api.get(`/${team_id}/iac/scan/${scan_id}/export`, { responseType: "blob" });
        toast.success("IAC report downloaded");
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
        toast.success("IAC scan restarted");
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
    toast.success("IAC scan restarted");
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
        not_assessed: number
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
        return response.data as SBOMSCAListResponse;
    } catch (error) {
        showErrorToast(error, "Error fetching sbom_sca scans");
        throw error;
    }
};

const deleteSBOMSCAScan = async (team_id: number, scan_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/sbom_sca/scan/${scan_id}`);
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
    type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast" | "cbom" | "ai_bom";
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
    type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast" | "cbom" | "ai_bom";
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
        toast.success("SCA + SBOM scan created");
        return response.data.scan_id as number;
    } catch (error) {
        throw error;
    }
};

/** Legacy: non–team-scoped list. Prefer getSBOMSCAScans(team_id) for [team_id]/sbom_sca page. */
const getSCASBOMConversations = async (): Promise<SCASBOMConversation[]> => {
    try {
        const response = await api.get("/sbom_sca/conversations");
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
        return response.data;
    } catch (error) {
        throw error;
    }
};

/** Legacy: non–team-scoped create. Prefer createSBOMSCAScan(team_id, title). */
const createSCASBOMConversation = async (title: string) => {
    try {
        const response = await api.post("/sbom_sca/conversation", { title });
        toast.success("SCA + SBOM scan created");
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

/** Matches backend JiraScanSettingsData for scans (db/schemas.py). */
export interface ScanJiraSettings {
    jira_project_id: string | null;
    auto_create_tickets?: boolean | null;
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
        // no success toast: the scan page polls this every 6 s while a scan runs (a toast per poll, u2 round 5)
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
        // no success toast: the scan page polls this every 6 s while a scan runs (a toast per poll, u2 round 5)
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
        toast.success("SCA + SBOM scan started")
        return response.data
    } catch (error) {
        throw error
    }
}

const getSCASBOMExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/sbom_sca/conversation/${conversation_id}/export`)
        toast.success("SCA + SBOM report downloaded")
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
        toast.success("SCA + SBOM report downloaded");
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
    toast.success("SCA + SBOM scan restarted");
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
        toast.success("SCA + SBOM scan restarted")
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
    generateFindingRemediation,
}

// -------------------------------------------------------------- CBOM API Routes --------------------------------------------------------------

/** CBOM finding from backend get_findings_for_scan_type (cbom branch) */
export interface CbomFinding {
  id: string
  /** CycloneDX inventory bom-ref (charts → finding join); absent on legacy rows */
  bom_ref?: string | null
  title: string
  description: string
  impact: string
  risk_score: number
  status: string
  compliance_controls: unknown
  owasp_top_10: unknown
  suggested_fix?: string | null
  algorithm_name?: string | null
  algorithm_type?: string | null
  crypto_strength?: string | null
  key_size?: number | null
  quantum_safe?: boolean | null
  location?: string | null
  snippet?: string | null
  remediation?: RemediationData | null
  /** Inventory assetType (certificate / related-crypto-material / …) */
  asset_type?: string | null
  material_kind?: string | null
  container_format?: string | null
  not_valid_after?: string | null
  self_signed?: boolean | null
  expired?: boolean | null
  /** Where in the file (code scans from this release on): first line, every occurrence, language. */
  line?: number | null
  occurrences?: number[]
  occurrence_count?: number | null
  language?: string | null
  /** First line number of the redacted `snippet` window. */
  snippet_start?: number | null
  snippet_note?: string | null
  weak?: boolean
  finding_codes?: string[]
}

/** CBOM scan metadata from backend get_scan_metadata (cbom branch) */
export interface CbomScanMetadata {
  repo_url?: string | null
  branch?: string | null
  zip_file_used?: boolean
  cbom_file_used?: boolean
  scan_binaries?: boolean
  cbom_json?: Record<string, unknown> | null
  // Additive chart/compliance payload from the reconciled aibom CBOM lane (I1).
  // Present on reconciled scans; null/absent on legacy worker CBOM scans (the
  // C9 CbomCryptoCharts then don't render). cbom_distributions feeds the 5 C9
  // crypto charts (algorithms/weakness/pqc/certificates/protocols).
  cbom_distributions?: Record<string, unknown> | null
  cbom_compliance?: Record<string, unknown> | null
  cbom_scores?: Record<string, unknown> | null
  // Normalized crypto dependency graph (nodes + edges), the peer of the AIBOM
  // lane's ai_bom_graph (I1). Pre-joined so the results-page dependency-graph
  // (F1) never re-walks the CycloneDX dependsOn/cryptoRefArray structure.
  // Absent on legacy worker CBOM scans (produced before the reconcile).
  cbom_graph?: CbomGraph | null
  cbom_graph_compact?: CbomGraph | null
  cbom_graph_expanded?: CbomGraph | null
  rbi_csf_rollup?: Record<string, unknown> | null
  certin_posture?: Record<string, unknown> | null
  // CERT-In Phase 4 additive keys
  attestations?: Record<string, unknown> | null
  bom_signature?: Record<string, unknown> | null
  vex_json?: Record<string, unknown> | null
}

/** Normalized crypto dependency graph surfaced in CBOM scan_metadata (I1). */
export interface CbomGraphNode {
  id: string
  label: string
  kind: string
  asset_type?: string | null
  primitive?: string | null
  impact?: string | null
  quantum_vulnerable?: boolean
  weak?: boolean
}
export interface CbomGraphEdge {
  source: string
  target: string
  rel: string
}
export interface CbomGraph {
  nodes: CbomGraphNode[]
  edges: CbomGraphEdge[]
  meta?: {
    raw_node_count?: number
    raw_edge_count?: number
    view_node_count?: number
    view_edge_count?: number
    clustered_members?: number
    max_nodes?: number
    lane?: string
  }
}

/** CBOM single-scan dashboard from backend generate_scan_dashboard (scan.py cbom branch) */
export interface CbomScanDashboardData {
  card_data: {
    total_crypto_assets: number
    /** findings only (rows with a finding code); clean inventory is total_informational */
    total_crypto_vulnerabilities?: number
    total_informational?: number
    quantum_readiness_judged?: boolean
    total_weak_algorithms: number
    total_quantum_vulnerable: number
    total_certificates: number
    total_keys: number
    quantum_readiness_score: number
    average_risk_score: number
  }
  remediation_metrics: {
    mean_time_to_remediate: [number, number, number]
    critical_issues_fixed: number
    remediation_velocity: number
    high_priority_backlog: number
  }
  remediation_actions_required: {
    total_findings: number
    total_fixed: number
    total_in_progress: number
    total_not_started: number
    total_ignored: number
  }
  severity_distribution: { critical: number; high: number; medium: number; low: number; informational?: number }
  algorithm_type_distribution: Record<string, number>
  strength_distribution: Record<string, number>
  quantum_readiness: { quantum_safe: number; quantum_vulnerable: number; unknown?: number }
  owasp_top_10_issues: Record<string, number>
  compliance_controls: Record<string, number>
  top_risks: Array<{
    algorithm_name: string
    algorithm_type: string
    crypto_strength: string
    quantum_safe: boolean
    impact: string
  }>
}

/** CBOM conversation (scan) row returned by list scans endpoint. Same shape as SCASBOMConversation. */
export interface CBOMConversation {
  id: number
  title: string
  scan_status: string
  created_at: string
  last_updated: string
  estimated_credits: number | null
  average_risk_score: number | null
  branch: string | null
  repo_url: string | null
  owner_user_email: string | null
  owner_user_full_name: string | null
  total_quantum_vulnerable: number | null
  total_weak_algorithms: number | null
  zip_file_used: boolean | null
  cbom_file_used: boolean | null
  scan_binaries: boolean | null
  info: string | null
  risk_data: {
    total_critical: number
    total_high: number
    total_medium: number
    total_low: number
    total_weak?: number
    total_quantum_vulnerable?: number
    scan_binaries?: boolean
  } | null
  scan_metadata: CbomScanMetadata | null
}

/** Card counts returned by list CBOM scans */
export interface CBOMListCardData {
  pending_scans: number
  started_scans: number
  success_scans: number
  failure_scans: number
  not_started_scans: number
  scans_created_today: number
  scans_updated_today: number
}

/** CBOM list dashboard from backend generate_cbom_dashboard_data */
export interface CBOMDashboardData {
  severity_distribution: { critical: number; high: number; medium: number; low: number }
  algorithm_type_distribution: Record<string, number>
  strength_distribution: Record<string, number>
  quantum_readiness: { quantum_safe: number; quantum_vulnerable: number; unknown?: number }
  remediation_actions_required: {
    total_findings: number
    total_fixed: number
    total_in_progress: number
    total_not_started: number
    total_ignored: number
  }
  top_risks: Array<{
    algorithm_name: string
    algorithm_type: string
    crypto_strength: string
    quantum_safe: boolean
    impact: string
    /** where the row came from: a code scan or a CBOM Sources run (absent on older responses) */
    origin?: CbomResultOrigin | null
  }>
  /** CBOM Sources collections counted next to the code scans (latest completed collection per source) */
  sources?: { collections: number; assets: number; deduplicated: number }
  card_data: {
    total_crypto_assets: number
    total_weak_algorithms: number
    total_quantum_vulnerable: number
    total_certificates: number
    total_keys: number
    quantum_readiness_score: number
    /** false: no asset has a quantum verdict; quantum_readiness_score is then a 0 placeholder (show "n/a") */
    quantum_readiness_judged?: boolean
    average_risk_score: number
  }
}

export interface CBOMListResponse {
  scans_list_data: CBOMConversation[]
  dashboard_data: CBOMDashboardData
  /** each CBOM Sources source's latest completed collection (one entry per source) */
  sources_runs?: CbomSourcesRun[]
  /** CB-38: the team's newest CBOM Sources runs (at most 200, newest first), one row per run; absent on older backends */
  runs_list_data?: RunListRow[]
  /** CB-38: how many runs the team has in total (more than runs_list_data.length when older runs were not loaded) */
  runs_total?: number
}

/** CB-38: one CBOM Sources run as a row of the CBOM Scans table (GET /{team_id}/cbom/scans `runs_list_data`). */
export interface RunListRow {
  kind: "run"
  id: number
  /** "Sources run #<id> · <source names joined ', '>" */
  title: string
  created_at: string
  last_updated: string | null
  finished_at: string | null
  /** the run status mapped to the scan statuses (contracts/cbom/status_buckets.json `run_to_unified`) */
  scan_status: "not_started" | "pending" | "started" | "success" | "partial" | "failure" | "cancelled"
  run_status: "queued" | "running" | "done" | "partial" | "failed" | "cancelled"
  risk_data: {
    total_critical: number
    total_high: number
    total_medium: number
    total_low: number
    total_informational: number
    total_quantum_vulnerable: number
  } | null
  average_risk_score: number | null
  sources: { id: number; name: string; kind: string }[]
  repo_url: null
  branch: null
  /** credits charged for the run */
  estimated_credits: number | null
  credits_refunded: number | null
  owner_user_email: string | null
  owner_user_full_name: string | null
  asset_count: number
  endpoints_probed: number
  jobs_total: number
  jobs_done: number
  linked_scan_id: number | null
  /** the severity counts are those judged when the run collected the assets */
  counts_basis: "as_collected"
}

export interface CBOMConversationResponse {
  title: string
  repo_url?: string | null
  scan_status: string
  scan_metadata?: CbomScanMetadata | Record<string, unknown> | null
  data: any
  dashboard?: CbomScanDashboardData | null
  findings?: CbomFinding[] | null
  messages: SCASBOMConversationMessage[]
  integration_settings?: Record<string, unknown> | null
  info?: ScanInfoField | null
}

/** Team-scoped: GET /{team_id}/cbom/scans */
const getCBOMScans = async (team_id: number): Promise<CBOMListResponse> => {
  try {
    const response = await api.get(`/${team_id}/cbom/scans`);
    return response.data as CBOMListResponse;
  } catch (error) {
    showErrorToast(error, "Error fetching CBOM scans");
    throw error;
  }
};

/** Team-scoped: GET /{team_id}/cbom/scan/{scan_id} */
const getCBOMScanData = async ({
  queryKey,
}: {
  queryKey: ["cbom-conversation-data", number, number];
}): Promise<CBOMConversationResponse> => {
  const [, team_id, scan_id] = queryKey;
  try {
    const response = await api.get(`/${team_id}/cbom/scan/${scan_id}`);
    // no success toast: the scan page polls this every 6 s while a scan runs (a toast per poll, u2 round 5)
    return response.data as CBOMConversationResponse;
  } catch (error) {
    showErrorToast(error, "Error fetching CBOM scan data");
    throw error;
  }
};

const createCBOMScan = async (team_id: number, title: string): Promise<number> => {
  try {
    const response = await api.post(`/${team_id}/cbom/scan`, { title });
    toast.success("CBOM scan created");
    return response.data.scan_id as number;
  } catch (error) {
    throw error;
  }
};

const deleteCBOMScan = async (team_id: number, scan_id: number) => {
  try {
    const response = await api.delete(`/${team_id}/cbom/scan/${scan_id}`);
    return response.data;
  } catch (error) {
    throw error;
  }
};

const renameCBOMScan = async ({
  team_id,
  scan_id,
  title,
}: {
  team_id: number;
  scan_id: number;
  title: string;
}) => {
  try {
    const response = await api.put(`/${team_id}/cbom/scan/${scan_id}`, { title });
    return response.data;
  } catch (error) {
    throw error;
  }
};

/** Team-scoped: GET /{team_id}/cbom/scan/{scan_id}/export */
const getCBOMExportResults = async (team_id: number, scan_id: number): Promise<Blob | ArrayBuffer> => {
  try {
    const response = await api.get(`/${team_id}/cbom/scan/${scan_id}/export`, { responseType: "blob" });
    toast.success("CBOM report downloaded");
    return response.data;
  } catch (error) {
    showErrorToast(error, "Error fetching CBOM export results");
    throw error;
  }
};

/** CERT-In Phase 4 — attestation / sign / VEX / evidence-pack (BOM types). */
export type CertInBomScanType = "ai_bom" | "cbom" | "sbom_sca";

const postCertInAttestation = async (
  team_id: number,
  scan_type: CertInBomScanType,
  scan_id: number,
  framework: string,
  requirement_id: string,
  file: File,
  note?: string,
) => {
  const form = new FormData();
  form.append("framework", framework);
  form.append("requirement_id", requirement_id);
  form.append("file", file);
  if (note) form.append("note", note);
  const response = await api.post(
    `/${team_id}/${scan_type}/scan/${scan_id}/attestations`,
    form,
    { headers: { "Content-Type": "multipart/form-data" } },
  );
  toast.success("Attestation uploaded");
  return response.data as {
    attestations: Record<string, unknown>;
    compliance: Record<string, unknown>;
  };
};

const postCertInSign = async (
  team_id: number,
  scan_type: CertInBomScanType,
  scan_id: number,
) => {
  const response = await api.post(
    `/${team_id}/${scan_type}/scan/${scan_id}/sign`,
  );
  return response.data as { bom_signature: Record<string, unknown> };
};

const getCertInVex = async (
  team_id: number,
  scan_type: CertInBomScanType,
  scan_id: number,
  refresh = false,
) => {
  const response = await api.get(
    `/${team_id}/${scan_type}/scan/${scan_id}/vex`,
    { params: refresh ? { refresh: true } : undefined },
  );
  return response.data as Record<string, unknown>;
};

const getCertInEvidencePack = async (
  team_id: number,
  scan_type: CertInBomScanType,
  scan_id: number,
): Promise<Blob> => {
  const response = await api.get(
    `/${team_id}/${scan_type}/scan/${scan_id}/evidence-pack`,
    { responseType: "blob" },
  );
  return response.data as Blob;
};

/** Team-scoped: POST /{team_id}/cbom/scan/{scan_id}/reinitialize with FormData */
const reinitializeCBOMScanWithPayload = async (
  team_id: number,
  scan_id: number,
  start_scan_payload_string: string,
  uploaded_file?: File | null
) => {
  const form = buildScanFormData(start_scan_payload_string, uploaded_file);
  const response = await api.post<{ message: string }>(
    `/${team_id}/cbom/scan/${scan_id}/reinitialize`,
    form,
    { headers: { "Content-Type": "multipart/form-data" } }
  );
  toast.success("CBOM scan restarted");
  return response.data;
};

/**
 * Team-wide CBOM regulatory deliverables, rendered in-house as PDFs by the backend
 * (GET /{team_id}/cbom/deliverables/{slug}). Order and slugs mirror the backend registry;
 * backend/tests/test_cbom_deliverables_contract.py (T-CON-1) pins the slug list.
 */
export const CBOM_DELIVERABLES = [
  { slug: "scope-baseline-register", number: 1, title: "Scope Baseline & Asset Population Register" },
  { slug: "methodology-evidence-plan", number: 3, title: "Cryptographic Discovery Methodology & Evidence Plan" },
  { slug: "infrastructure-cloud-encryption-posture", number: 5, title: "Infrastructure & Cloud Encryption Posture" },
  { slug: "network-tls-protocol-assessment", number: 6, title: "Network, TLS & Crypto Protocol Assessment" },
  { slug: "certificate-estate-register", number: 7, title: "Certificate Estate Register" },
  { slug: "data-at-rest-encryption-assessment", number: 9, title: "Data-at-Rest Encryption Assessment" },
  { slug: "third-party-assurance-register", number: 10, title: "Third-Party Cryptographic Assurance & Attestation Register" },
  { slug: "pqc-migration-roadmap", number: 15, title: "PQC Migration Roadmap" },
  { slug: "board-executive-report", number: 16, title: "Board / IT Strategy Committee Regulatory & Executive Report" },
] as const;

export type CbomDeliverableSlug = (typeof CBOM_DELIVERABLES)[number]["slug"];

/** One row of the deliverables manifest (GET /{team_id}/cbom/deliverables). */
export interface CbomDeliverableManifestItem {
  slug: string
  number: number
  title: string
  description: string
  format: "pdf"
  /** UI hint only: the PDF route always answers 200 (with a banner when data is missing). */
  available: boolean
  /** Why the item is unavailable; used as the tooltip of the disabled menu item. */
  reason?: string | null
}

export interface CbomDeliverablesManifest {
  team_id: number
  generated_at: string
  basis: {
    eligible: number
    included_hint: number
    sources: number
    excluded: { failure: number; not_completed: number }
  }
  deliverables: CbomDeliverableManifestItem[]
}

/** Team-scoped: GET /{team_id}/cbom/deliverables (manifest). No toast: the menu stays enabled if this fails. */
const getCbomDeliverables = async (team_id: number): Promise<CbomDeliverablesManifest> => {
  const response = await api.get(`/${team_id}/cbom/deliverables`);
  return response.data as CbomDeliverablesManifest;
};

/** Team-scoped: GET /{team_id}/cbom/deliverables/{slug} (PDF). No toast here: the caller owns success/error UX. */
const downloadCbomDeliverable = async (
  team_id: number,
  slug: CbomDeliverableSlug,
): Promise<Blob> => {
  const response = await api.get(
    `/${team_id}/cbom/deliverables/${slug}`,
    { responseType: "blob" },
  );
  return response.data as Blob;
};

export {
  getCBOMScans,
  getCBOMScanData,
  createCBOMScan,
  deleteCBOMScan,
  renameCBOMScan,
  getCBOMExportResults,
  reinitializeCBOMScanWithPayload,
  postCertInAttestation,
  postCertInSign,
  getCertInVex,
  getCertInEvidencePack,
  getCbomDeliverables,
  downloadCbomDeliverable,
}

// -------------------------------------------------------------- AI BOM API Routes --------------------------------------------------------------

/** AI BOM finding from backend get_findings_for_scan_type (ai_bom branch) */
export interface AiBomFinding {
  id: string
  title: string
  description: string
  impact: string
  risk_score: number
  status: string
  compliance_controls: Record<string, string> | null
  owasp_top_10: Record<string, string> | null
  owasp_top_10_llm: Record<string, string> | null
  suggested_fix?: string
  asset_name?: string
  asset_type?: string
  provider?: string
  framework?: string
  version?: string
  license_type?: string
  risk_category?: string
  location?: string
  snippet?: string
  remediation?: RemediationData | null
}

/** AI BOM scan metadata from backend get_scan_metadata (ai_bom branch) */
export interface AiBomScanMetadata {
  repo_url?: string
  branch?: string
  zip_file_used?: boolean
  ai_bom_file_used?: boolean
  scan_binaries?: boolean
  ai_bom_json?: Record<string, unknown>
  ai_bom_compliance?: Record<string, unknown>
  ai_bom_graph?: { nodes?: unknown[]; edges?: unknown[]; meta?: Record<string, unknown> }
  ai_bom_graph_compact?: { nodes?: unknown[]; edges?: unknown[]; meta?: Record<string, unknown> }
  ai_bom_graph_expanded?: { nodes?: unknown[]; edges?: unknown[]; meta?: Record<string, unknown> }
  ai_bom_scores?: Record<string, unknown>
  ai_bom_spdx?: Record<string, unknown>
  ai_bom_sarif?: Record<string, unknown>
  rbi_csf_rollup?: Record<string, unknown> | null
  certin_posture?: Record<string, unknown> | null
  error_message?: string
  // CERT-In Phase 4 additive keys
  attestations?: Record<string, unknown> | null
  bom_signature?: Record<string, unknown> | null
  vex_json?: Record<string, unknown> | null
}

/** AI BOM single-scan dashboard from backend generate_scan_dashboard (scan.py ai_bom branch) */
export interface AiBomScanDashboardData {
  card_data: {
    total_ai_assets: number
    total_models: number
    total_datasets: number
    total_external_providers: number
    total_high_risk_assets: number
    total_unlicensed_assets: number
    governance_readiness_score: number
    average_risk_score: number
  }
  remediation_metrics: {
    mean_time_to_remediate: [number, number, number]
    critical_issues_fixed: number
    remediation_velocity: number
    high_priority_backlog: number
  }
  remediation_actions_required: {
    total_findings: number
    total_fixed: number
    total_in_progress: number
    total_not_started: number
    total_ignored: number
  }
  severity_distribution: { critical: number; high: number; medium: number; low: number }
  asset_type_distribution: Record<string, number>
  provider_distribution: Record<string, number>
  license_distribution: Record<string, number>
  risk_category_distribution: Record<string, number>
  owasp_top_10_llm_issues: Record<string, number>
  compliance_controls: Record<string, number>
  top_risks: Array<{
    asset_name: string
    asset_type: string
    provider: string
    license_type: string
    impact: string
  }>
}

/** AI BOM conversation (scan) row returned by list scans endpoint. Same shape as CBOMConversation. */
export interface AIBOMConversation {
  id: number
  title: string
  scan_status: string
  created_at: string
  last_updated: string
  estimated_credits: number | null
  average_risk_score: number | null
  branch: string | null
  repo_url: string | null
  owner_user_email: string | null
  owner_user_full_name: string | null
  total_high_risk_assets: number | null
  total_unlicensed_assets: number | null
  zip_file_used: boolean | null
  ai_bom_file_used: boolean | null
  /** Progress payload from worker; often `{ current: number }`, not a display string. */
  info: ScanInfoField | string | null
  risk_data: {
    total_critical: number
    total_high: number
    total_medium: number
    total_low: number
    total_high_risk?: number
    total_unlicensed?: number
  } | null
  scan_metadata: AiBomScanMetadata | null
}

export interface AIBOMListResponse {
  scans_list_data: AIBOMConversation[]
  dashboard_data: AiBomScanDashboardData
}

export interface AIBOMConversationResponse {
  title: string
  repo_url?: string | null
  scan_status: string
  scan_metadata?: AiBomScanMetadata | Record<string, unknown> | null
  data: any
  dashboard?: AiBomScanDashboardData | null
  findings?: AiBomFinding[] | null
  messages: SCASBOMConversationMessage[]
  integration_settings?: Record<string, unknown> | null
  info?: ScanInfoField | null
}

/** Team-scoped: GET /{team_id}/ai_bom/scans */
const getAIBOMScans = async (team_id: number): Promise<AIBOMListResponse> => {
  try {
    const response = await api.get(`/${team_id}/ai_bom/scans`);
    return response.data as AIBOMListResponse;
  } catch (error) {
    showErrorToast(error, "Error fetching AI BOM scans");
    throw error;
  }
};

/** Team-scoped: GET /{team_id}/ai_bom/scan/{scan_id} */
const getAIBOMScanData = async ({
  queryKey,
}: {
  queryKey: ["ai_bom-conversation-data", number, number];
}): Promise<AIBOMConversationResponse> => {
  const [, team_id, scan_id] = queryKey;
  try {
    const response = await api.get(`/${team_id}/ai_bom/scan/${scan_id}`);
    return response.data as AIBOMConversationResponse;
  } catch (error) {
    showErrorToast(error, "Error fetching AI BOM scan data");
    throw error;
  }
};

const createAIBOMScan = async (team_id: number, title: string): Promise<number> => {
  try {
    const response = await api.post(`/${team_id}/ai_bom/scan`, { title });
    toast.success("AI BOM scan created");
    return response.data.scan_id as number;
  } catch (error) {
    throw error;
  }
};

const deleteAIBOMScan = async (team_id: number, scan_id: number) => {
  try {
    const response = await api.delete(`/${team_id}/ai_bom/scan/${scan_id}`);
    return response.data;
  } catch (error) {
    throw error;
  }
};

const renameAIBOMScan = async ({
  team_id,
  scan_id,
  title,
}: {
  team_id: number;
  scan_id: number;
  title: string;
}) => {
  try {
    const response = await api.put(`/${team_id}/ai_bom/scan/${scan_id}`, { title });
    return response.data;
  } catch (error) {
    throw error;
  }
};

/** Team-scoped: GET /{team_id}/ai_bom/scan/{scan_id}/export */
const getAIBOMExportResults = async (team_id: number, scan_id: number): Promise<Blob | ArrayBuffer> => {
  try {
    const response = await api.get(`/${team_id}/ai_bom/scan/${scan_id}/export`, { responseType: "blob" });
    toast.success("AI BOM report downloaded");
    return response.data;
  } catch (error) {
    showErrorToast(error, "Error fetching AI BOM export results");
    throw error;
  }
};

/** Team-scoped: POST /{team_id}/ai_bom/scan/{scan_id}/reinitialize with FormData */
const reinitializeAIBOMScanWithPayload = async (
  team_id: number,
  scan_id: number,
  start_scan_payload_string: string,
  uploaded_file?: File | null
) => {
  const form = buildScanFormData(start_scan_payload_string, uploaded_file);
  const response = await api.post<{ message: string }>(
    `/${team_id}/ai_bom/scan/${scan_id}/reinitialize`,
    form,
    { headers: { "Content-Type": "multipart/form-data" } }
  );
  toast.success("AI BOM scan restarted");
  return response.data;
};

export {
  getAIBOMScans,
  getAIBOMScanData,
  createAIBOMScan,
  deleteAIBOMScan,
  renameAIBOMScan,
  getAIBOMExportResults,
  reinitializeAIBOMScanWithPayload,
}

// -------------------------------------------------------------- Remediation Types + API --------------------------------------------------------------

export interface RemediationFix {
    description: string
    original_code: string
    fixed_code: string
    language: string
    confidence: number
    validation_notes: string
    references: string[]
}

export interface RemediationExploitPayload {
    description: string
    payload: string
    impact_demonstration: string
    prerequisites: string
    difficulty: "trivial" | "easy" | "moderate" | "hard" | "expert"
    attack_vector: string
}

export interface KbRef { id: string; label?: string; name?: string | null; url?: string; basis?: string }
export interface KbCve {
    id: string
    url: string
    summary: string | null
    published?: string | null
    matched_on?: string
    cvss: { version: string | null; score: number | null; vector: string | null; severity: string | null } | null
}
export interface KbComplianceRef { framework: string; id: string; text: string; source: string; note?: string }
/** One finding code explained by the offline crypto knowledge base (no AI). */
export interface KbFindingDetail {
    code: string
    title: string
    observed?: string | null
    description: string
    attack: string
    impact: string
    category: string
    pqc?: string | null
    cwe: KbRef[]
    owasp_2021: KbRef[]
    owasp_2025: KbRef[]
    cves: KbCve[]
    standards: string[]
    compliance: KbComplianceRef[]
    remediation: { summary: string; steps: { platform: string; how: string }[] }
    verify: { label: string; command: string }[]
    references: string[]
}

/** In-house code fix for a CBOM finding (deterministic rewrite rules, no AI). */
export interface CbomCodeFix {
    version: string
    available: boolean
    kind: "code" | "dependency" | "config" | "manual" | "non-security-use"
    language: string
    original_code: string
    fixed_code: string
    diff: string
    confidence: number
    summary: string
    rules: string[]
    notes: string[]
    warnings: string[]
    commands: string[]
}

/** In-house exploit demonstration: narrative + a self-contained proof that runs only against keys, messages and
 * servers it creates on the analyst's machine (no AI, never touches the scanned system). */
export interface CbomExploitDemo {
    code: string
    family: string
    description: string
    difficulty: string
    attack_vector: string
    prerequisites: string
    impact_demonstration: string
    poc: { language: string; script: string; expected_marker: string; requires: string[] } | null
    verify: { label: string; command: string }[]
    safety: string
    version: string
}

export interface RemediationData {
    generated_at: string
    status: "completed" | "failed"
    fix?: RemediationFix
    exploit_payload?: RemediationExploitPayload | null
    diff?: string
    error?: string
    /** "knowledge_base" when built from the offline crypto knowledge base (CBOM) instead of a model. */
    source?: "knowledge_base"
    kb_version?: string
    details?: KbFindingDetail[]
    /** CBOM engine stamp ("kb+fixgen1+demo1"); results without it predate code fixes and are rebuilt. */
    engine?: string
    code_fix?: CbomCodeFix | null
    exploit_demo?: CbomExploitDemo | null
}

const generateFindingRemediation = async ({
    team_id,
    type,
    scan_id,
    finding_id,
}: {
    team_id: number
    type: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast" | "cbom" | "ai_bom"
    scan_id: number
    finding_id: string
}): Promise<RemediationData> => {
    const response = await api.post<RemediationData>(
        `/${team_id}/${type}/scan/${scan_id}/finding/${finding_id}/remediate`
    )
    return response.data
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
        return response.data as DiscoveryConversation[]
    } catch (error) {
        showErrorToast(error,"Error fetching discovery conversations")
        throw error
    }
}

const deleteDiscoveryConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/agent_discovery/conversation/${conversation_id}`)
        toast.success("Discovery scan deleted")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameDiscoveryConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/agent_discovery/conversation/${conversation_id}`, { title: title })
        toast.success("Discovery scan renamed")
        return response.data
    } catch (error) {
        throw error
    }
}

const createDiscoveryConversation = async (title: string) => {
    try {
        const response = await api.post("/agent_discovery/conversation", { title: title })
        toast.success("Discovery scan created")
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
        toast.success("Discovery scan started")
        return response.data
    } catch (error) {
        throw error
    }
}

const getDiscoveryExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/agent_discovery/conversation/${conversation_id}/export`)
        toast.success("Discovery report downloaded")
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
        toast.success("Discovery scan restarted")
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
        return response.data as LeakageConversation[]
    } catch (error) {
        showErrorToast(error,"Error fetching leakage conversations")
        throw error
    }
}

const deleteLeakageConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/leakage/conversation/${conversation_id}`)
        toast.success("Leakage scan deleted")
        return response.data
    } catch (error) {
        throw error
    }
}

const renameLeakageConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/leakage/conversation/${conversation_id}`, { title: title })
        toast.success("Leakage scan renamed")
        return response.data
    } catch (error) {
        throw error
    }
}

const createLeakageConversation = async (title: string) => {
    try {
        const response = await api.post("/leakage/conversation", { title: title })
        toast.success("Leakage scan created")
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
        toast.success("Leakage scan started")
        return response.data
    } catch (error) {
        throw error
    }
}

const getLeakageExportResults = async (conversation_id: number): Promise<any> => {
    try {   
        const response = await api.get(`/leakage/conversation/${conversation_id}/export`)
        toast.success("Leakage report downloaded")
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
        toast.success("Leakage scan restarted")
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

// -------------------------------------------------------------- Guardrails API Routes (DEPRECATED) --------------------------------------------------------------
// @deprecated Guardrails product UI is removed from user-facing surfaces.
// These helpers remain for internal/API callers and Deprecated* page exports — do not call from new UI.

/** @deprecated Guardrails UI removed — do not call from user-facing frontend. */
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

/** @deprecated Guardrails UI removed — do not call from user-facing frontend. */
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

/** @deprecated Guardrails UI removed — do not call from user-facing frontend. */
const getGuardrailsIntegrations = async (team_id: number): Promise<GuardrailsIntegrationsResponse> => {
    try {
        const response = await api.get(`/guardrails/${team_id}/integrations`)
        const data = response.data as { integrations: GuardrailsIntegration[]; dashboard_data: GuardrailsListDashboardData }
        return data
    } catch (error) {
        showErrorToast(error,"Error fetching guardrails integrations")
        throw error
    }
}

/** @deprecated Guardrails UI removed — do not call from user-facing frontend. */
const deleteGuardrailsIntegration = async (team_id: number, integration_id: number) => {
    try {
        const response = await api.delete(`/guardrails/${team_id}/integration/${integration_id}`)
        toast.success("Guardrails integration deleted")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error deleting guardrails integration")
        throw error
    }
}

/** @deprecated Guardrails UI removed — do not call from user-facing frontend. */
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

/** @deprecated Guardrails UI removed — do not call from user-facing frontend. */
const getGuardrailsIntegrationDashboard = async ({queryKey}: {queryKey: ['guardrails-integration-dashboard', string, string, number, number]}): Promise<GuardrailsIntegrationDashboard> => {
    const [, team_id, integration_id, limit, offset] = queryKey
    try {
        const response = await api.get(`/guardrails/${team_id}/integration/${integration_id}`, {
            params: { limit, offset },
        })
        return response.data as GuardrailsIntegrationDashboard
    } catch (error) {
        showErrorToast(error,"Error fetching guardrails integration dashboard")
        throw error
    }
}

export interface CreateGuardrailsIntegrationData {
    title: string
}

/** @deprecated Guardrails UI removed — do not call from user-facing frontend. */
const createGuardrailsIntegration = async (team_id: number, data: CreateGuardrailsIntegrationData) => {
    try {
        const response = await api.post(`/guardrails/${team_id}/integration`, data)
        toast.success("Guardrails integration created")
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

/** @deprecated Guardrails UI removed — do not call from user-facing frontend. */
const updateGuardrailsIntegration = async ({ team_id, integration_id, data }: { team_id: number; integration_id: number; data: UpdateGuardrailsIntegrationData }) => {
    try {
        const response = await api.put(`/guardrails/${team_id}/integration/${integration_id}`, data)
        toast.success("Guardrails integration updated")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error updating guardrails integration")
        throw error
    }
}

/** @deprecated Guardrails UI removed — do not call from user-facing frontend. */
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
        return response.data
    } catch (error) {
        throw error
    }
}

const renameDASTScan = async ({ team_id, scan_id, title }: { team_id: number; scan_id: number; title: string }) => {
    try {
        const response = await api.put(`/${team_id}/dast/scan/${scan_id}`, { title })
        return response.data
    } catch (error) {
        throw error
    }
}

const createDASTScan = async (team_id: number, title: string): Promise<number> => {
    try {
        const response = await api.post(`/${team_id}/dast/scan`, { title })
        toast.success("DAST scan created")
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
        return response.data as DASTConversation[]
    } catch (error) {
        showErrorToast(error,"Error fetching dast conversations")
        throw error
    }
}

const deleteDASTConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/dast/conversation/${conversation_id}`)
        return response.data
    } catch (error) {
        throw error
    }
}

const renameDASTConversation = async ({conversation_id, title}: {conversation_id: number, title: string}) => {
    try {
        const response = await api.put(`/dast/conversation/${conversation_id}`, { title: title })
        return response.data
    } catch (error) {
        throw error
    }
}

const createDASTConversation = async (title: string) => {
    try {
        const response = await api.post("/dast/conversation", { title: title })
        toast.success("DAST scan created")
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
        toast.success("DAST report downloaded")
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
        toast.success("DAST scan restarted")
        return response.data
    } catch (error) {
        throw error
    }
}

export interface DastProfileAuthPublic {
    login_url?: string
    xpath_of_username_field?: string
    xpath_of_password_field?: string
    username?: string
    xpath_of_submit_button?: string
}

export type DastScheduleKind =
    | "off"
    | "hourly"
    | "every_n_hours"
    | "daily"
    | "weekdays"
    | "weekly"
    | "monthly"
    | "once"
    | "cron"

export interface DastScheduleConfig {
    kind?: DastScheduleKind
    times?: string[] | null
    interval_hours?: number | null
    weekday?: number | null
    monthday?: number | null
    once_at?: string | null
    cron?: string | null
}

export interface DastScanProfile {
    id: number
    team_id: number
    owner_user_id: number
    title: string
    enabled: boolean
    target_url: string
    allowed_hosts: string[]
    auth: DastProfileAuthPublic
    scan_speed: "fast" | "medium" | "slow"
    max_urls: number
    additional_urls_to_scan: string[] | null
    exclude_url_patterns: string[] | null
    include_url_patterns: string[] | null
    schedule_kind: DastScheduleKind
    schedule_time: string | null
    schedule_weekday: number | null
    schedule_config?: DastScheduleConfig | null
    next_run_at: string | null
    inflight_scan_id: number | null
    last_scan_id: number | null
    last_run_at: string | null
    consent_ok: boolean
    created_at: string | null
    last_updated: string | null
}

export interface DastProfileWrite {
    title: string
    target_url: string
    auth: Omit<AuthRequirements, "password"> & { password?: string }
    allowed_hosts?: string[] | null
    scan_speed?: "fast" | "medium" | "slow"
    max_urls?: number
    additional_urls_to_scan?: string[] | null
    exclude_url_patterns?: string[] | null
    include_url_patterns?: string[] | null
    schedule_kind?: DastScheduleKind
    schedule_time?: string | null
    schedule_weekday?: number | null
    schedule_config?: DastScheduleConfig | null
    enabled?: boolean
    consent_ok: boolean
}

const listDASTProfiles = async (team_id: number): Promise<DastScanProfile[]> => {
    try {
        const response = await api.get(`/${team_id}/dast/profiles`)
        return response.data?.profiles ?? []
    } catch (error) {
        showErrorToast(error, "Error fetching DAST profiles")
        throw error
    }
}

const createDASTProfile = async (team_id: number, body: DastProfileWrite): Promise<DastScanProfile> => {
    try {
        const response = await api.post(`/${team_id}/dast/profiles`, body)
        toast.success("DAST profile saved")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error creating DAST profile")
        throw error
    }
}

const updateDASTProfile = async (
    team_id: number,
    profile_id: number,
    body: Partial<DastProfileWrite>
): Promise<DastScanProfile> => {
    try {
        const response = await api.put(`/${team_id}/dast/profiles/${profile_id}`, body)
        toast.success("DAST profile updated")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error updating DAST profile")
        throw error
    }
}

const deleteDASTProfile = async (team_id: number, profile_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/dast/profiles/${profile_id}`)
        toast.success("DAST profile deleted")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error deleting DAST profile")
        throw error
    }
}

const runDASTProfile = async (team_id: number, profile_id: number) => {
    try {
        const response = await api.post(`/${team_id}/dast/profiles/${profile_id}/run`)
        toast.success("DAST scan started")
        return response.data as { scan_id: number; task_id: string; status: string; credits?: number }
    } catch (error) {
        showErrorToast(error, "Error starting DAST profile")
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
    reinitializeDASTScan,
    listDASTProfiles,
    createDASTProfile,
    updateDASTProfile,
    deleteDASTProfile,
    runDASTProfile
}

// -------------------------------------------------------------- CI/CD API Routes --------------------------------------------------------------

export interface CicdIntegration {
    id: number
    title: string
    created_at: string
    last_updated: string
    scan_type: "sast" | "dast" | "cbom" | "llm" | "mcp" | "iac" | "leakage" | "sbom_sca" | "agent_discovery"
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
        return response.data as CicdIntegrationsResponse
    } catch (error) {
        showErrorToast(error,"Error fetching CI/CD integrations")
        throw error
    }
}

export interface CreateCicdIntegrationData {
    title: string
    scan_type: "sast" | "dast" | "cbom"
}

const createCicdIntegration = async (team_id: number, data: CreateCicdIntegrationData) => {
    try {
        const response = await api.post(`/${team_id}/cicd/integration`, data)
        toast.success("CI/CD integration created")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error creating CI/CD integration")
        throw error
    }
}

/** CBOM policy gate of the hosted CI path (backend utilities/cicd/cbom_gate.py) */
export interface CicdCbomGate {
    policy: string
    verdict: "pass" | "fail" | "no_result"
    fail_codes: string[]
    failing_count: number
    failing: { codes: string[]; title: string; location: string; line: number | null; impact: string | null }[]
    truncated: boolean
    reason: string
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
    scan_id?: number | null
    profile_id?: number | null
    trigger?: string | null
    scan_kind?: string | null
    /** CBOM policy gate verdict the pipeline received (POST /cicd/cbom/scan); null for logs made before the gate */
    gate?: CicdCbomGate | null
    cbom_page?: {
        data?: unknown
        dashboard?: CbomScanDashboardData | null
        findings?: CbomFinding[] | null
        scan_metadata?: CbomScanMetadata | Record<string, unknown> | null
    } | null
}

/** Per-date counts by impact (Critical, High, Medium, Low). Keys are date strings YYYY-MM-DD. */
export type VulnsOverTimeChartData = Record<string, { Critical?: number; High?: number; Medium?: number; Low?: number }>

export interface CicdIntegrationDashboard {
    cicd_integration_id: number
    title: string
    created_at: string
    last_updated: string
    scan_type: "sast" | "dast" | "cbom" | "llm" | "mcp" | "iac" | "leakage" | "sbom_sca" | "agent_discovery"
    api_key: string
    integration_active?: boolean
    integration_settings?: Record<string, { jira_project_id?: string | null; auto_create_tickets?: boolean | null } | null> | null
    scan_settings?: Record<string, { app_lang?: SastAppLang; exclude_path_arrays?: string[][] | null; scan_binaries?: boolean; include_vendored?: boolean } | null> | null
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
        return response.data as CicdIntegrationDashboard
    } catch (error) {
        showErrorToast(error,"Error fetching CI/CD integration dashboard")
        throw error
    }
}

const deleteCicdIntegration = async (team_id: number, integration_id: number) => {
    try {
        const response = await api.delete(`/${team_id}/cicd/integration/${integration_id}`)
        toast.success("CI/CD integration deleted")
        return response.data
    } catch (error) {
        showErrorToast(error,"Error deleting CI/CD integration")
        throw error
    }
}

export interface CicdIntegrationSettingsData {
    jira?: { jira_project_id?: string | null; auto_create_tickets?: boolean | null } | null
}

export interface CicdScanSettingsData {
    sast?: {
        app_lang: SastAppLang
        exclude_path_arrays?: string[][] | null
    } | null
    cbom?: {
        scan_binaries: boolean
        include_vendored: boolean
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
        toast.success("CI/CD integration updated")
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

// ---------------------------------------------------------------------------------- CBOM Sources API Routes ----------------------------------------------------------------------------------
// Scan nodes, servers, clusters, databases, cloud accounts, network scope and evidence for the CBOM
// scanner (backend/routers/cbom_sources.py).  Secrets are write-only: send them in `secrets`, read back
// only `secrets_set`.  Pollers and list fetchers never toast (they run every few seconds); mutations do.

export type CbomSourceKind =
    | "linux_servers" | "windows_servers" | "active_directory" | "kubernetes" | "database"
    | "aws_account" | "azure_subscription" | "gcp_project" | "ca_connector" | "idp" | "network_range"
    | "appliance" | "key_manager" | "host_agent" | "container_images"
export type CbomSourceGroup = "servers" | "kubernetes" | "databases" | "cloud" | "identity" | "network"
export type CbomNodeStatus = "pending_registration" | "registration_expired" | "online" | "offline"
export type CbomTestStatus = "never" | "pending" | "passed" | "partial" | "failed" | "not_available" | "error"
export type CbomJobStatus = "pending" | "claimed" | "success" | "failure" | "cancelled" | "expired"
export type CbomRunStatus = "queued" | "running" | "done" | "partial" | "failed" | "cancelled"
export type CbomConfidence = "Q0" | "Q1" | "Q2" | "Q3"
export type CbomIncludeKey = "servers" | "kubernetes" | "databases" | "cloud" | "network"
export type CbomInclude = Partial<Record<CbomIncludeKey, boolean>>

export interface CbomScanNode {
    id: number
    team_id: number
    owner_user_id: number
    name: string
    segment: string
    timezone: string
    deployment: "docker" | "ova" | "ami" | "helm"
    proxy_url: string | null
    has_proxy_ca: boolean
    proxy_tls_inspect: boolean
    status: CbomNodeStatus
    registration_issued_at: string | null
    registration_expires_at: string | null
    enrolled_at: string | null
    hostname: string | null
    node_version: string | null
    source_ips: string[]
    ssh_public_key: string | null
    capabilities: Record<string, unknown>
    clock_skew_s: number | null
    clock_in_sync: boolean | null
    last_heartbeat_at: string | null
    last_claim_at: string | null
    last_seen_ip: string | null
    last_node_error: string | null
    /** "required": every request is signed with the node's Ed25519 key; "legacy": enrolled before signing existed */
    signing: "required" | "legacy"
    /** SHA-256 of the client certificate the proxy verified at enrollment (mTLS), or null */
    client_cert_sha256: string | null
    /** "agent": collects only its own host, never given a credential (ZS_MODE=agent); pool_id: its agent pool token */
    mode?: "agent" | "agentless"
    pool_id?: number | null
    assigned_targets: number
    sources: number
    row_version: number
    created_at: string | null
    last_updated: string | null
}

export interface CbomNodeWrite {
    name?: string
    segment?: string
    timezone?: string
    deployment?: CbomScanNode["deployment"]
    proxy_url?: string | null
    proxy_ca_pem?: string | null
    proxy_tls_inspect?: boolean
    expected_version?: number
}

export interface CbomTestSample {
    target: string
    status: string
    reachable?: boolean
    login?: boolean
    privilege?: boolean
    note?: string
}

export interface CbomAwsCheck {
    check: string
    status: "pass" | "fail" | "skipped" | "error"
    detail: string
}

export interface CbomSource {
    id: number
    team_id: number
    owner_user_id: number
    kind: CbomSourceKind
    kind_label: string
    group: CbomSourceGroup
    name: string
    node_id: number | null
    node_name: string | null
    node_status: CbomNodeStatus | "missing" | null
    enabled: boolean
    config: Record<string, any>
    secrets_set: string[]
    target_count: number
    target_unit: string
    last_test_status: CbomTestStatus
    last_test_at: string | null
    last_test_summary: string | null
    last_test_job_id: number | null
    last_test_result: { samples?: CbomTestSample[]; checks?: CbomAwsCheck[]; member_accounts?: number; summary?: string; status?: string }
    row_version: number
    created_at: string | null
    last_updated: string | null
}

export interface CbomSourceWrite {
    kind?: CbomSourceKind
    name?: string
    node_id?: number | null
    clear_node?: boolean
    enabled?: boolean
    config?: Record<string, any>
    secrets?: Record<string, string>
    clear_secrets?: string[]
    expected_version?: number
    test_after_save?: boolean
}

export interface CbomJob {
    id: number
    run_id: number | null
    source_id: number | null
    source_name: string | null
    node_id: number | null
    node_name: string | null
    kind: "test_connection" | "collect" | "discovery"
    status: CbomJobStatus
    waiting_reason: string | null
    attempts: number
    credits: number
    refunded: boolean
    created_at: string | null
    claimed_at: string | null
    finished_at: string | null
    result: Record<string, any>
    error: string | null
    outcome?: "ok" | "partial" | "failed" | null
    asset_count?: number
    cancel_requested?: boolean
    runner?: "node" | "cloud"
    samples: string[]
    server_time: string
    /** A network range while it runs: addresses swept of the addresses in scope (null: not reported, e.g. an older
     * scan node, or the job is not running). */
    progress?: { done: number; total: number } | null
}

export type CbomImpact = "Critical" | "High" | "Medium" | "Low"

/** A date-based rule (certificate expiry, library end of life) judged this asset differently today than its run did:
 * the finding shown is today's, and this is what the run itself recorded. */
export interface CbomAsOfRun {
    date: string
    judged_on: string
    impact: CbomImpact | null
    finding_codes: string[]
    finding: string | null
}

export interface CbomAsset {
    id: number
    type: string
    cdx_type: string
    job_id: number
    source_id: number | null
    source_name: string | null
    target: string | null
    location: string
    name: string | null
    algorithm: string | null
    key_size: number | null
    protocol: string | null
    quantum_vulnerable: boolean | null
    impact: CbomImpact | null
    finding: string | null
    finding_codes: string[]
    as_of_run?: CbomAsOfRun | null
    facts: Record<string, unknown>
}

export interface CbomTargetResult {
    target: string
    status: string
    error?: string | null
    duration_ms?: number
    assets?: number
}

export interface CbomJobTargets {
    job_id: number
    source_id: number | null
    source_name: string | null
    status: CbomJobStatus
    outcome: "ok" | "partial" | "failed" | null
    attempt: number
    asset_count: number
    // partial: targets read with coverage gaps (cloud collectors); their parts that were not read are "Not collected" rows
    counts: { total?: number; ok?: number; partial?: number; failed?: number; skipped?: number } | null
    summary: string | null
    truncated: boolean
    asset_mismatch: { reported: number; stored: number } | null
    error: string | null
    targets: CbomTargetResult[]
    duration_s: number | null
}

export interface CbomAssetPage {
    total: number
    all_total: number
    page: number
    page_size: number
    items: CbomAsset[]
    facets: { type: Record<string, number>; impact: Record<string, number>; quantum_vulnerable: number }
    targets: CbomJobTargets[]
    run?: CbomRun
}

export interface CbomAssetFilters {
    type?: string
    impact?: CbomImpact | "none"
    quantum?: boolean
    q?: string
    page?: number
    page_size?: number
}

export interface CbomTestResponse {
    status: "queued" | "not_available" | "passed" | "partial" | "failed" | "error"
    job?: CbomJob
    message?: string
    targets?: CbomTargetResult[]
    checks?: CbomAwsCheck[]
    member_accounts?: number | null
    validated_at?: string
}

export interface CbomSourceSaveResponse {
    source: CbomSource
    test: { job_id: number } | CbomTestResponse | null
}

export interface CbomPortItem { port: number; protocol: string; label: string }
export interface CbomExclusionItem { cidr: string; reason: string }

export interface CbomSourcesSettings {
    aws_external_id: string
    /** false: the deployment has no CBOM_AWS_PRINCIPAL_ARN, so AWS accounts cannot be connected */
    aws_collection_configured?: boolean
    cert_domains: string[]
    network_exclusions: CbomExclusionItem[]
    sni_hostnames: string[]
    ports: CbomPortItem[]
    zeek_span: boolean
    scan_window: boolean[][]
    window_timezone: string
    rate_conn_per_s: number
    rate_parallel_per_server: number
    rate_handshakes_per_endpoint: number
    soc_email: string | null
    emergency_contact: string | null
    /** Mosca inputs in years: X = how long data must stay secret, Y = migration time, Z = years until a quantum computer. */
    risk_model: CbomRiskModel
    stop_all_network: boolean
    /** Refuse scan nodes that do not sign their requests (legacy nodes must be reset and enrolled again). */
    require_signed_nodes: boolean
    stop_all_changed_by: number | null
    stop_all_changed_at: string | null
    next_window_start: string | null
    in_window_now: boolean
    row_version: number
    last_updated: string | null
}

export interface CbomRiskModel {
    data_shelf_life_years: number | null
    migration_years: number | null
    threat_years: number | null
}

export type CbomPqcClass = "quantum-vulnerable" | "hybrid" | "quantum-safe" | "grover-weakened" | "not-applicable"

export interface CbomRunPosture {
    assets: number
    pqc_classes: Record<CbomPqcClass, number>
    pqc_readiness_pct: number | null
    hndl_assets: number
    impacts: Record<CbomImpact, number>
    top_codes: { code: string; count: number; title: string }[]
    mosca: { configured: boolean; x: number | null; y: number | null; z: number | null; at_risk?: boolean; years_over?: number; verdict?: string; note?: string }
    top_risks: { id: number; type: string; name: string; location: string; impact: CbomImpact; criticality: string; source_name: string | null; score: number; hndl: boolean; finding: string | null }[]
    compliance: { framework: string; clauses: { id: string; text: string; source: string; note?: string | null; assets: number; codes: string[] }[] }[]
    kb_version: string
    pqc_context: {
        mosca?: { inequality: string; definitions: Record<string, string>; source: string; paper: string }
        expert_survey?: { title: string; published: string; source: string; quotes: string[] }
        nist_ir_8547?: { quote: string; source: string; federal: string }
        z_note?: string
    }
}

export interface CbomAssetDetail {
    id: number
    type: string
    name: string | null
    location: string
    target: string | null
    impact: CbomImpact | null
    finding: string | null
    finding_codes: string[]
    as_of_run?: CbomAsOfRun | null
    algorithm: string | null
    key_size: number | null
    protocol: string | null
    quantum_vulnerable: boolean | null
    pqc_class: CbomPqcClass
    hndl: boolean
    source_name: string | null
    criticality: string
    facts: Record<string, unknown>
    details: KbFindingDetail[]
    library: null | {
        library: string; package: string; package_version: string; upstream_version: string; cves: string[]
        eol: { branch: string; date: string; passed: boolean; sources: string[] } | null
        cve_details: (KbCve | null)[]
    }
    kb_version: string
}

export type CbomSettingsWrite = Partial<Omit<CbomSourcesSettings,
    "aws_external_id" | "stop_all_network" | "stop_all_changed_by" | "stop_all_changed_at" | "next_window_start" |
    "in_window_now" | "row_version" | "last_updated">> & { expected_version?: number }

export interface CbomPlanItem {
    source_id?: number
    name: string
    kind: string
    group?: CbomSourceGroup
    node_id?: number | null
    node_name?: string | null
    units?: number
    unit?: string
    credits?: number
    status: "queued" | "skipped" | "waiting" | "gap"
    reason: string | null
    waiting_for_node?: boolean
    /** a scan-node job waits for its scan window (team or server's own) */
    window_applies?: boolean
    /** when a run queued now may start; null: now (or no window) */
    window_starts_at?: string | null
    area_key?: string
}

export interface CbomPlanGroup { credits: number; queued: number; skipped: number; units: number }

export interface CbomEstimate {
    total_credits: number
    groups: Partial<Record<CbomSourceGroup, CbomPlanGroup>>
    items: CbomPlanItem[]
    skipped: CbomPlanItem[]
    credit_balance?: number
    server_time?: string
}

export interface CbomSourcesOverview {
    server_time: string
    viewer: { user_id: number; is_admin: boolean }
    credit_balance: number
    rates: Record<string, number>
    nodes: { total: number; online: number; offline: number; pending: number }
    groups: Partial<Record<CbomSourceGroup, { sources: number; units: number; by_kind: Record<string, number>; failed_tests: number }>>
    plan: CbomEstimate
    evidence: { areas: number; answered: number; by_confidence: Record<CbomConfidence, number>; vendors: number }
    code: { cbom_scans: number }
    settings: {
        stop_all_network: boolean
        next_window_start: string | null
        in_window_now: boolean
        window_timezone: string
        aws_external_id: string
        network_exclusions: number
        ports: number
        sni_hostnames: number
        cert_domains: number
    }
}

export interface CbomRun {
    id: number
    team_id: number
    owner_user_id: number
    scan_id: number | null
    status: CbomRunStatus
    include: CbomInclude
    breakdown: { groups?: Record<string, CbomPlanGroup>; skipped?: CbomPlanItem[] }
    credits: { charged: number; refunded: number; net: number }
    soc_ack_by: number | null
    soc_ack_at: string | null
    cancelled_by: number | null
    cancelled_at: string | null
    finished_at?: string | null
    created_at: string | null
    last_updated: string | null
    jobs?: CbomJob[]
    job_counts?: Partial<Record<CbomJobStatus, number>>
    asset_count?: number
}

export interface CbomEvidenceQuestion { id: string; prompt: string; type: "text" | "choice" }

export interface CbomEvidenceArea {
    id: number
    area_key: string
    title: string
    owner_hint: string | null
    questions: CbomEvidenceQuestion[]
    owner: string | null
    confidence: CbomConfidence
    effective_confidence: CbomConfidence
    confidence_label: string
    confidence_set_by: number | null
    answers: Record<string, string>
    evidence_title: string | null
    evidence_url: string | null
    evidence_date: string | null
    due_date: string | null
    overdue: boolean
    row_version: number
    last_updated: string | null
}

export interface CbomEvidenceAreaWrite {
    owner?: string | null
    confidence?: CbomConfidence
    answers?: Record<string, string>
    evidence_title?: string | null
    evidence_url?: string | null
    evidence_date?: string | null
    due_date?: string | null
    expected_version?: number
}

export interface CbomVendor {
    id: number
    name: string
    contact_email: string | null
    area_key: string
    status: "not_sent" | "link_created" | "overdue" | "answered" | "expired"
    link_created_at: string | null
    link_expires_at: string | null
    answered_at: string | null
    answers: Record<string, string>
    confidence: CbomConfidence
    evidence_url: string | null
    row_version: number
    created_at: string | null
}

export interface CbomEvidenceResponse {
    server_time: string
    areas: CbomEvidenceArea[]
    vendors: CbomVendor[]
    by_confidence: Record<CbomConfidence, number>
    answered: number
}

export interface CbomTargetCount {
    valid: boolean
    error: string | null
    count: number | null
    lines?: number
    samples?: string[]
}

export interface CbomAuditEvent {
    id: number
    at: string
    actor_type: "user" | "node" | "vendor" | "system"
    actor_id: number | null
    action: string
    object_type: string
    object_id: number | null
    changed_fields: string[]
}

const cbomSourcesBase = (team_id: number) => `/${team_id}/cbom/sources`

// ---------- reads (no toasts: these run on page load and on polling intervals)
const getCbomSourcesOverview = async (team_id: number): Promise<CbomSourcesOverview> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/overview`)
    return response.data as CbomSourcesOverview
}

const listCbomScanNodes = async (team_id: number): Promise<{ nodes: CbomScanNode[]; server_time: string }> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/nodes`)
    return response.data
}

const listCbomSources = async (team_id: number, group?: CbomSourceGroup): Promise<{ sources: CbomSource[]; server_time: string }> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/items`, { params: group ? { group } : {} })
    return response.data
}

const getCbomSource = async (team_id: number, source_id: number): Promise<CbomSource> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/items/${source_id}`)
    return response.data.source as CbomSource
}

const getCbomJob = async (team_id: number, job_id: number): Promise<CbomJob> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/jobs/${job_id}`)
    return response.data.job as CbomJob
}

const getCbomSourcesSettings = async (team_id: number): Promise<CbomSourcesSettings> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/settings`)
    return response.data.settings as CbomSourcesSettings
}

const getCbomEvidence = async (team_id: number): Promise<CbomEvidenceResponse> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/evidence`)
    return response.data as CbomEvidenceResponse
}

const listCbomRuns = async (team_id: number, scan_id?: number): Promise<{ runs: CbomRun[]; server_time: string }> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/runs`, { params: scan_id ? { scan_id } : {} })
    return response.data
}

const getCbomRun = async (team_id: number, run_id: number): Promise<CbomRun> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/runs/${run_id}`)
    return response.data.run as CbomRun
}

const estimateCbomSources = async (team_id: number, include: CbomInclude, source_ids?: number[]): Promise<CbomEstimate> => {
    const response = await api.post(`${cbomSourcesBase(team_id)}/estimate`, { include, ...(source_ids ? { source_ids } : {}) })
    return response.data as CbomEstimate
}

/** Live target count for a textarea; never toasts (it runs while the user types). */
const countCbomTargets = async (team_id: number, targets: string[], exclusions: string[]): Promise<CbomTargetCount> => {
    const response = await api.post(`${cbomSourcesBase(team_id)}/targets/count`, { targets, exclusions })
    return response.data as CbomTargetCount
}

/** Text templates: sudoers, k8s-tier1, k8s-tier2, grant-<engine>. */
const getCbomTemplate = async (team_id: number, name: string): Promise<string> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/templates/${name}`, { responseType: "text", transformResponse: (d) => d })
    return response.data as string
}

const getCbomAwsTemplate = async (team_id: number, scope: "account" | "organization"): Promise<string> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/aws/template`, { params: { scope }, responseType: "text", transformResponse: (d) => d })
    return response.data as string
}

const getCbomAudit = async (team_id: number, limit = 100): Promise<{ events: CbomAuditEvent[] }> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/audit`, { params: { limit } })
    return response.data
}

// ---------- writes (toast on success; errors toast through showErrorToast and are rethrown)
const createCbomScanNode = async (team_id: number, body: CbomNodeWrite): Promise<{ node: CbomScanNode; registration_token: string }> => {
    try {
        const response = await api.post(`${cbomSourcesBase(team_id)}/nodes`, body)
        toast.success("Scan node added")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error adding the scan node")
        throw error
    }
}

const updateCbomScanNode = async (team_id: number, node_id: number, body: CbomNodeWrite): Promise<{ node: CbomScanNode }> => {
    try {
        const response = await api.patch(`${cbomSourcesBase(team_id)}/nodes/${node_id}`, body)
        toast.success("Scan node saved")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error saving the scan node")
        throw error
    }
}

const deleteCbomScanNode = async (team_id: number, node_id: number): Promise<void> => {
    try {
        await api.delete(`${cbomSourcesBase(team_id)}/nodes/${node_id}`)
        toast.success("Scan node deleted")
    } catch (error) {
        showErrorToast(error, "Error deleting the scan node")
        throw error
    }
}

/** reset=false: new token for a node that never registered; reset=true: revoke and register again.  An agent pool
 * node gets no token (null): its pod enrolls again by itself with the pool token. */
const newCbomNodeRegistration = async (team_id: number, node_id: number, reset: boolean): Promise<{ node: CbomScanNode; registration_token: string | null }> => {
    try {
        const path = reset ? "reset" : "registration-token"
        const response = await api.post(`${cbomSourcesBase(team_id)}/nodes/${node_id}/${path}`)
        toast.success(!reset ? "New registration token issued"
            : response.data?.registration_token ? "Node credential revoked; register the node again"
            : "Node credential revoked; the pod enrolls again by itself")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error issuing a registration token")
        throw error
    }
}

const createCbomSource = async (team_id: number, body: CbomSourceWrite): Promise<CbomSourceSaveResponse> => {
    try {
        const response = await api.post(`${cbomSourcesBase(team_id)}/items`, body)
        // AWS accounts are validated inline (the result is already in the response); others queue a node job.
        toast.success(body.test_after_save && response.data?.source?.kind !== "aws_account" ? "Saved; connection test queued" : "Source saved")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error saving the source")
        throw error
    }
}

const updateCbomSource = async (team_id: number, source_id: number, body: CbomSourceWrite): Promise<CbomSourceSaveResponse> => {
    try {
        const response = await api.patch(`${cbomSourcesBase(team_id)}/items/${source_id}`, body)
        // AWS accounts are validated inline (the result is already in the response); others queue a node job.
        toast.success(body.test_after_save && response.data?.source?.kind !== "aws_account" ? "Saved; connection test queued" : "Source saved")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error saving the source")
        throw error
    }
}

const deleteCbomSource = async (team_id: number, source_id: number): Promise<void> => {
    try {
        await api.delete(`${cbomSourcesBase(team_id)}/items/${source_id}`)
        toast.success("Source deleted")
    } catch (error) {
        showErrorToast(error, "Error deleting the source")
        throw error
    }
}

const testCbomSource = async (team_id: number, source_id: number): Promise<CbomTestResponse> => {
    try {
        const response = await api.post(`${cbomSourcesBase(team_id)}/items/${source_id}/test`)
        const data = response.data as CbomTestResponse
        if (data.status === "queued") toast.success("Connection test queued for the scan node")
        else if (data.status === "passed") toast.success(data.message || "All checks passed")
        else if (data.status === "partial") toast.warning(data.message || "Some checks did not pass; see the results")
        else if (data.status === "not_available") toast.info(data.message || "Validation is not available yet for this source")
        else toast.error("Some checks did not pass; see the results")
        return data
    } catch (error) {
        showErrorToast(error, "Error testing the source")
        throw error
    }
}

const updateCbomSourcesSettings = async (team_id: number, body: CbomSettingsWrite): Promise<CbomSourcesSettings> => {
    try {
        const response = await api.patch(`${cbomSourcesBase(team_id)}/settings`, body)
        toast.success("Settings saved")
        return response.data.settings as CbomSourcesSettings
    } catch (error) {
        showErrorToast(error, "Error saving settings")
        throw error
    }
}

const setCbomNetworkStop = async (team_id: number, on: boolean): Promise<CbomSourcesSettings> => {
    try {
        const response = await api.post(`${cbomSourcesBase(team_id)}/settings/stop-all`, { on })
        toast.success(on ? "All network scanning stopped" : "Network scanning resumed")
        return response.data.settings as CbomSourcesSettings
    } catch (error) {
        showErrorToast(error, "Error changing network scanning")
        throw error
    }
}

const startCbomDiscovery = async (team_id: number): Promise<{ jobs: CbomJob[] }> => {
    try {
        const response = await api.post(`${cbomSourcesBase(team_id)}/discovery`)
        toast.success("Discovery sweep queued")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error starting the discovery sweep")
        throw error
    }
}

const updateCbomEvidenceArea = async (team_id: number, area_key: string, body: CbomEvidenceAreaWrite): Promise<CbomEvidenceArea> => {
    try {
        const response = await api.patch(`${cbomSourcesBase(team_id)}/evidence/${area_key}`, body)
        toast.success("Evidence saved")
        return response.data.area as CbomEvidenceArea
    } catch (error) {
        showErrorToast(error, "Error saving evidence")
        throw error
    }
}

const createCbomVendor = async (team_id: number, body: { name: string; contact_email?: string | null }): Promise<CbomVendor> => {
    try {
        const response = await api.post(`${cbomSourcesBase(team_id)}/evidence/vendors`, body)
        toast.success("Vendor added")
        return response.data.vendor as CbomVendor
    } catch (error) {
        showErrorToast(error, "Error adding the vendor")
        throw error
    }
}

const updateCbomVendor = async (team_id: number, vendor_id: number, body: { name?: string; contact_email?: string | null; confidence?: CbomConfidence; expected_version?: number }): Promise<CbomVendor> => {
    try {
        const response = await api.patch(`${cbomSourcesBase(team_id)}/evidence/vendors/${vendor_id}`, body)
        toast.success("Vendor saved")
        return response.data.vendor as CbomVendor
    } catch (error) {
        showErrorToast(error, "Error saving the vendor")
        throw error
    }
}

const deleteCbomVendor = async (team_id: number, vendor_id: number): Promise<void> => {
    try {
        await api.delete(`${cbomSourcesBase(team_id)}/evidence/vendors/${vendor_id}`)
        toast.success("Vendor deleted")
    } catch (error) {
        showErrorToast(error, "Error deleting the vendor")
        throw error
    }
}

const createCbomVendorLink = async (team_id: number, vendor_id: number): Promise<{ vendor: CbomVendor; url: string; path: string }> => {
    try {
        const response = await api.post(`${cbomSourcesBase(team_id)}/evidence/vendors/${vendor_id}/link`)
        toast.success("Single-use link created")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error creating the link")
        throw error
    }
}

const startCbomRun = async (team_id: number, body: { include: CbomInclude; source_ids?: number[]; scan_id?: number; client_request_id: string; expected_credits?: number; soc_ack?: boolean }): Promise<{ run: CbomRun; replayed: boolean }> => {
    try {
        const response = await api.post(`${cbomSourcesBase(team_id)}/runs`, body)
        toast.success("Collection run queued")
        return response.data
    } catch (error) {
        showErrorToast(error, "Error starting the run")
        throw error
    }
}

const getCbomRunAssets = async (team_id: number, run_id: number, filters: CbomAssetFilters = {}): Promise<CbomAssetPage> => {
    const params: Record<string, string | number | boolean> = {}
    for (const [key, value] of Object.entries(filters)) {
        if (value !== undefined && value !== null && value !== "") params[key] = value as string | number | boolean
    }
    const response = await api.get(`${cbomSourcesBase(team_id)}/runs/${run_id}/assets`, { params })
    return response.data as CbomAssetPage
}

const getCbomRunPosture = async (team_id: number, run_id: number): Promise<CbomRunPosture> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/runs/${run_id}/posture`)
    return (response.data as { posture: CbomRunPosture }).posture
}

const getCbomAssetDetail = async (team_id: number, asset_id: number): Promise<CbomAssetDetail> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/assets/${asset_id}`)
    return (response.data as { asset: CbomAssetDetail }).asset
}

const getCbomJobAssets = async (team_id: number, job_id: number, page = 1): Promise<CbomAssetPage> => {
    const response = await api.get(`${cbomSourcesBase(team_id)}/jobs/${job_id}/assets`, { params: { page, page_size: 200 } })
    return response.data as CbomAssetPage
}

/** Saves the run's CycloneDX 1.6 CBOM through the authenticated client (a plain link would carry no token). */
const downloadCbomRunCbom = async (team_id: number, run_id: number): Promise<void> => {
    try {
        const response = await api.get(`${cbomSourcesBase(team_id)}/runs/${run_id}/cbom`, { responseType: "blob" })
        const url = URL.createObjectURL(response.data as Blob)
        const link = document.createElement("a")
        link.href = url
        link.download = `cbom-sources-run-${run_id}.cdx.json`
        document.body.appendChild(link)
        link.click()
        link.remove()
        setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (error) {
        showErrorToast(error, "Error downloading the CBOM")
        throw error
    }
}

const cancelCbomRun = async (team_id: number, run_id: number): Promise<{ run: CbomRun; refunded: number }> => {
    try {
        const response = await api.post(`${cbomSourcesBase(team_id)}/runs/${run_id}/cancel`)
        const data = response.data as { run: CbomRun; refunded: number }
        toast.success(data.refunded > 0 ? `Cancelled; ${data.refunded} credits refunded` : "Nothing left to cancel")
        return data
    } catch (error) {
        showErrorToast(error, "Error cancelling the run")
        throw error
    }
}

export {
    getCbomSourcesOverview,
    listCbomScanNodes,
    listCbomSources,
    getCbomSource,
    getCbomJob,
    getCbomSourcesSettings,
    getCbomEvidence,
    listCbomRuns,
    getCbomRun,
    getCbomRunAssets,
    getCbomRunPosture,
    getCbomAssetDetail,
    getCbomJobAssets,
    downloadCbomRunCbom,
    estimateCbomSources,
    countCbomTargets,
    getCbomTemplate,
    getCbomAwsTemplate,
    getCbomAudit,
    createCbomScanNode,
    updateCbomScanNode,
    deleteCbomScanNode,
    newCbomNodeRegistration,
    createCbomSource,
    updateCbomSource,
    deleteCbomSource,
    testCbomSource,
    updateCbomSourcesSettings,
    setCbomNetworkStop,
    startCbomDiscovery,
    updateCbomEvidenceArea,
    createCbomVendor,
    updateCbomVendor,
    deleteCbomVendor,
    createCbomVendorLink,
    startCbomRun,
    cancelCbomRun,
}
