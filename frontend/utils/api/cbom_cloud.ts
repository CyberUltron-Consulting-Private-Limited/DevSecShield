import api from "@/utils/interceptors";

/** Opt-ins of the AWS reader role; each is a CloudFormation parameter whose default the download sets. */
export interface CbomAwsOptIns {
  lambdaCmk: boolean;
  glue: boolean;
}

const base = (teamId: number) => `/${teamId}/cbom/sources`;

/** The CloudFormation template with the opt-in parameters defaulted to the account's switches. */
export async function getCbomAwsReaderTemplate(teamId: number, scope: "account" | "organization", optIns: CbomAwsOptIns): Promise<string> {
  const response = await api.get(`${base(teamId)}/aws/template`, {
    params: { scope, lambda_cmk: optIns.lambdaCmk, glue: optIns.glue },
    responseType: "text",
    transformResponse: (d: unknown) => d,
  });
  return response.data as string;
}

/** Read-only role scripts for Azure Key Vault and Google Cloud (metadata only, never values). */
export async function getCbomCloudReaderScript(teamId: number, provider: "azure" | "gcp"): Promise<string> {
  const response = await api.get(`${base(teamId)}/templates/${provider}-reader`, { responseType: "text", transformResponse: (d: unknown) => d });
  return response.data as string;
}
