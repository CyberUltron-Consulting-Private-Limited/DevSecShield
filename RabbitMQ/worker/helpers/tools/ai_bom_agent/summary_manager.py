from helpers.context import BaseSummaryManager
from helpers.context.schema import AIComponentVulnerability
from helpers.context.output_model import OutputModelManager
from pydantic import BaseModel, Field
from rich.console import Console
from langchain.schema import Document

console = Console()


class FinalAIComponentVulnerabilities(BaseModel):
    vulnerabilities: list[AIComponentVulnerability] = Field(
        ..., description="A list of AI/ML Component Vulnerabilities"
    )


RefinePrompt = """
## Your Task : \n
You are an AI/ML supply-chain security expert. Analyze the given AI/ML Component Vulnerabilities list and refine it with the new content provided to make it more coherent and detailed.
Focus on:
- Untrusted model deserialization (pickle-based weights: .pkl/.joblib/.pt/.pth/.ckpt/.bin can execute arbitrary code on load)
- Unpinned model versions (floating aliases / branch HEAD instead of dated snapshots or commit SHAs)
- Deprecated / end-of-life models that no longer receive safety or security updates
- Missing model card / lineage / provenance metadata
- License compliance gaps for models and datasets
- Data-privacy and training-configuration exposure (PII in datasets, provider train-on-data flags)
- Model theft / weight exposure (weights committed to source control or unprotected storage)
\n\n
---------------------------------------------------------------------------------------------------------
### The existing AI/ML Component Vulnerabilities list that needs to be refined is :\n
{summary}
\n\n\n
-----------------------------------------------------------------------------------------------------------
### Here is the new content that must be used to refine the existing AI/ML Component Vulnerabilities list :\n
{text}
\n
----------------------------------------------------------------------------------------------------------
"""

MapPrompt = """
## Your Task : \n
**You are an AI/ML supply-chain security expert. Analyze these AI-BOM (AI/ML Bill of Materials) scan results and extract the AI/ML Component Vulnerabilities that can help a cybersecurity professional identify AI supply-chain and governance risks.**

For example: An AI/ML Component Vulnerability could be "Pickle-based model weights model.pkl loaded with untrusted deserialization risk (arbitrary code execution)", "Unpinned OpenAI model 'gpt-4o' used without a dated snapshot - non-reproducible and supply-chain unstable", "Hugging Face model loaded from branch HEAD without a pinned commit revision" or any other AI/ML-specific component risk.

Note: This is only an example. Extract only vulnerabilities from the provided scan results.

Important guidelines:
- Extract pickle-based local model files (.pkl/.joblib/.pt/.pth/.ckpt/.bin) as CRITICAL severity (untrusted deserialization / arbitrary code execution on load)
- Extract unpinned hosted-provider or Hugging Face model references as MEDIUM severity (supply-chain instability / non-reproducibility)
- Extract deprecated / end-of-life models as HIGH severity
- Extract missing model-card / lineage / provenance as LOW severity inventory findings
- Extract license-compliance gaps for models and datasets as MEDIUM severity
- Extract data-privacy / training-config exposure (PII in datasets, train-on-data) as HIGH severity
- For each vulnerability, include the component name, component type, framework, version (if known), source/provider, license (if known), file location, code snippet, and risk category
- Populate owasp_top_10_llm with the relevant OWASP Top 10 for LLM Applications entries (e.g. Supply Chain Vulnerabilities, Insecure Output Handling, Training Data Poisoning, Sensitive Information Disclosure, Model Theft)
- Do NOT generate false positives - only report what is actually detected in the scan results

### Compliance Controls Mapping (MANDATORY):
For EVERY vulnerability, you MUST map it to the relevant compliance controls from the list below. AI/ML component vulnerabilities typically map to:
- **Untrusted model deserialization** (pickle weights): ISO 42001 - Model Lifecycle Management, NIST 800-53 - System and Information Integrity, NIST CSF - Protect, ISO 27001 - A.14 System Acquisition, Development, and Maintenance
- **Unpinned / non-reproducible models**: ISO 42001 - Model Lifecycle Management, ISO 27001 - A.15 Supplier Relationships, NIST 800-53 - Configuration Management, NIST CSF - Identify
- **Deprecated / EOL models**: ISO 42001 - Model Lifecycle Management, ISO 27001 - A.12 Operations Security, NIST CSF - Identify
- **Missing model card / lineage**: ISO 42001 - Data Governance and Transparency, ISO 27001 - A.8 Asset Management, NIST CSF - Identify
- **License compliance gaps**: ISO 27001 - A.18 Compliance, ISO 42001 - AI Risk Management, NIST 800-53 - System and Services Acquisition
- **Data-privacy / training-config exposure**: GDPR - Integrity and confidentiality, DPDP Act India - Security Safeguards, ISO 42001 - Data Governance and Transparency, NIST 800-53 - System and Communications Protection
- **Model theft / weight exposure**: ISO 27001 - A.8 Asset Management, NIST 800-53 - Access Control, ISO 42001 - AI Risk Management, NIST CSF - Protect

Always include at least 2-3 compliance controls per vulnerability. Use the exact enum values from the ComplianceControls schema.
\n\n
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
## AI-BOM Scan Results :
{text}
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
"""

CombinePrompt = """
## Your Task : \n
Analyze the AI/ML Component Vulnerabilities provided below that have been extracted from the codebase and combine them into a single deduplicated list.
Important: Combine related findings (e.g., multiple uses of the same model or framework across files) into a single comprehensive vulnerability entry, making the description as detailed as possible.
Group by: component type first, then by risk category, then by severity.
\n\n
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
## AI/ML Component Vulnerabilities :
{text}
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


class AIBOMSummaryManager(BaseSummaryManager, OutputModelManager):
    def __init__(self):

        output_model = self.get_ai_component_output_model()

        super().__init__(
            summary_output_model=output_model,
            refine_prompt_string=RefinePrompt,
            map_prompt_string=MapPrompt,
            combine_prompt_string=CombinePrompt,
            summary_starting_string="AI/ML Component Vulnerabilities Identified in the codebase are as follows : \n\n",
        )

    def format_to_string(
        self, input: type[FinalAIComponentVulnerabilities]
    ) -> str:
        """
        Responsible for formatting the summary output model to a string
        Returns:
            str
        """
        try:
            output_model_string = ""
            for vulnerability in input.vulnerabilities:
                temp = f"""
                \n\n
                =======================================================================================
                Title: {vulnerability.title} \n
                Description: {vulnerability.description} \n
                Impact: {vulnerability.impact} \n
                OWASP Top 10: {vulnerability.owasp_top_10} \n
                OWASP Top 10 LLM: {vulnerability.owasp_top_10_llm} \n
                Compliance Controls: {vulnerability.compliance_controls} \n
                Suggested Fix: {vulnerability.suggested_fix} \n
                Component Name: {vulnerability.component_name} \n
                Component Type: {vulnerability.component_type} \n
                Framework: {vulnerability.framework} \n
                Version: {vulnerability.version} \n
                Source: {vulnerability.source} \n
                License: {vulnerability.license} \n
                Risk Category: {vulnerability.risk_category} \n
                Location: {vulnerability.location} \n
                Snippet: {vulnerability.snippet} \n
                =======================================================================================
                \n\n
                """
                output_model_string += temp

            final_string = self.summary_starting_string + output_model_string
            return final_string
        except Exception as e:
            raise ValueError(
                f"Error in formatting summary output model to string: {e}"
            )

    def format_documents_to_string(
        self,
        documents: list[Document],
    ) -> str:
        """
        Responsible for formatting the documents into a string
        """
        try:
            documents_data = ""
            for document in documents:
                documents_data += f"""
                =======================================================
                Document Content : {document.page_content}\n
                =======================================================
                \n\n\n\n
                """

            return documents_data
        except Exception as e:
            raise ValueError(f"Error in formatting documents to string: {e}")
