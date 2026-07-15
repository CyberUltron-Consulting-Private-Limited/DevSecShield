from helpers.context import BaseSummaryManager
from helpers.context.schema import CryptographicAssetVulnerability
from helpers.context.output_model import OutputModelManager
from pydantic import BaseModel, Field
from rich.console import Console
from langchain.schema import Document

console = Console()


class FinalCryptographicAssetVulnerabilities(BaseModel):
    vulnerabilities: list[CryptographicAssetVulnerability] = Field(
        ..., description="A list of Cryptographic Asset Vulnerabilities"
    )


RefinePrompt = """
## Your Task : \n
You are a cryptography and post-quantum security expert. Analyze the given Cryptographic Asset Vulnerabilities list and refine it with the new content provided to make it more coherent and detailed.
Focus on:
- Identifying weak or deprecated algorithms (MD5, SHA-1, DES, RC4, etc.)
- Flagging algorithms vulnerable to quantum computing attacks (RSA, ECDSA, DH, etc.)
- Noting key sizes that are below recommended thresholds
- Identifying protocol weaknesses (TLS 1.0/1.1, SSLv3, etc.)
- Recommending post-quantum cryptography (PQC) alternatives where applicable
\n\n
---------------------------------------------------------------------------------------------------------
### The existing Cryptographic Asset Vulnerabilities list that needs to be refined is :\n
{summary}
\n\n\n
-----------------------------------------------------------------------------------------------------------
### Here is the new content that must be used to refine the existing Cryptographic Asset Vulnerabilities list :\n
{text}
\n
----------------------------------------------------------------------------------------------------------
"""

MapPrompt = """
## Your Task : \n
**You are a cryptography and post-quantum security expert. Analyze these CBOM (Cryptography Bill of Materials) scan results and extract the Cryptographic Asset Vulnerabilities that can help a cybersecurity professional identify cryptographic risks.**

For example: A Cryptographic Asset Vulnerability could be "Weak hashing algorithm MD5 used in authentication module", "RSA-1024 key found in certificate handling - vulnerable to quantum attacks", "Deprecated TLS 1.0 protocol usage detected" or any other crypto-specific vulnerability.

Note: This is only an example. Extract only vulnerabilities from the provided scan results.

Important guidelines:
- Extract weak algorithms (MD5, SHA-1, DES, RC4, 3DES, etc.) as HIGH/CRITICAL severity
- Extract quantum-vulnerable algorithms (RSA, ECDSA, DH, DSA) with proper quantum risk context
- Extract protocol weaknesses (TLS 1.0/1.1, SSLv3) as HIGH severity
- Extract small key sizes (RSA < 2048, AES < 128) as HIGH severity
- For each vulnerability, include the algorithm name, type, strength classification, key size if known, quantum safety status, file location, and code snippet
- Do NOT generate false positives - only report what is actually detected in the scan results

### Compliance Controls Mapping (MANDATORY):
For EVERY vulnerability, you MUST map it to the relevant compliance controls from the list below. Cryptographic vulnerabilities typically map to:
- **Weak/deprecated algorithms** (MD5, SHA-1, DES, RC4, 3DES): ISO 27001 - A.10 Cryptography, NIST 800-53 - System and Communications Protection, NIST CSF - Protect, PCI DSS - Requirement 4
- **Quantum-vulnerable algorithms** (RSA, ECDSA, DH, DSA): ISO 27001 - A.10 Cryptography, NIST 800-53 - System and Communications Protection, NIST CSF - Identify, CMMC - Level 3 (Good Cyber Hygiene)
- **Protocol weaknesses** (TLS 1.0/1.1, SSLv3): ISO 27001 - A.13 Communications Security, NIST 800-53 - System and Communications Protection, NIST CSF - Protect
- **Small key sizes** (RSA < 2048, AES < 128): ISO 27001 - A.10 Cryptography, NIST 800-53 - System and Communications Protection, NIST CSF - Protect
- **Certificate issues**: ISO 27001 - A.10 Cryptography, NIST 800-53 - Identification and Authentication
- **Key management issues**: ISO 27001 - A.10 Cryptography, NIST 800-53 - System and Communications Protection, GDPR - Integrity and confidentiality
- **Data encryption gaps**: GDPR - Integrity and confidentiality, ISO 27001 - A.10 Cryptography, NIST 800-53 - System and Communications Protection

Always include at least 2-3 compliance controls per vulnerability. Use the exact enum values from the ComplianceControls schema.
\n\n
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
## CBOM Scan Results :
{text}
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
"""

CombinePrompt = """
## Your Task : \n
Analyze the Cryptographic Asset Vulnerabilities provided below that have been extracted from the codebase and combine them into a single deduplicated list.
Important: Combine related findings (e.g., multiple uses of the same weak algorithm across files) into a single comprehensive vulnerability entry, making the description as detailed as possible.
Group by: algorithm type first, then by severity.
\n\n
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Cryptographic Asset Vulnerabilities :
{text}
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


class CBOMSummaryManager(BaseSummaryManager, OutputModelManager):
    def __init__(self):

        output_model = self.get_cryptographic_output_model()

        super().__init__(
            summary_output_model=output_model,
            refine_prompt_string=RefinePrompt,
            map_prompt_string=MapPrompt,
            combine_prompt_string=CombinePrompt,
            summary_starting_string="Cryptographic Asset Vulnerabilities Identified in the codebase are as follows : \n\n",
        )

    def format_to_string(
        self, input: type[FinalCryptographicAssetVulnerabilities]
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
                Compliance Controls: {vulnerability.compliance_controls} \n
                Suggested Fix: {vulnerability.suggested_fix} \n
                Algorithm Name: {vulnerability.algorithm_name} \n
                Algorithm Type: {vulnerability.algorithm_type} \n
                Crypto Strength: {vulnerability.crypto_strength} \n
                Key Size: {vulnerability.key_size} \n
                Quantum Safe: {vulnerability.quantum_safe} \n
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
