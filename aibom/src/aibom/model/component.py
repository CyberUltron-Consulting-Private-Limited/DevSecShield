"""Internal normalized AI inventory model (Pydantic v2).

This is the *single source of truth* the scanners populate and the serializers
(emit/cyclonedx.py, future emit/spdx.py) read from. It is deliberately
serializer-agnostic: it captures the AI inventory in clean, healthcare-aware
field names. The serializers are responsible for mapping these fields onto the
EXACT CycloneDX / SPDX spec field names. NO CycloneDX field names leak into
this module beyond what the LOCKED contract requires.

Healthcare data lives in dedicated typed fields on the model/dataset kinds and
is emitted by the serializer into CycloneDX ``properties[]`` under the
``clinical:`` / ``regulatory:`` / ``dataset:`` namespaces -- never as invented
top-level spec keys.

LOCKED AIComponent contract (discriminated union on ``kind``):
    common: bom_ref, name, version, kind, publisher, licenses, hashes, purl,
            properties, external_references
    model kind adds: model_card (ModelCard) with clinical extensions
    dataset kind adds: dataset_type, dataset_size, provenance, sensitivity,
            known_bias
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

# --------------------------------------------------------------------------- #
# Discriminator
# --------------------------------------------------------------------------- #

# Expanded shadow-AI taxonomy (Phase 4). Every kind is a registry entry — no
# special-casing (decision D4). New "discovered" kinds (agent, tool, MCP, vector
# store, …) are thin _BaseComponent subclasses that serialize via KIND_TO_CDX.
ComponentKind = Literal[
    # core (Phase 0-3)
    "model",
    "dataset",
    "framework",
    "prompt",
    "service",
    "infra",
    "secret",
    # agentic / tooling
    "agent",
    "tool",
    "mcp_server",
    "mcp_client",
    "guardrail",
    "orchestrator",
    "plugin",
    # data / retrieval
    "vector_store",
    "knowledge_base",
    "retriever",
    "reranker",
    "embedding_model",
    "notebook",
    # deployment / runtime
    "container",
    "cloud_service",
    "endpoint",
    "registry",
    "pipeline",
    "fine_tuning",
    "evaluation",
]


# --------------------------------------------------------------------------- #
# Shared value objects
# --------------------------------------------------------------------------- #


class Hash(BaseModel):
    """A content hash. Maps 1:1 to CycloneDX ``hashes[]`` ({alg, content})."""

    model_config = ConfigDict(extra="forbid")

    alg: str = Field(..., description="Hash algorithm, e.g. 'SHA-256'.")
    content: str = Field(..., description="Hex-encoded hash digest.")


class ExternalReference(BaseModel):
    """An external reference. ``url`` is mandatory (CycloneDX requires it)."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., description="Absolute URL. Required by the spec.")
    type: str = Field(
        default="other",
        description="CycloneDX externalReference type, e.g. 'model-card'.",
    )
    comment: str | None = None


class PerformanceMetric(BaseModel):
    """A quantitative performance metric.

    Maps to CycloneDX ``modelCard.quantitativeAnalysis.performanceMetrics[]``
    ({type, value, slice}).
    """

    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., description="Metric name, e.g. 'AUROC'.")
    value: str = Field(..., description="Metric value (string per spec).")
    slice: str | None = Field(
        default=None, description="Data slice the metric was computed over."
    )


class EthicalConsideration(BaseModel):
    """Maps to CycloneDX considerations.ethicalConsiderations[] (the 'risk' def)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    mitigation_strategy: str | None = None


class FairnessAssessment(BaseModel):
    """Maps to CycloneDX considerations.fairnessAssessments[]."""

    model_config = ConfigDict(extra="forbid")

    group_at_risk: str | None = None
    benefits: str | None = None
    harms: str | None = None
    mitigation_strategy: str | None = None


class Considerations(BaseModel):
    """Maps to CycloneDX ``modelCard.considerations``."""

    model_config = ConfigDict(extra="forbid")

    users: list[str] = Field(default_factory=list)
    use_cases: list[str] = Field(default_factory=list)
    technical_limitations: list[str] = Field(default_factory=list)
    ethical_considerations: list[EthicalConsideration] = Field(default_factory=list)
    fairness_assessments: list[FairnessAssessment] = Field(default_factory=list)


class PedigreeAncestor(BaseModel):
    """A model ancestor. Maps to CycloneDX ``pedigree.ancestors[]`` (a component)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str | None = None
    type: str = Field(
        default="machine-learning-model",
        description="CycloneDX component type of the ancestor.",
    )


class ModelCard(BaseModel):
    """Normalized model card with clinical-imaging extensions.

    The non-clinical fields map onto CycloneDX ``modelCard.modelParameters``,
    ``modelCard.quantitativeAnalysis`` and ``modelCard.considerations``.

    The CLINICAL extension fields (intended_use, modality, body_part,
    pacs_ae_title, fda_product_code, device_class, eu_ai_act_risk_tier) are NOT
    CycloneDX spec fields; the serializer emits them as ``properties[]`` under
    the ``clinical:`` / ``regulatory:`` namespaces.
    """

    model_config = ConfigDict(extra="forbid")

    # --- modelParameters ---
    approach_type: (
        Literal[
            "supervised",
            "unsupervised",
            "reinforcement-learning",
            "semi-supervised",
            "self-supervised",
        ]
        | None
    ) = None
    task: str | None = None
    architecture_family: str | None = Field(
        default=None, description="e.g. 'convolutional neural network'."
    )
    model_architecture: str | None = Field(
        default=None, description="e.g. 'ResNet-50'."
    )
    datasets: list[str] = Field(
        default_factory=list,
        description="bom_ref strings of dataset components this model trained on.",
    )
    inputs: list[str] = Field(
        default_factory=list, description="Input format descriptors."
    )
    outputs: list[str] = Field(
        default_factory=list, description="Output format descriptors."
    )

    # --- quantitativeAnalysis ---
    performance_metrics: list[PerformanceMetric] = Field(default_factory=list)

    # --- considerations ---
    considerations: Considerations | None = None

    # --- pedigree ---
    pedigree_ancestors: list[PedigreeAncestor] = Field(default_factory=list)

    # --- CLINICAL extensions -> clinical:/regulatory: properties ---
    intended_use: str | None = None
    modality: str | None = Field(
        default=None, description="DICOM modality, e.g. 'DX', 'CT', 'MR'."
    )
    body_part: str | None = None
    pacs_ae_title: str | None = Field(
        default=None, description="PACS Application Entity title."
    )
    fda_product_code: str | None = None
    device_class: str | None = Field(
        default=None, description="FDA device class, e.g. 'II (SaMD)'."
    )
    eu_ai_act_risk_tier: str | None = None

    # SPDX 3.0 AI-Profile signal: does the model use sensitive personal info
    # (e.g. PHI at inference)? Maps to ai_useSensitivePersonalInformation
    # (PresenceType). Also emitted as a clinical: property in CycloneDX.
    uses_sensitive_personal_information: (
        Literal["yes", "no", "noAssertion"] | None
    ) = None

    # Structured human-oversight signal (EU AI Act Art 14 / GMLP-7). A boolean
    # graph fact a compliance check reads directly — NOT inferred by substring-
    # scanning the free-text ``considerations.users`` list (which false-passes on
    # negation like "no human review" and false-fails on unlisted reviewer roles).
    human_oversight: Literal["yes", "no", "noAssertion"] | None = None


# --------------------------------------------------------------------------- #
# Component base + discriminated union members
# --------------------------------------------------------------------------- #


class _BaseComponent(BaseModel):
    """Common fields shared by every AIComponent kind."""

    model_config = ConfigDict(extra="forbid")

    bom_ref: str = Field(
        ..., description="Stable, unique reference for this component."
    )
    name: str
    version: str | None = None
    publisher: str | None = None
    licenses: list[dict] | None = Field(
        default=None,
        description=(
            "CycloneDX licenseChoice entries, "
            "e.g. [{'license': {'id': 'Apache-2.0'}}]."
        ),
    )
    hashes: list[Hash] | None = None
    purl: str | None = Field(default=None, description="Package URL (purl).")
    properties: dict[str, str] | None = Field(
        default=None,
        description=(
            "Namespaced healthcare key/value pairs "
            "(clinical:/regulatory:/dataset:)."
        ),
    )
    external_references: list[ExternalReference] | None = None


class ModelComponent(_BaseComponent):
    """A machine-learning model. Serializes to type 'machine-learning-model'."""

    kind: Literal["model"] = "model"
    model_card: ModelCard = Field(
        default_factory=ModelCard,
        description="Model card, incl. clinical extensions.",
    )


class DatasetComponent(_BaseComponent):
    """A dataset. Serializes to CycloneDX component type 'data'.

    The dataset_* fields are emitted by the serializer as ``dataset:`` properties.
    """

    kind: Literal["dataset"] = "dataset"
    dataset_type: str | None = Field(
        default=None, description="e.g. 'image (DICOM)'. SPDX dataset_datasetType."
    )
    dataset_size: str | None = Field(
        default=None,
        description="Free-text size, e.g. '412,000 studies' (SPDX wants an int).",
    )
    provenance: str | None = None
    sensitivity: str | None = None
    known_bias: str | None = None

    # --- richer Dataset-Profile capture (SPDX 3.0 Dataset Profile) ---
    availability: str | None = Field(
        default=None,
        description="SPDX dataset_datasetAvailability enum value, if it maps.",
    )
    data_collection_process: str | None = None
    data_preprocessing: list[str] = Field(default_factory=list)
    anonymization_method: list[str] = Field(default_factory=list)
    confidentiality_level: str | None = Field(
        default=None, description="SPDX dataset_confidentialityLevel (TLP-like)."
    )
    intended_use: str | None = None
    has_sensitive_personal_information: (
        Literal["yes", "no", "noAssertion"] | None
    ) = Field(
        default=None,
        description="SPDX dataset_hasSensitivePersonalInformation (PresenceType).",
    )


class FrameworkComponent(_BaseComponent):
    """An ML framework / library, e.g. torch. Serializes to type 'library'."""

    kind: Literal["framework"] = "framework"


class PromptComponent(_BaseComponent):
    """A prompt / prompt template. Serializes to type 'data'."""

    kind: Literal["prompt"] = "prompt"


class ServiceComponent(_BaseComponent):
    """An AI service / API endpoint. Serializes to type 'application'."""

    kind: Literal["service"] = "service"


class InfraComponent(_BaseComponent):
    """Infrastructure (compute/runtime). Serializes to type 'platform'."""

    kind: Literal["infra"] = "infra"


class SecretComponent(_BaseComponent):
    """A discovered secret/key reference. Serializes to type 'data'."""

    kind: Literal["secret"] = "secret"


# --- Expanded shadow-AI taxonomy (thin subclasses; serialize via KIND_TO_CDX) - #


class AgentComponent(_BaseComponent):
    """An autonomous / tool-using AI agent."""

    kind: Literal["agent"] = "agent"


class ToolComponent(_BaseComponent):
    """A tool/function an agent can call."""

    kind: Literal["tool"] = "tool"


class McpServerComponent(_BaseComponent):
    """A Model Context Protocol server."""

    kind: Literal["mcp_server"] = "mcp_server"


class McpClientComponent(_BaseComponent):
    """A Model Context Protocol client."""

    kind: Literal["mcp_client"] = "mcp_client"


class GuardrailComponent(_BaseComponent):
    """A safety / content guardrail."""

    kind: Literal["guardrail"] = "guardrail"


class OrchestratorComponent(_BaseComponent):
    """An agent/workflow orchestrator (the imaging 'traffic cop')."""

    kind: Literal["orchestrator"] = "orchestrator"


class PluginComponent(_BaseComponent):
    """A plugin / extension."""

    kind: Literal["plugin"] = "plugin"


class VectorStoreComponent(_BaseComponent):
    """A vector store / index (Chroma, pgvector, …)."""

    kind: Literal["vector_store"] = "vector_store"


class KnowledgeBaseComponent(_BaseComponent):
    """A RAG knowledge base / corpus."""

    kind: Literal["knowledge_base"] = "knowledge_base"


class RetrieverComponent(_BaseComponent):
    """A retriever."""

    kind: Literal["retriever"] = "retriever"


class RerankerComponent(_BaseComponent):
    """A reranker."""

    kind: Literal["reranker"] = "reranker"


class EmbeddingModelComponent(_BaseComponent):
    """An embedding model."""

    kind: Literal["embedding_model"] = "embedding_model"


class NotebookComponent(_BaseComponent):
    """A discovered notebook (.ipynb)."""

    kind: Literal["notebook"] = "notebook"


class ContainerComponent(_BaseComponent):
    """A container image / runtime (Ollama, vLLM, Triton, …)."""

    kind: Literal["container"] = "container"


class CloudServiceComponent(_BaseComponent):
    """A cloud AI service (Bedrock, SageMaker, Vertex, Azure OpenAI, …)."""

    kind: Literal["cloud_service"] = "cloud_service"


class EndpointComponent(_BaseComponent):
    """A network AI endpoint (api.openai.com, localhost:11434, …)."""

    kind: Literal["endpoint"] = "endpoint"


class RegistryComponent(_BaseComponent):
    """A model registry / hub."""

    kind: Literal["registry"] = "registry"


class PipelineComponent(_BaseComponent):
    """An ML / inference pipeline."""

    kind: Literal["pipeline"] = "pipeline"


class FineTuningComponent(_BaseComponent):
    """A fine-tuning job / artifact."""

    kind: Literal["fine_tuning"] = "fine_tuning"


class EvaluationComponent(_BaseComponent):
    """An evaluation / benchmark artifact."""

    kind: Literal["evaluation"] = "evaluation"


AIComponent = Annotated[
    ModelComponent
    | DatasetComponent
    | FrameworkComponent
    | PromptComponent
    | ServiceComponent
    | InfraComponent
    | SecretComponent
    | AgentComponent
    | ToolComponent
    | McpServerComponent
    | McpClientComponent
    | GuardrailComponent
    | OrchestratorComponent
    | PluginComponent
    | VectorStoreComponent
    | KnowledgeBaseComponent
    | RetrieverComponent
    | RerankerComponent
    | EmbeddingModelComponent
    | NotebookComponent
    | ContainerComponent
    | CloudServiceComponent
    | EndpointComponent
    | RegistryComponent
    | PipelineComponent
    | FineTuningComponent
    | EvaluationComponent,
    Field(discriminator="kind"),
]
"""Discriminated union over ``kind``. Use to validate heterogeneous inventories."""


# kind -> CycloneDX component ``type`` (one place; no per-kind special-casing, D4).
KIND_TO_CDX: dict[str, str] = {
    "model": "machine-learning-model",
    "dataset": "data",
    "framework": "library",
    "prompt": "data",
    "service": "application",
    "infra": "platform",
    "secret": "data",
    "agent": "application",
    "tool": "application",
    "mcp_server": "application",
    "mcp_client": "application",
    "guardrail": "application",
    "orchestrator": "application",
    "plugin": "application",
    "vector_store": "data",
    "knowledge_base": "data",
    "retriever": "application",
    "reranker": "application",
    "embedding_model": "machine-learning-model",
    "notebook": "file",
    "container": "container",
    "cloud_service": "application",
    "endpoint": "application",
    "registry": "application",
    "pipeline": "application",
    "fine_tuning": "data",
    "evaluation": "data",
}


def is_deidentified(ds: DatasetComponent) -> bool:
    """Whether a dataset is de-identified, from STRUCTURED fields only.

    The single canonical predicate shared by the scanner (DATASET_NO_DEIDENT
    flag) and the compliance checks (EU AIV-2, HIPAA-2). De-identification is
    asserted via the explicit presence flag or a recorded anonymization method,
    NEVER inferred from free text (which false-negates on negation and
    false-positives on unrelated mentions) — so the HIPAA gate fails closed.
    """
    if ds.has_sensitive_personal_information == "no":
        return True
    if ds.has_sensitive_personal_information == "yes":
        return False
    return bool(ds.anonymization_method)


# --------------------------------------------------------------------------- #
# BOM-level assembly
# --------------------------------------------------------------------------- #


class MetadataComponent(BaseModel):
    """The subject of the BOM (CycloneDX ``metadata.component``).

    Typically the deployed SaMD application the inventory describes. The full
    scan output (components + edges + flags + scores) lives in
    :class:`aibom.model.result.ScanResult`.
    """

    model_config = ConfigDict(extra="forbid")

    type: str = Field(
        default="application",
        description="CycloneDX component type for the BOM subject.",
    )
    name: str
    version: str | None = None


__all__ = [
    "ComponentKind",
    "Hash",
    "ExternalReference",
    "PerformanceMetric",
    "EthicalConsideration",
    "FairnessAssessment",
    "Considerations",
    "PedigreeAncestor",
    "ModelCard",
    "ModelComponent",
    "DatasetComponent",
    "FrameworkComponent",
    "PromptComponent",
    "ServiceComponent",
    "InfraComponent",
    "SecretComponent",
    "AgentComponent",
    "ToolComponent",
    "McpServerComponent",
    "McpClientComponent",
    "GuardrailComponent",
    "OrchestratorComponent",
    "PluginComponent",
    "VectorStoreComponent",
    "KnowledgeBaseComponent",
    "RetrieverComponent",
    "RerankerComponent",
    "EmbeddingModelComponent",
    "NotebookComponent",
    "ContainerComponent",
    "CloudServiceComponent",
    "EndpointComponent",
    "RegistryComponent",
    "PipelineComponent",
    "FineTuningComponent",
    "EvaluationComponent",
    "AIComponent",
    "MetadataComponent",
    "KIND_TO_CDX",
    "is_deidentified",
]
