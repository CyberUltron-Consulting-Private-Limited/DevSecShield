export const meta = {
  name: 'aibom-bench-triage',
  description: 'Evidence-based per-repo triage of OSS-vs-ours AI-BOM benchmark misses (REAL vs OSS false-positive)',
  phases: [{ title: 'Triage', detail: 'one Explore agent per repo grep-verifies every miss' }],
}

// Per-repo raw misses (Cisco ∪ Trusera) \ Ours — embedded so the run is self-contained.
const REPOS = [
  { id: '00-synthetic', dir: 'bench/repos/00-synthetic/.', misses: [['env:anthropic-api-key','secret'],['langchain','framework']] },
  { id: '01-chroma', dir: 'bench/repos/01-chroma/.', misses: [['ai','library'],['ai instructions','library'],['aws bedrock','model'],['azure openai','model'],['baseten-embedding-model','model'],['chroma codebase guidelines for ai agents','library'],['cohere-ai','library'],['config-model','model'],['crewai','framework'],['custom-model','model'],['dataset','dataset'],['env-secret-jina-api-key','secret'],['env:cohere-api-key','secret'],['env:google-api-key','secret'],['env:huggingface-api-key','secret'],['env:mistral-api-key','secret'],['env:openai-api-key','secret'],['google ai','model'],['google.generativeai','model'],['huggingface transformers','model'],['hyperparameter:batch-size','library'],['instructor-xl','model'],['jina-embeddings-v2-base-code','model'],['langchain','framework'],['large','model'],['model-artifact','library'],['new-model','model'],['ollama','provider'],['text-embeddings-inference)','model'],['together ai','model'],['training-run','library'],['vault-secret','secret'],['voyage-3-large','library']] },
  { id: '02-langchain', dir: 'bench/repos/02-langchain/libs/core', misses: [['anthropic:claude-haiku-4-5-20251001','model'],['crewai','framework'],['huggingface transformers','model'],['langgraph','framework'],['model-name','model'],['openai:gpt-5.5','model'],['runnablesequence','library'],['vllm','model']] },
  { id: '03-llama-index', dir: 'bench/repos/03-llama-index/llama-index-core', misses: [['aws bedrock','model'],['cohere','provider'],['crewai','framework'],['dataset','dataset'],['huggingface transformers','model'],['langchain','framework'],['llamaindex','framework'],['ml-pipeline','library'],['model','model'],['semantic kernel','framework'],['span-marker-mbert-base-multinerd','model'],['training-run','library'],['vllm','model']] },
  { id: '04-autogen', dir: 'bench/repos/04-autogen/python/packages/autogen-core', misses: [['crewai','framework'],['mistral api key','model']] },
  { id: '05-openai-cookbook', dir: 'bench/repos/05-openai-cookbook/examples', misses: [['babbage-002','model'],['boto3','model'],['chromadb','vector_store'],['code migration agent','library'],['crewai','framework'],['dataset','dataset'],['datasets','library'],['fastmcp','library'],['gpt-3.5-turbo','model'],['gpt-4o-2024-11-20','model'],['hyperparameter:batch-size','library'],['langchain','framework'],['llama-index','framework'],['mcp','mcp_server'],['o3','model'],['omni-moderation-latest','model'],['openai-agents','library'],['pinecone','vector_store'],['tiktoken','secret'],['training-run','library'],['transformers','framework'],['tts-1-hd','model'],['yfinance','mcp_server'],['{-m}','model'],['ag-news-samples.csv','dataset'],['winemag-data-130k-v2.csv','dataset']] },
  { id: '06-mcp-servers', dir: 'bench/repos/06-mcp-servers/src', misses: [['crewai','framework'],['mcp everything server - development guidelines','library']] },
  { id: '07-hf-minilm', dir: 'bench/repos/07-hf-minilm/.', misses: [['huggingface transformers','model'],['model-artifact','library'],['training-run','library']] },
  { id: '08-monai', dir: 'bench/repos/08-monai/.', misses: [['dataset','dataset'],['env:ngc-api-key','secret'],['experiment-tracker','library'],['fl-best-model','model'],['huggingface transformers','model'],['hyperparameter:dropout','library'],['model-artifact','library'],['model.pt','model_file'],['training-run','library']] },
  { id: '09-tf-bedrock', dir: 'bench/repos/09-tf-bedrock/.', misses: [['aws-bedrock-custom-model.custom-model','model'],['aws-bedrockagent-agent.agent-supervisor','framework']] },
  { id: '10-trl-sft', dir: 'bench/repos/10-trl-sft/trl', misses: [['crewai','framework'],['dataset','dataset'],['experiment-tracker','library'],['huggingface transformers','model'],['hyperparameter:batch-size','library'],['model-artifact','library'],['model.safetensors','model_file'],['pytorch-model.bin','model_file'],['qwen2.5-0.5b-instruct','model'],['qwen3-0.6b','model'],['vllm','model']] },
]

phase('Triage')

const SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    repo: { type: 'string' },
    real: { type: 'array', items: { type: 'object', additionalProperties: false,
      properties: { name: { type: 'string' }, type_class: { type: 'string' },
        evidence: { type: 'string' }, scanner_gap: { type: 'string' } },
      required: ['name', 'type_class', 'evidence', 'scanner_gap'] } },
    fps: { type: 'array', items: { type: 'object', additionalProperties: false,
      properties: { name: { type: 'string' }, type_class: { type: 'string' },
        category: { type: 'string', enum: ['prose_extraction','doc_heading','hallucination_zero_hits','name_variant','dev_tooling','mislabel','malformed','generic_placeholder','resource_address','env_var_reference','data_file'] },
        reason: { type: 'string' } },
      required: ['name', 'type_class', 'category', 'reason'] } },
  },
  required: ['repo', 'real', 'fps'],
}

const results = await parallel(REPOS.map((r) => () =>
  agent(
    `You are triaging AI-BOM benchmark MISSES for repo "${r.id}", cloned at \`${r.dir}\` (run all commands from the DevSecShield repo root).\n\n` +
    `Two open-source AI-BOM tools (Cisco, Trusera) detected these (normalized_name, type_class) components that OUR tool did NOT:\n` +
    `${JSON.stringify(r.misses)}\n\n` +
    `For EVERY miss, INSPECT the repo at \`${r.dir}\` (grep for the name across code/manifests/notebooks; read the relevant file) and classify it as exactly ONE of:\n` +
    `- REAL: a genuine AI/ML component truly declared/imported/used in THIS repo that an AI-BOM scanner SHOULD detect (e.g. an agent framework imported in code like \`import langchain\`/\`from crewai\`, a provider SDK, a concrete model id passed to an API, a real weight file). Give evidence (file path + grep snippet) + a short scanner_gap label (e.g. code-import, notebook-model-ref, weight-file-subdir).\n` +
    `- OSS_FP: a false positive. Pick a category + reason. Guidance:\n` +
    `  * env_var_reference: a "secret" that is an env-var NAME/reference (env:OPENAI_API_KEY, os.environ[...]) — the SECURE pattern, not a hardcoded literal. Always FP.\n` +
    `  * hallucination_zero_hits: grep the repo; if ZERO real hits the name is OSS regex-noise (Trusera 'crewai' is almost always this).\n` +
    `  * prose_extraction / doc_heading: Cisco lifts README/notebook prose + markdown headings ('AI instructions', '... development guidelines', 'code migration agent').\n` +
    `  * name_variant: our tool detects the SAME thing under a different canonical name (langchain-core vs langchain, 'transformers' vs 'huggingface transformers', llama-index-core vs llamaindex). Say what WE call it.\n` +
    `  * mislabel: real thing, wrong type_class (Trusera tags the transformers LIBRARY as a 'model').\n` +
    `  * dev_tooling: build/test/docs dependency, not AI.\n` +
    `  * generic_placeholder: generic noun, no resolvable identity ('model','dataset','large','custom-model','training-run','model-artifact','experiment-tracker').\n` +
    `  * malformed: truncated/garbled ('text-embeddings-inference)', '{-m}').\n` +
    `  * resource_address: a Terraform resource address (type.local_name).\n` +
    `  * data_file: a raw .csv/.jsonl tutorial data FILE, not a declared/governed dataset.\n\n` +
    `BE SKEPTICAL of Cisco (it massively over-extracts from prose/notebooks) but HONEST: if something is genuinely imported/used and we miss it, it is REAL — do NOT fake-exclude it. Verify with grep before deciding. Cover EVERY miss exactly once.\n` +
    `Return {repo:"${r.id}", real:[...], fps:[...]}.`,
    { schema: SCHEMA, label: `triage:${r.id}`, phase: 'Triage', agentType: 'Explore' },
  ).then((v) => v || { repo: r.id, real: [], fps: [] })
))

return results.filter(Boolean)
