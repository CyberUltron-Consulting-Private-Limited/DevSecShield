# AI-BOM Benchmark — diff matrix (Ours vs Cisco vs Trusera)

Live runs of three tools on real repos. Misses = (Cisco ∪ Trusera) \ Ours, triaged into TRUE miss vs OSS false-positive (`fp_exclusions.json`). Gate: true-misses = 0 AND our-unique > 0.

| repo | Cisco | Trusera | Ours | true-misses | our-unique | SHA |
|------|------:|--------:|-----:|------------:|-----------:|-----|
| autogen | 0 | 2 | 31 | 0 | 31 | `027ecf0a379b` |
| chroma | 0 | 10 | 28 | 0 | 21 | `207de398a18c` |
| hf-model | 5 | 11 | 19 | 0 | 5 | `1110a243fdf4` |
| langchain | 0 | 25 | 234 | 0 | 221 | `57c83d44bc8a` |
| llama_index | 4 | 9 | 20 | 0 | 13 | `520aa4ec48c0` |
| mcp-servers | 6 | 2 | 14 | 0 | 10 | `7b1170d1da1e` |
| monai | 10 | 1 | 2 | 0 | 2 | `4ba89bd818a4` |
| openai-cookbook | 116 | 15 | 116 | 0 | 68 | `abd1e286b3b9` |
| repo0-synthetic | 7 | 5 | 13 | 0 | 4 | `local-fixtur` |
| tf-bedrock | 1 | 3 | 8 | 0 | 7 | `4b74b7dd5110` |
| transformers-ft | 6 | 1 | 10 | 0 | 7 | `c96378c4136f` |
| **TOTAL** | | | | **0** | **389** | |


**GATE — true-misses == 0:** ✅ PASS (0)
**GATE — our-unique > 0:** ✅ PASS (389)

> ⚠️ missing/failed tool outputs (NOT counted as empty): langchain/cisco

## Per-repo detail

### autogen
- **TRUE misses (0):** none ✅
- OSS-FP excluded (2): `framework:crewai`, `provider:mistral-api-key`
- our-unique (31): `provider:anthropic`, `framework:autogen`, `model:claude-3-5-haiku`, `model:claude-3-5-sonnet`, `model:claude-3-7-sonnet`, `model:claude-3-haiku`, `model:claude-3-opus`, `model:claude-3-sonnet`, `model:claude-4-opus`, `model:claude-4-sonnet`, `model:gemini`, `provider:google`, `model:gpt`, `model:gpt-35`, `model:gpt-4`, `model:gpt-41`, `model:gpt-45`, `model:gpt-4o`, `model:gpt-5`, `library:jsonref`, `model:llama`, `model:llama-4-maverick`, `model:llama-4-scout`, `model:llama3.3`, `provider:meta`, `provider:openai`, `library:opentelemetry-api`, `library:pillow`, `library:protobuf`, `library:pydantic`, `library:typing-extensions`

### chroma
- **TRUE misses (0):** none ✅
- OSS-FP excluded (3): `provider:azure`, `provider:bedrock`, `provider:huggingface`
- our-unique (21): `model:all-minilm-l6-v2`, `model:all-minilm-l6-v2-f32`, `provider:amazon`, `model:amazon.titan-embed-text-v1`, `library:boto3`, `model:embed-english-light-v2.0`, `model:embed-english-v2.0`, `model:embed-multilingual-v2.0`, `model:gemini-embedding-001`, `library:hugging-face-hub`, `library:local-inference-(:8000`, `model:mistral-embed`, `library:ollama-(local`, `framework:onnxruntime`, `provider:sentence-transformers`, `model:text-embedding-3`, `model:text-embedding-3-large`, `model:text-embedding-3-small`, `model:text-embedding-ada-002`, `model:textembedding-gecko`, `library:voyageai`

### hf-model
- **TRUE misses (0):** none ✅
- OSS-FP excluded (1): `provider:huggingface`
- our-unique (5): `model:all-minilm-l6-v2`, `provider:bedrock`, `library:google-vertex-ai`, `framework:torch`, `framework:transformers`

### langchain
- **TRUE misses (0):** none ✅
- OSS-FP excluded (12): `provider:anthropic-api-key`, `framework:crewai`, `provider:huggingface-transformers-model`, `provider:langchain-google-genai`, `provider:langchain-model`, `mcp_server:mcp-server:-docs-langchain`, `mcp_server:mcp-server:-reference-langchain`, `provider:openai-api-key`, `provider:tiktoken`, `provider:together-ai`, `provider:uv-setup-(github-action`, `framework:vllm`
- our-unique (221): `library:aiohttp`, `model:all-mpnet-base-v2`, `provider:amazon`, `model:amazon.titan-embed-text-v1`, `model:amazon.titan-text-express-v1`, `library:anthropic-api`, `library:async-timeout`, `model:bge-base-en`, `model:claude-2`, `model:claude-3-5-haiku`, `model:claude-3-5-haiku-latest`, `model:claude-3-5-sonnet`, `model:claude-3-7-sonnet`, `model:claude-3-7-sonnet-latest`, `model:claude-3-haiku`, `model:claude-3-opus`, `model:claude-3-sonnet`, `model:claude-4`, `model:claude-haiku-4-5`, `model:claude-haiku-latest`, `model:claude-opus`, `model:claude-opus-4`, `model:claude-opus-4-0`, `model:claude-opus-4-1`, `model:claude-opus-4-5`, `model:claude-opus-4-6`, `model:claude-opus-4-7`, `model:claude-opus-4-8`, `model:claude-opus-latest`, `model:claude-sonnet-4`, `model:claude-sonnet-4-0`, `model:claude-sonnet-4-20250514-v1`, `model:claude-sonnet-4-5`, `model:claude-sonnet-4-5-20250929-v1`, `model:claude-sonnet-4-6`, `model:claude-sonnet-latest`, `model:codestral-2508`, `model:codestral-latest`, `model:command-r-08-2024`, `model:command-r-plus`, `model:command-r-plus-08-2024`, `model:embed-english-v2.0`, `model:embed-english-v3.0`, `library:exa-py`, `library:fireworks-ai`, `model:gemini`, `model:gemini-3`, `model:gemini-3-flash-preview`, `model:gemini-3-pro-image`, `model:gemini-3-pro-image-preview`, `model:gemini-embedding-001`, `model:gemini-flash-latest`, `model:gemini-flash-lite-latest`, `model:gemini-pro-latest`, `secret:generic-credential`, `provider:google`, `library:google-vertex-ai`, `model:gpt`, `model:gpt-2`, `model:gpt-3`, `model:gpt-3-legacy`, `model:gpt-35-turbo`, `model:gpt-35-turbo-0125`, `model:gpt-35-turbo-instruct`, `model:gpt-4`, `model:gpt-4-0314`, `model:gpt-4-0613`, `model:gpt-4-32k`, `model:gpt-4-32k-0314`, `model:gpt-4-32k-0613`, `model:gpt-4-turbo`, `model:gpt-4-turbo-preview`, `model:gpt-4o`, `model:gpt-4o-2024-05-13`, `model:gpt-4o-2024-08-06`, `model:gpt-4o-2024-11-20`, `model:gpt-4o-mini`, `model:gpt-4o-mini-2024-07-18`, `model:gpt-4o-mini-search-preview`, `model:gpt-4o-search-preview`, `model:gpt-5`, `model:gpt-5-2025-01-01`, `model:gpt-5-chat`, `model:gpt-5-chat-latest`, `model:gpt-5-codex`, `model:gpt-5-image`, `model:gpt-5-image-mini`, `model:gpt-5-mini`, `model:gpt-5-nano`, `model:gpt-5-pro`, `model:gpt-5-pro-2025-10-06`, `model:gpt-5-turbo`, `model:gpt-audio`, `model:gpt-audio-mini`, `model:gpt-image`, `model:gpt-image-1`, `model:gpt-image-1-mini`, `model:gpt-image-2`, `model:gpt-oss`, `model:gpt-oss-120b`, `model:gpt-oss-20b`, `model:gpt-oss-safeguard-20b`, `provider:groq`, `library:httpx`, `library:httpx-sse`, `library:hugging-face-hub`, `library:jsonpatch`, `library:langchain-chroma`, `library:langchain-classic`, `library:langchain-deepseek`, `library:langchain-exa`, `library:langchain-fireworks`, `library:langchain-groq`, `library:langchain-huggingface`, `library:langchain-mistralai`, `library:langchain-model-profiles`, `library:langchain-nomic`, `library:langchain-ollama`, `library:langchain-openrouter`, `library:langchain-perplexity`, `library:langchain-protocol`, `library:langchain-qdrant`, `library:langchain-tests`, `library:langchain-text-splitters`, `library:langchain-xai`, `library:langsmith`, `model:llama`, `model:llama-2-7b-chat-hf`, `model:llama-3-8b-instruct`, `model:llama-4-maverick`, `model:llama-4-scout`, `model:llama-4-scout-17b-16e-instruct`, `model:llama3`, `model:llama3.1`, `model:llama3.2`, `model:llama4`, `library:local-inference-(:8000`, `library:mistral-api`, `model:mistral-compatible`, `model:mistral-embed`, `model:mistral-large`, `model:mistral-large-2407`, `model:mistral-large-2411`, `model:mistral-large-2512`, `model:mistral-large-latest`, `model:mistral-medium`, `model:mistral-medium-2505`, `model:mistral-medium-2508`, `model:mistral-medium-2604`, `model:mistral-medium-3`, `model:mistral-medium-3-5`, `model:mistral-medium-latest`, `model:mistral-nemo`, `model:mistral-nemo-base-2407`, `model:mistral-saba`, `model:mistral-small`, `model:mistral-small-24b-instruct-2501`, `model:mistral-small-2506`, `model:mistral-small-2603`, `model:mistral-small-latest`, `model:mistral-small3.1`, `model:mistral-small3.2`, `model:mistral-specific`, `model:mixtral-8x22b-instruct`, `model:mixtral-8x7b`, `model:mixtral-8x7b-32768`, `model:mixtral-8x7b-instruct`, `model:mixtral-8x7b-v0.1`, `provider:nomic`, `model:nomic-embed-text-v1`, `model:nomic-embed-text-v1.5`, `model:nova-lite-v1`, `model:nova-micro-v1`, `model:nova-premier-v1`, `model:nova-pro-v1`, `library:numpy`, `model:o1-pro`, `model:o3-deep-research`, `model:o3-mini`, `model:o3-mini-high`, `model:o3-pro`, `model:o4-mini`, `model:o4-mini-deep-research`, `model:o4-mini-high`, `library:ollama-(local`, `secret:openai-api-key`, `library:openrouter`, `library:packaging`, `library:perplexityai`, `library:pillow`, `library:pydantic`, `library:pytest`, `library:pytest-asyncio`, `library:pytest-benchmark`, `library:pytest-codspeed`, `library:pytest-recording`, `library:pytest-socket`, `library:pyyaml`, `library:requests`, `framework:spacy`, `library:sqlalchemy`, `library:syrupy`, `library:tenacity`, `model:text-ada-001`, `model:text-babbage-001`, `model:text-curie-001`, `model:text-davinci-002`, `model:text-davinci-003`, `model:text-embedding-3`, `model:text-embedding-3-large`, `model:text-embedding-3-small`, `model:text-embedding-ada-002`, `model:text-embedding-gecko`, `model:text-embedding-large`, `library:tiktoken`, `framework:tokenizers`, `library:tomli`, `framework:torch`, `library:typing-extensions`, `library:uuid-utils`, `library:vcrpy`

### llama_index
- **TRUE misses (0):** none ✅
- OSS-FP excluded (6): `model:cohere-api-key`, `framework:crewai`, `provider:huggingface`, `secret:llama-cloud-api-key`, `model:span-marker-mbert-base-multinerd`, `framework:vllm`
- our-unique (13): `provider:azure`, `library:boto3`, `library:google-vertex-ai`, `model:gpt-3`, `framework:haystack`, `model:llama3`, `library:sagemaker`, `provider:sentence-transformers`, `framework:spacy`, `model:text-embedding-ada-002`, `library:tiktoken`, `framework:torch`, `framework:transformers`

### mcp-servers
- **TRUE misses (0):** none ✅
- OSS-FP excluded (3): `framework:crewai`, `mcp_server:mcp-"everything"-server---development-guidelines`, `dataset:sdk`
- our-unique (10): `library:click`, `library:gitpython`, `library:httpx`, `library:markdownify`, `library:protego`, `library:pydantic`, `library:readabilipy`, `library:requests`, `library:tzdata`, `library:tzlocal`

### monai
- **TRUE misses (0):** none ✅
- OSS-FP excluded (11): `dataset:experiment-tracker`, `dataset:fl-best-model`, `dataset:fl-final-model`, `provider:huggingface`, `dataset:hyperparameter:batch-size`, `dataset:hyperparameter:dropout`, `dataset:hyperparameter:num-epochs`, `dataset:hyperparameter:warmup-steps`, `dataset:hyperparameter:weight-decay`, `model_file:model.pt`, `secret:ngc-api-key`
- our-unique (2): `library:hugging-face-hub`, `framework:torch`

### openai-cookbook
- **TRUE misses (0):** none ✅
- OSS-FP excluded (82): `dataset:-m`, `secret:-openai-api-key`, `dataset:ag-news-samples.csv`, `dataset:amazon-furniture-dataset.csv`, `secret:api-key`, `secret:azure-openai-api-key`, `dataset:babbage-002`, `provider:boto3`, `secret:braintrust-api-key`, `secret:cloudflare-sandbox-api-key`, `dataset:code-migration-agent`, `dataset:cookbook-recipes-nlg-10k.csv`, `framework:crewai`, `secret:cse-id`, `dataset:customer-service-synthetic.csv`, `dataset:dall-e-3`, `dataset:dataset.csv`, `dataset:dbpedia-samples.jsonl`, `dataset:drone-training.jsonl`, `secret:embeddings-model`, `secret:env-secret-livekit-api-key`, `secret:env-secret-openai-api-key`, `secret:env-secret-react-app-openai-api-key`, `dataset:eval-labels.jsonl`, `dataset:example-requests-to-parallel-process.jsonl`, `dataset:experiment-tracker`, `dataset:fine-food-reviews-1k.csv`, `dataset:fine-food-reviews-with-embeddings-1k.csv`, `model:ft:gpt-4o-2024-08-06:openai::aoy1m8vg`, `model:gpt-4o-2024-11-20`, `dataset:guardrail-test-data.jsonl`, `dataset:helpcenter-articles.csv`, `dataset:hyperparameter:batch-size`, `dataset:hyperparameter:learning-rate`, `dataset:imdb-top-1000.csv`, `dataset:input-guardrail-test-data.jsonl`, `dataset:items-tagged-and-captioned-embeddings.csv`, `dataset:items-tagged-and-captioned.csv`, `dataset:judgement-summary.csv`, `dataset:labelled-transactions.csv`, `dataset:library-transactions-with-embeddings-359.csv`, `dataset:main-mcp-server`, `dataset:main-mcp-tooling`, `dataset:marketing-sample-for-amazon-com-ecommerce--20200101-20200131--10k-data.csv`, `dataset:o3`, `dataset:omni-moderation-latest`, `secret:openai-agents-disable-tracing`, `secret:openai-build-hour-key`, `provider:openai-endpoint`, `provider:openai-model`, `model:openai.gpt`, `dataset:parsed-pdf-docs-with-embeddings.csv`, `secret:pinecone-api-key`, `secret:project-id`, `secret:qdrant-api-key`, `secret:qdrant-url`, `vector_store:redis`, `dataset:results-failsafeqa-baseline.csv`, `dataset:results-failsafeqa-optimized.csv`, `dataset:run-results-topk-baseline.csv`, `dataset:run-results-topk-optimized.csv`, `dataset:sample-styles-with-embeddings.csv`, `dataset:sample-styles.csv`, `dataset:scifact-claims.jsonl`, `dataset:scifact-corpus.jsonl`, `dataset:search-server`, `dataset:search-server-mcp-tooling`, `dataset:simulations.csv`, `dataset:snli`, `secret:stripe-secret-key`, `dataset:styles-2k.csv`, `dataset:styles-44k.csv`, `dataset:text-davinci-003`, `provider:tiktoken`, `dataset:toy-chat-fine-tuning.jsonl`, `dataset:trace-results.jsonl`, `dataset:traffic-accidents.csv`, `dataset:tts-1-hd`, `model:winemag-data-130k-v2.csv`, `dataset:winter-olympics-2022.csv`, `dataset:yahoo-finance-server-mcp-tooling`, `dataset:yfinance`
- our-unique (68): `library:agents-sdk-deployment-manager`, `provider:anthropic`, `library:boto3`, `model:claude`, `model:dall-e-2`, `model:dall-e-3`, `model:davinci-instruct`, `vector_store:faiss`, `library:flask`, `secret:generic-credential`, `provider:google`, `model:gpt-2`, `model:gpt-3`, `model:gpt-3-5-turbo`, `model:gpt-3-5-turbo-fine-tuning-and-api-updates`, `model:gpt-3-encoder`, `model:gpt-3-encoder-php`, `model:gpt-35-turbo`, `model:gpt-35-turbo-0613`, `model:gpt-4-0125-preview`, `model:gpt-4-0314`, `model:gpt-4-1106-vision-preview`, `model:gpt-4-32k`, `model:gpt-4-32k-0314`, `model:gpt-4-32k-0613`, `model:gpt-4-api-general-availability`, `model:gpt-4-langchain-docs`, `model:gpt-4-turbo-2024-04-09`, `model:gpt-4-turbo-and-gpt-4`, `model:gpt-4-vision`, `model:gpt-4o-2024-05-13`, `model:gpt-4o-costs`, `model:gpt-4o-mini-realtime-preview`, `model:gpt-4o-realtime-preview`, `model:gpt-4o-realtime-preview-2024-12-17`, `model:gpt-4v`, `model:gpt-5-1-for-developers`, `model:gpt-5-class`, `model:gpt-5-nano`, `model:gpt-5-series`, `model:gpt-audio`, `model:gpt-image-1-mini`, `model:gpt-realtime-2`, `model:gpt-realtime-mini`, `library:instructor`, `library:matplotlib`, `vector_store:milvus`, `model:o1-mini`, `model:o3-2025-04-16`, `model:o4-mini-2025-04-16-data-sharing`, `model:o4-mini-deep-research-alpha`, `model:o4-mini-medium-simple-prompt`, `library:pandas`, `library:pydantic`, `library:python-dotenv`, `library:realtime-evals`, `library:seaborn`, `provider:sentence-transformers`, `model:text-ada-001`, `model:text-babbage-001`, `model:text-curie-001`, `model:text-davinci-001`, `model:text-davinci-002`, `model:text-davinci-003`, `model:text-embedding-ada002`, `library:tiktoken`, `framework:torch`, `library:yfinance`

### repo0-synthetic
- **TRUE misses (0):** none ✅
- OSS-FP excluded (1): `secret:anthropic-api-key`
- our-unique (4): `library:numpy`, `secret:openai-api-key`, `library:pydantic`, `library:requests`

### tf-bedrock
- **TRUE misses (0):** none ✅
- OSS-FP excluded (3): `provider:aws-bedrock-custom-model.custom-model`, `provider:aws-bedrockagent-agent-alias.bedrock-agent-alias`, `provider:aws-bedrockagent-agent.agent-supervisor`
- our-unique (7): `provider:amazon`, `model:amazon.titan-embed-text-v2`, `provider:anthropic`, `provider:bedrock`, `model:claude-3-5-sonnet-20241022-v2`, `model:claude-3-7-sonnet-20250219-v1`, `model:claude-3-sonnet-20240229-v1`

### transformers-ft
- **TRUE misses (0):** none ✅
- OSS-FP excluded (4): `dataset:evaluate`, `dataset:hyperparameter:batch-size`, `dataset:hyperparameter:gradient-accumulation-steps`, `dataset:hyperparameter:max-seq-length`
- our-unique (7): `library:evaluate`, `library:hugging-face-hub`, `library:protobuf`, `framework:scikit-learn`, `library:scipy`, `framework:sentencepiece`, `framework:transformers`
