
import os
import json
from dotenv import load_dotenv
from langchain_community.vectorstores import VectorStore
from langchain_core.output_parsers import BaseOutputParser
from langchain_core.globals import set_llm_cache
from langchain_community.cache import SQLiteCache
from rich.console import Console
from pydantic import BaseModel
from langchain_aws import ChatBedrock, BedrockEmbeddings
from qdrant_client import QdrantClient
from qdrant_client.http.models import VectorParams, Distance
from langchain_qdrant import QdrantVectorStore
console = Console()

# Enable LLM response caching — identical prompts return cached results for determinism
_LLM_CACHE_DB = os.path.join(os.environ.get("TMPDIR", "/tmp"), ".devsecshield_llm_cache.db")
set_llm_cache(SQLiteCache(database_path=_LLM_CACHE_DB))
console.print(f"LLM response cache enabled at {_LLM_CACHE_DB}", style="dim green")


class _JsonSchemaOutputParser(BaseOutputParser):
    """Parses LLM text output into a Pydantic model via JSON extraction.
    Includes fuzzy matching for enum values that the LLM may slightly misformat.
    """
    output_model: type[BaseModel]

    @staticmethod
    def _best_enum_match(value: str, allowed: list[str]) -> str | None:
        """Find the closest matching enum value using normalized comparison."""
        # Exact match first
        if value in allowed:
            return value
        # Normalize: lowercase, strip punctuation/dots/dashes, collapse whitespace
        def _norm(s: str) -> str:
            return "".join(c.lower() for c in s if c.isalnum() or c == " ").strip()
        norm_value = _norm(value)
        for candidate in allowed:
            if _norm(candidate) == norm_value:
                return candidate
        return None

    def _get_enum_allowed_values(self, loc: tuple) -> list[str]:
        """Extract allowed enum values from the output model schema for a given error location."""
        try:
            schema = self.output_model.model_json_schema()
            defs = schema.get("$defs", {})
            # Walk the schema following the location path to find the enum type
            current = schema
            for key in loc:
                if isinstance(key, int):
                    # Array index — schema stays at items level
                    if "items" in current:
                        current = current["items"]
                        if "$ref" in current:
                            ref_name = current["$ref"].split("/")[-1]
                            current = defs.get(ref_name, current)
                    continue
                props = current.get("properties", {})
                if key in props:
                    current = props[key]
                    if "$ref" in current:
                        ref_name = current["$ref"].split("/")[-1]
                        current = defs.get(ref_name, current)
                    elif "items" in current:
                        items = current["items"]
                        if "$ref" in items:
                            ref_name = items["$ref"].split("/")[-1]
                            current = defs.get(ref_name, current)
            # current should now be the enum schema
            if "enum" in current:
                return [str(v) for v in current["enum"]]
        except Exception:
            pass
        return []

    def _fix_enum_errors(self, payload: dict, errors) -> dict:
        """Attempt to fix enum validation errors by fuzzy-matching allowed values."""
        import copy
        fixed = copy.deepcopy(payload)
        # Track list items to remove if unfixable (reverse order for safe removal)
        items_to_remove = []
        for error in errors:
            if error["type"] != "enum":
                continue
            loc = error["loc"]
            # Try to get allowed values from the model schema (reliable)
            allowed = self._get_enum_allowed_values(loc)
            if not allowed:
                # Fallback: parse from error context string
                ctx = error.get("ctx", {})
                expected = ctx.get("expected", "")
                for part in str(expected).split("'"):
                    part = part.strip().rstrip(",").strip()
                    if part and part not in (",", "or", ""):
                        allowed.append(part)
            if not allowed:
                continue
            # Navigate payload to the error location and fix
            obj = fixed
            for i, key in enumerate(loc[:-1]):
                if isinstance(obj, list) and isinstance(key, int):
                    obj = obj[key]
                elif isinstance(obj, dict):
                    obj = obj[key]
            last_key = loc[-1]
            if isinstance(obj, list) and isinstance(last_key, int):
                bad_val = obj[last_key]
            elif isinstance(obj, dict):
                bad_val = obj[last_key]
            else:
                continue
            match = self._best_enum_match(str(bad_val), allowed)
            if match:
                if isinstance(obj, list) and isinstance(last_key, int):
                    obj[last_key] = match
                elif isinstance(obj, dict):
                    obj[last_key] = match
            elif isinstance(obj, list) and isinstance(last_key, int):
                # Mark for removal: unfixable enum value in a list
                items_to_remove.append((loc[:-1], obj, last_key))
        # Remove unfixable list items in reverse index order to avoid shifting
        # Group by parent list object
        from collections import defaultdict
        removals_by_parent: dict[int, list[int]] = defaultdict(list)
        parent_refs = {}
        for parent_loc, parent_obj, idx in items_to_remove:
            obj_id = id(parent_obj)
            removals_by_parent[obj_id].append(idx)
            parent_refs[obj_id] = parent_obj
        for obj_id, indices in removals_by_parent.items():
            parent = parent_refs[obj_id]
            for idx in sorted(indices, reverse=True):
                if idx < len(parent):
                    parent.pop(idx)
        return fixed

    def parse(self, text: str):
        content = text
        # Strip <reasoning>...</reasoning> blocks if present
        if "<reasoning>" in content and "</reasoning>" in content:
            content = content.split("</reasoning>", 1)[-1].strip()
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("JSON object not found in model response")
        payload = json.loads(content[start : end + 1])
        # First attempt: strict validation
        try:
            return self.output_model.model_validate(payload)
        except Exception as first_err:
            # Second attempt: fix enum mismatches
            from pydantic import ValidationError
            if isinstance(first_err, ValidationError):
                fixed_payload = self._fix_enum_errors(payload, first_err.errors())
                try:
                    return self.output_model.model_validate(fixed_payload)
                except Exception:
                    pass
            raise first_err


def _build_structured_chain(base_llm, output_model: type[BaseModel]):
    """Build a chain: inject JSON schema instruction → LLM → parse JSON output."""
    from langchain_core.runnables import RunnableLambda
    from langchain_core.messages import SystemMessage

    schema_json = json.dumps(output_model.model_json_schema())

    def _inject_schema(input_value):
        if hasattr(input_value, "to_messages"):
            messages = list(input_value.to_messages())
        elif isinstance(input_value, list):
            messages = list(input_value)
        elif isinstance(input_value, str):
            from langchain_core.messages import HumanMessage
            messages = [HumanMessage(content=input_value)]
        else:
            from langchain_core.messages import HumanMessage
            messages = [HumanMessage(content=str(input_value))]
        messages.append(
            SystemMessage(content=f"You MUST return ONLY valid JSON (no extra text, no markdown fences) strictly following this schema:\n{schema_json}")
        )
        return messages

    inject = RunnableLambda(_inject_schema)
    parser = _JsonSchemaOutputParser(output_model=output_model)
    return inject | base_llm | parser

EXPECTED_EMBEDDING_DIM = 1024


class BaseUtilities:
    """
    ### Contains utilities like 
    - get_vector_store
    - get_llm
    - get_embedding_model
    """
    tracing : bool = True 
    llm_timeout: int = 60*10 # 10 minutes

    def __init__(self):
        raise NotImplementedError("Subclass must implement this method")
    

    def get_embedding_model(
        self,
        model: str = "amazon.titan-embed-text-v2:0",
    ):
        """
        Responsible for getting Bedrock Embedding model, based on the specified model
        """
        try:
            load_dotenv()
            aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
            aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
            aws_region = os.getenv("AWS_DEFAULT_REGION") or "ap-south-1"

            if not aws_access_key or not aws_secret_key:
                raise ValueError("AWS credentials not found")

            bedrock_embedding = BedrockEmbeddings(
                model_id=model,
                region_name=aws_region,
                credentials_profile_name=None,
            )
            console.print("Bedrock embedding model fetched successfully", style="dim green")
            return bedrock_embedding
        except Exception as e:
            raise ValueError(f"Error in getting embedding model: {e}")
    
    
    def get_aws_bedrock_llm(
        self,
    ):
        """
        Responsible for getting an unstructured LLM that uses AWS Bedrock
        """
        try:
            load_dotenv()
            AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
            AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
            AWS_REGION = os.getenv("AWS_DEFAULT_REGION")
            if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY or not AWS_REGION:
                raise Exception("AWS credentials not found")
            else:
                pass

            model = ChatBedrock(
                model="openai.gpt-oss-120b-1:0",
                region=AWS_REGION or "ap-south-1",
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                temperature=0,
                model_kwargs={"top_p": 1, "top_k": 1},
            )
            console.print(f"Unstructured LLM fetched successfully",style="dim green")
            return model
        except Exception as e:
            raise ValueError(f"Error in getting unstructured LLM: {e}")
    
    
    def get_llm(
        self,
        model: str = "openai.gpt-oss-120b-1:0",
        temperature: float = 0.0,
        max_tokens: int | None = None,
        output_model: type[BaseModel] = None,
        ):
        """
        Responsible for getting Bedrock LLM, based on the specified model, temperature, max_tokens
        """
        try:
            load_dotenv()
            aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
            aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
            aws_region = os.getenv("AWS_DEFAULT_REGION") or "ap-south-1"

            if not aws_access_key or not aws_secret_key:
                raise ValueError("AWS credentials not found")
            
            if output_model:
                base_llm = ChatBedrock(
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    region=aws_region,
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    model_kwargs={"top_p": 1, "top_k": 1},
                )
                try:
                    llm = base_llm.with_structured_output(schema=output_model)
                    console.print("Structured Bedrock LLM fetched successfully (native)", style="dim green")
                except (ValueError, NotImplementedError):
                    llm = _build_structured_chain(base_llm, output_model)
                    console.print("Structured Bedrock LLM fetched successfully (JSON fallback)", style="dim yellow")
            else:
                llm = ChatBedrock(
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    region=aws_region,
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    model_kwargs={"top_p": 1, "top_k": 1},
                )
                console.print("Unstructured Bedrock LLM fetched successfully", style="dim green")
            
            return llm
        except Exception as e:
            raise ValueError(f"Error in getting LLM: {e}")
    
    
    
    def get_vector_store(self, collection_name: str)->VectorStore:
        """
        Responsible for getting the qdrant vector store for the specified collection.
        Handles dimension mismatch by recreating collections configured for old embedding sizes.
        """
        try:
            # getting qdrant client from url and api key 
            load_dotenv()
            is_docker_container = os.getenv("IS_DOCKER_CONTAINER", "False") == "True"
            qdrant_host = os.getenv("QDRANT_HOST", "qdrant" if is_docker_container else "localhost")
            qdrant_port = os.getenv("QDRANT_PORT", "6333" if is_docker_container else "7333")
            qdrant_url = f"http://{qdrant_host}:{qdrant_port}"

            # getting api key from environment variable
            QDRANT_API_KEY = os.getenv("QDRANT_API_KEY")
            if not QDRANT_API_KEY:
                raise ValueError("QDRANT_API_KEY not found")
            else:
                console.print(f"QDRANT_API_KEY is set to {QDRANT_API_KEY[:10]}...",style="dim green")

            qdrant_client = QdrantClient(url=qdrant_url, api_key=QDRANT_API_KEY, check_compatibility=False)

            # Check existing collection dimensions and recreate if mismatched
            if qdrant_client.collection_exists(collection_name):
                collection_info = qdrant_client.get_collection(collection_name)
                existing_dim = None
                vectors_config = collection_info.config.params.vectors
                if isinstance(vectors_config, VectorParams):
                    existing_dim = vectors_config.size
                elif isinstance(vectors_config, dict) and "" in vectors_config:
                    existing_dim = vectors_config[""].size

                if existing_dim and existing_dim != EXPECTED_EMBEDDING_DIM:
                    console.print(
                        f"Collection '{collection_name}' has dimension {existing_dim}, "
                        f"expected {EXPECTED_EMBEDDING_DIM}. Recreating collection.",
                        style="bold yellow",
                    )
                    qdrant_client.delete_collection(collection_name)
                    qdrant_client.create_collection(
                        collection_name=collection_name,
                        vectors_config=VectorParams(
                            size=EXPECTED_EMBEDDING_DIM,
                            distance=Distance.COSINE,
                        ),
                    )
                    console.print(f"Collection '{collection_name}' recreated with {EXPECTED_EMBEDDING_DIM} dimensions.", style="bold green")
            else:
                console.print(f"Collection '{collection_name}' does not exist, creating it.", style="bold yellow")
                qdrant_client.create_collection(
                    collection_name=collection_name,
                    vectors_config=VectorParams(
                        size=EXPECTED_EMBEDDING_DIM,
                        distance=Distance.COSINE,
                    ),
                )
                console.print(f"Collection '{collection_name}' created with {EXPECTED_EMBEDDING_DIM} dimensions.", style="bold green")
            
            
            # getting vector store from collection name , embedding model and qdrant client
            vectorstore = QdrantVectorStore(
                collection_name=collection_name,
                embedding=self.get_embedding_model(),
                client=qdrant_client,
            )

            # returning the vector store
            return vectorstore
        except Exception as e:
            raise ValueError(f"Error in getting vector store: {e}")
    
    
    
    
    
