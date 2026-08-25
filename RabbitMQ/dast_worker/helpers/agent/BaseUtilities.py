
import json
import os
from dotenv import load_dotenv
from langsmith import traceable
from rich.console import Console
from pydantic import BaseModel
from helpers.agent.BaseSummaryManager import BaseSummaryManager
from langchain_aws import ChatBedrock
import base64
from langchain_core.output_parsers import BaseOutputParser
from langchain_core.prompts import PromptTemplate
from dotenv import load_dotenv
from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, SystemMessage

load_dotenv()
console = Console(markup=False)


class _JsonSchemaOutputParser(BaseOutputParser):
    """Parse Bedrock text into a Pydantic model; fuzzy-fix enum mismatches (scan-worker parity)."""

    output_model: type[BaseModel]

    @staticmethod
    def _best_enum_match(value: str, allowed: list[str]) -> str | None:
        if value in allowed:
            return value

        def _norm(s: str) -> str:
            return "".join(c.lower() for c in s if c.isalnum() or c == " ").strip()

        norm_value = _norm(value)
        for candidate in allowed:
            if _norm(candidate) == norm_value:
                return candidate
        return None

    def _get_enum_allowed_values(self, loc: tuple) -> list[str]:
        try:
            schema = self.output_model.model_json_schema()
            defs = schema.get("$defs", {})
            current = schema
            for key in loc:
                if isinstance(key, int):
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
            if "enum" in current:
                return [str(v) for v in current["enum"]]
        except Exception:
            pass
        return []

    def _fix_enum_errors(self, payload: dict, errors) -> dict:
        import copy
        from collections import defaultdict

        fixed = copy.deepcopy(payload)
        items_to_remove = []
        for error in errors:
            if error["type"] != "enum":
                continue
            loc = error["loc"]
            allowed = self._get_enum_allowed_values(loc)
            if not allowed:
                ctx = error.get("ctx", {})
                expected = ctx.get("expected", "")
                for part in str(expected).split("'"):
                    part = part.strip().rstrip(",").strip()
                    if part and part not in (",", "or", ""):
                        allowed.append(part)
            if not allowed:
                continue
            obj = fixed
            for key in loc[:-1]:
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
                items_to_remove.append((obj, last_key))
        removals_by_parent: dict[int, list[int]] = defaultdict(list)
        parent_refs = {}
        for parent_obj, idx in items_to_remove:
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
        content = text if isinstance(text, str) else getattr(text, "content", str(text))
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict) and "text" in item:
                    parts.append(str(item["text"]))
            content = "\n".join(parts)
        if "<reasoning>" in content and "</reasoning>" in content:
            content = content.split("</reasoning>", 1)[-1].strip()
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("JSON object not found in model response")
        payload = json.loads(content[start : end + 1])
        try:
            return self.output_model.model_validate(payload)
        except Exception as first_err:
            from pydantic import ValidationError
            if isinstance(first_err, ValidationError):
                fixed_payload = self._fix_enum_errors(payload, first_err.errors())
                try:
                    return self.output_model.model_validate(fixed_payload)
                except Exception:
                    pass
            raise first_err


def _build_structured_chain(base_llm, output_model: type[BaseModel]):
    from langchain_core.runnables import RunnableLambda

    schema_json = json.dumps(output_model.model_json_schema())

    def _inject_schema(input_value):
        if hasattr(input_value, "to_messages"):
            messages = list(input_value.to_messages())
        elif isinstance(input_value, list):
            messages = list(input_value)
        elif isinstance(input_value, str):
            messages = [HumanMessage(content=input_value)]
        else:
            messages = [HumanMessage(content=str(input_value))]
        messages.append(
            SystemMessage(
                content=(
                    "You MUST return ONLY valid JSON (no extra text, no markdown fences) "
                    f"strictly following this schema:\n{schema_json}"
                )
            )
        )
        return messages

    return RunnableLambda(_inject_schema) | base_llm | _JsonSchemaOutputParser(output_model=output_model)


class BaseUtilities:
    """
    ### Contains utilities like 
    - generate_structured_response
    - generate_map_reduce_summary
    - get_llm
    """
    tracing : bool = True 
    llm_timeout: int = 60*10 # 10 minutes

    def __init__(
        self,
        documents: list[Document] = None,
    ):
        self.documents = documents
    

    
    
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
                    model_kwargs={"top_p": 1},
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
                    model_kwargs={"top_p": 1},
                )
                console.print("Unstructured Bedrock LLM fetched successfully", style="dim green")
            
            return llm
        except Exception as e:
            raise ValueError(f"Error in getting LLM: {e}")
    
    

    def generate_structured_response(
        self, 
        prompt: str,
        system_prompt: str,
        output_model: type[BaseModel],
        image: bytes = None,
        llm_model: str = "openai.gpt-oss-120b-1:0",
    ) -> type[BaseModel] | str:
        try:
            llm = self.get_llm(model=llm_model, temperature=0.0, output_model=output_model)

            console.print("Generating Structured response .... ", style="bold bright_yellow")

            if image:
                console.print("Image input Detected", style="bright_cyan")
                image_data = base64.b64encode(image).decode("ascii")
                user_prompt = (
                    f"{prompt}\n\n"
                    "Use the following base64 image payload as supporting evidence while answering:\n"
                    f"{image_data}"
                )
            else:
                console.print("Pure Text input Detected", style="bright_cyan")
                user_prompt = prompt

            response = llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)])
            return response
        except Exception as e:
            console.print(f"Error: {e}",style="bold red")
            raise e
    

    @traceable
    def generate_map_reduce_summary(
        self,
        summary_manager: BaseSummaryManager,
    )->type[BaseModel] | str:
        """
        Responsible for generating a map reduce summary of documents, based on the specified prompt
        Requires : self.documents to be set
        """
        try:

            # STEP [ 1 ] ----------------> Extract required utils from summary manager class and validation --------------------------
            
            refine_prompt_string = summary_manager.refine_prompt_string
            map_prompt_string = summary_manager.map_prompt_string
            combine_prompt_string = summary_manager.combine_prompt_string
            summary_output_model : type[BaseModel] = summary_manager.summary_output_model
            summary_starting_string = summary_manager.summary_starting_string



            

            # STEP [ 2 ] ----------------> Validation and fallback prompts--------------------------------- --------------------------
            
            if not self.documents:
                console.print("No documents to summarize; returning empty vulnerability list", style="dim yellow")
                return summary_output_model(vulnerabilities=[])
            if not refine_prompt_string or not map_prompt_string or not combine_prompt_string:
                console.print(f"Combine prompt string or map prompt string is not set. Therfore using fallback prompts",style="dim yellow")
                refine_prompt_string = "Refine the given summary to make it more coherent and detailed:\n\nThe existing summary that needs to be refined is  :\n {summary} \n\n\nHere is the new content that must be used to refine the existing summary : {text}"
                map_prompt_string = "Summarize this content:\n\n{text}"
                combine_prompt_string = "Create a coherent summary of the logical components of the codebase from the given summaries {text}"
            if not summary_starting_string:
                console.print(f"Summary starting string is not set. Therefore using fallback starting string",style="dim yellow")
                summary_starting_string = "Logical Components Identified in the codebase are as follows : \n\n"




            # STEP [ 3 ] ----------------> Setting up map , combine and refine chains--------------------------------- --------------------------
            
            map_prompt_template = map_prompt_string 
            map_prompt = PromptTemplate( input_variables=["text"], template=map_prompt_template )
            map_chain = map_prompt | self.get_llm( output_model=summary_output_model )

            refine_prompt_template = refine_prompt_string 
            refine_prompt = PromptTemplate(input_variables=["text","summary"],template=refine_prompt_template)
            refine_chain = refine_prompt | self.get_llm(output_model=summary_output_model)

            combine_prompt_template = combine_prompt_string
            combine_prompt = PromptTemplate(input_variables=["text"],template=combine_prompt_template)
            combine_chain = combine_prompt | self.get_llm(output_model=summary_output_model)






            # STEP [ 4 ] ----------------> Mapping ( each document is mapped to a summary )--------------------------------- --------------------------
            
            map_results = []
            console.print(f"Mapping length of documents {len(self.documents)}",style="dim yellow")
            for i in range(0, len(self.documents), 10): # summarizing 10 documents at a time
                documents_batch = self.documents[i:i+10]
                documents_data = summary_manager.format_documents_to_string( documents=documents_batch )

                # for testing 
                # documents_for_ingestion = { "documents_data": documents_data }
                # with open(f"logging_stuff_ingestion_{i}.json", "w+") as f:
                #     json.dump(documents_for_ingestion, f, indent=4)

                console.print(f"Documents data length before summarizing {len(documents_data)}",style="dim bright_cyan")
                map_chain_response = map_chain.invoke({"text": documents_data})
                documents_summary = summary_manager.format_to_string( input=map_chain_response )

                console.print(f"Map Summary for Documents {i} to {i+10} .  Content length of map summary: {len(documents_summary)}",style="dim bright_cyan")

                # for testing 
                # logging_stuff = { "documents_summary": documents_summary }
                # with open(f"logging_stuff_map_{i}.json", "w+") as f:
                #     json.dump(logging_stuff, f, indent=4)

                map_results.append(documents_summary)       





            # STEP [ 5 ] ----------------> Reducing ( the summaries are reduced to a single summary 10 at a time )-------------------------------------------------------------
            
            
            # =========================== if the map results has only 1 item , then skip summarization and return that one map result =========================================
            if len(map_results)==1 : 
                console.print("Skipping Combine and Refine steps as there is only 1 Map summary result .", style="dim yellow")
                return map_chain_response
            
            
            # =================================== Creating initial summary that will be refined ===================================
            console.print(f"Map results length : {len(map_results)}",style="dim yellow")
            console.print(f"Initial Summary : Combining first batch (upto 10 ) map results",style="dim yellow")
            combine_chain_response = combine_chain.invoke({"text": "\n\n".join(map_results[:10])})
            summary_to_be_refined = summary_manager.format_to_string( input=combine_chain_response )

            
            # ========================================= Refining the initial summary by 10 summaries at a time ===================================
            if len(map_results) > 10:
                for i in range(10, len(map_results), 10):
                    summaries_concatenated = "\n\n".join(map_results[i:i+10])

                    # for testing 
                    # logging_stuff = { "summaries_concatenated": summaries_concatenated, "summary_to_be_refined": summary_to_be_refined }
                    # with open(f"logging_stuff_refine_{i}.json", "w+") as f:
                    #     json.dump(logging_stuff, f, indent=4)
                    

                    refine_chain_response = refine_chain.invoke({"text": summaries_concatenated, "summary": summary_to_be_refined})
                    summary_to_be_refined = summary_manager.format_to_string( input=refine_chain_response ) 
                    console.print(f"Refine result for batch {i} to {i+10} .  Content length of refine result: {len(summary_to_be_refined)}",style="dim bright_cyan")
                
                return refine_chain_response
            else:
                # for testing 
                # logging_stuff = { "summary_to_be_refined": summary_to_be_refined }
                # with open("logging_stuff_final.json", "w+") as f:
                #     json.dump(logging_stuff, f, indent=4)

                return combine_chain_response
            
        except Exception as e:
            raise ValueError(f"Error in generating map reduce summary of codebase: {e}")
    
    
    
    
    
    
