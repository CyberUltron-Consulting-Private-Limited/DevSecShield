
from pprint import pprint
from rich.console import Console
from langchain_community.document_loaders.generic import GenericLoader
from helpers.context.custom_language_parser import LanguageParser
from helpers.context.codebase_context import file_path_matches_pattern, CodebaseContext
from pathlib import Path
import os
from dotenv import load_dotenv
from langchain_aws import ChatBedrock
from langchain.chains.llm import LLMChain
from langchain.prompts import PromptTemplate
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.chains.summarize import load_summarize_chain
from langchain.schema import Document

load_dotenv()

console = Console()


def test_loader(
    repo_path:str,
    exclude_path_arrays:list[list[str]],
    default_exclude_paths:list[str],
):
    loader = GenericLoader.from_filesystem(
        path=repo_path,
        glob="**/*",
        suffixes=[".py"],
        show_progress=True,
        parser=LanguageParser(),
    )
    iterator = loader.lazy_load()
    docs = []

    documents = []
    default_excluded_count, parsing_error_count , excluded_count = 0,0,0
    for document in iterator:

        # ------------------> Logic where we skip files ( Parsing error or in default exclude paths )
        if "parsing_error" in document.metadata:
            parsing_error_count += 1
            continue # skip the document if it has a parsing error
        if any(path in document.metadata['source'] for path in default_exclude_paths):
            default_excluded_count += 1
            continue # skip the document if it is in the default exclude paths

        # ------------------> Logic where we skip files ( in exclude paths )
        dont_allow_count = 0
        for path_array in exclude_path_arrays:
            if not file_path_matches_pattern(document.metadata['source'] , path_array ):
                dont_allow_count += 1
        if dont_allow_count > 0:
            excluded_count += 1
            continue # skip the document if it is in the exclude paths

        # ------------------> Accept Document 
        documents.append(document)

    console.print(f"{len(documents)} Documents loaded successfully",style="dim green")
    console.print(f"\n Parsing error Count: {parsing_error_count} , Excluded Count: {excluded_count}, default excluded count: {default_excluded_count}",style="dim yellow")
    console.print("Sources: ",style="green")
    unique_sources = list(set([document.metadata['source'] for document in documents]))
    for source in unique_sources:
        console.print(f"    - {source}",style="dim green")
    
    return documents

def testing(
    exclude_path_arrays:list[list[str]],
):
    filepaths = [
        r"C:/Users/HP/Desktop/RiskPilot/frontend/src/components/Dashboard/Table.tsx",
        r"C:/Users/HP/Desktop/RiskPilot/frontend/src/components/Something/Table.tsx",
        r"C:/Users/HP/Desktop/RiskPilot/frontend/haha/components/AAAAA/Table.tsx",
        r"C:/Users/HP/Desktop/RiskPilot/frontend/package.json",
        r"C:/Users/HP/Desktop/RiskPilot/frontend/package-lock.json",
        r"C:/Users/HP/Desktop/RiskPilot/frontend/haha/components/BBB/Table.tsx",
        r"C:/Users/HP/Desktop/RiskPilot/frontend/haha/components/BBB/Table.tsx",
        r"C:/Users/HP/Desktop/RiskPilot/backend/.venv/Scripts/python.exe",
        r"C:/Users/HP/Desktop/RiskPilot/backend/.venv/Scripts/pip.exe",
        r"C:/Users/HP/Desktop/RiskPilot/backend/__pycache__/__init__.py",
        r"C:/Users/HP/Desktop/RiskPilot/backend/__pycache__/__init__.py",
        r"C:/Users/HP/Desktop/RiskPilot/backend/__init__.py",
        r"C:/Users/HP/Desktop/RiskPilot/backend/api_routes/routing_scan.py",
        r"C:/Users/HP/Desktop/RiskPilot/backend/api_routes_and_stuff/routing_scan.py",
        r"C:/Users/HP/Desktop/RiskPilot/testing/api_routes_and_stuff/routing_scan.py",
        r"C:/Users/HP/Desktop/RiskPilot - Copy/backend/llm_scan_utils/llm_scan_utils.py",
    ]

    for filepath in filepaths:

        matches_count = 0
        for path_array in exclude_path_arrays:
            if file_path_matches_pattern(filepath , path_array ):
                matches_count += 1
        if matches_count > 0:
            console.print(f"{filepath} matches the pattern",style="dim green")
        else:
            console.print(f"{filepath} does not match the pattern",style="dim red")

def testing_chain_aws_bedrock(documents:list[Document]):
    load_dotenv()
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.getenv("AWS_DEFAULT_REGION")
    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY or not AWS_REGION:
        raise Exception("AWS credentials not found")
    else:
        pass

    llm = ChatBedrock(
        model="openai.gpt-oss-20b-1:0",
        region=AWS_REGION or "ap-south-1",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )


    # Split text into chunks
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=2000,
        chunk_overlap=100
    )

    # Define custom prompts
    map_prompt = PromptTemplate(
        input_variables=["text"],
        template="Summarize this content:\n{text}"
    )

    combine_prompt = PromptTemplate(
        input_variables=["text"],
        template="Combine these summaries into a coherent summary:\n{text}"
    )

    # Create and run the chain
    chain = load_summarize_chain(
        llm,
        chain_type="map_reduce",
        map_prompt=map_prompt,
        combine_prompt=combine_prompt,
        # verbose=True
    )

    summary = chain.run(documents)



if __name__ == "__main__":
    testing_exclude_path_arrays = [ 
        ["RiskPilot" , "frontend" , "src" , "components" , "Dashboard" , "Table.tsx" ] , 
        [ ".venv" ] ,
        [ "mcpscan_utils"] , 
        [ "normal_scan_utils"] ,
        [ "api_routes"],
        [ "package.json" ],
        [ "package-lock.json" ]
         ]
    # testing_include_path_arrays = [
    #     [ "llm_scan_utils" ],
    #     [ "package-lock.json" ]
    #      ]

    patterns = [
        []
    ]
    
    # repo_path = Path("C:/Users/HP/Desktop/RiskPilot - Copy/backend/")
    # codebase_context = CodebaseContext(
    #     directory=repo_path,
    #     # exclude_path_arrays=testing_exclude_path_arrays,
    #     include_path_arrays=testing_include_path_arrays,
    #     include_files_extensions=[".py"],
    # )
    # documents = codebase_context.load_documents_of_extension(".py")

    # sources = set([document.metadata['source'] for document in documents])
    # for source in sources:
    #     console.print(f"- {source}",style="dim green")
    # metadata = codebase_context.metadata
    # for excluded_document in metadata["excluded_documents"]:
    #     console.print(f"- {excluded_document}",style="dim red")
    # for included_document in metadata["included_documents"]:
    #     console.print(f"- {included_document}",style="dim green")
    
    testing(testing_exclude_path_arrays)
    # documents = test_loader(repo_path, testing_exclude_path_arrays, default_exclude_paths)
    # testing_chain_aws_bedrock(documents)








