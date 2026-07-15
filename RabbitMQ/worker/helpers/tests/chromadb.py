import os
from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_core.documents.base import Document
from langchain_aws import BedrockEmbeddings
from rich.console import Console


console = Console()

if __name__ == "__main__":
    
    try:
        load_dotenv()
        aws_region = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
        bedrock_embedding = BedrockEmbeddings(
            model_id="amazon.titan-embed-text-v2:0",
            region_name=aws_region,
        )
        console.print("Bedrock embedding model fetched successfully", style="dim green")

        
        vector_store = Chroma(
            collection_name="testing_collection",
            embedding_function=bedrock_embedding,
            host="localhost",
            port=9090,
            # headers={"X_CHROMA_TOKEN" : "new-token"}
        )
        console.print(f"Vector store object instantiated !")

        doc1 = Document(page_content="The fox was very sly")
        doc2 = Document(page_content="The Fox did not want to take a bath")
        doc3 = Document(page_content="The bird flew very high")
        doc_list = [ doc1, doc2 , doc3]
        
        doc_ids = vector_store.add_documents(doc_list)
        console.print(f"Document Ids of docs added : {doc_ids}",style = "bold yellow")

        result = vector_store.similarity_search(k=1,query="fox")
        console.print(f"Vector search result : {result}",style="bold green")


    except Exception as e:
        console.print(f"Error occured while testing chromadb : {str(e)}",style="bold red")