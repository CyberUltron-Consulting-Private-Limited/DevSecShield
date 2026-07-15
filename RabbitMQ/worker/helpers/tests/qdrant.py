import os
from dotenv import load_dotenv
from langchain_qdrant import QdrantVectorStore
from langchain_core.documents.base import Document
from langchain_aws import BedrockEmbeddings
from rich.console import Console
from qdrant_client import QdrantClient
from qdrant_client.http.models.models import VectorParams, Distance

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

        #checking if collection exists
        collection_name = "testing_collection"
        client = QdrantClient(url="http://localhost:6333",api_key="qdrantapikey",check_compatibility=False)
        if not client.collection_exists(collection_name):
            console.print(f"Collection {collection_name} does not exist, creating it",style="dim yellow")
            client.create_collection(collection_name=collection_name,
                                     vectors_config=VectorParams(size=1024, distance=Distance.COSINE))
            console.print(f"Collection {collection_name} created successfully",style="dim green")
        else:
            console.print(f"Collection {collection_name} already exists, using it",style="dim green")

        vector_store = QdrantVectorStore(
            collection_name=collection_name,
            embedding=bedrock_embedding,
            client=client,
        )
        console.print(f"Qdrant Vector store object instantiated !",style="dim green")

        doc1 = Document(page_content="The fox was very sly")
        doc2 = Document(page_content="The Fox did not want to take a bath")
        doc3 = Document(page_content="The bird flew very high")
        doc_list = [ doc1, doc2 , doc3]
        
        doc_ids = vector_store.add_documents(doc_list)
        console.print(f"Qdrant Document Ids of docs added : {doc_ids}",style = "bold yellow")

        result = vector_store.similarity_search(k=1,query="fox")
        console.print(f"Qdrant Vector search result : {result}",style="bold green")


    except Exception as e:
        console.print(f"Error occured while testing qdrant : {str(e)}",style="bold red")