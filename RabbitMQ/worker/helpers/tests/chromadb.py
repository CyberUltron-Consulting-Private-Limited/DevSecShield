import os
from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_core.documents.base import Document
from langchain_openai import OpenAIEmbeddings
from rich.console import Console


console = Console()

if __name__ == "__main__":
    
    try:
        load_dotenv()
        OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
        if not OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY not found")
        else:
            pass
        openai_embedding = OpenAIEmbeddings(
            api_key=OPENAI_API_KEY,
        )
        console.print(f"OpenAI embedding model fetched successfully",style="dim green")

        
        vector_store = Chroma(
            collection_name="testing_collection",
            embedding_function=openai_embedding,
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