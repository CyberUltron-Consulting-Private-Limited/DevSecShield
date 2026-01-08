from pydantic import BaseModel
from langchain_core.documents import Document
from langchain_community.vectorstores import VectorStore
from rich.console import Console
from tools.context.schema import BaseVulnerability
from tools.context.output_model import OutputModelManager

console = Console()

class BaseAgent(OutputModelManager):

    def __init__(self):
        console.print(f"BaseAgent initialized without overriding the __init__ method",style="dim yellow")
        raise NotImplementedError("Subclasses must implement this method")
    
    
    def run_agent(self):
        console.print(f"Running Agent ....",style="dim yellow")
        raise NotImplementedError("Subclasses must implement this method")
    
    
    # TODO : Implement this method
    def generate_response(
        self, 
        prompt: str,
        system_prompt: str,
        output_model: type[BaseModel],
    ) -> type[BaseModel] | str:
        pass
    

    # TODO : Implement this method
    def query_vector_store(
        self,
        vector_store: VectorStore,
        query: str,
        k: int = 10,
    ) -> list[Document]:
        pass

    

if __name__ == "__main__":
    agent = BaseAgent()
    model = agent.get_output_model(BaseVulnerability)
            