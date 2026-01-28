from helpers.tools.sca_sbom_agent.parser import parse_sbom_results_to_strings
import json
from rich.console import Console
from langchain.text_splitter import CharacterTextSplitter
from langchain.schema import Document
console = Console()


if __name__ == "__main__":
    try:
        with open("C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\worker\\misc\\sbom_results_testing.json", "r") as f:
            results = json.load(f)
        strings = parse_sbom_results_to_strings(results)
        
        # for index,string in enumerate[str](strings):
            
        #     if index%2==0:
        #         console.print(string,style="bold orange1")
        #     else:
        #         console.print(string,style="bold blue1")
        #     console.print("=="*50,style="bold bright_cyan")
        
        console.print(f"Length of strings: {len(strings)}",style="bold bright_cyan")
        

        #combining 10 findings into a single string and append ad document to the docs list
        docs = []
        for i in range(0,len(strings),10):
            concatenated_strings = " ".join(strings[i:i+10])
            document = Document(page_content=concatenated_strings)
            docs.append(document)

        console.print(f"Length of docs: {len(docs)}",style="bold bright_cyan")
        for index,doc in enumerate(docs):
            console.print(f"Doc # {index + 1} length : {len(doc.page_content)}",style="bold bright_cyan")
            if index%2==0:
                console.print(doc.page_content,style="bold orange1")
            else:
                console.print(doc.page_content,style="bold blue1")
            console.print("=="*50,style="bold bright_cyan")

    except Exception as e:
        console.print(f"Error: {e}",style="bold red")