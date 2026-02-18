from langchain_community.document_loaders import DirectoryLoader
from langchain_community.document_loaders import TextLoader
from langchain_community.docstore.document import Document



def load_dir_to_documents(dir_path: str) -> list[Document]:
    loader = DirectoryLoader(f"{dir_path}/", glob="**/*.md", loader_cls=TextLoader, show_progress=True)
    documents = loader.load()

    print(f"Number of Documents: {len(documents)}")

    # for idx, document in enumerate(documents, start=1):
    #     print(f"\nDocument {idx}")
    #     print("Content:\n", document.page_content)
    #     print("Metadata:\n", document.metadata)

if __name__ == "__main__":
    load_dir_to_documents("markdown_output")