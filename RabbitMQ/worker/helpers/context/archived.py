
def get_chroma_client(self, dev_environment: bool = True):
    """
    Responsible for getting the chroma client
    """
    try:
        load_dotenv()
        is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
        
        if is_docker_container and is_docker_container == "True":
            chroma_host = "13.203.233.15"
            chroma_port = "9090"
            chroma_url = f"http://{chroma_host}:{chroma_port}"
        elif dev_environment:
            chroma_url = "http://localhost:9090"
        else:
            chroma_host = "13.203.233.15"
            chroma_port = "9090"
            chroma_url = f"http://{chroma_host}:{chroma_port}"

        chroma_client = Chroma(host=chroma_host, port=chroma_port)
        console.print(f"Chroma client fetched successfully",style="dim green")
        return chroma_client

    except Exception as e:
        raise ValueError(f"Error in getting chroma client: {e}")

def get_chroma_vector_store(self, collection_name: str)->VectorStore:
    """
    Responsible for getting the vector store for the specified collection
    """
    try:
        vector_store = Chroma(
            collection_name=collection_name,
            embedding_function=self.get_embedding_model(),
            host="localhost",
            port=9090,
            # headers={"X_CHROMA_TOKEN" : "new-token"}
        )
        console.print(f"Chroma Vector store object instantiated !",style="dim green")
        return vector_store
    except Exception as e:
        raise ValueError(f"Error in getting chroma vector store: {e}")

def get_mongo_client_db(self, dev_environment: bool = True):
    """
    Responsible for getting the mongo client for Database ( collection not specified here yet )
    """
    try:
        load_dotenv()
        is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
        
        if is_docker_container and is_docker_container == "True":
            mongo_username = os.environ['MONGO_INITDB_ROOT_USERNAME']
            mongo_password = os.environ['MONGO_INITDB_ROOT_PASSWORD']
            mongo_host = "13.203.233.15"
            mongo_port = "27017"    
            mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"
        elif dev_environment:
            mongo_url = "mongodb://localhost:27017/"
        else:
            mongo_username = os.environ['MONGO_INITDB_ROOT_USERNAME']
            mongo_password = os.environ['MONGO_INITDB_ROOT_PASSWORD']
            mongo_host = "13.203.233.15"
            mongo_port = "27017"
            mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"
        
        mongo_client = MongoClient(mongo_url)
        mongo_db = mongo_client['devsecshield_backend_server_db']
        console.print(f"Mongo client fetched successfully",style="dim green")
        return mongo_db
        
    except Exception as e:
        raise ValueError(f"Error in getting mongo client: {e}")