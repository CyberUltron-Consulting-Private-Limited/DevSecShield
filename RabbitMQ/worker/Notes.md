
- Use this exact command when spinning up a celery worker 
```uv run celery -A scan_worker worker -P threads --loglevel=info -Q scan_worker_queue```

- Use this exact command when spinning up a celery worker for cicd :
```uv run celery -A cicd_worker worker -P threads --loglevel=info -Q cicd_worker_queue```

- The Agent discovery service still uses openai , change that 

- Where ever repo cloning happens , it doesn't matter if the .git is present in the repo url or not , it will be cloned anyway and the directory will be returned.

- the script to initialize the qdrant vector database ( or clear it and recreate ) is at 
```helpers/context/qdrant_utils.py```

