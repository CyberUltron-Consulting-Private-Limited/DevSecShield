
- Use this exact command when spinning up a celery worker 
```uv run celery -A scan_worker worker -P threads --loglevel=info```

- The Agent discovery service still uses openai , change that 

- Where ever repo cloning happens , it doesn't matter if the .git is present in the repo url or not , it will be cloned anyway and the directory will be returned.

