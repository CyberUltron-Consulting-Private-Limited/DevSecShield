
- Use this exact command when spinning up a celery worker 
```uv run celery -A scan_worker worker -P threads --loglevel=info```

- The Agent discovery service still uses openai , change that 