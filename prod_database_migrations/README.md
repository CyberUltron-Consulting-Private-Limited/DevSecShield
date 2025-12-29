## Commands ( workaround for import complexities )

### run these from the root directory of the project
1. Run this to create a migration file : 
```
uv run alembic --config prod_database_migrations\alembic.ini revision --autogenerate   -m "Added LLM Benchmarking table"
```

2. Run this to apply the migration : 
```
uv run alembic --config prod_database_migrations\alembic.ini upgrade head
```