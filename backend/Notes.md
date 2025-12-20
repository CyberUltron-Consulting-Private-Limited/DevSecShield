## Guardrails API 

Public API Routes : 
1. route to send input prompt to guardrails and start the scan
2. route to get the scan task status / results 

Dashboard API Routes : 
1. route to create a new integration 
2. route to get all integrations for a user
3. route to delete an integration
4. route to update an integration ( renaming , adding/ deleting scanners , modifying scanner settings )
5. route to get a specific integration dashboard data
6. route to get the integration settings of all the scanners in the integration


## Notes 

- the last_updated field is updated on 3 occasions : 
    - when the conversation is created
    - when the conversation task status is fetched from the celery backend
    - when new message is sent to the conversation

- Do a ``uv pip install -U "langchain[aws]"`` 

- To create mongo db tables , from root directory run ``uv run python -m backnend.init_mongo_db`` ( for MONGO DB ) 
- To create postgres db tables , use alembic 

- add branch selection to repo cloning 
``Repo.clone_from(url, tmp_dir, depth=1,branch="branch_name")``

- find integrations for all other repos to figure out size of repo before accepting the scan request

- the UI uses an auto incrementing integer for message id , but the backend uses the mongo db message id ( _id ) to store the messages in the database . But when fetching the messages from the database , we return the messages with integer ids that increment from 1 to n ( n being the number of messages )