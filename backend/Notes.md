## To do 

- SAST : add a field in the SAST Conversation table to store the table_data ( which we will be allowing the user to export as a PDF )
- SAST : connect UI to backend after above is done


## Notes 

- the last_updated field is updated on 3 occasions : 
    - when the conversation is created
    - when the conversation task status is fetched from the celery backend
    - when new message is sent to the conversation

- Do a ``uv pip install -U "langchain[aws]"`` 

- To create tables , from root directory run ``uv run python -m backnend.init_db`` ( no longer needed you can use alembic for this )

- add branch selection to repo cloning 
``Repo.clone_from(url, tmp_dir, depth=1,branch="branch_name")``

- find integrations for all other repos to figure out size of repo before accepting the scan request

- the UI uses an auto incrementing integer for message id , but the backend uses the mongo db message id ( _id ) to store the messages in the database . But when fetching the messages from the database , we return the messages with integer ids that increment from 1 to n ( n being the number of messages )