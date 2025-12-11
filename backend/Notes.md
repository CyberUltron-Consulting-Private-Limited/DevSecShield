## To do 

- SAST : add a field in the SAST Conversation table to store the table_data ( which we will be allowing the user to export as a PDF )
- SAST : connect UI to backend after above is done


## Notes 

- Do a ``uv pip install -U "langchain[aws]"`` 

- To create tables , from root directory run ``uv run python -m backnend.init_db``

- add branch selection to repo cloning 
``Repo.clone_from(url, tmp_dir, depth=1,branch="branch_name")``

- find integrations for all other repos to figure out size of repo before accepting the scan request

- the UI uses an auto incrementing integer for message id , but the backend uses the mongo db message id ( _id ) to store the messages in the database . But when fetching the messages from the database , we return the messages with integer ids that increment from 1 to n ( n being the number of messages )