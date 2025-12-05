## To do 

- SAST conversations list + deletion + rename ✅
- SAST conversation get ✅
- SAST conversation scan start + scan poll  ✅
- SAST conversation message send 🟨
    - add empty message to mongo db log and pass message id to create response func
    - let response func write to the same message document ( as specified in the message id ) after streaming is complete 
    - think about how to implement , parent message id . ( or maybe get rid of it , because the array might handle this sequence itself )
        - it must be fault tolerant ( it should represent the correct sequence of messages )



## Notes 

- Do a ``uv pip install -U "langchain[aws]"`` 

- To create tables , from root directory run ``uv run python -m backnend.main``

- add branch selection to repo cloning 
``Repo.clone_from(url, tmp_dir, depth=1,branch="branch_name")``

- find integrations for all other repos to figure out size of repo before accepting the scan request

- the UI uses an auto incrementing integer for message id , but the backend uses the mongo db message id ( _id ) to store the messages in the database . But when fetching the messages from the database , we return the messages with integer ids that increment from 1 to n ( n being the number of messages )