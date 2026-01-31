## Methods left to implement : 
- *C:\Users\HP\Desktop\DevSecShield\backend\utilities\team\credits.py*  ✅ Done 
- *C:\Users\HP\Desktop\DevSecShield\backend\utilities\scan\estimate_scan.py* ✅ Done 
- *C:\Users\HP\Desktop\DevSecShield\backend\utilities\scan\format_input.py* ✅ Done 
- *C:\Users\HP\Desktop\DevSecShield\backend\utilities\db\metadata.py* ✅ Done 
- *C:\Users\HP\Desktop\DevSecShield\backend\utilities\pdf\combined.py* ✅ Done 



## Userflow 

- landing page will be a page with analytics that accumulate data across all teams and there will be a sidebar with navigation to specific teams.
- each team related screen on the ui will have a team_id in the path parameter ( this is how we will be maintaining the current active team that the user is interacting with ) ( validation will need to be done for team_ids to ensure this user is allowed to access this team ) 

- 1 credit is : 
    - **0.5 MB** of source code files ( ~ 71 source code files ) 
    - **~ 0.836 $** ( ~ 76 INR )
    - assuming 1 message costs 0.0048 $ ( 12.6K input + 10.3K output tokens ) 
        - therefore **1 message = 0.0048/0.836 = 0.006 credits** 



## Database Architecture 

**User** ✅ confirmed 
- id ( int  )  # PK, auto
- email ( str )
- password ( str )
- first_name ( str , None by default )
- last_name ( str , None by default )
- profile_photo ( str , None by default )
- session_active ( bool , False by default )
- last_active ( datetime , now UTC by default )
- is_superuser ( bool , False by default )

**Team** ✅ confirmed 
- id ( int  )  # PK, auto
- name ( str )
- description ( str , None by default )
- created_at ( datetime , now UTC by default )
- credit_balance ( int , 0 by default )
- integration_settings ( dict/JSON , { "jira" : {} } by default )
- settings ( dict/JSON , { } by default ) ( for future ise if it comes in handy )


Note : every user by default is a member of the "default-team"

**TeamMembers** ✅ confirmed 
- id ( int  )  # PK, auto
- team_id ( int ) ( foreign key to team.id ) ( index ) 
- user_id ( int ) ( foreign key to user.id ) ( index )
- role ( "admin"/"member" , "member" by default , "admin" when creating Team ) ( admin can remove / add members to the team )


**VerificationCode** ✅ confirmed 
- id ( int , None by default )  # PK, auto
- email ( str )
- code ( str )
- created_at ( datetime , now UTC by default )
- expires_at ( datetime , now + 10 min by default )

**Scans** ⭐⭐⭐ Main Scans table  ✅ confirmed 
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id ) ( index )
- owner_user_id ( int ) ( foreign key to user.id ) 
- credit_consumed ( float , 0 by default )
- task_id ( str , None by default )
- scan_type ( "sast"/"llm"/"mcp"/"iac"/"leakage"/"sbom_sca"/"agent_discovery"/"dast" ) ( index )
- metadata ( dict/JSON , {} by default ) ( stores the metadata of the scan )
- scan_status ( "pending"/"started"/"retry"/"failure"/"success"/"NOT_STARTED" , "NOT_STARTED" by default ) 
- title ( str )
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- scan_data ( dict/JSON , {} by default )

Note : 
- messages will be limited by credits . 
- only the user who created the scan can start the scan or update the scan or send messages to the scan / guardrails integration / cicd integration
- scan can only be started after the user has estimated the credits for the scan and the credits are available in the user's credit balance
- reinitialize will not deduct credits for scan ( only starting scan will deduct credits )


**GuardrailsIntegration** ✅ confirmed 
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id ) ( index )
- api_key ( str )
- title ( str )
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- settings ( dict/JSON , default_settings by default )

**CicdIntegration** ✅ confirmed 
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id ) ( index )
- api_key ( str )
- title ( str )
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- scan_type ( "sast"/"llm"/"mcp"/"iac"/"leakage"/"sbom_sca"/"agent_discovery" , None by default )
- results ( dict/JSON , {} by default )

Changes : 
- get rid of mongo conversations and use the postgres conversation id in the mongo message log to query all messages of a conversation . 
- no need to maintain messages array since we query messages based on conversation id . 
- no need to maintain user_id or team_id in messages log or active context log since we query messages based on conversation id . 


Old tables ( for reference ) : 
*SAST*
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id )
- task_id ( str , None by default )
- metadata ( dict/JSON , {} by default ) ( stores the metadata of the scan like repo url , mode , or zip file used or not , app language , etc )
- scan_status ( "pending"/"started"/"retry"/"failure"/"success"/"NOT_STARTED" , "NOT_STARTED" by default )
- title ( str ) 
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- scan_data ( dict/JSON , {} by default )
- message_limit ( int )

*LLM*
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id )
- task_id ( str , None by default )
- metadata ( dict/JSON , {} by default ) ( stores the metadata of the scan like model type , model name , probes used , generations )
- scan_status ( "pending"/"started"/... , "NOT_STARTED" by default )
- title ( str )
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- scan_data ( dict/JSON , {} by default )
- message_limit ( int )

*MCP*
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id )
- task_id ( str , None by default )
- metadata ( dict/JSON , {} by default ) ( stores the metadata of the scan )
- scan_status ( "pending"/"started"/... , "NOT_STARTED" by default )
- title ( str )
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- scan_data ( dict/JSON , {} by default )
- message_limit ( int )

*IAC*
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id )
- task_id ( str , None by default )
- metadata ( dict/JSON , {} by default ) ( stores the metadata of the scan like repo url , mode , or zip file used or not , IAC contexts scanned for )
- scan_status ( "pending"/"started"/... , "NOT_STARTED" by default )
- title ( str )
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- scan_data ( dict/JSON , {} by default )
- message_limit ( int )


*SBOM_SCA*
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id )
- task_id ( str , None by default )
- metadata ( dict/JSON , {} by default ) ( stores the metadata of the scan like repo url , mode , or zip file used or not , SBOM file used or not  )
- scan_status ( "pending"/"started"/... , "NOT_STARTED" by default )
- title ( str )
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- scan_data ( dict/JSON , {} by default )
- message_limit ( int )

*Agent_Discovery*
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id )
- task_id ( str , None by default )
- metadata ( dict/JSON , {} by default ) ( stores the metadata of the scan like repo url , mode , or zip file used or not , Agent Discovery contexts scanned for )
- scan_status ( "pending"/"started"/... , "NOT_STARTED" by default )
- title ( str )
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- scan_data ( dict/JSON , {} by default )
- message_limit ( int )

*DAST*
- id ( int , None by default )  # PK, auto
- team_id ( int ) ( foreign key to team.id )
- task_id ( str , None by default )
- metadata ( dict/JSON , {} by default ) ( stores the metadata of the scan like target url , auth mode )
- scan_status ( "pending"/"started"/... , "NOT_STARTED" by default )
- title ( str )
- created_at ( datetime , now UTC by default )
- last_updated ( datetime , now UTC by default )
- scan_data ( dict/JSON , {} by default )
- message_limit ( int )


## Notes 
- ORM: SQLModel. PostgreSQL via Alembic. Conversation messages live in MongoDB; conversation_id links to Mongo.
- the last_updated field is updated on 3 occasions : 
    - when the conversation is created
    - when the conversation task status is fetched from the celery backend
    - when new message is sent to the conversation

- Do a ``uv pip install -U "langchain[aws]"`` 

- To create mongo db tables , from root directory run ``uv run python -m backnend.init_mongo_db`` ( for MONGO DB ) 
- To create postgres db tables , use alembic 


- the UI uses an auto incrementing integer for message id , but the backend uses the mongo db message id ( _id ) to store the messages in the database . But when fetching the messages from the database , we return the messages with integer ids that increment from 1 to n ( n being the number of messages )