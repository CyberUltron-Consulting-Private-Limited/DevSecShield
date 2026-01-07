## Adding Dashboard fields to All features :

### AI Guardrails 

1. total scans ( Card UI )
2. successful scans ( Card UI )
3. failed scans ( Card UI )
4. pending scans ( Card UI )
5. started scans ( Card UI )
6. not started scans ( Card UI )

7. Line Chart UI ( scanners and their scores for each log ( top 6 most recent logs ))
- y axis : risk score
- x axis : scan log time 

8. Line chart UI ( log trends ( past 7 days , past 30 days ))
- y axis : number of scans run
- x axis : time 

9. Pie chart UI ( to show how many have been flagged as high risk , medium risk , low risk  or not flagged )
- labels : high risk , medium risk , low risk , not flagged
- values : number of scans
Note: High risk is 80% or more , Medium risk is 50% to 80% , Low risk is 20% to 50% , Not flagged is 0% to 20%

10 . Hexagon Chart UI ( to show the average risk scores for each scanner taking into consideration the past 7 days logs , past 30 days logs )
- endpoints : Scanner types 
- the lines correspond to average risk scores for each scanner type

---------------------------------------------------------------------------------------------------

### CI CD Integrations 

1. total scans ( Card UI )
2. successful scans ( Card UI )
3. failed scans ( Card UI )
4. pending scans ( Card UI )
5. started scans ( Card UI )
6. not started scans ( Card UI )

7. Line Chart UI ( scan trends ( past 7 days , past 30 days ))
- y axis : number of scans run
- x axis : time 

8. Pie chart UI ( to show how many have been flagged as high risk , medium risk , low risk  or not flagged )
- labels : high risk , medium risk , low risk , not flagged ( use semgrep provided risk categories )
- values : number of scans

9. Hexagon Chart UI ( to show the average risk scores for each scanner type taking into consideration the past 7 days logs , past 30 days logs )
- endpoints : Scanner types 
- the lines correspond to average risk scores for each scanner type

---------------------------------------------------------------------------------------------------

### SAST 

1. total scans ( Card UI )
2. successful scans ( Card UI )
3. failed scans ( Card UI )
4. pending scans ( Card UI )
5. started scans ( Card UI )
6. not started scans ( Card UI )


7. Line chart UI ( to show how many have been flagged as high risk , medium risk , low risk  or not flagged )
- y axis : impact categories of findings
- x axis : finding

8. Pie chart UI ( to show classification of findings based on finding class ex: path traversal , sql injection , etc )
- labels : path traversal , sql injection , etc
- values : number of findings

9. Linechart UI ( to show how many owasp vulns for each finding)
- y axis : number of owasp vulns
- x axis : finding name

10. Barchart UI ( to show how many CWEs mapped to specific findings )
- y axis : number of CWEs
- x axis : finding name

---------------------------------------------------------------------------------------------------

### SBOM_SCA 

1. total scans ( Card UI )
2. successful scans ( Card UI )
3. failed scans ( Card UI )
4. pending scans ( Card UI )
5. started scans ( Card UI )
6. not started scans ( Card UI )

7. Line Chart UI ( to show how many have been flagged as high risk , medium risk , low risk  or not flagged )
- y axis : severity categories of findings
- x axis : finding

8. Pie chart UI ( findings based on package )
- labels : package name
- values : number of findings

9. Bar Chart UI ( to show each finding and their CVSS scores )
- y axis : CVSS score
- x axis : finding 

10 . Line Chart UI ( to show each finding and their risk scores)
- y axis : risk score
- x axis : finding 

11. Triangle Chart UI ( to show the average risk scores ( on a scale of 10 ) between CVSS scores , Risk score and EPSS scores ) 
each finding will have its risk score , EPSS score and CVSS score ( out of 10 )

---------------------------------------------------------------------------------------------------

### IAC 

1. total scans ( Card UI )
2. successful scans ( Card UI )
3. failed scans ( Card UI )
4. pending scans ( Card UI )
5. started scans ( Card UI )
6. not started scans ( Card UI )

7. 
---------------------------------------------------------------------------------------------------
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