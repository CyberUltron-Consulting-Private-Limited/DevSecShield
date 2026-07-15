command 
```
nuclei -u https://demo.testfire.net/login.jsp -headless -t templates,yaml -me markdown_dir
```

```
uv run playwright install
```

DAST Agent Workflow :

Step 1 : Security Header Check : 
- use playwright to check the security headers of the website
- code already available 
- no need for auth state 

Step 2 : Crawling The URL : 
- build a crawler to crawl the website and get the URLs of the pages


The following steps are to be done for each page of the website :

    Step 1 : XSS Scan : 
    - run nuclei xss template ( login + navigate to desired page + testing xss payloads )
    - use AI to find x-path of input field to test 

    Step 2 : SQL Injection Scan : 
    - run nuclei sql injection template ( login + navigate to desired page + testing sql injection payloads )
    - use AI to find x-path of input field to test 

    Step 3 : Page Analysis : 
    - analyze the page and find the vulnerabilities 

    Step 4 : Nuclei template generation using AI and scan : 
    - run nuclei template generation using AI and scan the page ( login + navigate to desired page + testing vulnerabilities )


Use all the information gathered to write to a report file at checkpoints in the workflow . 
Load the report , and use map-reduce to generate a final report 


