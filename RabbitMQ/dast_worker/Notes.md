## Notes : 

This command will run the Wapiti DAST scan :
```
uv run wapiti \
-u http://localhost:8090/bodgeit \
-f json \
-o output.json \
--form-data "username=shivanathnikhil@gmail.com&password=Testing@123" \
--form-url "http://localhost:8090/bodgeit/register.jsp" \
-m common \
--flush-session \
--user-agent "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36 SE 2.X MetaSr 1.0" \
--max-scan-time 60 
```

remember : for example the username must be url encoded ( use a library for this )
This link is your holy grail : 
```
https://github.com/wapiti-scanner/wapiti/blob/master/doc/wapiti.ronn
```

- This command runs the ZAP API daemon 
```
docker run -u zap -p 8080:8080 -i zaproxy/zap-stable zap-x.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.key=hahahaha1234 
```

- Scan Modes : ( not being used , all scans run in pen test mode )
```
sample website with 44 URLS 

St-Low-Th-High : ~ 9 Mins ( comprehensive and sometimes the CPU Usage shoots up to ~900 % utilization )
Pen Test : ~ 3.5 Mins
API : ~ 2 Mins
API-Minimal : ~ 1.5 Mins
QA Standard : ~ 9.5 Mins ( comprehensive and sometimes the CPU Usage shoots up to ~900 % utilization )



```