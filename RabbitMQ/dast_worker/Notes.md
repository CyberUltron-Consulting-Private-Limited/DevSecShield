## Notes : 

- This command runs the ZAP API daemon 
```
docker run -u zap -p 8080:8080 -i zaproxy/zap-stable zap-x.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.key=hahahaha1234 
```

- Scan Modes :
```
sample website with 44 URLS 

St-Low-Th-High : ~ 9 Mins ( comprehensive and sometimes the CPU Usage shoots up to ~900 % utilization )
Pen Test : ~ 3.5 Mins
API : ~ 2 Mins
API-Minimal : ~ 1.5 Mins
QA Standard : ~ 9.5 Mins ( comprehensive and sometimes the CPU Usage shoots up to ~900 % utilization )



```