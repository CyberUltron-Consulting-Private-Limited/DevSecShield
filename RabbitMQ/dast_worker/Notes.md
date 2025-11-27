## Notes : 

- This command runs the ZAP API daemon 
```
docker run -u zap -p 8080:8080 -i zaproxy/zap-stable zap-x.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.key=hahahaha1234 
```