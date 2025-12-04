# Source - https://stackoverflow.com/q
# Posted by Robert Ritz, modified by community. See post 'Timeline' for change history
# Retrieved 2025-12-04, License - CC BY-SA 4.0

import requests
import time
query = "How tall is the Eiffel tower?"
url = "http://127.0.0.1:8081/sast/conversation/1/message"
headers = {
    "Authorization": "Bearer 123",
    "Content-Type": "application/json",
    "Accept": "text/event-stream"
}

response = requests.post(url, headers=headers, stream=True)

for chunk in response.iter_lines():
    time.sleep(1)
    print("PAUSING")
    if chunk:
        print(chunk.decode("utf-8"))
