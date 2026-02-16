from playwright.sync_api import sync_playwright
from rich.console import Console
from playwright.sync_api import Request
from playwright.sync_api import Response

console = Console()

def intercept_request(request:Request):
    # we can update requests with custom headers
    console.print(f"request: {request.url}",style="bold yellow")
    console.print(f"request method: {request.method}",style="bold yellow")
    console.print(f"request headers: {request.headers}",style="bold yellow")
    console.print(f"request post data: {request.post_data}",style="bold yellow")

    return request

def intercept_response(response:Response):
    # we can extract details from background requests
    console.print(f"response: {response.url}",style="bold yellow")
    console.print(f"response status: {response.status}",style="bold yellow")
    console.print(f"response headers: {response.headers}",style="bold yellow")
    return response

def finished_request(request:Request):

    console.print(f"finished request: {request.all_headers()}",style="bold bright_blue")
    return request

with sync_playwright() as pw:
    try:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1920, "height": 1080})
        page = context.new_page()
        # enable intercepting for this page
        page.on("request", intercept_request)
        page.on("response", intercept_response)
        page.on("requestfinished", finished_request)

        page.goto("https://threatshield.zeroshield.ai")
    except Exception as e:
        console.print(f"Error while testing:{str(e)[:100]}",style="bold red")
    finally:
        browser.close()
        context.close()
        page.close()
        pw.close()
