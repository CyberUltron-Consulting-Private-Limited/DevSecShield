from helpers.agent.BaseTest import BaseTest

class XSSCheck(BaseTest):

    def __init__(self, url: str):
        self.url = url

    def run(self):
        """
        Run the XSS check
        """
        pass