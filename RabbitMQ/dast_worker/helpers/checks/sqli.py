from helpers.agent.BaseTest import BaseTest


class SQLInjectionCheck(BaseTest):

    def __init__(self, url: str):
        self.url = url

    def run(self):
        """
        Run the SQL injection check
        """
        pass