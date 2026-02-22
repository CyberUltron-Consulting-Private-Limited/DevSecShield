from helpers.checks.page_analysis import PageAnalysisCheck
from helpers.agent.context import AuthRequirements


if __name__ == "__main__":

    url = "https://demo.testfire.net/login.jsp"

    xpath_of_username_field = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input"
    xpath_of_password_field = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input"
    username = "jsmith"
    password = "demo123"
    xpath_of_submit_button = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[3]/td[2]/input"

    auth = AuthRequirements(
        login_url=url,
        xpath_of_username_field=xpath_of_username_field,
        xpath_of_password_field=xpath_of_password_field,
        username=username,
        password=password,
        xpath_of_submit_button=xpath_of_submit_button
    )

    page_analysis_check = PageAnalysisCheck(url=url,auth=auth)
    result = page_analysis_check.run()
    print(result)