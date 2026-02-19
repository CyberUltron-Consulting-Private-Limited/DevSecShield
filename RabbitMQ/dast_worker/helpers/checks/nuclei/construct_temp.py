from helpers.agent.context import AuthRequirements
from helpers.checks.nuclei.basic_templates import login_template, navigate_template
from helpers.checks.nuclei.sqli_template import sqli_template



def construct_login_template(auth_requirements: AuthRequirements,template_name: str,template_severity: str,target_url: str) -> str: # construct a nuclei template from the auth requirements

    username_xpath = auth_requirements.xpath_of_username_field
    username_value = auth_requirements.username

    password_xpath = auth_requirements.xpath_of_password_field
    password_value = auth_requirements.password

    submit_xpath = auth_requirements.xpath_of_submit_button
    
    template = login_template.replace("<TEMPLATE_ID>", template_name)
    template = template.replace("<TEMPLATE_NAME>", template_name)
    template = template.replace("<TEMPLATE_SEVERITY>", template_severity)
    template = template.replace("<TARGET_URL>", target_url)
    template = template.replace("<USERNAME_XPATH>", username_xpath)
    template = template.replace("<USERNAME_VALUE>", username_value)
    template = template.replace("<PASSWORD_XPATH>", password_xpath)
    template = template.replace("<PASSWORD_VALUE>", password_value)
    template = template.replace("<SUBMIT_XPATH>", submit_xpath)

    return template

def construct_navigate_template(target_url: str) -> str:
    template = navigate_template.replace("<NAVIGATE_URL>", target_url)
    return template


def construct_sqli_template(input_field_xpath: str,button_xpath: str) -> str:
    template = sqli_template.replace("<INPUT_FIELD_XPATH>", input_field_xpath)
    template = template.replace("<BUTTON_XPATH>", button_xpath)
    return template

def create_login_navigate_template(
    base_url: str,
    auth_requirements: AuthRequirements,
    navigate_url: str,
) -> str:
    login_template = construct_login_template(auth_requirements,template_name="login_template",template_severity="high",target_url=base_url)
    navigate_template = construct_navigate_template(template_name="navigate_template",template_severity="high",target_url=navigate_url)
    result_template = login_template + navigate_template
    return result_template

def create_login_navigate_sqli_template(
    base_url: str,
    auth_requirements: AuthRequirements,
    navigate_url: str,
    input_field_xpath: str,
    button_xpath: str,
) -> str:
    login_template = construct_login_template(auth_requirements,template_name="login_template",template_severity="high",target_url=base_url)
    navigate_template = construct_navigate_template(target_url=navigate_url)
    sqli_template = construct_sqli_template(input_field_xpath=input_field_xpath,button_xpath=button_xpath)
    result_template = login_template + navigate_template + sqli_template
    return result_template


if __name__ == "__main__":
    url = "https://demo.testfire.net/login.jsp"
    xpath_of_username_field = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input"
    xpath_of_password_field = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input"
    xpath_of_submit_button = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[3]/td[2]/input"
    username = "jsmith"
    password = "demo123"
    auth = AuthRequirements(xpath_of_username_field=xpath_of_username_field,xpath_of_password_field=xpath_of_password_field,xpath_of_submit_button=xpath_of_submit_button,username=username,password=password)
    
    input_field_xpath = "/html/body/div[1]/form/table/tbody/tr[1]/td[2]/input[1]"
    button_xpath = "/html/body/div[1]/form/table/tbody/tr[1]/td[2]/input[2]"

    template = create_login_navigate_sqli_template(base_url=url,auth_requirements=auth,navigate_url="https://demo.testfire.net/index.jsp",input_field_xpath=input_field_xpath,button_xpath=button_xpath)
    

    with open("login_template.yaml", "w") as f:
        f.write(template)


