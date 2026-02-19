

login_template =  """
id: <TEMPLATE_ID>

info:
  name: <TEMPLATE_NAME>
  author: pdteam
  severity: <TEMPLATE_SEVERITY>

headless:

  - steps:
      - args:
          url: "<TARGET_URL>"
        action: navigate
      - action: waitload
      - args:
          by: xpath
          xpath: <USERNAME_XPATH>
        action: click
      - action: waitload
      - args:
          by: xpath
          value: <USERNAME_VALUE>
          xpath: <USERNAME_XPATH>
        action: text
      - args:
          by: xpath
          xpath: <PASSWORD_XPATH>
        action: click
      - action: waitload
      - args:
          by: xpath
          value: <PASSWORD_VALUE>
          xpath: <PASSWORD_XPATH>
        action: text
      - args:
          by: xpath
          xpath: <SUBMIT_XPATH>
        action: click
      - action: waitload

"""

navigate_template =  """

  - steps:
      - action: navigate
        args:
          url: "<NAVIGATE_URL>"

      - action: waitload

      - action: script
        name: extract_html
        args:
          code: |
            () => {
              return document.documentElement.outerHTML;
            }
    extractors:
      - type: regex
        part: extract_html
        regex:
          - "(?s)(.*)" # This regex captures the entire output of the script action

"""