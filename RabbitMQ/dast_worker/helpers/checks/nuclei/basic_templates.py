

login_template =  """
id: template_template_name

info:
  name: template_template_name
  author: pdteam
  severity: high

headless:

  - steps:
      - args:
          url: "<LOGIN_URL>"
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
      - args:
          url: "<NAVIGATE_URL>"
        action: navigate

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

navigate_action_template = """

      - args:
          url: "<NAVIGATE_URL>"
        action: navigate

      - action: waitload
"""