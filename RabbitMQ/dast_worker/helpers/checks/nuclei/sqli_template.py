


sqli_template = """

  - steps:
      

      # Type XSS payload into the input field
      - action: type
        args:
          by: xpath
          xpath: "<INPUT_FIELD_XPATH>"
          value: "<script>alert('XSS-testing')</script>"

      # Click the submit button
      - action: click
        args:
          by: xpath
          xpath: "<BUTTON_XPATH>"

      - action: waitload


    matchers:
      - type: word
        part: body
        words:
          - "<script>alert('XSS-testing')</script>"
          - "XSS-testing"
        condition: or

      - type: dsl
        dsl:
          - 'contains(body, "alert(") && contains(body, "XSS-testing")'
        condition: or
"""