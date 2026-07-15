xss_template = """


      # click on the input field first before filling 
      - args:
          by: xpath
          xpath: <INPUT_FIELD_XPATH>
        action: click
      - action: waitload

      # Type XSS payload into the input field
      - args:
          by: xpath
          xpath: <INPUT_FIELD_XPATH>
          value: <script>alert('XSS-testing')</script>
        action: text

      # Click the submit button
      - args:
          by: xpath
          xpath: <SUBMIT_BUTTON_XPATH>
        action: click

      - action: waitload

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