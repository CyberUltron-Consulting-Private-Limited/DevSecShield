# Unknown reasons

An UNKNOWN verdict is not evidenceable from the BOM. The manual check is what a person records. `non_production_hint` is a path label and is not one of these reasons.

<!-- table:unknown-reasons -->
| reason | label | manual check |
| --- | --- | --- |
| variable_overridden | A variable is set outside this file | Open the variable assignment and record the literal that wins. |
| variable_no_default | A variable has no default | Give the variable a default or record the value used at apply time. |
| unresolved_expression | An expression could not be resolved | Replace the expression with the literal that is applied. |
| dynamic_block | A dynamic block hides the value | Expand the dynamic block and record each concrete value. |
| module_call | A module call hides the value | Open the module source and record the concrete argument. |
| template_marker | A template marker hides the value | Render the template and record the concrete value. |
| unresolved_include | An included file could not be read | Provide the included file and re-scan. |
| unresolved_reference | A reference could not be resolved | Resolve the reference to a resource in this scan. |
| layer_not_observable | This layer is not visible in the declaration | Inspect that layer outside the repository. |
| attribute_not_modeled | The attribute is not in the coverage rules | Confirm the setting against the vendor document for this resource. |
| default_unknown | No documented default decides this setting | Record the provider default that applies to this account. |
| provider_version_dependent | The result depends on the provider version | Record the provider version and the default it documents. |
| parse_error | The file could not be parsed | Repair the file so it parses, then re-scan. |
| import_not_tested | The imported result did not test this item | Re-run the customer's tool with this item enabled. |
| conflicting_declaration | Two declarations disagree | Keep the declaration that is applied and remove the other. |
| import_observation | An imported result recorded an observation without a verdict | Read the customer's tool output for this host. |
