"""The decision for every tree-sitter node type of the bundled grammars (``syntax._TsBuilder``), so that the walker
never skips code it was not told about. A node type is one of:

* handled by ``syntax._TsBuilder`` (a handler method or one of its node sets: names, strings, numbers, functions,
  classes, control flow, comments, ``_FORBIDDEN``);
* ``TYPE_ONLY``: types, annotations / attributes, modifiers, module directives - no code runs there, the subtree is
  dropped (C# array sizes inside an ``array_type`` are kept as expressions);
* ``GENERIC``: built by the fallback - every named child is built and its value flows into the parent (blocks,
  statement wrappers, argument lists, declarations whose declarators are handled, plain operators).

``syntax.known_types(lang)`` is their union. A node type in none of them (a grammar upgrade, a construct nobody
reviewed) is built as ``forbidden`` and a rewrite that adds one is withheld: the coverage guard fails closed. The
test ``test_round5_every_grammar_node_type_has_a_decision`` reads every named node type of every bundled grammar.
"""
from __future__ import annotations


def _s(text: str) -> frozenset[str]:
    return frozenset(text.split())


# names inside types: skipped when the expressions of a type are collected (C# array sizes), and in parameter lists
TYPE_LEAVES = _s("""identifier type_identifier qualified_name generic_name alias_qualified_name predefined_type
simple_identifier package_identifier field_identifier scoped_identifier scoped_type_identifier nested_identifier
nested_type_identifier type_argument_list type_arguments user_type implicit_type""")

_TS_TYPES = _s("""abstract_method_signature accessibility_modifier adding_type_annotation ambient_declaration array_type
asserts asserts_annotation call_signature conditional_type constraint construct_signature constructor_type default_type
existential_type extends_type_clause flow_maybe_type function_signature function_type generic_type implements_clause
index_signature index_type_query infer_type interface_body interface_declaration intersection_type literal_type
lookup_type mapped_type_clause method_signature nested_type_identifier object_type omitting_type_annotation
opting_type_annotation optional_type override_modifier parenthesized_type predefined_type property_signature
readonly_type rest_type template_literal_type template_type this_type tuple_type type_alias_declaration
type_annotation type_arguments type_identifier type_parameter type_parameters type_predicate type_predicate_annotation
type_query union_type""")

TYPE_ONLY: dict[str, frozenset[str]] = {
    "javascript": frozenset(),
    "typescript": _TS_TYPES,
    "java": _s("""annotated_type annotation annotation_argument_list element_value_array_initializer element_value_pair
    marker_annotation array_type boolean_type catch_type dimensions extends_interfaces floating_point_type generic_type
    integral_type modifiers permits scoped_type_identifier super_interfaces superclass throws type_arguments type_bound
    type_identifier type_list type_parameter type_parameters void_type wildcard receiver_parameter asterisk
    package_declaration module_declaration module_body exports_module_directive opens_module_directive
    provides_module_directive requires_modifier requires_module_directive uses_module_directive"""),
    "kotlin": _s("""annotation class_modifier file_annotation function_modifier function_type function_type_parameters
    inheritance_modifier member_modifier modifiers non_nullable_type nullable_type parameter_modifier
    parameter_modifiers parenthesized_type platform_modifier property_modifier reification_modifier type_alias
    type_arguments type_constraint type_constraints type_modifiers type_parameter type_parameter_modifiers
    type_parameters type_projection use_site_target user_type variance_modifier visibility_modifier package_header
    shebang"""),
    "go": _s("""array_type channel_type field_declaration field_declaration_list function_type generic_type
    implicit_length_array_type interface_type map_type method_elem negated_type package_clause parenthesized_type
    pointer_type qualified_type slice_type struct_type type_alias type_arguments type_constraint type_declaration
    type_elem type_identifier type_parameter_declaration type_parameter_list type_spec"""),
    "csharp": _s("""array_rank_specifier array_type attribute attribute_argument attribute_argument_list attribute_list
    attribute_target_specifier global_attribute constructor_constraint delegate_declaration explicit_interface_specifier
    implicit_type modifier nullable_type predefined_type ref_type scoped_type tuple_element tuple_type
    type_argument_list type_parameter type_parameter_constraint type_parameter_constraints_clause type_parameter_list
    preproc_region preproc_endregion preproc_nullable preproc_pragma"""),
}

_JS_GENERIC = _s("""arguments array_pattern assignment_pattern await_expression break_statement class_heritage
class_static_block computed_property_name continue_statement else_clause empty_statement escape_sequence export_clause
export_specifier export_statement formal_parameters hash_bang_line import_attribute import_clause import_specifier
lexical_declaration meta_property named_imports namespace_export namespace_import object_assignment_pattern
object_pattern optional_chain pair_pattern program regex_flags regex_pattern rest_pattern return_statement
sequence_expression spread_element statement_block statement_identifier string_fragment switch_body switch_case
switch_default template_substitution ternary_expression throw_statement using_declaration variable_declaration
yield_expression""")

GENERIC: dict[str, frozenset[str]] = {
    "javascript": _JS_GENERIC,
    "typescript": _JS_GENERIC | _s("""enum_assignment enum_body extends_clause import_alias import_require_clause
    instantiation_expression internal_module module nested_identifier optional_parameter required_parameter
    type_assertion"""),
    "java": _s("""annotation_type_body annotation_type_element_declaration argument_list array_creation_expression
    assert_statement block break_statement catch_formal_parameter class_literal constant_declaration constructor_body
    continue_statement dimensions_expr enum_body enum_body_declarations enum_constant escape_sequence field_declaration
    formal_parameter formal_parameters guard inferred_parameters interface_body local_variable_declaration
    multiline_string_fragment program resource_specification return_statement scoped_identifier spread_parameter
    static_initializer string_fragment switch_block_statement_group switch_label switch_rule synchronized_statement
    ternary_expression throw_statement yield_statement"""),
    "kotlin": _s("""annotated_expression annotated_lambda block class_parameter class_parameters
    constructor_delegation_call delegation_specifier delegation_specifiers enum_class_body enum_entry escape_sequence
    explicit_delegation function_value_parameters in_expression interpolation is_expression label labeled_expression
    lambda_parameters multi_variable_declaration parameter primary_constructor property_delegate qualified_identifier
    range_expression range_test return_expression source_file spread_expression string_content throw_expression
    type_test value_argument value_arguments variable_declaration"""),
    "go": _s("""argument_list blank_identifier block break_statement const_declaration continue_statement dot
    empty_statement escape_sequence fallthrough_statement for_clause goto_statement import_spec_list
    interpreted_string_literal_content iota keyed_element label_name parameter_declaration parameter_list
    raw_string_literal_content receive_statement return_statement slice_expression source_file statement_list
    type_conversion_expression type_instantiation_expression var_declaration var_spec_list variadic_argument
    variadic_parameter_declaration"""),
    "csharp": _s("""accessor_list alias_qualified_name and_pattern argument_list array_creation_expression
    await_expression base_list block bracketed_argument_list bracketed_parameter_list break_statement catch_declaration
    catch_filter_clause character_literal_content checked_expression checked_statement collection_element
    collection_expression compilation_unit conditional_expression constant_pattern constructor_initializer
    continue_statement declaration_list discard element_binding_expression empty_statement enum_member_declaration
    enum_member_declaration_list escape_sequence event_declaration event_field_declaration expression_element
    field_declaration file_scoped_namespace_declaration goto_statement implicit_array_creation_expression
    implicit_parameter implicit_stackalloc_expression interpolation interpolation_alignment_clause interpolation_brace
    interpolation_format_clause interpolation_quote interpolation_start is_expression local_declaration_statement
    member_binding_expression namespace_declaration negated_pattern or_pattern parameter parameter_list
    parenthesized_pattern parenthesized_variable_designation primary_constructor_base_type qualified_name
    range_expression raw_string_content raw_string_end raw_string_start ref_expression relational_pattern
    return_statement spread_element stackalloc_expression string_content string_literal_content
    string_literal_encoding switch_body switch_expression_arm throw_expression throw_statement tuple_pattern
    type_pattern variable_declaration when_clause with_expression with_initializer yield_statement"""),
}
