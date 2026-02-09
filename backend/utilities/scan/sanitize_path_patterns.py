def sanitize_path_patterns(path_patterns: list[str]) -> list[str]:
    """
    Removes any empty or whitespace-only strings from the list of path patterns.
    Returns a new list with the sanitized path patterns.
    """
    sanitized_path_patterns = []
    for path_pattern in path_patterns:
        if len(path_pattern) <= 0:
            continue
        elif "".join(path_pattern) == "":
            continue
        elif "".join(path_pattern).strip() == "":
            continue
        sanitized_path_patterns.append(path_pattern)
    return sanitized_path_patterns