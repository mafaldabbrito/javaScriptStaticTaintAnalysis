import os
import json

def load_file(filename):
    """
    Loads a specific JavaScript (.js) file from the given folder.
    Returns the file content as a string.
    """
    file_path = filename
    if not filename.endswith('.js'):
        raise ValueError("Only .js files are supported.")
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"{file_path} does not exist.")
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

def load_slice(slice_filename):
    """
    Loads a specific JavaScript code slice from the 'slices' folder.
    """
    return load_file(slice_filename)

def load_pattern(pattern_filename):
    """
    Loads a specific pattern file from the 'patterns' folder.
    Supports JSON files.
    """
    file_path = pattern_filename
    if pattern_filename.endswith('.json'):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"{file_path} does not exist.")
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

def load_pattern_and_slice(pattern_filename, slice_filename):
    """
    Loads a pattern JSON and JS slice, returning a Pattern object and the AST of the slice.
    """
    from models.pattern import Pattern
    from utils.ast_parser import Parser
    import tempfile
    import os
    patterns = []

    # Load pattern JSON
    pattern_data = load_pattern(pattern_filename)
    for patt in pattern_data:
        pattern_obj = Pattern(
            name=patt['vulnerability'],
            sources=patt.get('sources', []),
            sanitizers=patt.get('sanitizers', []),
            sinks=patt.get('sinks', []),
            implicit=(patt.get('implicit', '').lower() == 'yes')
        )
        patterns.append(pattern_obj)

    # Load JS code slice
    js_code = load_slice(slice_filename)
    # Write JS code to a temporary file for parsing
    with tempfile.NamedTemporaryFile('w+', suffix='.js', delete=False) as tmp_file:
        tmp_file.write(js_code)
        tmp_file_path = tmp_file.name
    try:
        parser = Parser(tmp_file_path)
        ast = parser.parse_js_code()
    finally:
        os.remove(tmp_file_path)
    return patterns, ast