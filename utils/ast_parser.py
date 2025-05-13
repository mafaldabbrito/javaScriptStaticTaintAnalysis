from esprima import parseScript  # For JavaScript code

class Parser:

    def __init__(self, filename):
        self.filename = filename
    
    def parse_js_code(self):
        """Parse JavaScript code and return the AST"""
        js_code = open(self.filename, "r").read()
        # Use esprima to parse the JavaScript code
        # and generate the AST
        try:
            ast_tree = parseScript(js_code, {"range": True})
            return ast_tree
        except Exception as e:
            print(f"Error parsing JavaScript: {e}")
            return None


