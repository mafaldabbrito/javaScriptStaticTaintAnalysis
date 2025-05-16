from collections.abc import Iterable

class TraversalVisitor:
    def __init__(self):
        self.initialized_variables = set()

    def visit(self, node):
  
        if hasattr(node, 'type'):
            if node.type == "Program":
                node = node.body
                for child in node:
                    self.visit(child)
            elif node.type == "VariableDeclaration":
                print(f"Visiting variable declaration: {node.kind}")
                print(f"At line: {node.loc.start.line}")
                if node.kind == "var":
                    for declaration in node.declarations:
                        if hasattr(declaration, 'id'):
                            self.initialized_variables.add((declaration.id.name, node.loc.start.line))
                            print(f"Visiting variable: {declaration.id.name}")

            elif node.type == "FunctionDeclarator":
                print(f"Visiting function: {node.id.name}")
                print(f"At line: {node.loc.start.line}")
                self.visit(node.body)
            else:
                print(f"Visiting node of type: {node.type}")
                print(f"At line: {node.loc.start.line}")
                for child in node:
                    self.visit(child)
                
        # Recursively visit child nodes
        # Only iterate if node is a non-string, non-method iterable
        
            
            
    def get_initialied_vars(self):
        return self.initialized_variables
    