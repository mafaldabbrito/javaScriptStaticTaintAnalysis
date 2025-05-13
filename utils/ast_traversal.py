from collections.abc import Iterable

class TraversalVisitor:
    def __init__(self):
        self.visited_nodes = []

    def visit(self, node):
        if node not in self.visited_nodes:
            if hasattr(node, 'type'):
                if node.type == "Program":
                    node = node.body
                elif node.type == "VariableDeclaration":
                    print(f"Visiting variable declaration: {node.kind}")
                    print(f"At line: {node.range[0]}")
                    self.visit(node.declarations)
                elif node.type == "FunctionDeclarator":
                    print(f"Visiting function: {node.id.name}")
                    print(f"At line: {node.range[0]}")
                    self.visit(node.body)
                else:
                    print(f"Visiting node of type: {node.type}")
                    print(f"At line: {node.range[0]}")
                    
            # Recursively visit child nodes
            # Only iterate if node is a non-string, non-method iterable
            if isinstance(node, Iterable) and not isinstance(node, (str, bytes)) and not callable(node):
                for child in node:
                    self.visit(child)
            
    def get_visited_nodes(self):
        return self.visited_nodes