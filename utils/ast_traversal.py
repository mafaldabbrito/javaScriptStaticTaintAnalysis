class NodeVisitor:
    def visit(self, node):
        if not hasattr(node, 'type'):
            return

        method_name = f'visit_{node.type}'
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        if not hasattr(node, 'type') or node.type is None:
            return
        print(f"Generic visit for node type: {node.type}")
        for key, value in vars(node).items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self.visit(item)
            elif hasattr(value, 'type'):
                self.visit(value)


class TraversalVisitor(NodeVisitor):
    def __init__(self):
        self.initialized_variables = set()

    def visit_VariableDeclaration(self, node):
        print(f"=== Variable declaration: {node.kind} ===")
        print(f"At line: {node.loc.start.line}")
        if node.kind == "var":
            for declaration in node.declarations:
                if hasattr(declaration, 'id'):
                    self.initialized_variables.add((declaration.id.name, node.loc.start.line))
                    print(f"Initialized variable: {declaration.id.name}")
        print(f"=== End of Variable declaration ===")

    def visit_FunctionDeclaration(self, node):
        print(f"=== Function: {node.id.name} ===")
        print(f"At line: {node.loc.start.line}")
        if hasattr(node.body, 'body'):
            for stmt in node.body.body:
                if hasattr(stmt, 'type') and not stmt.type == "VariableDeclaration":
                    self.visit(stmt)
        print(f"=== End of Function: {node.id.name} ===")

    def visit_AssignmentExpression(self, node):
        print(f"=== Assignment: {node.left.name} ===")
        print(f"At line: {node.loc.start.line}")
        if hasattr(node.left, 'name'):
            self.initialized_variables.add((node.left.name, node.loc.start.line))
            print(f"Assigned variable: {node.left.name}")
        print(f"=== End of Assignment ===")
        
                

    def visit_Program(self, node):
        for stmt in node.body:
            self.visit(stmt)

    def get_initialized_vars(self):
        return self.initialized_variables
