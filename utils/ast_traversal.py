from models.multilabel import MultiLabel
from models.multilabelling import MultiLabelling
from models.vulnerabilities import Vulnerabilities


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



# The TraversalVisitor should:
# - Visit function calls and variable declarations/assignments and eventually function calls .
# - Use the Policy to check:
#     - If a function call is a source, sink, or sanitizer.
# - Maintain per-variable labels via MultiLabelling.
# - When visiting a sink:
#     - Use Policy.detect_illegal_flows(...) to check for unsafe data flows.
# For that the Visitor should own:
# - A Policy instance
# - A MultiLabelling instance


class TraversalVisitor(NodeVisitor):
    def __init__(self, policy):
        self.initialized_variables = set()
        self.policy = policy
        self.labelling = MultiLabelling()
        self.vulnerabilities = Vulnerabilities()


    def visit_VariableDeclaration(self, node):

        print(f"=== Variable declaration: {node.kind} ===")
        print(f"At line: {node.loc.start.line}")
        if node.kind == "var":
            for declaration in node.declarations:
                if hasattr(declaration, 'id'):
                    self.initialized_variables.add(declaration.id.name)
                    print(f"Initialized variable: {declaration.id.name}")
                    if hasattr(declaration, 'init'):
                        if hasattr(declaration.init, 'type') and declaration.init.type == "FunctionExpression":
                            self.visit(declaration.init)
                        elif hasattr(declaration.init, 'type') and declaration.init.type == "CallExpression":
                            self.visit(declaration.init)
                        elif hasattr(declaration.init, 'type') and declaration.init.type == "AssignmentExpression":
                            self.visit(declaration.init)
                        elif hasattr(declaration.init, 'type') and declaration.init.type == "Identifier":
                            for pname in self.policy.get_patterns_with_source(declaration.init.name):

                                print(f"Source detected: {declaration.init.name} in pattern {pname}")
                                label = self.labelling.get_multilabel(declaration.id.name) or MultiLabel(list(self.policy._patterns.values()))
                                label.add_source(pname, declaration.init.name, declaration.loc.start.line)
                                self.labelling.set_multilabel(declaration.id.name, label)
                            
                            print(f"Assigned variable: {declaration.init.name}")

                            for pname in self.policy.get_patterns_with_sink(declaration.id.name):

                                print(f"Sink detected: {declaration.id.name} in pattern {pname}")
                                multi_label = self.labelling.get_multilabel(declaration.id.name)
                                if multi_label:
                                    illegal_flows = self.policy.detect_illegal_flows(declaration.id.name, multi_label)
                                    print(illegal_flows)
                                    if illegal_flows:
                                        self.vulnerabilities.add_illegal_flow(declaration.id.name, illegal_flows, declaration.loc.start.line)
                                        
                                        print(f"Illegal flow detected for variable: {declaration.id.name} in pattern {pname}")
                                        # Handle illegal flows as needed
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
            self.initialized_variables.add(node.left.name)
            print(f"Initialized variable: {node.left.name}")
            if hasattr(node.right, 'type') and node.right.type == "CallExpression":
                current_label = self.labelling.get_multilabel(node.left.name) or MultiLabel(list(self.policy._patterns.values()))

                for pname in self.policy.get_patterns_with_source(node.right.callee.name):
                    print(f"Source detected: {node.right.callee.name} in pattern {pname}")
                    current_label.add_source(pname, node.right.callee.name, node.loc.start.line)
                    
                # Combine the labels from the right side with the left side and set it
                current_label.combine(self.labelling.get_multilabel(node.right.callee.name))
                self.labelling.set_multilabel(node.left.name, current_label)

                for pname in self.policy.get_patterns_with_sink(node.left.name):
                    print(f"Sink detected: {node.left.name} in pattern {pname}")
                    multi_label = self.labelling.get_multilabel(node.left.name)
                    if multi_label:
                        illegal_flows = self.policy.detect_illegal_flows(node.left.name, multi_label)
                        print(illegal_flows)
                        if illegal_flows:
                            self.vulnerabilities.add_illegal_flow(node.left.name, illegal_flows, node.loc.start.line)
                            print(f"Illegal flow detected for variable: {node.left.name} in pattern {pname}")

                self.visit(node.right)
            elif hasattr(node.right, 'type') and node.right.type == "Identifier":

                current_label = self.labelling.get_multilabel(node.left.name) or MultiLabel(list(self.policy._patterns.values()))
                print(f"Assigned variable: {node.right.name}")


                if node.right.name not in self.initialized_variables:
                    for pname in self.policy.get_patterns_without_source(node.right.name):
                        print(f"Source added: {node.right.name} in pattern {pname}")
                        current_label.add_source(pname, node.right.name, node.loc.start.line)
                       

                # Check if the right side is a source
                for pname in self.policy.get_patterns_with_source(node.right.name):
                    print(f"Source detected: {node.right.name} in pattern {pname}")
                    current_label.add_source(pname, node.right.name, node.loc.start.line)
                    
                # Combine the labels from the right side with the left side and set it
                current_label.combine(self.labelling.get_multilabel(node.right.name))
                self.labelling.set_multilabel(node.left.name, current_label)

                for pname in self.policy.get_patterns_with_sink(node.left.name):
                    print(f"Sink detected: {node.left.name} in pattern {pname}")
                    multi_label = self.labelling.get_multilabel(node.left.name)
                    if multi_label:
                        illegal_flows = self.policy.detect_illegal_flows(node.left.name, multi_label)
                        print(illegal_flows)
                        if illegal_flows:
                            self.vulnerabilities.add_illegal_flow(node.left.name, illegal_flows, node.loc.start.line)
                            print(f"Illegal flow detected for variable: {node.left.name} in pattern {pname}")
        print(f"=== End of Assignment ===")     

    def visit_CallExpression(self, node):
        print(f"=== Function call: {node.callee.name} ===")
        print(f"At line: {node.loc.start.line}")
        
        function_label = self.labelling.get_multilabel(node.callee.name) or MultiLabel(list(self.policy._patterns.values()))

        if hasattr(node, 'arguments'):

            for arg in node.arguments:
                if hasattr(node.right, 'type') and node.right.type == "CallExpression":
                    self.visit(node.right)

                elif hasattr(arg, 'type') and arg.type == "Identifier":
                   

                    if arg.name not in self.initialized_variables:
                        
                        for pname in self.policy.get_patterns_without_source(arg.name):
                            print(f"Source added: {arg.name} in pattern {pname}")
                            function_label.add_source(pname, arg.name, node.loc.start.line)
                            

                    for pname in self.policy.get_patterns_with_source(arg.name):
                        print(f"Source detected: {arg.name} in pattern {pname}")
                        function_label.add_source(pname, arg.name, node.loc.start.line)

                    # Combine the labels from the right side with the left side but don't set it because it's a function call
                    function_label.combine(self.labelling.get_multilabel(arg.name))

        for pname in self.policy.get_patterns_with_sink(node.callee.name):
                    print(f"Sink function detected: {node.callee.name} in pattern {pname}")
                    if function_label:
                        illegal_flows = self.policy.detect_illegal_flows(node.callee.name, function_label)
                        print(illegal_flows)
                        if illegal_flows:
                            self.vulnerabilities.add_illegal_flow(node.callee.name, illegal_flows, node.loc.start.line)
                            print(f"Illegal flow detected for variable: {node.callee.name} in pattern {pname}")        
        print(f"=== End of Function call ===")


    def visit_Program(self, node):
        for stmt in node.body:
            self.visit(stmt)

    def get_vulnerabilities(self):
        return self.vulnerabilities.get_all()
    
    def get_output(self, filepath):
        return self.vulnerabilities.export_json(filepath)

    def get_initialized_vars(self):
        return self.initialized_variables
