from copy import deepcopy
from models.multilabel import MultiLabel
from models.multilabelling import MultiLabelling
from models.vulnerabilities import Vulnerabilities


class NodeVisitor:
    def visit(self, node):
        """
        Visit a node in the AST by dispatching to the appropriate visit method based on node type.

        Parameters:
        node: The AST node to visit. Should have a 'type' attribute.

        Returns:
        The result of the specific visit method for the node type, or None if not applicable.
        """
        if not hasattr(node, 'type'):
            return

        method_name = f'visit_{node.type}'
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        """
        Default visit method for AST nodes without a specific visitor method.

        Parameters:
        node: The AST node to visit.

        Returns:
        None
        """
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
    def __init__(self, policy):
        """
        Initialize the TraversalVisitor with a policy, multilabelling, and vulnerabilities tracker.

        Parameters:
        policy: The Policy instance used for source, sink, and sanitizer detection.
        """
        self.initialized_variables = set()
        self.policy = policy
        self.labelling = MultiLabelling()
        self.vulnerabilities = Vulnerabilities()

    # Not tested in this implementation
    # TODO: test this function
    def visit_VariableDeclaration(self, node):
        """
        Visit a VariableDeclaration node in the AST and process variable initialization and labelling.

        Parameters:
        node: The AST node representing the variable declaration. Should have 'kind', 'declarations', and 'loc' attributes.

        Returns:
        None
        """
        print(f"=== Variable declaration: {node.kind} ===")
        print(f"At line: {node.loc.start.line}")
        if node.kind == "var":
            for declaration in node.declarations:
                if hasattr(declaration, 'id'):
                    self.initialized_variables.add(declaration.id.name)
                    print(f"Initialized variable: {declaration.id.name}")
                    if hasattr(declaration, 'init'):
                        if hasattr(declaration.init, 'type') and not declaration.init.type == "Identifier":
                            self.visit(declaration.init)
                        else:
                            for pname in self.policy.get_patterns_with_source(declaration.init.name):

                                print(f"Source detected: {declaration.init.name} in pattern {pname}")
                                label = self.labelling.get_multilabel(declaration.id.name) or MultiLabel(list(self.policy._patterns.values()))
                                label.add_source(pname, declaration.init.name, declaration.loc.start.line)
                                self.labelling.set_multilabel(declaration.id.name, label)
                            
                            print(f"Assigned variable: {declaration.init.name}")

                            self.analyze_if_sink_vulnerabilities(declaration.id.name, declaration.loc.start.line)

        print(f"=== End of Variable declaration ===")

    # Not tested in this implementation
    # TODO: test this function
    def visit_FunctionDeclaration(self, node):
        """
        Visit a FunctionDeclaration node in the AST and process its body.

        Parameters:
        node: The AST node representing the function declaration. Should have 'id', 'body', and 'loc' attributes.

        Returns:
        None
        """
        print(f"=== Function: {node.id.name} ===")
        print(f"At line: {node.loc.start.line}")
        if hasattr(node.body, 'body'):
            for stmt in node.body.body:
                if hasattr(stmt, 'type') and not stmt.type == "VariableDeclaration":
                    self.visit(stmt)
        print(f"=== End of Function: {node.id.name} ===")

    def visit_AssignmentExpression(self, node):
        """
        Visit an AssignmentExpression node in the AST and process variable assignment and labelling.

        Parameters:
        node: The AST node representing the assignment expression. Should have 'left', 'right', and 'loc' attributes.

        Returns:
        MultiLabel or None: The label resulting from the assignment, or None if not applicable.
        """
        new_label =  MultiLabel(list(self.policy._patterns.values()))
        print(f"=== Assignment: {node.left.name} ===")
        print(f"At line: {node.loc.start.line}")

        if hasattr(node.left, 'name'):

            self.initialized_variables.add(node.left.name)
            print(f"Initialized variable: {node.left.name}")

            # Visit the left side of the assignment
            # Label of the left side
            current_label = deepcopy(self.labelling.get_multilabel(node.left.name) or MultiLabel(list(self.policy._patterns.values())))

        # Visit the right side of the assignment
        # Combine the labels from the right side with the left side
        # Set the label for the left side
        new_label=self.visit(node.right)

        if hasattr(node.left, 'type') and node.left.type == "MemberExpression":
            self.initialized_variables.add(node.left.property.name)
            # combine the labels from the right and the object and property of the MemberExpression
            object_label = self.labelling.get_multilabel(node.left.object) or MultiLabel(list(self.policy._patterns.values()))
            property_label = self.labelling.get_multilabel(node.left.property) or MultiLabel(list(self.policy._patterns.values()))

            current_label = object_label.combine(new_label)
            self.labelling.set_multilabel(node.left.object.name, current_label)
            current_label = property_label.combine(new_label)
            self.labelling.set_multilabel(node.left.property.name, current_label)

            # Check if the left side is a sink and if so detect illegal flows and add them to the vulnerabilities
            self.analyze_if_sink_vulnerabilities(node.left.object.name, node.loc.start.line)
            
            self.analyze_if_sink_vulnerabilities(node.left.property.name, node.loc.start.line)

        else:
            new_label=current_label.combine(new_label)
            self.labelling.set_multilabel(node.left.name, current_label)

            # Check if the left side is a sink and if so detect illegal flows and add them to the vulnerabilities
            self.analyze_if_sink_vulnerabilities(node.left.name, node.loc.start.line)

        print(f"=== End of Assignment ===")    
        return new_label 

    
    def analyze_if_sink_vulnerabilities(self, sink_name, line, multi_label=None):
        """
        Analyze if the given variable or function is a sink and record any illegal flows found.

        Parameters:
        sink_name (str): The name of the variable or function to check as a sink.
        line (int): The line number in the source code where the sink occurs.
        multi_label (MultiLabel, optional): The label associated with the possible sink. If None, it will be retrieved from the labelling.

        Returns:
        None
        """
        for pname in self.policy.get_patterns_with_sink(sink_name):
            print(f"Sink detected: {sink_name} in pattern {pname}")
            if multi_label is None:
                multi_label = self.labelling.get_multilabel(sink_name)
            if multi_label:
                illegal_flows = self.policy.detect_illegal_flows(sink_name, multi_label)
                    
                if illegal_flows:
                    self.vulnerabilities.add_illegal_flow(sink_name, illegal_flows, line)
                    print(f"Illegal flow detected for variable: {sink_name} in pattern {pname}")

    def visit_CallExpression(self, node):
        """
        Visit a CallExpression node in the AST and process function call labelling, sources, sinks, and sanitizers.

        Parameters:
        node: The AST node representing the function call. Should have 'callee', 'arguments', and 'loc' attributes.

        Returns:
        MultiLabel or None: The label resulting from the function call, or None if not applicable.
        """
        new_label = MultiLabel(list(self.policy._patterns.values()))
        print(f"=== Function call: {node.callee.name} ===")
        print(f"At line: {node.loc.start.line}")
        
        function_label = self.labelling.get_multilabel(node.callee.name) or MultiLabel(list(self.policy._patterns.values()))

        if hasattr(node, 'arguments'):

            for arg in node.arguments:
                if hasattr(arg, 'type') and arg.type == "Literal":
                   continue

                # Visit the argument node
                new_label=self.visit(arg)
                
                # Combine the labels from the argument with the function label
                new_label=function_label.combine(new_label)

                # Check if the function is a sanitizer and add it to the label
                for pname in self.policy.get_patterns_with_sanitizer(node.callee.name):
                    print(f"Sanitizer detected: {node.callee.name} in pattern {pname}")
                    function_label.add_sanitizer(pname,node.callee.name, node.loc.start.line)
                    new_label=function_label

        if hasattr(node.callee, 'type') and node.callee.type == "MemberExpression":
            new_label=self.visit(node.callee.object)
            function_callee_name=node.callee.property.name

        else:
            function_callee_name=node.callee.name

        # Check if the function is a source and add it to the label
        for pname in self.policy.get_patterns_with_source(function_callee_name):
            print(f"Source detected: {function_callee_name} in pattern {pname}")
            new_label.add_source(pname, function_callee_name, node.loc.start.line)

        self.analyze_if_sink_vulnerabilities(function_callee_name, node.loc.start.line, new_label)

             
        print(f"=== End of Function call ===")
        return new_label


    def visit_BinaryExpression(self, node):
        """
        Visit a BinaryExpression node in the AST and compute the combined label for the expression.

        Parameters:
        node: The AST node representing the binary expression. It should have 'left', 'right', and 'operator' attributes.

        Returns:
        MultiLabel: The combined label resulting from the left and right operands of the binary expression.
        """

        new_label = MultiLabel(list(self.policy._patterns.values()))
        print(f"=== Binary expression: {node.operator} ===")
        print(f"At line: {node.loc.start.line}")
        if hasattr(node, 'right'):
            right_label=self.visit(node.right)
        if hasattr(node, 'left'):
            left_label=self.visit(node.left)
       
        if left_label is not None:
            left_label.combine(new_label)
            new_label=left_label.combine(right_label)
        elif right_label is not None:
            right_label.combine(new_label)
            new_label=right_label
                    
        print(f"=== End of Binary expression ===")

        return new_label
    

    
    def visit_Identifier(self, node):
        """
        Visit an Identifier node in the AST and retrieve or create its label.

        Parameters:
        node: The AST node representing the identifier. Should have 'name' and 'loc' attributes.

        Returns:
        MultiLabel: The label for the identifier, updated if it is a source.
        """

        print(f"=== Identifier: {node.name} ===")
        print(f"At line: {node.loc.start.line}")
        current_label= self.labelling.get_multilabel(node.name) or MultiLabel(list(self.policy._patterns.values()))
        
        # Check if the identifier is initialized if not add it as a source
        if node.name not in self.initialized_variables:
            for pname in self.policy.get_patterns_without_source(node.name):
                print(f"Source added: {node.name} in pattern {pname}")
                current_label.add_source(pname, node.name, node.loc.start.line)
        
        # Check if the identifier is a source
        for pname in self.policy.get_patterns_with_source(node.name):
            print(f"Source detected: {node.name} in pattern {pname}")
            current_label.add_source(pname, node.name, node.loc.start.line)

        return  current_label

    def visit_MemberExpression(self, node):
        """
        Visit a MemberExpression node in the AST and retrieve its label.

        Parameters:
        node: The AST node representing the member expression. Should have 'object' and 'property' attributes.

        Returns:
        MultiLabel: The label for the member expression.
        """
        print(f"=== Member expression: {node.object.name}.{node.property.name} ===")
        print(f"At line: {node.loc.start.line}")
        object_label= self.visit(node.object)
        property_label= self.visit(node.property)
        current_label=object_label.combine(property_label)
        
        return current_label
    
    def visit_IfStatement(self, node):
        """
        Visit an IfStatement node in the AST and process its consequent and alternate branches.

        Parameters:
        node: The AST node representing the if statement. Should have 'test', 'consequent', and 'alternate' attributes.

        Returns:
        None
        """ 
          
        print(f"=== If statement ===")
        print(f"At line: {node.loc.start.line}")
        # self.visit(node.test)
        consequent_visitor = deepcopy(self)
        consequent_visitor.visit(node.consequent)
        

        if hasattr(node, 'alternate'):
            alternate_visitor = deepcopy(self)
            alternate_visitor.visit(node.alternate)
            # Join the visitors to combine their findings
            self.join_visitors(alternate_visitor)
            
        self.join_visitors(consequent_visitor)

        print(f"=== End of If statement ===")
    
    def visit_Program(self, node):
        """
        Visit a Program node in the AST and process all statements in its body.

        Parameters:
        node: The AST node representing the program. Should have a 'body' attribute.

        Returns:
        None
        """
        for stmt in node.body:
            self.visit(stmt)

    def get_vulnerabilities(self):
        """
        Retrieve all detected vulnerabilities.

        Returns:
        list: A list of all detected vulnerabilities.
        """
        return self.vulnerabilities.get_all()
    
    def get_output(self, filepath):
        """
        Export detected vulnerabilities to a JSON file.

        Parameters:
        filepath (str): The path to the output JSON file.

        Returns:
        str: The path to the exported JSON file.
        """
        return self.vulnerabilities.export_json(filepath)

    def get_initialized_vars(self):
        """
        Get the set of initialized variable names.

        Returns:
        set: The set of initialized variable names.
        """
        return self.initialized_variables
    
    def join_visitors(self, other):
        """
        Join the current visitor with another visitor.

        Parameters:
        other: Another TraversalVisitor instance to join with.

        Returns:
        None
        """
        self.labelling.combine(other.labelling)
        self.vulnerabilities.combine(other.vulnerabilities)
        
