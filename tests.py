from models.pattern import Pattern
from models.multilabel import MultiLabel
from models.policy import Policy
from models.multilabelling import MultiLabelling
from models.vulnerabilities import Vulnerabilities


if __name__ == "__main__":
   # Define patterns
   # dom_xss = Pattern(
   #     name="DOM XSS",
   #     sources=["document.URL"],
   #     sanitizers=["DOMPurify.sanitize"],
   #     sinks=["document.write"]
   # )

   # patterns = [dom_xss]
   # policy = Policy(patterns)
   # Load patterns and slices
   from utils.ast_parser import Parser
   from utils.ast_traversal import TraversalVisitor
   from utils.load_patterns_and_slices import load_pattern_and_slice
   pattern, ast = load_pattern_and_slice("1a-basic-flow.patterns.json", "1a-basic-flow.js")
   policy = Policy(pattern)
   
   # Simulate a program
   multilabel = MultiLabel(pattern)
  
   
   # Test AST Traversal
   visitor = TraversalVisitor(policy)
   visitor.visit(ast)  # ast is the top-level Program node
   print("=== Initialized Variables ===")
   for var in visitor.get_initialized_vars():
      print(f"Variable: {var[0]}, Line: {var[1]}")

   print("=== Vulnerabilities ===")
   for vuln in visitor.get_vulnerabilities():
      print(vuln)
   
   # Export vulnerabilities to JSON
   visitor.get_output("vulnerabilities.json")

   print("=== MultiLabelling ===")
   for var, label in visitor.labelling.get_all_mappings().items():
      print(f"Variable: {var}, Label: {label}")

