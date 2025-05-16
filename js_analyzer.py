from models.pattern import Pattern
from models.multilabel import MultiLabel
from models.policy import Policy
from models.multilabelling import MultiLabelling
from models.vulnerabilities import Vulnerabilities


if __name__ == "__main__":

   from utils.ast_traversal import TraversalVisitor
   from utils.load_patterns_and_slices import load_pattern_and_slice
   import sys
   import os

   if len(sys.argv) != 3:
      print("Usage: python js_analyzer.py <js_file> <pattern_file>")
      sys.exit(1)
   pattern_file = sys.argv[2]
   js_file = sys.argv[1]
   pattern, ast = load_pattern_and_slice(pattern_file, js_file)
   policy = Policy(pattern)
   
   # Create a MultiLabel object
   multilabel = MultiLabel(pattern)
  
   
   # Start AST Traversal
   visitor = TraversalVisitor(policy)
   visitor.visit(ast)  # ast is the top-level Program node

   print("=== Initialized Variables ===")
   for var in visitor.get_initialized_vars():
      print(f"Variable: {var}")

   print("=== Vulnerabilities ===")
   for vuln in visitor.get_vulnerabilities():
      print(vuln)
   
   # Export vulnerabilities to JSON
   base_name = os.path.basename(js_file)
   name_only = base_name.split('.')[0]
   output_file = f"{name_only}.output.json"
   visitor.get_output(output_file)

   print("=== MultiLabelling ===")
   for var, label in visitor.labelling.get_all_mappings().items():
      print(f"Variable: {var}, Label: {label}")

