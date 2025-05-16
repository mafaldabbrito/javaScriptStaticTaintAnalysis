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

   # # Simulate a program
   # multilabel = MultiLabel(patterns)
   # multilabel.add_source("DOM XSS", "document.URL")
   # multilabel.add_sanitizer("DOM XSS",  "document.URL", "DOMPurify.sanitize")  # <- Comment this line to test unsanitized

   # # Track variable flows
   # env = MultiLabelling()
   # env.set_multilabel("output", multilabel)

   # # Check for illegal flow
   # illegal_flows = policy.detect_illegal_flows("document.write", env.get_multilabel("output"))

   # # Report
   # vulnerabilities = Vulnerabilities()
   # source_positions = {
   #     "document.URL": 1,
   #     "DOMPurify.sanitize": 3
   # }
   # sink_position = 4

   # vulnerabilities.add_illegal_flow("document.write", illegal_flows, source_positions, sink_position)

   # print("=== Detected Vulnerabilities ===")
   # for v in vulnerabilities.get_all():
   #     print(v)

   # vulnerabilities.export_json("vulnerabilities_report.json")
   # print("\nReport saved to vulnerabilities_report.json")

   # Test AST Parser
   from utils.ast_parser import Parser
   from utils.ast_traversal import TraversalVisitor
   parser=Parser("test.js")
   ast = parser.parse_js_code()
   # if ast_tree:
   #     print("AST Tree:")
   #     print(ast_tree)
   # else:
   #     print("Failed to parse the JavaScript code.")
   # Test AST Traversal
   visitor = TraversalVisitor()
   visitor.visit(ast)  # ast is the top-level Program node
   print("=== Initialized Variables ===")
   for var in visitor.get_initialized_vars():
      print(f"Variable: {var[0]}, Line: {var[1]}")
