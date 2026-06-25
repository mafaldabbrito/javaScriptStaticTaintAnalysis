# JavaScript Static Taint Analysis

A Python-based static analysis tool that detects information flow vulnerabilities in JavaScript code. The analyzer identifies taint flows from **sources** (data entry points) through **sinks** (dangerous operations), while tracking sanitization functions that mitigate risks.

## Overview

This tool performs **static taint analysis** on JavaScript code by:
1. Parsing JavaScript files into an Abstract Syntax Tree (AST)
2. Defining vulnerability patterns (sources, sinks, sanitizers)
3. Traversing the AST to track variable assignments and data flows
4. Identifying potential security vulnerabilities where unsanitized data reaches dangerous operations

### Key Concepts

- **Source**: A function that introduces potentially untrusted data (e.g., `document.URL`, `user.input()`)
- **Sink**: A dangerous operation that should only receive trusted data (e.g., `eval()`, `innerHTML`, `SQL queries`)
- **Sanitizer**: A function that cleans/validates data, breaking taint propagation (e.g., `encodeURI()`, `parseInt()`)
- **Taint Flow**: A path from a source to a sink that hasn't been sanitized

## Project Structure

```
.
├── js_analyzer.py              # Main entry point
├── models/                      # Core object models
│   ├── pattern.py              # Pattern class: defines sources, sinks, sanitizers
│   ├── policy.py               # Policy class: applies vulnerability patterns
│   ├── label.py                # Label class: tracks taint for a single pattern
│   ├── multilabel.py           # MultiLabel class: manages multiple pattern labels
│   ├── multilabelling.py       # MultiLabelling class: maps variables to their labels
│   └── vulnerabilities.py      # Vulnerabilities class: stores and exports findings
├── utils/                       # Utility modules
│   ├── ast_parser.py           # Parses JavaScript into AST
│   ├── ast_traversal.py        # AST visitor pattern for taint analysis
│   └── load_patterns_and_slices.py  # Loads pattern and code files
├── patterns/                    # JSON pattern definitions (organized by test category)
├── slices/                      # JavaScript test cases
├── tests/                       # Validation scripts and expected outputs
└── test.sh                      # Test runner script
```

## Usage

### Basic Usage

```bash
python js_analyzer.py <javascript_file> <pattern_file>
```

**Example:**
```bash
python js_analyzer.py slices/1-basic-flow/1a-basic-flow.js patterns/1-basic-flow/1a-basic-flow.patterns.json
```

### Running Tests

```bash
# Run all tests
./test.sh 1a 1b 2 3a 3b 3c 3d 4a 4b 5a 5b 5c 6a 6b 7 8 9

# Run specific tests
./test.sh 1a 2 6a
```

## How It Works

### 1. Pattern Definition (JSON)

Patterns define vulnerability rules in JSON format:

```json
{
  "pattern": "XSS",
  "sources": ["document.URL", "user.input"],
  "sinks": ["innerHTML", "document.write"],
  "sanitizers": ["encodeURI", "escapeHTML"],
  "implicit": false
}
```

### 2. AST Parsing & Traversal

- **AST Parser** converts JavaScript code into an abstract syntax tree
- **TraversalVisitor** walks the tree using the Visitor pattern
- For each node, the analyzer tracks variable assignments and function calls

### 3. Taint Propagation

- When a **source** is encountered, the variable is marked as tainted
- When a **sink** is encountered, the analyzer checks if the variable is tainted
- When a **sanitizer** is called on a tainted variable, the taint is removed
- **Control flow** (conditionals, loops) is analyzed to handle implicit flows

### 4. Output

Vulnerabilities are exported to JSON with:
- Vulnerability type (pattern name)
- Source function and location
- Sink function and location
- Data flow path

## Architecture & Design Patterns

### Object-Oriented Design (OOP)

The project demonstrates core OOP principles:

#### 1. **Encapsulation**
- Each model class encapsulates related data and behavior
- Private attributes (`_vulns`, `_pattern_counters`) hide implementation details
- Getter methods provide controlled access to data

```python
class Pattern:
    def __init__(self, name, sources, sanitizers, sinks, implicit):
        self.sources = set(sources)      # Encapsulated as set for O(1) lookup
        self.sanitizers = set(sanitizers)
        self.sinks = set(sinks)
    
    def is_source(self, source: str):  # Controlled access
        return source in self.sources
```

#### 2. **Single Responsibility Principle**
- **Pattern**: Defines vulnerability patterns
- **Policy**: Applies patterns to specific vulnerabilities
- **MultiLabel**: Manages labels for a single variable
- **Vulnerabilities**: Collects and exports findings
- **TraversalVisitor**: Handles AST traversal and taint analysis

#### 3. **Visitor Pattern**
- `NodeVisitor` base class implements the Visitor pattern
- `TraversalVisitor` extends it to add taint analysis behavior
- Decouples traversal logic from node structure

```python
class NodeVisitor:
    def visit(self, node):
        method_name = f'visit_{node.type}'
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

class TraversalVisitor(NodeVisitor):
    def visit_CallExpression(self, node):
        # Handle function calls during traversal
        ...
```

#### 4. **Composition Over Inheritance**
- `TraversalVisitor` composes `MultiLabelling`, `Policy`, and `Vulnerabilities`
- Each component handles its own responsibility
- Flexible and maintainable

#### 5. **Data Abstraction**
- Complex data relationships abstracted into classes
- Sets used for efficient lookups (sources, sinks, sanitizers)
- Dictionaries used for variable-to-label mappings

### Static Analysis Techniques

#### 1. **AST-Based Analysis**
- Parses JavaScript into an abstract syntax tree
- Enables precise program analysis without executing code
- Handles complex control flow structures

#### 2. **Data Flow Analysis**
- Tracks taint propagation through assignments
- Handles function calls and parameter passing
- Manages implicit flows through control structures

#### 3. **Pattern Matching**
- Defines security policies as patterns (sources + sinks + sanitizers)
- Flexible: different patterns for different vulnerability types
- Reusable across multiple code bases

#### 4. **Fixed-Point Iteration**
- Implicit flow analysis may require multiple passes
- Variables re-evaluated until no new taints are discovered
- Ensures soundness for complex control flow

## Learning Outcomes

This project demonstrates practical applications of:

### 1. **Object-Oriented Programming**
- Class design and responsibility assignment
- Inheritance and composition
- Design patterns (Visitor, Observer patterns)
- Encapsulation and data hiding

### 2. **Static Analysis**
- Abstract Syntax Trees (AST) and parsing
- Data flow analysis (taint tracking)
- Control flow analysis
- Fixed-point iteration for iterative analysis

### 3. **Software Architecture**
- Separation of concerns (models, utilities, analysis)
- Visitor pattern for tree traversal
- Configuration-driven analysis (pattern files)
- Extensibility through modular design

### 4. **Security Analysis**
- Source-sink analysis for vulnerability detection
- Sanitization-aware taint tracking
- Information flow security
- Implicit vs. explicit flows

### 5. **Python Programming**
- Set operations for efficient membership testing
- Dictionary-based mapping structures
- JSON parsing and generation
- Class methods and property management
- String representation methods (`__str__`, `__repr__`)

### 6. **Practical Vulnerability Detection**
- Real-world security patterns
- XSS, injection, and code execution vulnerabilities
- Understanding data flow security properties

## Example Test Case

### JavaScript Code (`slices/1-basic-flow/1a-basic-flow.js`)
```javascript
var x = document.URL;      // Source: x is tainted
var y = x;                 // y inherits taint
eval(y);                   // Sink: VULNERABILITY - tainted data to eval()
```

### Pattern (`patterns/1-basic-flow/1a-basic-flow.patterns.json`)
```json
{
  "pattern": "Code Injection",
  "sources": ["document.URL"],
  "sinks": ["eval"],
  "sanitizers": [],
  "implicit": false
}
```

### Output
The analyzer detects that `x` flows from `document.URL` (source) to `eval` (sink) without sanitization.

## Extending the Tool

### Adding a New Pattern

1. Create a pattern JSON file with sources, sinks, and sanitizers
2. Create corresponding test JavaScript file
3. Run the analyzer: `python js_analyzer.py <js_file> <pattern_file>`
4. Add validation test to verify expected vulnerabilities

### Adding Analysis Features

- Modify `TraversalVisitor` in `utils/ast_traversal.py`
- Implement new `visit_*` methods for AST node types
- Update `MultiLabelling` to track additional properties

## Dependencies

- Python 3.x
- No external dependencies (uses built-in `json`, `ast` parsing modules)

## Future Enhancements

- Function summarization for interprocedural analysis
- Alias analysis for sophisticated data flow
- Constant propagation for value-based filtering
- Correlation-based implicit flow detection
- IDE integration for real-time vulnerability detection
