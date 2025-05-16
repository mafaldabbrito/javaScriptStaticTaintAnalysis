#!/bin/bash

# Arrays of JavaScript files and corresponding pattern and validation files
JS_FILES=(
    "slices/1-basic-flow/1a-basic-flow.js"
    "slices/1-basic-flow/1b-basic-flow.js"
    "slices/2-expr-binary-ops/2-expr-binary-ops.js"
    "slices/3-expr/3a-expr-func-calls.js"
    "slices/3-expr/3b-expr-func-calls.js"
    "slices/3-expr/3c-expr-attributes.js"
    "slices/3-expr/3d-expr-test.js"
    "slices/4-conds-branching/4a-conds-branching.js"
    "slices/4-conds-branching/4b-conds-branching.js"
    "slices/5-loops/5a-loops-unfolding.js"
    "slices/5-loops/5b-loops-unfolding.js"
    "slices/5-loops/5c-loops-unfolding.js"
    "slices/6-sanitization/6a-sanitization.js"
    "slices/6-sanitization/6b-sanitization.js"
    "slices/7-conds-implicit/7-conds-implicit.js"
    "slices/8-loops-implicit/8-loops-implicit.js"
    "slices/9-regions-guards/9-regions-guards.js"
)

PATTERN_FILES=(
    "patterns/1-basic-flow/1a-basic-flow.patterns.json"
    "patterns/1-basic-flow/1b-basic-flow.patterns.json"
    "patterns/2-expr-binary-ops/2-expr-binary-ops.patterns.json"
    "patterns/3-expr/3a-expr-func-calls.patterns.json"
    "patterns/3-expr/3b-expr-func-calls.patterns.json"
    "patterns/3-expr/3c-expr-attributes.patterns.json"
    "patterns/3-expr/3d-expr-test.patterns.json"
    "patterns/4-conds-branching/4a-conds-branching.patterns.json"
    "patterns/4-conds-branching/4b-conds-branching.patterns.json"
    "patterns/5-loops/5a-loops-unfolding.patterns.json"
    "patterns/5-loops/5b-loops-unfolding.patterns.json"
    "patterns/5-loops/5c-loops-unfolding.patterns.json"
    "patterns/6-sanitization/6a-sanitization.patterns.json"
    "patterns/6-sanitization/6b-sanitization.patterns.json"
    "patterns/7-conds-implicit/7-conds-implicit.patterns.json"
    "patterns/8-loops-implicit/8-loops-implicit.patterns.json"
    "patterns/9-regions-guards/9-regions-guards.patterns.json"
)

OUTPUT_FILES=(
    "output/1a-basic-flow.output.json"
    "output/1b-basic-flow.output.json"
    "output/2-expr-binary-ops.output.json"
    "output/3a-expr-func-calls.output.json"
    "output/3b-expr-func-calls.output.json"
    "output/3c-expr-attributes.output.json"
    "output/3d-expr-test.output.json"
    "output/4a-conds-branching.output.json"
    "output/4b-conds-branching.output.json"
    "output/5a-loops-unfolding.output.json"
    "output/5b-loops-unfolding.output.json"
    "output/5c-loops-unfolding.output.json"
    "output/6a-sanitization.output.json"
    "output/6b-sanitization.output.json"
    "output/7-conds-implicit.output.json"
    "output/8-loops-implicit.output.json"
    "output/9-regions-guards.output.json"
)

VALIDATION_FILES=(
    "tests/1a.json"
    "tests/1b.json"
    "tests/2.json"
    "tests/3a.json"
    "tests/3b.json"
    "tests/3c.json"
    "tests/3d.json"
    "tests/4a.json"
    "tests/4b.json"
    "tests/5a.json"
    "tests/5b.json"
    "tests/5c.json"
    "tests/6a.json"
    "tests/6b.json"
    "tests/7.json"
    "tests/8.json"
    "tests/9.json"
)

# Test identifiers corresponding to the file sets
TEST_IDS=("1a" "1b" "2" "3a" "3b" "3c" "3d" "4a" "4b" "5a" "5b" "5c" "6a" "6b" "7" "8" "9")

# Ensure all arrays have the same number of elements
if [[ ${#JS_FILES[@]} -ne ${#PATTERN_FILES[@]} ]] || [[ ${#JS_FILES[@]} -ne ${#OUTPUT_FILES[@]} ]] || [[ ${#JS_FILES[@]} -ne ${#VALIDATION_FILES[@]} ]]; then
    echo "Error: Arrays are not of the same length."
    exit 1
fi

# Function to run selected tests based on provided arguments
run_tests() {
    local selected_tests=("$@")
    for i in "${!JS_FILES[@]}"; do
        local test_id=${TEST_IDS[i]}

        # Check if the current test ID is in the selected tests
        if [[ " ${selected_tests[@]} " =~ " ${test_id} " ]]; then
            JS_FILE=${JS_FILES[i]}
            PATTERN_FILE=${PATTERN_FILES[i]}
            OUTPUT_FILE=${OUTPUT_FILES[i]}
            VALIDATION_FILE=${VALIDATION_FILES[i]}
            
            echo "Running test $test_id with:"
            echo "JS File: $JS_FILE"
            echo "Pattern File: $PATTERN_FILE"
            echo "Output File: $OUTPUT_FILE"
            echo "Validation File: $VALIDATION_FILE"
            
            # Step 1: Run the JS Analyzer
            echo "Running JS Analyzer..."
            if python3 js_analyzer.py "$JS_FILE" "$PATTERN_FILE"; then
                echo "JS Analyzer completed successfully."
            else
                echo "Error running JS Analyzer for $JS_FILE. Skipping test $test_id."
                continue
            fi
            
            # Step 2: Run the validation
            echo "Running validation..."
            if python3 tests/validate.py -o "$OUTPUT_FILE" -t "$VALIDATION_FILE"; then
                echo "Validation completed successfully."
            else
                echo "Error during validation for $OUTPUT_FILE. Skipping test $test_id."
                continue
            fi

            echo "Test $test_id completed successfully."
            echo "----------------------------------------"
        fi
    done
    echo "Selected tests completed."
}

# Check if any arguments were provided
if [[ $# -eq 0 ]]; then
    echo "No test identifiers provided. Please provide test identifiers like '1a', '1b', '2', etc."
    exit 1
fi

# Run the tests with the provided arguments
run_tests "$@"
