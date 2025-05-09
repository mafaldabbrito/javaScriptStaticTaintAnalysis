from models.multilabel import MultiLabel

class Policy:
    def __init__(self, patterns):
        """
        Constructor for Policy.
        :param patterns: A list of Pattern objects.
        """
        self._patterns = {pattern.get_name(): pattern for pattern in patterns}

    # Selectors
    def get_vulnerability_names(self):
        """Returns a list of all vulnerability pattern names."""
        return list(self._patterns.keys())

    def get_patterns_with_source(self, source_name):
        """Returns a list of pattern names for which the given name is a source."""
        return [name for name, p in self._patterns.items() if p.is_source(source_name)]

    def get_patterns_with_sanitizer(self, sanitizer_name):
        """Returns a list of pattern names for which the given name is a sanitizer."""
        return [name for name, p in self._patterns.items() if p.is_sanitizer(sanitizer_name)]

    def get_patterns_with_sink(self, sink_name):
        """Returns a list of pattern names for which the given name is a sink."""
        return [name for name, p in self._patterns.items() if p.is_sink(sink_name)]
    
    # Core flow-checking operation
    def detect_illegal_flows(self, name, multilabel):
        """
        Given a variable/function name and a MultiLabel describing the flow of data to it,
        return a new MultiLabel containing only the illegal flows.
        A flow is illegal if:
        - The name is a sink in a pattern
        - There is at least one source in the label for that pattern
        - And that source is not sanitized

        :param name: The name of the sink variable/function
        :param multilabel: A MultiLabel instance describing the current flows
        :return: A new MultiLabel with only the patterns where illegal flows occur
        """
        illegal_patterns = [
            pname for pname, pattern in self._patterns.items()
            if pattern.is_sink(name)
        ]

        result = MultiLabel(list(self._patterns.values()))

        for pname in illegal_patterns:
            label = multilabel.get_label(pname)
            if not label:
                continue

            pattern = self._patterns[pname]
            for source in label.get_sources():
               
                applied_sanitizers = label.get_sanitizers(source)

                # Add the source to the result regardless of sanitization
                result.add_source(pname, source)

                # Add all applied sanitizers to the result
                for sanitizer in applied_sanitizers:
                    result.add_sanitizer(pname, source, sanitizer)

        return result
