from models.label import Label

class MultiLabel:
    def __init__(self, patterns):
        """
        Constructor for MultiLabel.

        Generalizes the Label class in order to be able to represent distinct
        labels corresponding to different patterns for a specific resources.

        :param patterns: A list of Pattern objects.
        """
        self._labels = {}  # pattern_name -> Label
        self._patterns = {}  # pattern_name -> Pattern

        for pattern in patterns:
            name = pattern.get_name()
            self._labels[name] = Label()
            self._patterns[name] = pattern

    def add_source(self, pattern_name, source_name, line, sanitizers=None):
        """
        Add a source to the label associated with a given pattern,
        :param pattern_name: Name of the pattern.
        :param source_name: Name of the source.
        :param line: Line number where the source is found.
        :param sanitizers: Optional list of (sanitizer_name, line) tuples.
        """
        if pattern_name in self._patterns:
            self._labels[pattern_name].add_source(source_name, line, sanitizers)

    def add_sanitizer(self, pattern_name, source_name, sanitizer_name, line):
        """
        Add a sanitizer to the label associated with a given pattern,
        :param pattern_name: Name of the pattern.
        :param source_name: Name of the source.
        :param sanitizer_name: Name of the sanitizer.
        :param line: Line number where the sanitizer is found.
        """
        if pattern_name in self._patterns:
            self._labels[pattern_name].add_sanitizer(source_name, sanitizer_name, line)

    # Selectors
    def get_label(self, pattern_name):
        """Return the Label object for a specific pattern name."""
        return self._labels.get(pattern_name)

    def get_all_labels(self):
        """Return a copy of all labels."""
        return dict(self._labels)

    # Combinor
    def combine(self, other):
        """
        Combine this MultiLabel with another one, returning a new MultiLabel.
        Only patterns present in both will be combined.
        """
        if other is None:
            return self
        combined_patterns = list(self._patterns.values())
        new_multilabel = MultiLabel(combined_patterns)

        for pattern_name in self._labels:
            if pattern_name in other._labels:
                label1 = self._labels[pattern_name]
                label2 = other._labels[pattern_name]
                combined_label = label1.combine(label2)
                new_multilabel._labels[pattern_name] = combined_label

        for pattern_name in self._labels:
            if pattern_name in other._labels:
                label1 = self._labels[pattern_name]
                label2 = other._labels[pattern_name]
                combined_label = label1.combine(label2)
                self._labels[pattern_name] = combined_label
        return self
    def __repr__(self):
        """
        String representation of the MultiLabel.
        """
        return f"MultiLabel ({self._labels})"
