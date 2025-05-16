class Label:
    """
    Represents the integrity of information that is carried by a resource for a specific pattern.
    Now tracks the line location for each source and sanitizer.
    """
    def __init__(self):
        """
        Constructor for an empty Label object.
        """
        # Dict[str, Dict[str, Any]]
        # Each source maps to {'line': int, 'sanitizers': Dict[str, int]}
        self.source_sanitizers = {}

    def add_source(self, source_name, line, sanitizers=None):
        """
        Adds a new source to the label with optional sanitizers.
        :param source_name: Name of the source.
        :param line: Line number where the source is found.
        :param sanitizers: Optional list of (sanitizer_name, line) tuples.
        """
        if source_name not in self.source_sanitizers:
            self.source_sanitizers[source_name] = {
                'line': line,
                'sanitizers': {}
            }
            if sanitizers:
                for sanitizer_name, sanitizer_line in sanitizers:
                    self.source_sanitizers[source_name]['sanitizers'][sanitizer_name] = sanitizer_line

    def add_sanitizer(self, source_name, sanitizer_name, line):
        """
        Adds a sanitizer to a specific source.
        :param source_name: Name of the source.
        :param sanitizer_name: Name of the sanitizer.
        :param line: Line number where the sanitizer is found.
        """
        if source_name in self.source_sanitizers:
            self.source_sanitizers[source_name]['sanitizers'][sanitizer_name] = line
        else:
            self.source_sanitizers[source_name] = {
                'line': None,
                'sanitizers': {sanitizer_name: line}
            }

    # Selectors
    def get_sources(self):
        # Returns list of (source_name, line)
        return [(src, data['line']) for src, data in self.source_sanitizers.items()]

    def get_sanitizers(self, source_name):
        # Returns list of (sanitizer_name, line)
        if source_name in self.source_sanitizers:
            return list(self.source_sanitizers[source_name]['sanitizers'].items())
        return []

    # Combinor
    def combine(self, other_label):
        """
        Combines the current label with another label, returning a new independent Label object.
        Sanitizers are preserved per source.
        :param other_label: Another Label instance.
        :return: A new Label instance.
        """
        new_label = Label()

        # Copy current sources and sanitizers
        for source, data in self.source_sanitizers.items():
            new_label.source_sanitizers[source] = {
                'line': data['line'],
                'sanitizers': dict(data['sanitizers'])
            }

        # Merge with other label
        for source, data in other_label.source_sanitizers.items():
            if source in new_label.source_sanitizers:
                # Keep the earliest line number for the source
                if data['line'] is not None:
                    if (new_label.source_sanitizers[source]['line'] is None or
                        data['line'] < new_label.source_sanitizers[source]['line']):
                        new_label.source_sanitizers[source]['line'] = data['line']
                # Merge sanitizers, keeping earliest line
                for sanitizer, line in data['sanitizers'].items():
                    if (sanitizer not in new_label.source_sanitizers[source]['sanitizers'] or
                        line < new_label.source_sanitizers[source]['sanitizers'][sanitizer]):
                        new_label.source_sanitizers[source]['sanitizers'][sanitizer] = line
            else:
                new_label.source_sanitizers[source] = {
                    'line': data['line'],
                    'sanitizers': dict(data['sanitizers'])
                }

        return new_label

    def __repr__(self):
        return f"Label ({self.source_sanitizers})"