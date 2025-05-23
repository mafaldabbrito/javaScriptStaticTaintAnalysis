class Label:
    """
    Represents the integrity of information that is carried by a resource for a specific pattern.
    Now tracks the line location for each source and sanitizer.
    Supports multiple sources with the same name and line, with or without sanitizers.
    """
    def __init__(self):
        """
        Constructor for an empty Label object.
        """
        # List[Dict]: Each dict has 'source', 'line', and 'sanitizers' (list of lists)
        self.sources = []

    def add_source(self, source, line, sanitizers=None):
        """
        Adds a new source to the label with optional sanitizers.
        :param source: Name of the source.
        :param line: Line number where the source is found.
        :param sanitizers: Optional list of (sanitizer_name, line) tuples or list of lists.
        """
        entry = {
            'source': source,
            'line': line,
            'sanitizers': []
        }
        if sanitizers:
            # Accepts list of tuples or list of lists
            for sanitizer in sanitizers:
                entry['sanitizers'].append(list(sanitizer))
        self.sources.append(entry)

    def add_sanitizer(self, source, source_line, sanitizer_name, sanitizer_line):
        """
        Adds a sanitizer to a specific source occurrence.
        If multiple sources match, adds to the first one without this sanitizer.
        """
        for entry in self.sources:
            if entry['source'] == source and entry['line'] == source_line:
                if [sanitizer_name, sanitizer_line] not in entry['sanitizers']:
                    entry['sanitizers'].append([sanitizer_name, sanitizer_line])
                    return
        # If not found, create a new source occurrence with this sanitizer
        self.sources.append({
            'source': source,
            'line': source_line,
            'sanitizers': [[sanitizer_name, sanitizer_line]]
        })

    # Selectors
    def get_sources_and_sanitizers(self):
        # Returns list of (source, line, sanitizers_list)
        result = []
        for entry in self.sources:
            source = entry['source']
            source_line = entry['line']
            if entry['sanitizers']:
                result.append((source, source_line, entry['sanitizers']))
            else:
                result.append((source, source_line, None))
        return result

    def get_sanitizers(self, key):
        # Returns list of [sanitizer_name, line] for all matching sources
        # key is a tuple (source, line)
        result = []
        for entry in self.sources:
            if entry['source'] == key[0] and entry['line'] == key[1]:
                result.extend(entry['sanitizers'])
        return result

    # Combinor
    def combine(self, other_label):
        """
        Combines the current label with another label, returning a new independent Label object.
        """
        new_label = Label()
        # Deep copy all sources
        for entry in self.sources + other_label.sources:
            new_label.sources.append({
                'source': entry['source'],
                'line': entry['line'],
                'sanitizers': [list(s) for s in entry['sanitizers']]
            })
        return new_label

    def __repr__(self):
        return f"Label ({self.sources})"

    def __eq__(self, other):
        if not isinstance(other, Label):
            return False
        # Compare sources deeply
        if len(self.sources) != len(other.sources):
            return False
        for s, o in zip(self.sources, other.sources):
            if s['source'] != o['source'] or s['line'] != o['line']:
                return False
            # Compare sanitizers as lists of lists
            if sorted(s['sanitizers']) != sorted(o['sanitizers']):
                return False
        return True


