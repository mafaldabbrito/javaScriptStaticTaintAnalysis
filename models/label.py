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

    def add_source(self, source, line, sanitizers=None, implicit=False):
        """
        Adds a new source to the label with optional sanitizers.
        :param source: Name of the source.
        :param line: Line number where the source is found.
        :param sanitizers: Optional list of (sanitizer_name, line) tuples or list of lists.
        """
        entry = {
            'source': source,
            'line': line,
            'sanitizers': [],
            'implicit': implicit
        }
        for existing_entry in self.sources:
            if existing_entry['source'] == source and existing_entry['line'] == line and sanitizers == existing_entry['sanitizers'] and implicit == existing_entry['implicit']:
               return
        if sanitizers:
            # Accepts list of tuples or list of lists
            for sanitizer in sanitizers:
                entry['sanitizers'].append(list(sanitizer))
        # Check if the source already exists
       
        self.sources.append(entry)

    def add_sanitizer(self, source, source_line, sanitizer_name, sanitizer_line, implicit):
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
            'sanitizers': [[sanitizer_name, sanitizer_line]],
            'implicit': implicit
        })

    # Selectors
    def get_sources_and_sanitizers(self):
        # Returns list of (source, line, sanitizers_list)
        result = []
        for entry in self.sources:
            source = entry['source']
            source_line = entry['line']

            if entry['sanitizers']:
                result.append((source, source_line, entry['sanitizers'], entry['implicit']))
            else:
                result.append((source, source_line, None, entry['implicit']))
        return result

    def get_sanitizers(self, key):
        # Returns list of [sanitizer_name, line] for all matching sources
        # key is a tuple (source, line)
        result = []
        for entry in self.sources:
            if entry['source'] == key[0] and entry['line'] == key[1]:
                result.extend(entry['sanitizers'])
        return result

    def make_all_sources_implicit(self):
        # Marks the source as implicit
        for entry in self.sources:
            entry['implicit'] = True
            
        return

    # Combinor
    def combine(self, other_label):
        """
        Combines the current label with another label, returning a new independent Label object.
        """
        new_label = Label()
        for entry in self.sources + other_label.sources:
            # Check if an identical entry already exists
            exists = False
            for existing in new_label.sources:
                if (existing['source'] == entry['source'] and
                    existing['line'] == entry['line'] and
                    sorted(existing['sanitizers']) == sorted(entry['sanitizers'])):
                    exists = True
                    if entry['implicit'] and not existing['implicit']:
                        existing['implicit'] = entry['implicit']
                    break
            if not exists:
                new_label.sources.append({
                    'source': entry['source'],
                    'line': entry['line'],
                    'sanitizers': [list(s) for s in entry['sanitizers']],
                    'implicit': entry['implicit']
                })
        return new_label

    def __repr__(self):
        lines = []
        for entry in self.sources:
            src = f"{entry['source']},{entry['line']}"
            sanitizers = (
                ", ".join(f"{s[0]},{s[1]}" for s in entry['sanitizers'])
                if entry['sanitizers'] else "None"
            )
            implicit = "implicit" if entry.get('implicit') else "explicit"
            lines.append(f"[{src} | sanitizers: {sanitizers} | {implicit}]")
        return "Label: " + "; ".join(lines)

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


