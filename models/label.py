class Label:
    """
    Represents the integrity of information that is carried by a resource

    """
    def __init__(self):
        """
        Constructor for an empty Label object.
        """
        self.source_sanitizers = {}  # Dict[str, Set[str]]

    def add_source(self, source_name, sanitizers=None):
        """
        Adds a new source to the label with optional sanitizers.
        :param source_name: Name of the source.
        :param sanitizers: Optional set of sanitizers to initialize the source with.
        """
        if source_name not in self.source_sanitizers:
            self.source_sanitizers[source_name] = set(sanitizers) if sanitizers else set()
    
    def add_sanitizer(self, source_name, sanitizer_name):
        """
        Adds a sanitizer to a specific source.
        :param source_name: Name of the source.
        :param sanitizer_name: Name of the sanitizer.
        """
        if source_name in self.source_sanitizers:
            self.source_sanitizers[source_name].add(sanitizer_name)
        else:
            self.source_sanitizers[source_name] = {sanitizer_name}

    # Selectors
    def get_sources(self):
        return list(self.source_sanitizers.keys())

    def get_sanitizers(self, source_name):
        return list(self.source_sanitizers.get(source_name, set()))
    
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
        for source, sanitizers in self.source_sanitizers.items():
            new_label.source_sanitizers[source] = set(sanitizers)

        # Merge with other label
        for source, sanitizers in other_label.source_sanitizers.items():
            if source in new_label.source_sanitizers:
                new_label.source_sanitizers[source].update(sanitizers)
            else:
                new_label.source_sanitizers[source] = set(sanitizers)

        return new_label
    
    def __repr__(self):
        return f"Label ({self.source_sanitizers})"
    
        