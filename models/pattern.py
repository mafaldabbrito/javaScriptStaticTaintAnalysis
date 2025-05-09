class Pattern:
    def __init__(self, name, sources, sanitizers, sinks):
        """
        Constructor for a Pattern object.

        :param name: The name of the vulnerability pattern.
        :param sources: A list of source function names.
        :param sanitizers: A list of sanitizer function names.
        :param sinks: A list of sink function names.
        """
        self.name = name
        self.sources = set(sources)
        self.sanitizers = set(sanitizers)
        self.sinks = set(sinks)

    def __repr__(self):
        return f"Patern(name={self.name}, sources={self.sources}, sinks={self.sinks})"
    def __str__(self):
        return f"Patern: {self.name}, Sources: {self.sources}, Sinks: {self.sinks}"
    
    # Selectors (getters)
    def get_name(self):
        return self.name

    def get_sources(self):
        return list(self.sources)

    def get_sanitizers(self):
        return list(self.sanitizers)

    def get_sinks(self):
        return list(self.sinks)
    
    # Tests 
    def is_source(self, source: str):
        """
        Check if the source is in the pattern.
        """
        return source in self.sources
    
    def is_sink(self, sink: str):
        """
        Check if the sink is in the pattern.
        """
        return sink in self.sinks
    
    def is_sanitizer(self, sanitizer: str):
        """
        Check if the sanitizer is in the pattern.
        """
        return sanitizer in self.sanitizers if self.sanitizers else False