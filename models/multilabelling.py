class MultiLabelling:
    def __init__(self):
        """
        Constructor for MultiLabelling.
        Initializes an empty mapping from variable names to MultiLabels.
        """
        self._mapping = {}

    # Getter
    def get_multilabel(self, name):
        """
        Returns the MultiLabel assigned to the given variable name.
        :param name: The variable name (str).
        :return: MultiLabel object, or None if not found.
        """
        return self._mapping.get(name)

    # Setter
    def set_multilabel(self, name, multilabel):
        """
        Updates the MultiLabel assigned to the given variable name.
        :param name: The variable name (str).
        :param multilabel: A MultiLabel object.
        """
        self._mapping[name] = multilabel

    # Helper method to get all mappings (for inspection)
    def get_all_mappings(self):
        """
        Returns the complete mapping of variable names to MultiLabels.
        :return: Dict[str, MultiLabel]
        """
        return dict(self._mapping)
