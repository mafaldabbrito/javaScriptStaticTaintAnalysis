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

    def combine(self, other):
        """
        Combines this MultiLabelling with another MultiLabelling object.
        If a variable name exists in both, the other's MultiLabel overwrites the current one.
        :param other: Another MultiLabelling object.
        :return: A new MultiLabelling object with the combined mappings.
        """
        for name, other_label in other._mapping.items():
            if name in self._mapping:
                self._mapping[name] = self._mapping[name].combine(other_label)
            else:
                self._mapping[name] = other_label

    def __eq__(self, other):
        """
        Checks for deep equality comparison of all mappings by variable name and MultiLabel equality.
        :param other: Another MultiLabelling object.
        :return: True if equal, False otherwise.
        """
        if not isinstance(other, MultiLabelling):
            return False
        if set(self._mapping.keys()) != set(other._mapping.keys()):
            return False
        for k in self._mapping:
            if self._mapping[k] != other._mapping[k]:
                return False
        return True

    # Helper method to get all mappings (for inspection)
    def get_all_mappings(self):
        """
        Returns the complete mapping of variable names to MultiLabels.
        :return: Dict[str, MultiLabel]
        """
        return dict(self._mapping)


