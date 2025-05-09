import json


class Vulnerabilities:
    def __init__(self):
        """
        Constructor: initializes the internal storage for discovered vulnerabilities.
        """
        self._vulns = []

    def add_illegal_flow(self, name, multilabel, source_positions, sink_position):
        """
        Adds information about illegal flows to the internal list.

        :param name: The sink name (str) where the flow ends.
        :param multilabel: MultiLabel object with illegal flows only.
        :param source_positions: dict mapping source names to their line numbers (e.g., {"document.URL": 1})
        :param sink_position: line number of the sink (e.g., 4)
        """
        for pattern_name in multilabel.get_all_labels():
            label = multilabel.get_label(pattern_name)
            if not label:
                continue

            for source in label.get_sources():
                sanitized = label.get_sanitizers(source)
                vuln_entry = {
                    "vulnerability": pattern_name,
                    "source": [source, source_positions.get(source, "?")],
                    "sink": [name, sink_position],
                    "implicit_flows": "no",  # default, extendable if you track implicit flows
                    "unsanitized_flows": "yes" if not sanitized else "no",
                    "sanitized_flows": [[ [s, source_positions.get(s, "?")] for s in sanitized ]] if sanitized else []
                }
                self._vulns.append(vuln_entry)

    def get_all(self):
        """Returns all collected vulnerabilities."""
        return self._vulns

    def __repr__(self):
        def format_vuln(vuln):
            lines = [
                '{',
                f'  "vulnerability": "{vuln["vulnerability"]}",\n',
                f'  "source": {vuln["source"]},\n',
                f'  "sink": {vuln["sink"]},\n',
                f'  "implicit_flows": "{vuln["implicit_flows"]}",\n',
                f'  "unsanitized_flows": "{vuln["unsanitized_flows"]}",\n',
                f'  "sanitized_flows": {vuln["sanitized_flows"]}\n',
                '}'
            ]
            return '\n'.join(lines)

        return '\n\n'.join(format_vuln(v) for v in self._vulns)

    def export_json(self, filepath):
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self._vulns, f, indent=2)
