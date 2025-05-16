import json
import os


class Vulnerabilities:
    def __init__(self):
        """
        Constructor: initializes the internal storage for discovered vulnerabilities.
        """
        self._vulns = []

    def add_illegal_flow(self, name, multilabel, sink_position):
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
                # Initialize a counter dictionary if it doesn't exist
                if not hasattr(self, '_pattern_counters'):
                    self._pattern_counters = {}

                # Increment the counter for this pattern_name
                count = self._pattern_counters.get(pattern_name, 0) + 1
                self._pattern_counters[pattern_name] = count

                vuln_entry = {
                    "vulnerability": f"{pattern_name}_{count}",
                    "source": source,
                    "sink": [name, sink_position],
                    "unsanitized_flows": "yes" if not sanitized else "no",
                    "sanitized_flows": [[s for s in sanitized]] if sanitized else [],
                    "implicit": "no"  # default, extendable if you track implicit flows
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
                f'  "unsanitized_flows": "{vuln["unsanitized_flows"]}",\n',
                f'  "sanitized_flows": {vuln["sanitized_flows"]}\n',
                f'  "implicit": "{vuln["implicit_flows"]}",\n'
                '}'
            ]
            return '\n'.join(lines)

        return '\n\n'.join(format_vuln(v) for v in self._vulns)

    def export_json(self, filepath):
        output_dir = os.path.join(os.path.dirname(filepath), "output")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        output_path = os.path.join(output_dir, os.path.basename(filepath))
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self._vulns, f, indent=4)
