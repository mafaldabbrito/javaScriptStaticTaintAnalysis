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
        if not hasattr(self, '_pattern_counters'):
            self._pattern_counters = {}
        if not hasattr(self, '_flow_index'):
            self._flow_index = {}

        for pattern_name in multilabel.get_all_labels():
            label = multilabel.get_label(pattern_name)
            if not label:
                continue

            for source_info in label.get_sources_and_sanitizers():
                sanitized = source_info[2]  # This is a list of sanitizers
                source = (source_info[0], source_info[1])  # (source_name, line_number)
                sink = (name, sink_position)
                flow_key = (source[0], source[1], sink[0], sink[1], pattern_name)

                # Check if this flow already exists
                idx = self._flow_index.get(flow_key)
                if idx is not None:
                    vuln_entry = self._vulns[idx]
                    # Append sanitized_flows if new sanitizers are present
                    if sanitized and sanitized not in vuln_entry["sanitized_flows"]:
                        vuln_entry["sanitized_flows"].append(sanitized)
                    # Update unsanitized_flows: only "no" if all appearances have sanitizers
                    if not sanitized:
                        vuln_entry["unsanitized_flows"] = "yes"
                    else:
                        # Only set to "no" if unsanitized_flows is not already "yes"
                        if vuln_entry["unsanitized_flows"] != "yes":
                            vuln_entry["unsanitized_flows"] = "no"
                else:
                    # Increment the counter for this pattern_name
                    count = self._pattern_counters.get(pattern_name, 0) + 1
                    self._pattern_counters[pattern_name] = count

                    vuln_entry = {
                        "vulnerability": f"{pattern_name}_{count}",
                        "source": source,
                        "sink": list(sink),
                        "unsanitized_flows": "yes" if not sanitized else "no",
                        "sanitized_flows": [sanitized] if sanitized else [],
                        "implicit": "no"
                    }
                    self._vulns.append(vuln_entry)
                    self._flow_index[flow_key] = len(self._vulns) - 1

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
