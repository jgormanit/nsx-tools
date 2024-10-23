# NSX Tools

This repository contains a collection of scripts for various NSX (VMware NSX) tasks. These scripts provide automation and simplification for managing NSX environments.

## Scripts
`idps-signature-exporter/idps-signature-exporter.py` - This script allows you to export the intrusion detection service signatures from an NSX Manager to a CSV file.

`NSX-AppliedToDFW-Exporter/NSX-AppliedToDFW-Exporter.py` - This script exports all Distributed Firewall (DFW) rules from the NSX Manager where the "Applied To" field is set to "DFW".

`dfw-rules-with-logging-exporter/dfw-rules-with-logging-exporter.py` - This script exports Distributed Firewall (DFW) rules from the NSX Manager that have logging enabled and saves them to a CSV file.

`nsxv2t-nat-parser-to-hapi/nsxv2t-nat-parser-to-hapi.py` - This script converts NAT configurations from NSX-v XML format to NSX-T JSON format ready to be pushed to the NSX-T hierarchical API.

`cleanup-unused-dfw-rules/cleanup-unused-dfw-rules.py` - This script collects, disables and deletes Distributed Firewall rules. Allowing you to cleanup large amounts of rules in batches.

`identify_zero_hit_dfw_rules.py` - This script identifies all rules in a specific NSX Manager where the Rule Hit count is 0. It uses the statistics from the NSX Manager.