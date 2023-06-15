# NSX Tools

This repository contains a collection of scripts for various NSX (VMware NSX) tasks. These scripts provide automation and simplification for managing NSX environments.

## Scripts
`idps-signature-exporter/idps-signature-exporter.py` - This script allows you to export the intrusion detection service signatures from an NSX Manager to a CSV file.

`NSX-AppliedToDFW-Exporter/NSX-AppliedToDFW-Exporter.py` - This script exports all Distributed Firewall (DFW) rules from the NSX Manager where the "Applied To" field is set to "DFW".

`dfw-rules-with-logging-exporter/dfw-rules-with-logging-exporter.py` - This script exports Distributed Firewall (DFW) rules from the NSX Manager that have logging enabled and saves them to a CSV file.