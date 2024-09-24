# Cleanup Unused Distributed Firewall Rules

## Disclaimer
The script was written to disable and delete distributed firewall rules. No responsibility is taken by the author for the results of its use in any environment.

# <u>**BEFORE USING THE SCRIPT:**</u>
Take a backup of your NSX Manager AND Distributed Firewall config before using this script.
- Backup documentation: https://docs.vmware.com/en/VMware-NSX/4.1/administration/GUID-5D9C2F04-56B6-4B40-AF56-DA3046B552C6.html?hWord=N4IghgNiBcIEZgMYGsCuAHEBfIA
- Export the Distributed Firewall config from the system to an accesible location: https://docs.vmware.com/en/VMware-NSX/4.1/administration/GUID-FCE6567E-1174-49CC-90F1-BA7B695B28F0.html
- It is **strongly recommended** to only run collect mode once. If collect mode **MUST** be run again you should backup ALL data in the output folder from the first collection to be used for future reference.

## Overview
The `cleanup_unused_dfw_rules_1.0.py` script is designed to disable and/or delete Distributed Firewall rules. It has multiple modes of function and relies on CSV data as the source of truth for which rules should be disabled/deleted within the environment. This CSV data is generally exported from vRealize Network Insight (VRNI) as a dump of "Unused rules" or rules that do not have any rule hits in X period of time. Only rules that exist within this CSV can be disabled/deleted using this script.


## Features
- **Section Data Collection**: Collects and saves firewall section data from NSX API to JSON files. This content contains ALL rules within each section. This is used to build the API Payload for disabling/deleting the rules listed in the CSV.
- **Rule Disable**: Disables specific firewall rules based on the CSV data. Rules are disable using multiple API calls, regardless of if rules exist within the same section or across multiple sections.
- **Rule Delete**: Deletes specific firewall rules based on the CSV data. Rules are deleted using multiple API calls, regardless of if rules exist within the same section or across multiple sections.
- **Rule Restore**: Restores all rules for a specified section or all sections if no section ID is specified
- **NSX Manager and Firewall Type Filtering**: Only rules from the NSX Manager specified in the `NSX_MANAGER_FQDN` variable can be disabled. The content of  the `NSX_MANAGER_FQDN` variable must match the `NSX Manager` field in the CSV data. Any rules that exist in an alternate NSX Manager will not be touched (even if they exist within the CSV). Only rules where type is equal to `Distributed Firewall` will be modified. Any others within the CSV will be ignored, even if they exist within the specified NSX Manager.
- **Logging**: A log file named `rule-change-log.txt` is created in the `OUTPUT_DIR` directory. Logs information relating to the interaction with the NSX API, this includes Method, Section ID, Rule ID and Payload JSON.


## Usage
- To use this script, you will need Python installed on your system. The script can be run in four modes: collect mode, disable mode, delete mode and restore mode.
- Once the below variables have been updated, the script must first be run in "collect mode" which will build the appropriate JSON content for later reference to then disable, delete objects or restore objects. These JSON files will not be changed unless collect mode is run again so they can be used as a reference for the original state of the section/rules before any changes were made. If you want to revert the changes to a section later please use restore mode OR you could PATCH the content of the section JSON (gathered during collect) to the NSX API for that particular section directly. eg. ```PATCH /policy/api/v1/infra/domains/default/security-policies/<section-id>```
- Once the collect mode is done, confirm the data is populated in the JSON files and then you can run the disable or delete mode with appropriate arguments to limit the scope of the changes if you wish eg. disable <section-id> <rule-id>

### Variables
Update the following variables in the `cleanup-unused-dfw-rules_1.0.py` script:
- `NSX_MANAGER_FQDN`: The fully qualified domain name of the NSX Manager.
- `CSV_LOCATION`: The path to the CSV file containing the firewall rules.
- `OUTPUT_DIR`: The directory where output JSON and log files will be saved.
- `FIREWALL_TYPE`: The type of firewall to process (default is `Distributed Firewall`).

By default the script will prompt for credentails. This is set with the following variable in the script:
- `prompt_for_creds = True`: By default, prompt for credentials
If you wish to use hardcode credentials change the above variable in the script to False and update the below variables in the script.
- `NSX_USERNAME`: The username for NSX Manager authentication.
- `NSX_PASSWORD`: The password for NSX Manager authentication.

### CSV File Format and Data
The CSV file should have the following fields:

```
Name,Destination Negate,Source Negate,Service Profile,Status,Section Name,Section ID,IP Protocol,ruleComment,associatedFwRules,Firewall Type,Direction,Scope,Rule ID,Action,Configured Destination,Configured Source,Sequence ID,Flow,NSX Manager,Configured Service,Manager
rule1,false,false,,Enabled,Policy_Default_Test1,Copy_of_Test-App1,IPv4 and IPv6,,rule1,Distributed Firewall,INOUT,,1001,ALLOW,,,10,,nsx01.example.com,,nsx.example.com
rule2,false,false,,Enabled,Policy_Default_Test2,Test-App2,IPv4 and IPv6,,rule2,Edge Firewall,INOUT,,1002,ALLOW,,,20,,nsx01.example.com,,nsx.example.com
```

---
### Running the Script

#### Collect Mode
Collects the rules for all sections or a specified section based on the content of the CSV and command line argument.

**All sections**:
```
python script.py collect
```

**Specific section**:
```
python script.py collect <section_id>
```
---
#### Disable Mode
Disables rules for all sections, a individual section or disables a single rule within a specific section based on the content of the CSV data and command line argument.

**All sections**:
```
python script.py disable
```

**Specific section**:
```
python script.py disable <section_id>
```

**Individual Rule within a Specific section**:
```
python script.py disable <section_id> <rule_id>
```
---
#### Delete Mode
Deletes rules for all sections, a individual section or deletes a single rule within a specific section based on the content of the CSV data and command line argument.

**All sections**:
```
python script.py delete
```

**Specific section**:
```
python script.py delete <section_id>
```

**Individual Rule within a Specific section**:
```
python script.py delete <section_id> <rule_id>
```
#### Restore Mode
Restores rules for all sections (based on section data in CSV) or all rules in a specified section based on the content of the CSV, the output JSON files and command line argument.

**All sections**:
```
python script.py restore
```

**Specific section**:
```
python script.py restore <section_id>
```

---