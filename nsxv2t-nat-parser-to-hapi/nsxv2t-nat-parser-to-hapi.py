import xml.etree.ElementTree as ET
import json
import sys
import logging
import os
from datetime import datetime

# Setup basic configuration for logging
log_file_path = os.path.join(os.path.dirname(__file__), 'nat_conversion.log')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(log_file_path), logging.StreamHandler(sys.stdout)])

# Tier-0/Tier-1 ID must be provided in gateway_id variable.
# You can get the object ID by going to your Tier-0/Tier-1 in the NSX-T UI, clicking the three-dots and then click Copy Path to Clipboard.
# This will provide the full path to the object including the object ID eg. /infra/tier-1s/predefined_id
# In this case you ONLY need the object ID.
gateway_id = 'predefined_id'
# Marked_for_delete is used to delete all NAT policy on the specified Tier-1
# If you wish to remove the NAT policy, update the marked_for_delete field in the generated JSON file to true then PATCH it again OR
# update the variable in this script then re-generate the output JSON and PATCH the JSON body as you did when first pushing the NAT policy to NSX.
marked_for_delete = False

def convert_xml_to_json(xml_file_path):
    try:
        # Attempt to read the XML file
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        logging.info("XML file loaded successfully.")

        # Prepare JSON output with hierarchical structure
        json_output = {
            "resource_type": "Infra",
            "id": "infra",
            "children": [
                {
                    "Tier1": {
                        "resource_type": "Tier1",
                        "id": gateway_id,
                        "children": [
                            {
                                "PolicyNat": {
                                    "resource_type": "PolicyNat",
                                    "id": "USER",
                                    "children": []
                                },
                                "resource_type": "ChildPolicyNat",
                                "marked_for_delete": marked_for_delete
                            }
                        ]
                    },
                    "resource_type": "ChildTier1"
                }
            ]
        }

        # List to hold PolicyNatRule children
        policy_nat_rules = json_output["children"][0]["Tier1"]["children"][0]["PolicyNat"]["children"]

        # Process each NAT rule found in the XML
        for nat_rule in root.find('natRules'):
            action = nat_rule.find('action').text.lower()
            nat_rule_id = nat_rule.find('ruleId').text
            policy_nat_rule = {
                "PolicyNatRule": {
                    "sequence_number": int(nat_rule_id),
                    "action": "SNAT" if action == 'snat' else "DNAT",
                    "translated_network": nat_rule.find('translatedAddress').text,
                    "scope": ["/infra/tier-1s/" + gateway_id],
                    "enabled": nat_rule.find('enabled').text.lower() == 'true',
                    "logging": nat_rule.find('loggingEnabled').text.lower() == 'true',
                    "firewall_match": "MATCH_INTERNAL_ADDRESS",
                    "resource_type": "PolicyNatRule",
                    "id": nat_rule_id,
                    "display_name": f"Nat Rule {nat_rule_id}",
                    "description": "Converted from NSX-v"
                },
                "resource_type": "ChildPolicyNatRule"
            }

            # Set source_network for SNAT rules
            if action == 'snat':
                policy_nat_rule["PolicyNatRule"]["source_network"] = nat_rule.find('originalAddress').text

            # Set destination_network for DNAT rules
            if action == 'dnat':
                policy_nat_rule["PolicyNatRule"]["destination_network"] = nat_rule.find('originalAddress').text

            policy_nat_rules.append(policy_nat_rule)
            logging.info(f"Processed NAT Rule ID {nat_rule_id}: {policy_nat_rule['PolicyNatRule']}")

        # Generate output filename with timestamp and XML filename
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        xml_filename = os.path.splitext(os.path.basename(xml_file_path))[0]
        output_filename = f"{xml_filename}_{timestamp}.json"

        # Convert to JSON string and log the outcome
        json_string = json.dumps(json_output, indent=4)
        print(json_string)
        logging.info(f"JSON conversion completed successfully. Saving to {output_filename}")

        # Save to a file with the dynamic filename
        with open(output_filename, "w") as json_file:
            json_file.write(json_string)
            logging.info(f"JSON data saved to {output_filename}")

    except ET.ParseError as e:
        logging.error(f"Error parsing XML: {e}")
    except FileNotFoundError:
        logging.error(f"Error: The file '{xml_file_path}' does not exist.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.error("Usage: python script.py <path_to_xml_file>")
        sys.exit(1)

    xml_file_path = sys.argv[1]
    convert_xml_to_json(xml_file_path)
