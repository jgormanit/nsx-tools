import csv
import json
import os
import sys
import requests
import urllib3
from datetime import datetime
import re
import getpass

# Suppress only the single InsecureRequestWarning from urllib3 needed for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Regular expression for detecting UUID format (e.g., 8-4-4-4-12 hexadecimal characters)
UUID_REGEX = re.compile(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')

# Variables for NSX-T Manager connection and CSV file location
prompt_for_creds = True  # If true, prompt for NSX credentials, otherwise use hardcoded credentials
NSX_MANAGER_FQDN = 'nsx01.lab.local'
CSV_LOCATION = 'C:/Users/localadmin/rule_data.csv'
OUTPUT_DIR = 'C:/Users/localadmin/output/'
LOG_FILE = os.path.join(OUTPUT_DIR, 'rule_change_log.txt')
MAPPING_FILE = f'sp-object-policy-id-mp-id-mapping-{NSX_MANAGER_FQDN}.json'

# Handle credentials based on the prompt_for_creds variable
if prompt_for_creds:
    NSX_USERNAME = input("Enter NSX Username: ")
    NSX_PASSWORD = getpass.getpass("Enter NSX Password: ")
else:
    NSX_USERNAME = 'usernamehere'  # Hardcoded default username if prompt_for_creds is False
    NSX_PASSWORD = 'password'      # Hardcoded default password if prompt_for_creds is False


# Default Firewall Type. Other Firewall types are not supported at this stage.
FIREWALL_TYPE = 'Distributed Firewall'

# Ensure the output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Function to determine if the Section ID is an MP ID (UUID format) or a Policy ID
def get_policy_id(section_id, mp_to_policy_id):
    """
    Function to determine if the Section ID is a UUID (MP ID) or a direct Policy ID.
    If it's an MP ID, do a lookup in the mapping file. Otherwise, return the Section ID directly.
    """
    if UUID_REGEX.match(section_id):
        # Section ID is an MP ID, perform lookup in the mapping file
        policy_id = mp_to_policy_id.get(section_id)
        if not policy_id:
            raise ValueError(f"Policy ID not found for MP ID {section_id}")
        return policy_id
    else:
        # Section ID is already a policy ID
        return section_id

# Function to send GET request to NSX API
def get_section_info(section_id):
    url = f'https://{NSX_MANAGER_FQDN}/policy/api/v1/infra/domains/default/security-policies/{section_id}'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.get(url, headers=headers, auth=(NSX_USERNAME, NSX_PASSWORD), verify=False)
    log_payload('GET', section_id, None, None, url)
    return response.json()

# Function to send PATCH request to NSX API
def send_patch_request(payload, section_id, rule_id):
    url = f'https://{NSX_MANAGER_FQDN}/policy/api/v1/infra/domains/default/security-policies/{section_id}/rules/{rule_id}'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.patch(url, headers=headers, auth=(NSX_USERNAME, NSX_PASSWORD), data=json.dumps(payload), verify=False)
    log_payload('PATCH', section_id, rule_id, payload, url)
    return response

# Function to send DELETE request to NSX API
def send_delete_request(section_id, rule_id):
    url = f'https://{NSX_MANAGER_FQDN}/policy/api/v1/infra/domains/default/security-policies/{section_id}/rules/{rule_id}'
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.delete(url, headers=headers, auth=(NSX_USERNAME, NSX_PASSWORD), verify=False)
    log_payload('DELETE', section_id, rule_id, None, url)
    return response

# Function to create JSON payload from rule data for PATCH requests
def create_json_payload_for_patch(rule):
    payload = {
        "action": rule["action"],
        "rule_id": rule["rule_id"],
        "sequence_number": rule["sequence_number"],
        "disabled": True
    }
    return payload

# Function to create a mapping of policy IDs to MP IDs
def create_policy_mp_mapping():
    url = f'https://{NSX_MANAGER_FQDN}/policy/api/v1/search/query?query=resource_type:SecurityPolicy&included_fields=display_name,id,realization_id'
    headers = {
        'Content-Type': 'application/json'
    }
    mapping = []
    while url:
        response = requests.get(url, headers=headers, auth=(NSX_USERNAME, NSX_PASSWORD), verify=False)
        data = response.json()
        mapping.extend(data.get('results', []))
        cursor = data.get('cursor')
        if cursor:
            url = f'https://{NSX_MANAGER_FQDN}/policy/api/v1/search/query?query=resource_type:SecurityPolicy&included_fields=display_name,id,realization_id&cursor={cursor}'
        else:
            url = None
    with open(MAPPING_FILE, 'w') as file:
        json.dump(mapping, file, indent=4)
    print(f"Policy to MP ID mapping saved to {MAPPING_FILE}")

# Function to load the policy to MP ID mapping from the JSON file
def load_policy_mp_mapping():
    if not os.path.exists(MAPPING_FILE):
        create_policy_mp_mapping()
    with open(MAPPING_FILE, 'r') as file:
        return json.load(file)

# Function to log the payload to a log file
def log_payload(method, section_id, rule_id, payload, url):
    log_entry = f"{datetime.now()} - Method: {method}, URL: {url}, Section ID: {section_id}, Rule ID: {rule_id}, Payload: {json.dumps(payload) if payload else 'None'}\n"
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(log_entry)

# Function to print and simple user info
def log_and_print_message(message, method=None, section_id=None, rule_id=None, payload=None, url=None):
    print(message)
    if method:
        log_payload(method, section_id, rule_id, payload, url)
    # Log to the file in any case
    log_entry = f"{datetime.now()} - {message}\n"
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(log_entry)

# Function to collect data for each unique Section ID
def collect_mode(target_section_id=None):
    create_policy_mp_mapping()  # Recreate the mapping file
    policy_mp_mapping = load_policy_mp_mapping()
    mp_to_policy_id = {item['realization_id']: item['id'] for item in policy_mp_mapping}
    unique_section_ids = set()
    non_matching_sections = set()
    csv_sections = set()

    # Read the CSV file and collect unique Section IDs
    with open(CSV_LOCATION, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            csv_sections.add(row['Section ID'])
            if row['Manager'] == NSX_MANAGER_FQDN and row['Firewall Type'] == FIREWALL_TYPE:
                if target_section_id and row['Section ID'] != target_section_id:
                    continue
                unique_section_ids.add(row['Section ID'])
            else:
                non_matching_sections.add(row['Section ID'])

    # Fetch and save data for each unique Section ID using the policy ID
    for mp_id in unique_section_ids:
        try:
            policy_id = get_policy_id(mp_id, mp_to_policy_id)
        except ValueError as e:
            log_and_print_message(str(e))
            continue
        
        section_info = get_section_info(policy_id)
        output_file = os.path.join(OUTPUT_DIR, f'section_{policy_id}.json')
        with open(output_file, 'w') as json_file:
            json.dump(section_info, json_file, indent=4)
        log_and_print_message(f"Section ID {policy_id} - Data saved to {output_file}")

    # Log sections not collected because of NSX Manager or Firewall Type mismatch
    if non_matching_sections:
        log_and_print_message("The following sections were not collected because their NSX Manager or Firewall Type did not match the specified criteria:")
        for section_id in non_matching_sections:
            log_and_print_message(f"Section ID {section_id}")

    # Log sections not found in the CSV file
    if target_section_id and target_section_id not in csv_sections:
        log_and_print_message(f"Section ID {target_section_id} not found in CSV file", 'NOT FOUND', target_section_id)

# Function to disable rules based on the CSV file
def disable_mode(target_section_id=None, target_rule_id=None):
    policy_mp_mapping = load_policy_mp_mapping()
    mp_to_policy_id = {item['realization_id']: item['id'] for item in policy_mp_mapping}
    csv_sections = set()
    csv_rules = set()

    with open(CSV_LOCATION, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            csv_sections.add(row['Section ID'])
            # Skip rows with empty Rule ID and log additional information
            if not row['Rule ID']:
                message = (
                    f"Skipping row with empty Rule ID.\n"
                    f"Name: {row['Name']}\n"
                    f"Section Name: {row['Section Name']}\n"
                    f"Section ID: {row['Section ID']}"
                )
                log_and_print_message(message)
                continue
            csv_rules.add((row['Section ID'], int(row['Rule ID'])))
            if row['Manager'] == NSX_MANAGER_FQDN and row['Firewall Type'] == FIREWALL_TYPE:
                section_id = row['Section ID']
                rule_id = int(row['Rule ID'])

                if target_section_id and section_id != target_section_id:
                    continue
                if target_rule_id and rule_id != target_rule_id:
                    continue

                if row['Status'].lower() == 'disabled':
                    log_and_print_message(f"Rule ID {rule_id} in section {section_id} is already disabled, skipping.", 'SKIP', section_id, rule_id)
                    continue

                # Load the corresponding section JSON file
                try:
                    policy_id = get_policy_id(section_id, mp_to_policy_id)
                except ValueError as e:
                    log_and_print_message(str(e))
                    continue

                section_file = os.path.join(OUTPUT_DIR, f'section_{policy_id}.json')
                if not os.path.exists(section_file):
                    log_and_print_message(f"Section file for Section ID {policy_id} not found", 'NOT FOUND', policy_id, rule_id)
                    continue

                with open(section_file, 'r') as json_file:
                    section_data = json.load(json_file)

                # Find the rule in the section data
                rule = next((r for r in section_data.get("rules", []) if r["rule_id"] == rule_id), None)

                if rule:
                    # Create the payload, log it, and send the PATCH request
                    payload = create_json_payload_for_patch(rule)
                    response = send_patch_request(payload, policy_id, rule["id"])
                    log_and_print_message(f"Rule ID {rule_id} has been disabled.", 'PATCH', policy_id, rule_id, payload, 'PATCH request sent')
                else:
                    log_and_print_message(f"Rule ID {rule_id} not found in section {policy_id}")

    # Log section or rule not found in the CSV file
    if target_section_id and target_section_id not in csv_sections:
        log_and_print_message(f"Section ID {target_section_id} not found in CSV file", 'NOT FOUND', target_section_id)

    if target_rule_id and (target_section_id, target_rule_id) not in csv_rules:
        log_and_print_message(f"Rule ID {target_rule_id} in section {target_section_id} not found in CSV file", 'NOT FOUND', target_section_id, target_rule_id)

# Function to delete rules based on the CSV file
def delete_mode(target_section_id=None, target_rule_id=None):
    policy_mp_mapping = load_policy_mp_mapping()
    mp_to_policy_id = {item['realization_id']: item['id'] for item in policy_mp_mapping}
    csv_sections = set()
    csv_rules = set()

    with open(CSV_LOCATION, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            csv_sections.add(row['Section ID'])
            # Skip rows with empty Rule ID and log additional information
            if not row['Rule ID']:
                message = (
                    f"Skipping row with empty Rule ID.\n"
                    f"Name: {row['Name']}\n"
                    f"Section Name: {row['Section Name']}\n"
                    f"Section ID: {row['Section ID']}"
                )
                log_and_print_message(message)
                continue
            csv_rules.add((row['Section ID'], int(row['Rule ID'])))
            if row['Manager'] == NSX_MANAGER_FQDN and row['Firewall Type'] == FIREWALL_TYPE:
                section_id = row['Section ID']
                rule_id = int(row['Rule ID'])

                if target_section_id and section_id != target_section_id:
                    continue
                if target_rule_id and rule_id != target_rule_id:
                    continue

                # Load the corresponding section JSON file
                try:
                    policy_id = get_policy_id(section_id, mp_to_policy_id)
                except ValueError as e:
                    log_and_print_message(str(e))
                    continue

                section_file = os.path.join(OUTPUT_DIR, f'section_{policy_id}.json')
                if not os.path.exists(section_file):
                    log_and_print_message(f"Section file for Section ID {policy_id} not found", 'NOT FOUND', policy_id, rule_id)
                    continue

                with open(section_file, 'r') as json_file:
                    section_data = json.load(json_file)

                # Find the rule in the section data
                rule = next((r for r in section_data.get("rules", []) if r["rule_id"] == rule_id), None)

                if rule:
                    # Log it and send the DELETE request
                    response = send_delete_request(policy_id, rule["id"])
                    log_and_print_message(f"Rule ID {rule_id} has been deleted.", 'DELETE', policy_id, rule_id, None, 'DELETE request sent')
                else:
                    log_and_print_message(f"Rule ID {rule_id} not found in section {policy_id}")

    # Log section or rule not found in the CSV file
    if target_section_id and target_section_id not in csv_sections:
        log_and_print_message(f"Section ID {target_section_id} not found in CSV file", 'NOT FOUND', target_section_id)

    if target_rule_id and (target_section_id, target_rule_id) not in csv_rules:
        log_and_print_message(f"Rule ID {target_rule_id} in section {target_section_id} not found in CSV file", 'NOT FOUND', target_section_id, target_rule_id)

# Function to restore policies based on the CSV file or all policies if no specific section_id is provided
def restore_mode(target_section_id=None):
    policy_mp_mapping = load_policy_mp_mapping()  # Load policy-to-MP ID mapping
    mp_to_policy_id = {item['realization_id']: item['id'] for item in policy_mp_mapping}
    
    # Restore all sections if no specific section_id is provided
    if not target_section_id:
        with open(CSV_LOCATION, mode='r') as file:
            csv_reader = csv.DictReader(file)
            sections_to_restore = {row['Section ID'] for row in csv_reader if row['Manager'] == NSX_MANAGER_FQDN and row['Firewall Type'] == FIREWALL_TYPE}
    else:
        sections_to_restore = {target_section_id}
    
    for mp_id in sections_to_restore:
        try:
            # Get the policy ID using the MP ID or directly use the provided policy ID
            policy_id = get_policy_id(mp_id, mp_to_policy_id)
        except ValueError as e:
            log_and_print_message(str(e))
            continue
        
        # Path to the JSON file containing the section details
        section_file = os.path.join(OUTPUT_DIR, f'section_{policy_id}.json')
        if not os.path.exists(section_file):
            log_and_print_message(f"Section file for Section ID {policy_id} not found", 'NOT FOUND', policy_id)
            continue
        
        # Load the section data from the JSON file
        with open(section_file, 'r') as json_file:
            section_data = json.load(json_file)
        
        # Send PATCH request to restore the policy
        url = f'https://{NSX_MANAGER_FQDN}/policy/api/v1/infra/domains/default/security-policies/{policy_id}'
        headers = {'Content-Type': 'application/json'}
        
        response = requests.patch(url, headers=headers, auth=(NSX_USERNAME, NSX_PASSWORD), data=json.dumps(section_data), verify=False)
        log_payload('PATCH', policy_id, None, section_data, url)
        
        if response.status_code == 200:
            log_and_print_message(f"Section ID {policy_id} has been successfully restored.", 'PATCH', policy_id, None, section_data, url)
        else:
            log_and_print_message(f"Failed to restore Section ID {policy_id}. Status code: {response.status_code}", 'PATCH', policy_id, None, section_data, url)
    
    if not sections_to_restore:
        log_and_print_message("No sections found to restore.")


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in ["collect", "disable", "delete", "restore"]:
        print("Usage: python script.py [collect|disable|delete|restore] [section_id] [rule_id]")
        sys.exit(1)

    mode = sys.argv[1]
    target_section_id = sys.argv[2] if len(sys.argv) > 2 else None
    target_rule_id = int(sys.argv[3]) if len(sys.argv) > 3 else None
    
    if mode == "collect":
        collect_mode(target_section_id)
    elif mode == "disable":
        disable_mode(target_section_id, target_rule_id)
    elif mode == "delete":
        delete_mode(target_section_id, target_rule_id)
    elif mode == "restore":
        restore_mode(target_section_id)

