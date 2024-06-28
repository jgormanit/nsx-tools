import csv
import json
import os
import sys
import requests
import urllib3
from datetime import datetime

# Suppress only the single InsecureRequestWarning from urllib3 needed for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Variables for NSX-T Manager connection and CSV file location
NSX_MANAGER_FQDN = 'nsx01.lab.local'
NSX_USERNAME = 'usernamehere'
NSX_PASSWORD = 'password'
CSV_LOCATION = 'C:/User/localadmin/rule_data.csv'
OUTPUT_DIR = 'C:/Users/localadmin/output/'
LOG_FILE = os.path.join(OUTPUT_DIR, 'rule-change-log.txt')

# Default Firewall Type. Other Firewall types are not supported at this stage.
FIREWALL_TYPE = 'Distributed Firewall'

# Ensure the output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

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

# Function to collect data for each unique Section ID
def collect_mode(target_section_id=None):
    unique_section_ids = set()
    non_matching_sections = set()
    csv_sections = set()

    # Read the CSV file and collect unique Section IDs
    with open(CSV_LOCATION, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            csv_sections.add(row['Section ID'])
            if row['NSX Manager'] == NSX_MANAGER_FQDN and row['Firewall Type'] == FIREWALL_TYPE:
                if target_section_id and row['Section ID'] != target_section_id:
                    continue
                unique_section_ids.add(row['Section ID'])
            else:
                non_matching_sections.add(row['Section ID'])

    # Fetch and save data for each unique Section ID
    for section_id in unique_section_ids:
        section_info = get_section_info(section_id)
        output_file = os.path.join(OUTPUT_DIR, f'section_{section_id}.json')
        with open(output_file, 'w') as json_file:
            json.dump(section_info, json_file, indent=4)
        print(f"Section ID {section_id} - Data saved to {output_file}")

    # Log sections not collected because of NSX Manager or Firewall Type mismatch
    if non_matching_sections:
        print("The following sections were not collected because their NSX Manager or Firewall Type did not match the specified criteria:")
        for section_id in non_matching_sections:
            print(f"Section ID {section_id}")

    # Log sections not found in the CSV file
    if target_section_id and target_section_id not in csv_sections:
        log_payload('NOT FOUND', target_section_id, None, None, 'Section ID not found in CSV')
        print(f"Section ID {target_section_id} not found in CSV file")

# Function to log the payload to a log file
def log_payload(method, section_id, rule_id, payload, url):
    with open(LOG_FILE, 'a') as log_file:
        log_entry = f"{datetime.now()} - Method: {method}, URL: {url}, Section ID: {section_id}, Rule ID: {rule_id}, Payload: {json.dumps(payload) if payload else 'None'}\n"
        log_file.write(log_entry)

# Function to disable rules based on the CSV file
def disable_mode(target_section_id=None, target_rule_id=None):
    csv_sections = set()
    csv_rules = set()

    with open(CSV_LOCATION, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            csv_sections.add(row['Section ID'])
            csv_rules.add((row['Section ID'], int(row['Rule ID'])))
            if row['NSX Manager'] == NSX_MANAGER_FQDN and row['Firewall Type'] == FIREWALL_TYPE:
                section_id = row['Section ID']
                rule_id = int(row['Rule ID'])

                if target_section_id and section_id != target_section_id:
                    continue
                if target_rule_id and rule_id != target_rule_id:
                    continue
                
                if row['Status'].lower() == 'disabled':
                    print(f"Rule ID {rule_id} in section {section_id} is already disabled, skipping.")
                    log_payload('SKIP', section_id, rule_id, None, 'Already disabled')
                    continue

                # Load the corresponding section JSON file
                section_file = os.path.join(OUTPUT_DIR, f'section_{section_id}.json')
                if not os.path.exists(section_file):
                    log_payload('NOT FOUND', section_id, rule_id, None, 'Section file not found')
                    print(f"Section file for Section ID {section_id} not found")
                    continue

                with open(section_file, 'r') as json_file:
                    section_data = json.load(json_file)

                # Find the rule in the section data
                rule = next((r for r in section_data["rules"] if r["rule_id"] == rule_id), None)

                if rule:
                    # Create the payload, log it, and send the PATCH request
                    payload = create_json_payload_for_patch(rule)
                    response = send_patch_request(payload, section_id, rule["id"])
                    print(f"Rule ID {rule_id} - Response: {response.status_code}")
                else:
                    print(f"Rule ID {rule_id} not found in section {section_id}")

    # Log section or rule not found in the CSV file
    if target_section_id and target_section_id not in csv_sections:
        log_payload('NOT FOUND', target_section_id, None, None, 'Section ID not found in CSV')
        print(f"Section ID {target_section_id} not found in CSV file")

    if target_rule_id and (target_section_id, target_rule_id) not in csv_rules:
        log_payload('NOT FOUND', target_section_id, target_rule_id, None, 'Rule ID not found in CSV')
        print(f"Rule ID {target_rule_id} in section {target_section_id} not found in CSV file")

# Function to delete rules based on the CSV file
def delete_mode(target_section_id=None, target_rule_id=None):
    csv_sections = set()
    csv_rules = set()

    with open(CSV_LOCATION, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            csv_sections.add(row['Section ID'])
            csv_rules.add((row['Section ID'], int(row['Rule ID'])))
            if row['NSX Manager'] == NSX_MANAGER_FQDN and row['Firewall Type'] == FIREWALL_TYPE:
                section_id = row['Section ID']
                rule_id = int(row['Rule ID'])

                if target_section_id and section_id != target_section_id:
                    continue
                if target_rule_id and rule_id != target_rule_id:
                    continue

                # Load the corresponding section JSON file
                section_file = os.path.join(OUTPUT_DIR, f'section_{section_id}.json')
                if not os.path.exists(section_file):
                    log_payload('NOT FOUND', section_id, rule_id, None, 'Section file not found')
                    print(f"Section file for Section ID {section_id} not found")
                    continue

                with open(section_file, 'r') as json_file:
                    section_data = json.load(json_file)

                # Find the rule in the section data
                rule = next((r for r in section_data["rules"] if r["rule_id"] == rule_id), None)

                if rule:
                    # Log it and send the DELETE request
                    response = send_delete_request(section_id, rule["id"])
                    print(f"Rule ID {rule_id} - Response: {response.status_code}")
                else:
                    print(f"Rule ID {rule_id} not found in section {section_id}")

    # Log section or rule not found in the CSV file
    if target_section_id and target_section_id not in csv_sections:
        log_payload('NOT FOUND', target_section_id, None, None, 'Section ID not found in CSV')
        print(f"Section ID {target_section_id} not found in CSV file")

    if target_rule_id and (target_section_id, target_rule_id) not in csv_rules:
        log_payload('NOT FOUND', target_section_id, target_rule_id, None, 'Rule ID not found in CSV')
        print(f"Rule ID {target_rule_id} in section {target_section_id} not found in CSV file")

if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in ["collect", "disable", "delete"]:
        print("Usage: python script.py [collect|disable|delete] [section_id] [rule_id]")
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
