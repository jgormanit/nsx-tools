import requests
import pandas as pd
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set the username, password, and NSX IP or FQDN
username = "your_username"
password = "your_password"
nsx_manager = "nsxmgr01.corp.org"

# Set the directory and file name for CSV export
csv_directory = '/Users/username/documents/'  # Replace with the desired directory
current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
csv_filename = "{}_appliedto_dfw_rules_{}.csv".format(nsx_manager, current_time)
csv_filepath = csv_directory + csv_filename

# Prepare the HTTP connection to NSX Manager
session = requests.Session()
session.verify = False  # Disable SSL verification
session.auth = (username, password)  # Set authentication credentials

# Set variables
security_policy_endpoint = "/policy/api/v1/infra/domains/default/security-policies/"
rule_data = []

# Get Distributed Firewall Security policies. This is required to retrieve all the rules.
security_policy_response = session.get("https://" + nsx_manager + security_policy_endpoint).json()
security_policies = security_policy_response['results']

# Count the number of API calls made
api_call_count = 1

# Iterate over each security policy
for policy in security_policies:
    # Store security policy ID
    security_policy_id = policy['id']
    
    # Get all rules within the specified Security Policy
    rules_endpoint = "https://" + nsx_manager + security_policy_endpoint + security_policy_id + "/rules"
    rules_response = session.get(rules_endpoint).json()
    rules = rules_response['results']
    
    # Increment the API call count
    api_call_count += 1
    
    # For each rule, append it to the rule_data array
    rule_data.extend(rules)

# Create pandas DataFrame from rule_data list
df = pd.DataFrame.from_records(rule_data)

# Filter columns of the DataFrame to only include the specified ones
filtered_df = df[['parent_path', 'rule_id', 'display_name', 'scope']].copy()

# Count total rows before filtering only rules with scope set to "ANY"
count_all_rules = len(filtered_df)

# Remove [] brackets from the scope column to ensure proper querying
filtered_df.loc[:, 'scope'] = filtered_df['scope'].str[0]

# Filter DataFrame to only include rules with scope set to "ANY"
filtered_df = filtered_df[filtered_df['scope'] == 'ANY']

# Export data to a CSV file
filtered_df.to_csv(csv_filepath, index=False)

# Print the number of API calls made
print("Number of API calls made:", api_call_count)

print("Data exported to", csv_filepath)
