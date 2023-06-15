import json
import requests
import pandas as pd
import urllib3
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set NSX Manager credentials
username = 'your_username'
password = 'your_password'
nsx_manager_ip = 'your_nsx_manager_ip'

# Set the directory to save the CSV file
csv_directory = '/path/to/save/csv/'

# Prepare the HTTP connection to NSX Manager
session = requests.Session()
session.verify = False
session.auth = (username, password)
nsx_manager_url = f'https://{nsx_manager_ip}'

# Set API endpoints
security_policy_endpoint = "/policy/api/v1/infra/domains/default/security-policies/"
all_rules_data = []

# Initialize the API requests counter
api_requests_count = 0

# Get Distributed Firewall Security policies to retrieve all rules
security_policies_response = session.get(f"{nsx_manager_url}{security_policy_endpoint}").content
api_requests_count += 1
security_policies = json.loads(security_policies_response)

# Iterate over each security policy
for policy in security_policies['results']:
    # Store security policy ID
    security_policy_id = policy['id']
    
    # Get all rules within the specified Security Policy
    rules_endpoint = f"{nsx_manager_url}{security_policy_endpoint}{security_policy_id}/rules"
    rules_response = session.get(rules_endpoint).content
    api_requests_count += 1
    rules = json.loads(rules_response)
    
    # For each rule in the rules, append it to the all_rules_data list
    for rule in rules['results']:
        all_rules_data.append(rule)

# Create pandas DataFrame from the all_rules_data list
df = pd.DataFrame.from_dict(all_rules_data)

# Filter columns of the DataFrame to include specific ones
filtered_df = df.filter(items=['parent_path', 'rule_id', 'display_name', 'action', 'logged'])

# Filter DataFrame to include rules with logging set to True
logged_rules_df = filtered_df[filtered_df['logged'] == True]

# Generate the current date and time
current_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Construct the CSV file name with the current date and time
csv_filename = f'dfw_rules_with_logging_{current_datetime}.csv'

# Concatenate the directory and filename
csv_path = csv_directory + csv_filename

# Export data to a CSV file using pandas and remove the index column
logged_rules_df.to_csv(csv_path, index=False)

# Print the number of API requests made
print(f"Total API requests made: {api_requests_count}")

# Print the CSV file export location
print(f"CSV file exported to: {csv_path}")
