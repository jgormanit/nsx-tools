import requests
import pandas as pd
import urllib3
import time
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set the username, password, and NSX IP or FQDN
username = "your_username"
password = "your_password"
nsx_ip = "nsxmgr01.corp.org"

# Set the API endpoint for retrieving intrusion service signatures
# Note: Signature versions and their IDs can be retrieved using the following API: GET /policy/api/v1/infra/settings/firewall/security/intrusion-services/signature-versions/
signature_version = "DEFAULT"  # Replace with the desired signature version ID
# Signature versions and their IDs can be retrieved using the following API: GET /policy/api/v1/infra/settings/firewall/security/intrusion-services/signature-versions/
api_endpoint = "/policy/api/v1/infra/settings/firewall/security/intrusion-services/signature-versions/{}/signatures".format(signature_version)

# Set the directory and file name for CSV export
csv_directory = '/Users/randomuser/Documents/'
current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
csv_filename = "{}_idps-signatures_{}_{}.csv".format(nsx_ip, signature_version, current_time)
csv_filepath = csv_directory + csv_filename

# Prepare the HTTP connection to NSX Manager
session = requests.Session()
session.verify = False
session.auth = (username, password)
nsx_mgr = 'https://' + nsx_ip

# Function to retrieve all pages of data for a given API endpoint
def get_all_pages(api_url, api_request_count):
    all_data = []
    cursor = None

    try:
        while True:
            params = {'cursor': cursor} if cursor else {}
            response = session.get(api_url, params=params)
            response.raise_for_status()  # Raise an exception if the response status code indicates an error
            api_request_count[0] += 1  # Increment the API request count
            data = response.json()

            # Extend the all_data list with results from the current page
            all_data.extend(data['results'])

            # Check if there is a cursor for the next page
            if 'cursor' in data:
                cursor = data['cursor']
            else:
                break
    except requests.exceptions.RequestException as e:
        # Log the error message
        error_message = f"An error occurred during API request: {str(e)}"
        print(error_message)
        return None

    return all_data

# Measure the execution time
start_time = time.time()

# Get all pages of data for the intrusion service signatures API
api_request_count = [0]  # Initialize the API request count
signature_data = get_all_pages(nsx_mgr + api_endpoint, api_request_count)

if signature_data is not None:
    # Create a pandas dataframe directly from the signature_data using list comprehension
    df = pd.DataFrame.from_dict([item for item in signature_data])

    try:
        # Export the information to a CSV file in the specified directory
        df.to_csv(csv_filepath, index=False)
        print("CSV file exported successfully.")
    except IOError as e:
        # Log the error message
        error_message = f"An error occurred while exporting the CSV file: {str(e)}"
        print(error_message)
    except FileNotFoundError as e:
        # Log the error message for a bad directory
        error_message = f"Invalid directory for CSV export: {str(e)}"
        print(error_message)

# Calculate the execution time
execution_time = time.time() - start_time

# Print the execution time and the total number of API requests
print("Execution time: {:.2f} seconds".format(execution_time))
print("Total API requests: {}".format(api_request_count[0]))