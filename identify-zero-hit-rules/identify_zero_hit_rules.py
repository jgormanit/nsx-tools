import requests
import json
import urllib3

# Suppress only the single InsecureRequestWarning from urllib3 needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define the variables at the top of the script
nsx_manager_fqdn = "nsx_manager_fqdn_here"
username = "nsx_user_here"
password = "nsx_pass_here"

def get_security_policies(nsx_manager_fqdn, username, password):
    url = f"https://{nsx_manager_fqdn}/policy/api/v1/infra/domains/default/security-policies/"
    response = requests.get(url, auth=(username, password), verify=False)
    response.raise_for_status()
    return response.json()

def get_security_policy_statistics(nsx_manager_fqdn, username, password, policy_id):
    url = f"https://{nsx_manager_fqdn}/policy/api/v1/infra/domains/default/security-policies/{policy_id}/statistics"
    response = requests.get(url, auth=(username, password), verify=False)
    if response.status_code == 400:
        print(f"Bad Request for URL: {url}")
        print(response.text)
        return None
    response.raise_for_status()
    return response.json()

def main(nsx_manager_fqdn, username, password):
    policies = get_security_policies(nsx_manager_fqdn, username, password)
    zero_hit_rules = []

    for policy in policies.get("results", []):
        if policy.get("resource_type") == "SecurityPolicy" and policy.get("category") != "Ethernet":
            policy_id = policy.get("id")
            stats = get_security_policy_statistics(nsx_manager_fqdn, username, password, policy_id)
            if stats is None:
                continue

            for result in stats.get("results", []):
                for rule in result.get("statistics", {}).get("results", []):
                    if rule.get("hit_count", 1) == 0:  # default hit_count to 1 if not present to avoid zero hit false positive if field does not exist for some reason
                        zero_hit_rules.append({
                            "security_policy_id": policy_id,
                            "internal_rule_id": rule.get("internal_rule_id")
                        })

    print(json.dumps(zero_hit_rules, indent=2))

if __name__ == "__main__":
    main(nsx_manager_fqdn, username, password)
