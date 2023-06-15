# NSX DFW Rules with Logging Exporter

This script exports Distributed Firewall (DFW) rules from the NSX Manager that have logging enabled and saves them to a CSV file.

## Prerequisites

- Python 3.x
- Packages listed in `requirements.txt`

## Usage

1. Install Python 3.x if it is not already installed on your system.

2. Install the required packages by running the following command: `pip3 install -r requirements.txt`

3. Open the script file `dfw_rules_with_logging_exporter.py` and update the following variables:
- `username`: NSX Manager username
- `password`: NSX Manager password
- `nsx_manager_ip`: NSX Manager IP address
- `csv_directory`: Directory path for CSV export (e.g., '/path/to/save/csv/')

4. Run the script using the following command: `python3 dfw_rules_with_logging_exporter.py`

5. The script will connect to the NSX Manager, retrieve the security policies and rules from the Distributed Firewall, filter the rules to include only those with logging enabled, and export them to a CSV file in the specified directory. The CSV file will be named in the format: `dfw_rules_with_logging_<current_date_time>.csv`.

6. After the script finishes execution, you will see the following output:

Total API requests made: <api_requests_count>
CSV file exported to: <csv_path>

## Notes

- The script uses the provided NSX Manager credentials and API endpoints to retrieve the security policies and rules from the Distributed Firewall.
- The exported CSV file contains the following columns: `parent_path`, `rule_id`, `display_name`, `action`, `logged`.
- The SSL verification is disabled for simplicity. Make sure to use it in a secure environment.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


