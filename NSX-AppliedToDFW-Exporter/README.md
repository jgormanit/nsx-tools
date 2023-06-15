# NSX AppliedToDFW Exporter

This script exports all Distributed Firewall (DFW) rules from the NSX Manager where the "Applied To" field is set to "DFW".

## Prerequisites

- Python 3.x
- Packages listed in `requirements.txt`

## Usage

1. Install Python 3.x if it is not already installed on your system.

2. Install the required packages by running the following command:
    ```
    pip3 install -r requirements.txt
    ```

3. Open the script file `NSX-AppliedToDFW-Exporter.py` and update the following variables:
    - `username`: NSX Manager username
    - `password`: NSX Manager password
    - `nsx_manager_ip`: NSX Manager IP address
    - `csv_export_directory`: Directory path for CSV export (e.g., '/path/to/export/')

4. Run the script using the following command:
    ```
    python3 NSX-AppliedToDFW-Exporter.py
    ```

5. The script will connect to the NSX Manager, retrieve the security rules from the Distributed Firewall, and export them to a CSV file in the specified directory. The CSV file will be named in the format: `<nsx_manager_ip>_appliedto_dfw_rules_<current_time>.csv`.

6. After the script finishes execution, you will see the following output:
    ```
    Number of API calls made: <api_call_count>
    Data exported to <csv_filepath>
    ```

## Notes

- The script uses the provided NSX Manager credentials and API endpoints to retrieve the security rules from the Distributed Firewall.
- The exported CSV file contains the following columns: `parent_path`, `rule_id`, `display_name`, `scope`.
- The script filters the rules to include only those with the scope set to "ANY".
- The SSL verification is disabled for simplicity. Make sure to use it in a secure environment.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
