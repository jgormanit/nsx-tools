# NSX Intrusion Detection Service Signature Exporter

This script allows you to export the intrusion detection service signatures from an NSX Manager to a CSV file.

## Prerequisites

- Python 3.x
- Packages listed in `requirements.txt`

## Usage

1. Install Python 3.x if it is not already installed on your system.

2. Install the required packages by running the following command:
    ```
    pip3 install -r requirements.txt
    ```

3. Open the script file `idps_signature_exporter.py` and update the following variables:
    - `username`: NSX Manager username
    - `password`: NSX Manager password
    - `nsx_ip`: NSX Manager IP or FQDN
    - `signature_version`: Desired signature version ID
    - `csv_directory`: Directory path for CSV export (e.g., '/path/to/export/')
    
4. Run the script using the following command:
    ```
    python3 idps_signature_exporter.py
    ```

5. The script will connect to the NSX Manager, retrieve the intrusion detection service signatures for the specified version, and export them to a CSV file in the specified directory. The CSV file will be named in the format: `<nsx_ip>_idps-signatures_<signature_version>_<current_time>.csv`.

6. After the script finishes execution, you will see the following output:
    ```
    CSV file exported successfully.
    Execution time: <execution_time> seconds
    Total API requests: <api_request_count>
    ```

## Notes

- The script uses the provided NSX Manager credentials and API endpoints to retrieve the intrusion detection service signatures.
- The signature version ID can be obtained using the API endpoint: `GET /policy/api/v1/infra/settings/firewall/security/intrusion-services/signature-versions/`.
- The exported CSV file contains the detailed information of the intrusion detection service signatures.
- The script disables the SSL verification for simplicity. Make sure to use it in a secure environment.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
