# NSXv to NSX-T NAT Parser to Hierarchical API (H-API)

## Disclaimer
The script was written to parse specific environment configuration and may not translate alternate configurations correctly. Please review the script to make sure it can handle your specific NAT config before use.

## Overview
The `nsxv2t-nat-parser-to-hapi.py` script is designed to convert NAT configurations from NSX-v XML format to NSX-T JSON format for the NSX-T hierarchical API.

## Features
- **XML to JSON Conversion**: Converts NAT rules from NSX-v API output in XML format to JSON.
- **Hierarchical Structure**: Outputs JSON in a nested structure compatible with NSX-T's hierarchical API.
- **SNAT and DNAT Rule Handling**: Distinguishes between SNAT and DNAT rules, setting fields accordingly.
- **Logging**: Generates detailed logs of the conversion process and outputs them to a log file.

## Usage
To use this script, you will need Python installed on your system. The script takes one command-line argument: the path to the XML file containing the NSX-v NAT configuration in XML format.
1. Gather the NAT configuration from your selected NSX-v ESG using the below API. If you are unclear on how to use NSX-v API, consult the documentation:
```
GET https://<nsxv-manager-fqdn>/api/4.0/edges/{edgeId}/nat/config
```
2. Store the output data from the above API call into an XML file eg. sample.xml.
```
<?xml version="1.0" encoding="UTF-8"?>
<nat>
    <version>64</version>
    <enabled>true</enabled>
    <natRules>
        <natRule>
            <ruleId>196611</ruleId>
            <ruleTag>196611</ruleTag>
            <loggingEnabled>false</loggingEnabled>
            <enabled>true</enabled>
            <translatedAddress>172.19.100.0/24</translatedAddress>
            <ruleType>user</ruleType>
            <action>snat</action>
            <originalAddress>192.168.100.0/24</originalAddress>
            <snatMatchDestinationAddress>any</snatMatchDestinationAddress>
            <protocol>any</protocol>
            <originalPort>any</originalPort>
            <translatedPort>any</translatedPort>
            <snatMatchDestinationPort>any</snatMatchDestinationPort>
        </natRule>
        <natRule>
            <ruleId>196857</ruleId>
            <ruleTag>196857</ruleTag>
            <loggingEnabled>false</loggingEnabled>
            <enabled>true</enabled>
            <translatedAddress>192.168.100.251</translatedAddress>
            <ruleType>user</ruleType>
            <action>dnat</action>
            <originalAddress>172.25.100.251</originalAddress>
            <dnatMatchSourceAddress>any</dnatMatchSourceAddress>
            <protocol>any</protocol>
            <originalPort>any</originalPort>
            <translatedPort>any</translatedPort>
            <dnatMatchSourcePort>any</dnatMatchSourcePort>
        </natRule>
    </natRules>
    <nat64Rules/>
</nat>
```
3. Update the following variable in the `nsxv2t-nat-parser-to-hapi.py` script.
- `tier1_id`: This must be the ID of an existing Tier-0/Tier-1 Gateway. In my case, my Tier-1 Gateway Object ID is: `predefined_id`
4. Run the `nsxv2t-nat-parser-to-hapi.py` script using the following command (*Replace `sample.xml` with the actual path to your XML file*). See the "Output" section below for information related to files generated and field translation from NSXv to NSX-T:

```
python nsxv2t-nat-parser-to-hapi.py sample.xml
```
5. You can then PATCH the generated JSON file/content to NSX-T API using curl or Postman. In this example, I use postman with the following information (Depending on configuration size, it may take a moment during the PATCH):
- PATCH to NSX-T hierarchical api
- Provide the configuration body in the required nested structure for H-API
```
PATCH https://<nsx-t-manager-fqdn>/policy/api/v1/infra
```
Body:
```
{
    "resource_type": "Infra",
    "id": "infra",
    "children": [
        {
            "Tier1": {
                "resource_type": "Tier1",
                "id": "predefined_id",
                "children": [
                    {
                        "PolicyNat": {
                            "resource_type": "PolicyNat",
                            "id": "USER",
                            "children": [
                                {
                                    "PolicyNatRule": {
                                        "sequence_number": 196611,
                                        "action": "SNAT",
                                        "translated_network": "172.19.100.0/24",
                                        "scope": [
                                            "/infra/tier-1s/predefined_id"
                                        ],
                                        "enabled": true,
                                        "logging": false,
                                        "firewall_match": "MATCH_INTERNAL_ADDRESS",
                                        "resource_type": "PolicyNatRule",
                                        "id": "196611",
                                        "display_name": "Nat Rule 196611",
                                        "description": "Converted from NSX-v",
                                        "source_network": "192.168.100.0/24"
                                    },
                                    "resource_type": "ChildPolicyNatRule"
                                },
                                {
                                    "PolicyNatRule": {
                                        "sequence_number": 196857,
                                        "action": "DNAT",
                                        "translated_network": "192.168.100.251",
                                        "scope": [
                                            "/infra/tier-1s/predefined_id"
                                        ],
                                        "enabled": true,
                                        "logging": false,
                                        "firewall_match": "MATCH_INTERNAL_ADDRESS",
                                        "resource_type": "PolicyNatRule",
                                        "id": "196857",
                                        "display_name": "Nat Rule 196857",
                                        "description": "Converted from NSX-v",
                                        "destination_network": "172.25.100.251"
                                    },
                                    "resource_type": "ChildPolicyNatRule"
                                }
                            ]
                        },
                        "resource_type": "ChildPolicyNat",
                        "marked_for_delete": false
                    }
                ]
            },
            "resource_type": "ChildTier1"
        }
    ]
}
```
6. You should see a 200 OK status and an empty return body. Now check NSX to confirm your rules exist on the specified Tier0/Tier1 Gateway.

## Parser Output details
- The script outputs a JSON file in the same directory where the script is run. The filename includes the original XML filename and a timestamp to ensure uniqueness and traceability. In this example, it created: *sample_20240424130551.json*.
- A log file named `nat_conversion.log` is also generated in the same directory, detailing information such as:
  - Successful loading and parsing of the XML file.
  - Details of each NAT rule processed.
  - Any errors or issues encountered during the conversion.

### Field Definitions for translation
- **NSX-v**:
  - `originalAddress`: Original address or address range. This is the source address for SNAT rules, and the destination address for DNAT rules.
  - `translatedAddress`: Translated address or address range.
- **NSX-T**:
  - `source_network`: Represents the source network address This supports single IP address or comma separated list of single IP addresses or CIDR. This does not support IP range or IP sets. For SNAT, NO_SNAT, NAT64 and REFLEXIVE rules, this is a mandatory field and represents the source network of the packets leaving the network. For DNAT and NO_DNAT rules, optionally it can contain source network of incoming packets. NULL value for this field represents ANY network. 
  - `destination_network`: Represents the destination network. This supports single IP address or comma separated list of single IP addresses or CIDR. This does not support IP range or IP sets. For DNAT and NO_DNAT rules, this is a mandatory field, and represents the destination network for the incoming packets. For other type of rules, optionally it can contain destination network of outgoing packets. NULL value for this field represents ANY network. 
  - `translated_network`: Represents the translated network address. This supports single IP address or comma separated list of single IP addresses or CIDR. If user specify the CIDR, this value is actually used as an IP pool that includes both the subnet and broadcast addresses as valid for NAT translations. This does not support IP range or IP sets. Comma separated list of single IP addresses is not suported for DNAT and REFLEXIVE rules. For SNAT, DNAT, NAT64 and REFLEXIVE rules, this ia a mandatory field, which represents the translated network address. For NO_SNAT and NO_DNAT this should be empty. 

## Field Mapping
- **SNAT Rules**: 
  - `source_network` is set from the `originalAddress`.
  - `translated_network` is derived from the `translatedAddress`.
  - Other fields like `enabled`, `logging`, and `firewall_match` are directly mapped based on their respective XML tags.
- **DNAT Rules**:
  - `destination_network` is set from the `originalAddress`.
  - `translated_network` is derived from the `translatedAddress`.
  - Similar to SNAT, other fields are mapped directly.



