"""
knowledge_base.py

Legitimate document corpus for the RAG-based IoT/cyber threat-intelligence
assistant. Each document simulates a real trusted-source entry: a CVE record,
a MITRE ATT&CK technique writeup, or a vendor security advisory.

Each document is a dict with:
    id        - unique identifier
    source    - simulated trusted source label (used later by the defense)
    title     - short title
    text      - the actual content the retriever will search over
"""

LEGITIMATE_DOCS = [
    {
        "id": "doc_001",
        "source": "NVD",
        "title": "CVE-2023-XXXX: Default Credentials in IoT Camera Firmware",
        "text": (
            "CVE-2023-XXXX affects several low-cost IP camera models that ship "
            "with a hardcoded default administrator password. Attackers can "
            "gain full device control over the network without authentication. "
            "Mitigation: change the default credentials immediately upon "
            "deployment, disable remote administration interfaces, and apply "
            "the vendor firmware patch that removes the hardcoded account."
        ),
    },
    {
        "id": "doc_002",
        "source": "MITRE-ATT&CK",
        "title": "T1200: Hardware Additions in IoT Environments",
        "text": (
            "Adversaries may introduce unauthorized hardware to gain a foothold "
            "in IoT networks. This technique is common in industrial and smart "
            "building deployments. Mitigation: maintain a hardware asset "
            "inventory, use network access control (802.1X) to block unknown "
            "devices, and monitor for unexpected MAC addresses on segmented "
            "IoT VLANs."
        ),
    },
    {
        "id": "doc_003",
        "source": "Vendor-Advisory-Siemens",
        "title": "Siemens Security Advisory SSA-2023-01: Firmware Signature Bypass",
        "text": (
            "A vulnerability in certain Siemens SIMATIC controllers allows "
            "unsigned firmware to be loaded if signature verification is "
            "disabled during a maintenance window. Mitigation: always keep "
            "firmware signature verification enabled, restrict firmware update "
            "access to authenticated engineering stations, and audit update "
            "logs for unsigned image attempts."
        ),
    },
    {
        "id": "doc_004",
        "source": "NVD",
        "title": "CVE-2022-YYYY: Insecure MQTT Broker Configuration",
        "text": (
            "Many IoT deployments use MQTT brokers configured without "
            "authentication or TLS, exposing telemetry and control topics to "
            "anyone on the network. Mitigation: enforce TLS for all MQTT "
            "traffic, require client certificate or username/password "
            "authentication, and apply topic-level access control lists."
        ),
    },
    {
        "id": "doc_005",
        "source": "MITRE-ATT&CK",
        "title": "T1498: Network Denial of Service Against IoT Gateways",
        "text": (
            "Adversaries may flood IoT gateway devices with traffic to disrupt "
            "sensor data collection or control loops. Mitigation: deploy rate "
            "limiting and traffic shaping at the gateway, use redundant "
            "gateways where safety-critical, and monitor for abnormal traffic "
            "spikes with anomaly detection."
        ),
    },
    {
        "id": "doc_006",
        "source": "Vendor-Advisory-Siemens",
        "title": "Siemens Security Advisory SSA-2023-07: Weak TLS Cipher Support",
        "text": (
            "Certain SIMATIC S7 communication modules support deprecated TLS "
            "1.0/1.1 ciphers, permitting downgrade attacks. Mitigation: disable "
            "TLS 1.0/1.1 support, restrict to TLS 1.2 or higher with modern "
            "cipher suites, and rotate any certificates issued under the "
            "weaker configuration."
        ),
    },
    {
        "id": "doc_007",
        "source": "NVD",
        "title": "CVE-2021-ZZZZ: Command Injection in Smart Thermostat Web Interface",
        "text": (
            "A command injection vulnerability in the web management interface "
            "of a popular smart thermostat allows remote code execution via a "
            "crafted device name field. Mitigation: apply the vendor patch, "
            "disable the web interface if not needed, and place the device "
            "behind a firewall restricting inbound access to the management "
            "port."
        ),
    },
    {
        "id": "doc_008",
        "source": "MITRE-ATT&CK",
        "title": "T1078: Valid Accounts Used Against Industrial Control Systems",
        "text": (
            "Adversaries may obtain and abuse valid engineering or operator "
            "credentials to access ICS/SCADA systems. Mitigation: enforce "
            "multi-factor authentication for engineering workstation access, "
            "rotate credentials regularly, and apply least-privilege roles "
            "separating monitoring from control functions."
        ),
    },
]
