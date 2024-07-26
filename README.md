#PRODIGY_CS_04

Packet Sniffer

A simple packet sniffer tool using Python and Scapy for capturing and analyzing network packets. This tool displays relevant information such as source and destination IP addresses, protocols, and payload data.
Overview

The packet sniffer captures network packets on a specified network interface and displays details such as:

    Source IP address
    Destination IP address
    Protocol (TCP/UDP)
    Source and destination ports
    Payload data

Disclaimer

Use this tool responsibly and ensure that you have permission to capture network traffic on the network you are analyzing. Unauthorized packet sniffing can be illegal and unethical.
Features

    Captures IP packets
    Displays TCP and UDP packet information
    Shows source and destination IPs and ports
    Displays payload data if available

Requirements

    Python 3.x
    Scapy library

Installation
1. Install Python

Ensure Python 3.x is installed on your system. You can download it from the official Python website.
2. Install Scapy

Install the Scapy library using pip. Open your terminal or command prompt and run:

bash

pip install scapy

For Python 3, you might need:

bash

pip3 install scapy

3. Download the Script

Usage
Linux/macOS

    Find Your Network Interface

    List available network interfaces:

    bash

ifconfig

or:

bash

ip a

Run the Script

Navigate to the directory where packet_sniffer.py is saved:

bash

cd path/to/your/script

Run the script with elevated privileges:

bash

    sudo python3 packet_sniffer.py

Windows

    Find Your Network Interface

    Open Command Prompt and list network interfaces:

    bash

ipconfig

Identify the network interface you want to use.

Run the Script

Open Command Prompt as Administrator, navigate to the script directory:

bash

cd path\to\your\script

Run the script:

bash

    python packet_sniffer.py

Configuration

    Network Interface: Modify the interface variable in the script to match your network interface (e.g., eth0, wlan0, en0).

Troubleshooting

    Permissions: Ensure you have the necessary permissions to run packet sniffing tools. Use sudo on Linux/macOS or run Command Prompt as Administrator on Windows.

    Network Interface: Double-check the network interface name to ensure it is correctly specified.

    Scapy Installation: Verify that Scapy is installed correctly by running:

    bash

    python -c "import scapy; print(scapy.__version__)"

Contributing

Contributions are welcome! Please fork the repository, make changes, and submit a pull request.
License

This project is licensed under the MIT License. See the LICENSE file for details.
