# PSNetSec

<p align="center">
  <picture>
    <img alt="PSNetSec logo" src="https://i.ibb.co/wF1C6fBN/431515774-169891cf-30a5-4e99-974a-2a8a8ed35355.png" style="max-width: 100%;">
  </picture>
  <br/>
</p>

## About

PSNetSec is an open-source PowerShell-based toolkit designed for network administrators and security professionals. It provides tools for network scanning, SNMP data retrieval, and secure data handling. The project leverages multithreading for efficient processing and supports encryption for sensitive data.

## Features

- **Network Scanning**: Perform ICMP-based network scans to detect devices and their statuses.
- **SNMP Data Retrieval**: Collect detailed information from devices using SNMP v1 protocol.
- **Multithreading**: Utilize multithreading to speed up operations like scanning and data retrieval.
- **Encryption**: Secure sensitive data using AES encryption (CBC for PowerShell 5, GCM for PowerShell 7).
- **Customizable**: Easily configure known devices and SNMP OIDs using CSV and YAML files.
- **Extensible**: Modular design allows for easy integration and extension.

## Project Structure

```
PSNetSec/
├── GhostPulse.ps1          # Network scanning script
├── SNMProbe.ps1            # SNMP data retrieval script
├── config/
│   ├── known-devices.csv.example  # Example CSV for known devices
│   ├── snmp-oids.yml.example      # Example YAML for SNMP OIDs
├── libs/
│   ├── GhostPulseLib.psd1         # Manifest for GhostPulse library
│   ├── GhostPulseLib.psm1         # Functions for network scanning
│   ├── SecurityLib.psd1           # Manifest for Security library
│   ├── SecurityLib.psm1           # Functions for encryption and security
│   ├── SNMPLib.psd1               # Manifest for SNMP library
│   ├── SNMPLib.psm1               # Functions for SNMP data retrieval
├── models/
│   ├── ExceptionsModel.psm1       # Custom exception classes      [Currently unused]
│   ├── RestModel.psm1             # REST API interaction classes  [Currently unused]
├── README.md               # Project documentation
```

## Requirements

- **PowerShell**: Version 5.1 or later (PowerShell 7 recommended for GCM encryption).
- **Modules**:
  - `ThreadJob`: For multithreading.
  - `powershell-yaml`: For YAML file parsing.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/PSNetSec.git
   cd PSNetSec
   ```

2. Install required PowerShell modules:
   ```powershell
   Install-Module -Name ThreadJob -Scope CurrentUser
   Install-Module -Name powershell-yaml -Scope CurrentUser
   ```

3. Configure the project:
   - Copy `config/known-devices.csv.example` to `config/known-devices.csv` and update it with your known devices.
   - Copy `config/snmp-oids.yml.example` to `config/snmp-oids.yml` and update it with your SNMP OIDs.

## Usage

### GhostPulse

GhostPulse performs ICMP-based network scans to detect devices.

#### Syntax
```powershell
GhostPulse.ps1 [-t <target>] [-i <input file>] [-o <output file>] [-up] [-v] [-h]
```

#### Examples
- Scan a single network:
  ```powershell
  .\GhostPulse.ps1 -t 192.168.1.0/24 -o output.csv
  ```
- Scan multiple networks from a file:
  ```powershell
  .\GhostPulse.ps1 -i networks.txt -o output.csv -up
  ```

### SNMProbe

SNMProbe retrieves SNMP data from devices. Input should be the output from GhostPulse or follow the same structure.

#### Syntax
```powershell
SNMProbe.ps1 [-i <input file>] [-o <output file>] [-e] [-c] [-h]
```

#### Examples
- Retrieve SNMP data and save it as JSON:
  ```powershell
  .\SNMProbe.ps1 -i input.csv -o output.json
  ```
- Retrieve SNMP data and encrypt the output:
  ```powershell
  .\SNMProbe.ps1 -i input.csv -o output.json -e -c
  ```

## Configuration

### Known Devices (`config/known-devices.csv`)
Define the models and types of devices in your network. Example:
```csv
Model;Type
FG;Firewall
Cisco Aironet;Wireless Access Point
SG;Switch
```

### SNMP OIDs (`config/snmp-oids.yml`)
Define the SNMP OIDs and communities for your devices. Example:
```yaml
devices:
  Cisco:
    model:
      - .1.3.6.1.2.1.47.1.1.1.1.7.67108992
    serial:
      - .1.3.6.1.2.1.47.1.1.1.1.11.67108992
  Fortigate:
    serial:
      - .1.3.6.1.4.1.12356.100.1.1.1.0
```

## Roadmap

- [ ] Improve modularity
- [ ] SNMP v2 & v3 support
- [ ] More complete IP scanning options

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and push them to your fork.
4. Submit a pull request with a detailed description of your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [ThreadJob](https://www.powershellgallery.com/packages/ThreadJob): For multithreading support.
- [powershell-yaml](https://www.powershellgallery.com/packages/powershell-yaml): For YAML parsing.

## Contact

For questions or feedback, please open an issue on the [GitHub repository](https://github.com/your-username/PSNetSec).
