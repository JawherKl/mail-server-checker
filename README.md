# Mail Server Checker (MSC)

![mail_checker](https://github.com/JawherKl/mail-server-checker/blob/main/mail_checker.png)

## Overview
The **Mail Server Checker** is a PHP tool designed to analyze and verify various email protocols (SPF, DMARC, DKIM) related to domain mail servers. It retrieves and displays DNS records, providing a comprehensive analysis of your email server's configuration and security.

## Features
- Retrieve and display various DNS records for a specified domain.
  - Supported record types: A, NS, MX, SOA, TXT.
- Verify SPF, DMARC, and DKIM records for email security.
- Clean and structured output for easy readability.
- Detailed error reporting and suggestions for fixing issues.

## Requirements
- PHP 7.4 or higher
- Composer

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/JawherKl/mail-server-checker.git
   ```

2. Navigate to the project directory:
   ```bash
   cd mail-server-checker
   ```

3. Install dependencies using Composer:
   ```bash
   composer install
   ```

## Usage

To check a domain's mail server configuration, run the following command:

```bash
php checker.php example.com
```

Replace `example.com` with the domain you want to check. The tool will display the DNS records and verify the SPF, DMARC, and DKIM configurations.

## Example Output

```plaintext
Domain: example.com

A Records:
- 192.0.2.1

NS Records:
- ns1.example.com
- ns2.example.com

MX Records:
- mail.example.com (Priority: 10)

SPF Record:
- v=spf1 include:_spf.example.com ~all

DMARC Record:
- v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com

DKIM Record:
- Selector: default
- Public Key: (Public key data here)

Analysis:
- SPF: Pass
- DMARC: Pass
- DKIM: Pass
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
