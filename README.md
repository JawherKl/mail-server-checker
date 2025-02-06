# Mail Server Checker (MSC)

![mail_checker](https://github.com/JawherKl/mail-server-checker/blob/main/mail_checker.png)

## Overview
The **Mail Server Checker** is a PHP new tool designed to analyze and verify the different protocols (SPF, DMARC, DKIM) releated to the domain mail server, all that verification and analyse based at PHP-based fonction `dns_get_records` to get the DNS records for a given specifique mailing domain. It can check various DNS record types, including A, NS, MX, SOA, and TXT, providing detailed information about the mail server configuration and its associated DNS records.

## Features
- Retrieve and display various DNS records for a specified domain.
- Support for multiple DNS record types (A, NS, MX, SOA, TXT).
- Clean and structured output for easy readability.

## Requirements
- PHP 7.4 or higher
- Composer

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/JawherKl/mail-server-checker.git
   ```
