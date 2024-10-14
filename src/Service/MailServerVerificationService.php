<?php

namespace App\Service;

use MxToolbox\MxToolbox;
use MxToolbox\Exceptions\MxToolboxRuntimeException;
use MxToolbox\Exceptions\MxToolboxLogicException;
use Ramsey\Uuid\Uuid;

use Iodev\Whois\Factory;
use Iodev\Whois\Whois as WhoisWhois;
use League\Uri\Components\Query;
use League\Uri\Modifier;
use League\Uri\Uri;
use Spatie\Dns\Dns;

class MailServerVerificationService
{
    public function checkSPF(string $domain)
    {
        $startTime = microtime(true);
        // Variables to track timeouts, errors, and whether an error occurred
        $timeout = false;
        $isError = false;
        $errorMessage = [];
        $timeoutThreshold = 5; // seconds
        try {
            // Perform DNS lookup and SPF analysis
            $spfData = $this->getSpfRecord($domain);
            $reportingNameServer = $this->getReportingNameServer($domain);
            $dnsLookupResults = $this->getDnsLookup($domain); // Fetch related DNS lookups
    
            // End timing
            $endTime = microtime(true);
    
            // Check for timeout (if execution time exceeds threshold)
            $executionTime = ($endTime - $startTime);
            if ($executionTime > $timeoutThreshold) {
                $timeout = true;
                throw new \Exception("Request timed out after $timeoutThreshold seconds.");
            }
    
        } catch (\Exception $e) {
            // Handle any error that occurs during the process
            $isError = true;
            $errorMessage = ["error"=>$e->getMessage()];
            // Set default values in case of an error
            $spfData = null;
            $reportingNameServer = null;
        }
        // Calculate time to complete in milliseconds
        $timeToComplete = ($endTime - $startTime) * 1000;
        // Structure the response
        $response = [
            "UID" => Uuid::uuid4()->toString(),
            "ArgumentType" => "domain",
            "Command" => "spf",
            "CommandArgument" => $domain,
            "TimeRecorded" => (new \DateTime())->format(\DateTime::ATOM),
            "ReportingNameServer" => $reportingNameServer,
            "TimeToComplete" => round((microtime(true) - $startTime)*1000),
            "RelatedIP" => $this->getRelatedIP($domain),
            "ResourceRecordType" => 16,
            "IsEmptySubDomain" => $this->getIsEmptySubDomain($domain),
            "IsEndpoint" => $this->getIsEndpoint($domain),
            "HasSubscriptions" => $this->getHasSubscriptions($domain),
            "Failed" => $this->getFailedSpfChecks($spfData, $domain),
            "Warnings" => $this->getWarningSpfChecks($spfData),
            "Passed" => $this->getPassedSpfChecks($spfData),
            "Timeouts" => $timeout,
            "Errors" => $errorMessage,
            "IsError" => $isError,
            "Information" => $this->getSpfInfo($spfData),
            "Transcript" => $this->generateSpfTranscript($domain, $spfData, $dnsLookupResults),
            "EmailServiceProvider" => $this->getInfoMxToolbox($domain),
            "DnsServiceProvider" => $this->getDnsServiceProvider($spfData),
            "RelatedLookups" => $this->getDnsLookup($domain)
        ];
        return $response;
    }

    private function getReportingNameServer(string $domain): string
    {
        // Get the IP address of the nameserver
        $nsRecords = dns_get_record($domain, DNS_NS);
        if (!empty($nsRecords)) {
            $nsDomain = $nsRecords[0]['target'];
            $ipAddress = gethostbyname($nsDomain); // Get IP from NS domain
            // Convert IP address to domain name
            $reportingDomain = gethostbyaddr($ipAddress);
            return $reportingDomain !== $ipAddress ? $reportingDomain : $ipAddress;
        }
        return "No nameserver found";
    }

    private function getRelatedIP(string $domain): ?string
    {
        // Perform a DNS lookup to get A or AAAA records (IPv4 or IPv6 addresses)
        $dnsRecords = dns_get_record($domain, DNS_A | DNS_AAAA);
        
        $ips = [];
        foreach ($dnsRecords as $record) {
            if (isset($record['ip'])) {
                $ips[] = $record['ip']; // Get IPv4 address
            } elseif (isset($record['ipv6'])) {
                $ips[] = $record['ipv6']; // Get IPv6 address
            }
        }

        // Return null if no IPs found, otherwise return a comma-separated list of IPs
        return !empty($ips) ? implode(', ', $ips) : null;
    }

    private function getIsEmptySubDomain(string $domain): bool
    {
        // Check if this domain is a subdomain
        $isSubdomain = (substr_count($domain, '.') > 1);

        // Perform a DNS lookup to check if there are any A, AAAA, or MX records
        $dnsRecords = dns_get_record($domain, DNS_A | DNS_AAAA | DNS_MX);

        // If it's a subdomain and has no records, consider it an empty subdomain
        return $isSubdomain && empty($dnsRecords);
    }

    private function getIsEndpoint(string $domain): bool
    {
        // Fetch the SPF record for the domain
        $spfRecord = dns_get_record($domain, DNS_TXT);

        // Search for SPF in the TXT records
        foreach ($spfRecord as $record) {
            if (strpos($record['txt'], 'v=spf1') === 0) {
                // Check if the record ends with '-all', which indicates an endpoint
                return strpos($record['txt'], '-all') !== false;
            }
        }

        return false;
    }

    private function getHasSubscriptions(string $domain): bool
    {
        // Fetch the SPF record for the domain
        $spfRecord = dns_get_record($domain, DNS_TXT);

        // Search for SPF in the TXT records
        foreach ($spfRecord as $record) {
            if (strpos($record['txt'], 'v=spf1') === 0) {
                // Check if the SPF record contains the "include:" directive, indicating a subscription
                return strpos($record['txt'], 'include:') !== false;
            }
        }

        return false;
    }

    private function getDnsServiceProvider(string $spfRecord)
    {
        // Define a list of known DNS providers with their identifying patterns
        $dnsProviders = [
            'Google' => 'include:_spf.google.com',
            'Microsoft' => 'include:spf.protection.outlook.com',
            'Amazon AWS' => 'include:amazonses.com',
            'GoDaddy' => 'include:secureserver.net',
            'Cloudflare' => 'include:_spf.cloudflare.com',
            'Zoho' => 'include:zoho.com',
            'Mailchimp' => 'include:servers.mcsv.net',
            'Yahoo' => 'include:spf.mail.yahoo.com',
            'Ovh' => 'include:mx.ovh.com'
        ];

        // Iterate through the list of providers and check if their pattern exists in the SPF record
        foreach ($dnsProviders as $providerName => $providerPattern) {
            if (strpos($spfRecord, $providerPattern) !== false) {
                return $providerName;  // Return the provider name if a match is found
            }
        }

        // If no known providers are found, return null
        return null;
    }

    private function getDnsPhpChecks($domain) {
        //$nsRecords = dns_get_record($domain, DNS_NS);// get all nameserver
        //$nsRecords = getmxrr($domain, $mxRecords);// for validation
        //$nsRecords = dns_get_mx($domain, $mxRecords);// for validation dns
        //$nsRecords = checkdnsrr($domain);// for checkdnsrr
        //$nsRecords = dns_check_record($domain);// for dns_check_record
        //$nsRecords = gethostname();// for get hostname
        //$nsRecords = gethostbynamel($domain);// for get list of IP hostname
        //$nsRecords = gethostbyname($domain);// for get IP hostname
        //$nsRecords = gethostbyaddr(gethostbyname($domain));// to get off hostname
        $nsRecords = net_get_interfaces();// 
        return $nsRecords;
    }

    private function checkSpfSyntax($domain) {
        /*$validator = new EmailValidator();
        $multipleValidations = new MultipleValidationWithAnd([
            new RFCValidation(),
            new DNSCheckValidation()
        ]);
        //ietf.org has MX records signaling a server with email capabilities
        // Add actual SPF syntax validation logic here (this is a placeholder)
        return $validator->isValid($domain, new RFCValidation()); // Assume valid for now*/ 
         // Simulate SPF syntax check results
        return [
            "TXT:$domain", 
            "TXT:spf.example.com",
            "TXT:mails-tourmag.com"
        ];
        //return true;
    }

    private function checkDmarcSyntax($domain) {
        /* 
        $validator = new EmailValidator();
        $multipleValidations = new MultipleValidationWithAnd([
            new RFCValidation(),
            new DNSCheckValidation()
        ]);
        // Add actual DMARC syntax validation logic here (this is a placeholder)
        return $validator->isValid($domain, new RFCValidation()); // Assume valid for now
        */
    
        // Simulate DMARC syntax check results
        return [
            "TXT:$domain",
            "TXT:dmarc.example.com",
            "TXT:hub-score.com"
        ];
        // return true; // Optionally return true if all validations pass
    }

    private function checkDkimSyntax($domain) {
        /* 
        $validator = new EmailValidator();
        $multipleValidations = new MultipleValidationWithAnd([
            new RFCValidation(),
            new DNSCheckValidation()
        ]);
        // Add actual DMARC syntax validation logic here (this is a placeholder)
        return $validator->isValid($domain, new RFCValidation()); // Assume valid for now
        */
    
        // Simulate DMARC syntax check results
        return [
            "TXT:$domain",
            "TXT:dkim.example.com",
            "TXT:hub-score.com"
        ];
        // return true; // Optionally return true if all validations pass
    }

    private function checkIps($domain) {
        $whois = Factory::get()->createWhois();
        // Checking availability
        if ($whois->isDomainAvailable($domain)) {
            print "Bingo! Domain is available! :)";
        }

        // Supports Unicode (converts to punycode)
        if ($whois->isDomainAvailable("почта.рф")) {
            print "Bingo! Domain is available! :)";
        }

        // Getting raw-text lookup
        $response = $whois->lookupDomain($domain);
        print $response->text;

        // Getting parsed domain info
        $info = $whois->loadDomainInfo($domain);
        return $info;
    }

    private function getDomainHttpsInfo($domain) {
        $uri = Uri::new($domain);
        $uri->getScheme(); // returns 'http'
        $uri->getHost();   // returns 'example.com'

        $newUri = Modifier::from($uri)->appendQuery('q=new.Value');
        echo $newUri; // 'https://example.com?q=value&q=new.Value#fragment'

        $query = Query::fromUri($newUri);
        $query->get('q');    // returns 'value'
        $query->getAll('q'); // returns ['value', 'new.Value']
        $query->parameter('q'); // returns 'new.Value'
        return $query->getAll('q');
    }

    private function getSpfRecord(string $domain)
    {
        // Use DNS functions to fetch SPF record
        $records = dns_get_record($domain, DNS_TXT);
        foreach ($records as $record) {
            if (strpos($record['txt'], 'v=spf1') !== false) {
                return $record['txt'];
            }
        }
        return null;
    }

    private function parseSpfRecord($spfString)
    {
        $spfArray = [];
        $parts = preg_split('/\s+/', trim($spfString)); // Split by whitespace

        foreach ($parts as $index => $part) {
            // Check for the prefix and value
            if (strpos($part, 'include:') === 0) {
                $spfArray[] = [
                    "Prefix" => "+",
                    "Type" => "include",
                    "Value" => str_replace('include:', '', $part),
                    "PrefixDesc" => "Pass",
                    "Description" => "The specified domain is searched for an 'allow'.",
                    "RecordNum" => null
                ];
            } elseif ($part === '-all') {
                $spfArray[] = [
                    "Prefix" => "-",
                    "Type" => "all",
                    "Value" => "",
                    "PrefixDesc" => "Fail",
                    "Description" => "Always matches. It goes at the end of your record.",
                    "RecordNum" => null
                ];
            } elseif (strpos($part, 'v=') === 0) {
                $spfArray[] = [
                    "Prefix" => "",
                    "Type" => "v",
                    "Value" => str_replace('v=', '', $part),
                    "PrefixDesc" => "",
                    "Description" => "The SPF record version.",
                    "RecordNum" => null
                ];
            } else {
                // Handle other types of records (e.g., IP addresses, a records, etc.)
                $spfArray[] = [
                    "Prefix" => "+",
                    "Type" => "record",
                    "Value" => $part,
                    "PrefixDesc" => "Pass",
                    "Description" => "Record found.",
                    "RecordNum" => null
                ];
            }
        }

        return $spfArray;
    }

    private function parseDmarcRecord($dmarcString)
    {
        $dmarcArray = [];
        $parts = preg_split('/;\s*/', trim($dmarcString)); // Split by semicolon and optional whitespace

        foreach ($parts as $part) {
            // Split each part into key-value pairs
            $keyValue = explode('=', $part, 2);
            
            if (count($keyValue) === 2) {
                $key = trim($keyValue[0]);
                $value = trim($keyValue[1]);

                // Handle DMARC policy tags
                switch ($key) {
                    case 'v':
                        $dmarcArray[] = [
                            "Type" => "version",
                            "Value" => $value,
                            "Description" => "The DMARC record version."
                        ];
                        break;
                    case 'p':
                        $dmarcArray[] = [
                            "Type" => "policy",
                            "Value" => $value,
                            "Description" => "The DMARC policy for the domain."
                        ];
                        break;
                    case 'pct':
                        $dmarcArray[] = [
                            "Type" => "percentage",
                            "Value" => $value,
                            "Description" => "The percentage of messages subjected to filtering."
                        ];
                        break;
                    case 'rua':
                        $dmarcArray[] = [
                            "Type" => "reporting-uri-aggregate",
                            "Value" => $value,
                            "Description" => "URI(s) to which aggregate reports are sent."
                        ];
                        break;
                    case 'ruf':
                        $dmarcArray[] = [
                            "Type" => "reporting-uri-forensic",
                            "Value" => $value,
                            "Description" => "URI(s) to which forensic reports are sent."
                        ];
                        break;
                    case 'sp':
                        $dmarcArray[] = [
                            "Type" => "subdomain-policy",
                            "Value" => $value,
                            "Description" => "The policy for subdomains."
                        ];
                        break;
                    case 'adkim':
                        $dmarcArray[] = [
                            "Type" => "alignment-mode",
                            "Value" => $value,
                            "Description" => "The alignment mode for DKIM."
                        ];
                        break;
                    case 'aspf':
                        $dmarcArray[] = [
                            "Type" => "alignment-mode",
                            "Value" => $value,
                            "Description" => "The alignment mode for SPF."
                        ];
                        break;
                    // You can add more tags as needed
                    default:
                        $dmarcArray[] = [
                            "Type" => "unknown",
                            "Value" => $part,
                            "Description" => "Unknown or unsupported DMARC tag."
                        ];
                        break;
                }
            }
        }

        return $dmarcArray;
    }

    private function getPassedSpfChecks($spfData)
    {
        $passedChecks = [];
        $spfRecords = $this->parseSpfRecord($spfData);
        $spfCount = count($spfRecords);

        // Check for SPF Record Published
        if ($spfCount > 0) {
            $passedChecks[] = [
                "ID" => 361,
                "Name" => "SPF Record Published",
                "Info" => "SPF Record found",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
            ];
        }

        // Check for deprecated records
        $deprecatedFound = false;
        foreach ($spfRecords as $record) {
            if (strpos($record['Value'], 'ptr') !== false || strpos($record['Value'], 'exp') !== false) {
                $deprecatedFound = true;
                break;
            }
        }
        if ($deprecatedFound) {
            $passedChecks[] = [
                "ID" => 355,
                "Name" => "SPF Record Deprecated",
                "Info" => $deprecatedFound ? "Deprecated records found" : "No deprecated records found",
                "PublicDescription" => "Hostname has returned a SPF Record that has been deprecated.\n\n"
                    . "SPF records must now only be published as a DNS TXT (type 16) Resource Record (RR) [RFC1035]. "
                    . "Alternative DNS RR types that were supported during the experimental phase of SPF were discontinued in 2014.\n\n"
                    . "According to RFC 7208 Section 3.1: SPF records should no longer use mechanisms like 'ptr' or DNS RR types other than TXT. "
                    . "Records found that violate these requirements are deprecated.",
                "IsExcludedByUser" => false,
            ];
        } else {
            $passedChecks[] = [
                "ID" => 355,
                "Name" => "SPF Record Deprecated",
                "Info" => $deprecatedFound ? "Deprecated records found" : "No deprecated records found",
                "PublicDescription" => "Hostname has returned a SPF Record that has been deprecated.\n\n"
                    . "SPF records must now only be published as a DNS TXT (type 16) Resource Record (RR) [RFC1035]. "
                    . "Alternative DNS RR types that were supported during the experimental phase of SPF were discontinued in 2014.\n\n"
                    . "According to RFC 7208 Section 3.1: SPF records should no longer use mechanisms like 'ptr' or DNS RR types other than TXT. "
                    . "Records found that violate these requirements are deprecated.",
                "IsExcludedByUser" => false,
            ];
        }

        // Check for multiple records
        $passedChecks[] = [
            "ID" => 358,
            "Name" => "SPF Multiple Records",
            "Info" => $spfCount < 2 ? "Less than two records found" : "Multiple records found",
            "PublicDescription" => null,
            "IsExcludedByUser" => false,
        ];

        // Check for characters after ALL
        $invalidAfterAll = false;
        $allMechanismPosition = strrpos($spfData, 'all');

        // Find if there are any characters or terms after 'all'
        if ($allMechanismPosition !== false) {
            // Check if there is any text after the 'all' mechanism
            $remainingString = trim(substr($spfData, $allMechanismPosition + 3));
            if (!empty($remainingString)) {
                $invalidAfterAll = true;
            }
        }

        if ($invalidAfterAll) {
            $passedChecks[] = [
                "ID" => 477,
                "Name" => "SPF Contains characters after ALL",
                "Info" => "There are tags or characters after the 'all' mechanism. These are ignored by mail servers.",
                "PublicDescription" => "This alert means that you have a delivery problem due to a misconfigured SPF record. "
                    . "There are one or more tags after the 'all' indicator in your SPF record, which are ignored by mail servers. "
                    . "For example, in the record:\n\n"
                    . "'v=spf1 ip4:1.2.3.4 ip4:1.2.3.7 include:spf.example.com ~all include:spf2.microsoft.com'\n\n"
                    . "The 'include:spf2.microsoft.com' will be ignored because it falls after the 'all' tag.\n"
                    . "Ensure all desired mechanisms and terms are inserted before the 'all' mechanism as per RFC 7208 Section 5.1.",
                "IsExcludedByUser" => false,
            ];
        } else {
            $passedChecks[] = [
                "ID" => 477,
                "Name" => "SPF Contains characters after ALL",
                "Info" => "No tags or characters after 'all'.",
                "PublicDescription" => "There are no terms or mechanisms after the 'all' indicator in the SPF record, ensuring compliance with RFC 7208 Section 5.1.",
                "IsExcludedByUser" => false,
            ];
        }

        // Check for SPF Syntax
        // SPF Syntax Check
        $invalidSyntax = false;
        $syntaxErrorDetails = [];

        // Check for invalid mechanisms with text instead of domains/hostnames
        $invalidMechanisms = ['mx', 'a', 'ptr', 'exists', 'redirect', 'include'];
        $spfParts = explode(" ", $spfData);

        foreach ($spfParts as $part) {
            $mechanism = explode(":", $part);
            
            // Check for mechanisms that should contain domains/hostnames
            if (in_array($mechanism[0], $invalidMechanisms) && isset($mechanism[1])) {
                if (!filter_var($mechanism[1], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                    $invalidSyntax = true;
                    $syntaxErrorDetails[] = "Mechanism '{$mechanism[0]}' contains invalid domain or hostname: '{$mechanism[1]}'.";
                }
            }
            
            // Check for invalid IP formats in ip4 and ip6 mechanisms
            if (strpos($part, 'ip4:') !== false) {
                $ip = str_replace('ip4:', '', $part);
                if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $invalidSyntax = true;
                    $syntaxErrorDetails[] = "Invalid IPv4 address format: '{$ip}'.";
                }
            }
            if (strpos($part, 'ip6:') !== false) {
                $ip = str_replace('ip6:', '', $part);
                if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $invalidSyntax = true;
                    $syntaxErrorDetails[] = "Invalid IPv6 address format: '{$ip}'.";
                }
            }
        }

        if ($invalidSyntax) {
            $passedChecks[] = [
                "ID" => 478,
                "Name" => "SPF Syntax",
                "Info" => "The SPF record contains syntax errors that may cause email delivery issues.",
                "PublicDescription" => "Hostname returned invalid syntax for SPF record. There are misconfigured mechanisms in your SPF record. "
                    . "This can result in email delivery issues and messages being blocked without clear error messages. "
                    . "Common issues include mechanisms containing text rather than valid domains or hostnames, or incorrect IP address formats.\n\n"
                    . "Details: " . implode("\n", $syntaxErrorDetails),
                "IsExcludedByUser" => false,
            ];
        } else {
            $passedChecks[] = [
                "ID" => 478,
                "Name" => "SPF Syntax",
                "Info" => "The SPF record is valid and contains no syntax errors.",
                "PublicDescription" => "The SPF record was parsed correctly and contains no syntax errors.",
                "IsExcludedByUser" => false,
            ];
        }

        // SPF Included Lookups
        $dnsLookupCount = 0;
        $spfParts = explode(" ", $spfData);

        // DNS Lookup Mechanisms
        $dnsLookupMechanisms = ['include', 'mx', 'a', 'ptr', 'exists'];

        // Check each part of the SPF record
        foreach ($spfParts as $part) {
            // Check if the mechanism requires a DNS lookup
            foreach ($dnsLookupMechanisms as $lookupMechanism) {
                if (strpos($part, $lookupMechanism . ":") !== false) {
                    $dnsLookupCount++;
                }
            }

            // Count `redirect` as a DNS lookup
            if (strpos($part, 'redirect=') !== false) {
                $dnsLookupCount++;
            }
        }

        // Evaluate if the DNS lookup count exceeds the limit
        if ($dnsLookupCount > 10) {
            $passedChecks[] = [
                "ID" => 479,
                "Name" => "SPF Included Lookups",
                "Info" => "The SPF record requires more than 10 DNS lookups.",
                "PublicDescription" => "Your SPF record required more than 10 DNS Lookups to be performed during the test. "
                    . "According to RFC 7208, the number of mechanisms and modifiers that do DNS lookups must be limited to 10 or fewer per SPF check. "
                    . "The mechanisms that count toward this limit are: 'include', 'mx', 'a', 'ptr', 'exists', and 'redirect'.\n\n"
                    . "Excessive DNS lookups may cause issues like increased bandwidth usage, memory usage, or even make the record vulnerable to DoS attacks. "
                    . "Please reduce the number of DNS lookups by simplifying your SPF record or using SPF flattening services.",
                "IsExcludedByUser" => false,
            ];
        } else {
            $passedChecks[] = [
                "ID" => 479,
                "Name" => "SPF Included Lookups",
                "Info" => "The SPF record contains 10 or fewer DNS lookups.",
                "PublicDescription" => "The SPF record complies with RFC 7208, requiring no more than 10 DNS lookups. "
                    . "The number of 'include', 'mx', 'a', 'ptr', 'exists', and 'redirect' mechanisms is within the allowed limit.",
                "IsExcludedByUser" => false,
            ];
        }

        // SPF Type PTR Check
        $containsPtr = false;
        $spfParts = explode(" ", $spfData);

        // Check for the presence of 'ptr' mechanism in the SPF record
        foreach ($spfParts as $part) {
            if (strpos($part, 'ptr:') !== false || $part === 'ptr') {
                $containsPtr = true;
                break;
            }
        }

        // Provide feedback based on the presence of the PTR mechanism
        if ($containsPtr) {
            $passedChecks[] = [
                "ID" => 480,
                "Name" => "SPF Type PTR",
                "Info" => "The SPF record contains the discouraged 'ptr' mechanism.",
                "PublicDescription" => "Your domain's SPF record includes a sender mechanism type of PTR. "
                    . "The use of this mechanism is heavily discouraged as per RFC 4408. "
                    . "It is slow and unreliable, and per email delivery best practices, it is recommended to avoid including PTR type mechanisms in your SPF record.\n\n"
                    . "According to RFC 4408: 'Use of this mechanism is discouraged because it is slow, it is not as reliable as other mechanisms in cases of DNS errors, "
                    . "and it places a large burden on the arpa name servers. If used, proper PTR records must be in place for the domain's hosts and the 'ptr' mechanism "
                    . "should be one of the last mechanisms checked.'",
                "IsExcludedByUser" => false,
            ];
        } else {
            $passedChecks[] = [
                "ID" => 480,
                "Name" => "SPF Type PTR",
                "Info" => "The SPF record does not contain the discouraged 'ptr' mechanism.",
                "PublicDescription" => "Your SPF record is compliant with best practices and does not include the discouraged 'ptr' mechanism. "
                    . "Per RFC 4408, the use of 'ptr' mechanisms is slow and unreliable, and it is recommended to avoid including them in SPF records.",
                "IsExcludedByUser" => false,
            ];
        }

        // Check for void lookups
        $voidLookupCount = 0;
        $spfParts = explode(" ", $spfData);
        $lookupMechanisms = ['a', 'mx', 'include', 'ptr', 'exists']; // Define mechanisms that perform lookups

        foreach ($spfParts as $part) {
            // Check if the part is a mechanism that requires a lookup
            foreach ($lookupMechanisms as $mechanism) {
                if (strpos($part, $mechanism) !== false) {
                    // Perform the DNS lookup
                    $domain = str_replace("$mechanism:", '', $part);
                    $dnsResponse = $this->performDnsLookup($domain, 'TXT'); // This function should handle DNS lookups and return the response type
                    
                    // Check for void responses
                    if ($dnsResponse === 'NOERROR_WITH_NO_ANSWERS' || $dnsResponse === 'NXDOMAIN') {
                        $voidLookupCount++;
                    }
                    
                    // Stop checking if we've exceeded the limit
                    if ($voidLookupCount > 2) {
                        break 2; // Break out of both loops
                    }
                }
            }
        }

        // Provide feedback based on the count of void lookups
        if ($voidLookupCount > 2) {
            $passedChecks[] = [
                "ID" => 490,
                "Name" => "SPF Void Lookups",
                "Info" => "Your SPF record has exceeded the limit for void lookups.",
                "PublicDescription" => "The void lookup limit was introduced in RFC 7208 and refers to DNS lookups which either return an empty response (NOERROR with no answers) or an NXDOMAIN response. "
                    . "You have exceeded the limit of two void lookups in your SPF record, which can produce a 'permerror' result. This is meant to help prevent erroneous or malicious SPF records from contributing to a DNS-based denial of service attack.",
                "IsExcludedByUser" => false,
            ];
        } else {
            $passedChecks[] = [
                "ID" => 490,
                "Name" => "SPF Void Lookups",
                "Info" => "Number of void lookups is OK",
                "PublicDescription" => "Your SPF record is compliant with the recommended limit of two void lookups as per RFC 7208. "
                    . "Exceeding this limit could produce a 'permerror' result, potentially affecting email delivery.",
                "IsExcludedByUser" => false,
            ];
        }

        // SPF MX Resource Records Check
        $mxError = false; // Flag to track if any MX records exceed the limit
        $spfParts = explode(" ", $spfData);

        foreach ($spfParts as $part) {
            // Check for the mx mechanism
            if (strpos($part, 'mx') !== false) {
                $domain = str_replace('mx:', '', $part); // Extract the domain for mx lookup
                $mxRecords = $this->performMxLookup($domain); // This function should handle MX lookups and return a list of MX records

                foreach ($mxRecords as $mxRecord) {
                    // Perform A and AAAA lookups for each MX record
                    $aRecordsCount = count($this->performDnsLookup($mxRecord, 'A')); // Count A records
                    $aaaaRecordsCount = count($this->performDnsLookup($mxRecord, 'AAAA')); // Count AAAA records
                    $totalRecordsCount = $aRecordsCount + $aaaaRecordsCount; // Total address records

                    // Check if total exceeds 10
                    if ($totalRecordsCount > 10) {
                        $mxError = true; // Set error flag
                        break 2; // Exit both loops
                    }
                }
            }
        }

        // Provide feedback based on the MX resource record counts
        if ($mxError) {
            $passedChecks[] = [
                "ID" => 500,
                "Name" => "SPF MX Resource Records",
                "Info" => "Your SPF record contains an MX mechanism that exceeds the limit for address records.",
                "PublicDescription" => "If you encounter this message, it means your SPF record contains an mx mechanism which has one or more Mail Exchange (MX) resource records that contain more than 10 address records - either 'A' or 'AAAA'. "
                    . "Email sent from this domain may have delivery problems due to the permerror that will occur. According to RFC 7208 section 4.6.4, the evaluation of each 'MX' record MUST NOT result in querying more than 10 address records. "
                    . "Please ensure that each MX record has 10 or fewer address records to maintain proper email delivery.",
                "IsExcludedByUser" => false,
            ];
        } else {
            $passedChecks[] = [
                "ID" => 500,
                "Name" => "SPF MX Resource Records",
                "Info" => "Number of MX Resource Records is OK",
                "PublicDescription" => "Your SPF record does not exceed the limit for address records associated with MX mechanisms. "
                    . "This compliance ensures that email sent from your domain should not encounter delivery problems due to MX resource record limits.",
                "IsExcludedByUser" => false,
            ];
        }

        // SPF Record Null Value Check
        $nullValueError = false; // Flag to track null value responses
        $spfParts = explode(" ", $spfData);
        $lookupMechanisms = ['a', 'mx', 'include', 'ptr', 'exists']; // Mechanisms that require DNS lookups

        foreach ($spfParts as $part) {
            foreach ($lookupMechanisms as $mechanism) {
                if (strpos($part, $mechanism) !== false) {
                    $domain = str_replace($mechanism . ":", '', $part); // Extract the domain for lookup
                    $lookupResult = $this->performDnsLookup($domain, 'TXT'); // This function should handle DNS lookups

                    // Check if the lookup result is null (empty response)
                    if (is_null($lookupResult) || (isset($lookupResult['rcode']) && $lookupResult['rcode'] == 'NXDOMAIN')) {
                        $nullValueError = true; // Set error flag
                        break 2; // Exit both loops
                    }
                }
            }
        }

        // Provide feedback based on null value responses
        if ($nullValueError) {
            $passedChecks[] = [
                "ID" => 600,
                "Name" => "SPF Record Null Value",
                "Info" => "Your SPF record contains mechanisms that returned null values.",
                "PublicDescription" => "A null record in your SPF record is commonly an indication of a problem with the related DNS lookup. "
                    . "Any mechanism that contains a DNS lookup should return a valid result. This check has triggered because it's much more common for a null record to indicate an issue affecting your email delivery. "
                    . "You can generally run an A record lookup on the domain/sub-domain in question to get more specific results.",
                "IsExcludedByUser" => false,
            ];
        } else {
            $passedChecks[] = [
                "ID" => 600,
                "Name" => "SPF Record Null Value",
                "Info" => "No Null DNS Lookups found",
                "PublicDescription" => "All mechanisms in your SPF record returned valid results, indicating no issues with your DNS lookups. "
                    . "This compliance helps ensure that your email delivery will not be affected by DNS-related problems.",
                "IsExcludedByUser" => false,
            ];
        }

        return $passedChecks;
    }

    private function getWarningSpfChecks($spfRecord) {
        // Initialize an array to hold warning checks
        $warningChecks = [];
    
        // Split the SPF record into parts
        $parts = explode(' ', $spfRecord);
    
        // Count different mechanisms and other elements
        $includeCount = 0;
        $mxCount = 0;
        $aCount = 0;
        $ip4Count = 0;
        $ip6Count = 0;
        $ptrCount = 0;
    
        // Loop through the parts to count mechanisms
        foreach ($parts as $part) {
            if (strpos($part, 'include:') === 0) {
                $includeCount++;
            } elseif (strpos($part, 'mx:') === 0) {
                $mxCount++;
            } elseif (strpos($part, 'a:') === 0) {
                $aCount++;
            } elseif (strpos($part, 'ip4:') === 0) {
                $ip4Count++;
            } elseif (strpos($part, 'ip6:') === 0) {
                $ip6Count++;
            } elseif (strpos($part, 'ptr:') === 0) {
                $ptrCount++;
            }
        }
    
        // Check for various warning conditions
        if ($includeCount > 10) {
            $warningChecks[] = [
                "ID" => 500,
                "Name" => "SPF Include Count Warning",
                "Info" => "More than 10 include mechanisms found.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }
    
        if ($mxCount > 5) {
            $warningChecks[] = [
                "ID" => 501,
                "Name" => "SPF MX Count Warning",
                "Info" => "More than 5 MX records found.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }
    
        if ($aCount > 5) {
            $warningChecks[] = [
                "ID" => 502,
                "Name" => "SPF A Record Count Warning",
                "Info" => "More than 5 A records found.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }
    
        if ($ptrCount > 0) {
            $warningChecks[] = [
                "ID" => 503,
                "Name" => "SPF PTR Usage Warning",
                "Info" => "PTR records should be avoided as they are not reliable.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }
    
        if (preg_match('/all\s*$/', $spfRecord) && preg_match('/\s+\+/i', $spfRecord)) {
            $warningChecks[] = [
                "ID" => 504,
                "Name" => "SPF All Mechanism Warning",
                "Info" => "Using '+' with 'all' can cause security issues.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }
    
        return $warningChecks;
    }

    private function getFailedSpfChecks($spfRecord, $domain) 
    {
        // Initialize an array to hold failed checks
        $failedChecks = [];

        // Check if the SPF record is empty
        if (empty(trim($spfRecord))) {
            $failedChecks[] = [
                "ID" => 600,
                "Name" => "SPF Record Missing",
                "Info" => "No SPF record found.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
            return ["Failed" => $failedChecks];
        }

        // Check if SPF record has a valid syntax
        if (!$this->isValidSpfSyntax($spfRecord)) {
            $failedChecks[] = [
                "ID" => 601,
                "Name" => "SPF Syntax Error",
                "Info" => "The SPF record has invalid syntax.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Check if there are multiple SPF records for the domain
        // Assuming we have a function getSpfRecordsForDomain() that fetches all SPF records for a domain
        $allSpfRecords = $this->getSpfRecordsForDomain($domain);
        if (count($allSpfRecords) > 1) {
            $failedChecks[] = [
                "ID" => 602,
                "Name" => "Multiple SPF Records Found",
                "Info" => "More than one SPF record found for the domain.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Check for the presence of the 'all' mechanism without any qualifiers
        if (preg_match('/\s+all\s*$/', $spfRecord)) {
            $failedChecks[] = [
                "ID" => 603,
                "Name" => "SPF All Mechanism Misconfiguration",
                "Info" => "The 'all' mechanism must have a qualifier.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Return the failed checks
        return $failedChecks;
    }  


    private function getPassedDmarcChecks($dmarcData)
    {
        $passedChecks = [];
        $dmarcRecords = $this->parseDmarcRecord($dmarcData);
        $dmarcCount = count($dmarcRecords);

        // Check for DMARC Record Published
        if ($dmarcCount > 0) {
            $passedChecks[] = [
                "ID" => 361,
                "Name" => "DMARC Record Published",
                "Info" => "DMARC Record found",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
            ];
        }

        // Check for multiple records
        $passedChecks[] = [
            "ID" => 358,
            "Name" => "DMARC Multiple Records",
            "Info" => $dmarcCount < 2 ? "Less than two records found" : "Multiple records found",
            "PublicDescription" => null,
            "IsExcludedByUser" => false,
        ];

        // Check for valid policy
        foreach ($dmarcRecords as $record) {
            if (isset($record['p']) && !in_array(strtoupper($record['p']), ['NONE', 'QUARANTINE', 'REJECT'])) {
                $passedChecks[] = [
                    "ID" => 481,
                    "Name" => "DMARC Policy Validity",
                    "Info" => "Invalid policy specified in DMARC record: '{$record['p']}'.",
                    "PublicDescription" => "The DMARC policy must be one of 'none', 'quarantine', or 'reject'.",
                    "IsExcludedByUser" => false,
                ];
                break; // Stop checking after finding the first invalid policy
            }
        }

        // Check for 'rua' tag presence
        $ruaFound = false;
        foreach ($dmarcRecords as $record) {
            if (isset($record['rua'])) {
                $ruaFound = true;
                break;
            }
        }

        if ($ruaFound) {
            $passedChecks[] = [
                "ID" => 482,
                "Name" => "DMARC Reporting Address",
                "Info" => "Reporting URI for aggregate reports found.",
                "PublicDescription" => "The DMARC record contains a reporting address for aggregate reports.",
                "IsExcludedByUser" => false,
            ];
        } else {
            $passedChecks[] = [
                "ID" => 482,
                "Name" => "DMARC Reporting Address",
                "Info" => "No reporting URI for aggregate reports found.",
                "PublicDescription" => "It is recommended to include a 'rua' tag in the DMARC record for aggregate report reporting.",
                "IsExcludedByUser" => false,
            ];
        }

        // Check for 'pct' tag presence
        foreach ($dmarcRecords as $record) {
            if (isset($record['pct'])) {
                if ($record['pct'] < 0 || $record['pct'] > 100) {
                    $passedChecks[] = [
                        "ID" => 483,
                        "Name" => "DMARC Percentage Validity",
                        "Info" => "Invalid percentage value specified in DMARC record: '{$record['pct']}'.",
                        "PublicDescription" => "The 'pct' tag must be between 0 and 100.",
                        "IsExcludedByUser" => false,
                    ];
                    break; // Stop checking after finding the first invalid percentage
                } else {
                    $passedChecks[] = [
                        "ID" => 483,
                        "Name" => "DMARC Percentage Validity",
                        "Info" => "Valid percentage value specified in DMARC record: '{$record['pct']}'.",
                        "PublicDescription" => null,
                        "IsExcludedByUser" => false,
                    ];
                }
            }
        }

        // DMARC Syntax Check
        $invalidSyntax = false;
        $syntaxErrorDetails = [];

        // Check for common DMARC syntax issues
        $dmarcParts = explode(";", $dmarcData);
        foreach ($dmarcParts as $part) {
            // You can add specific checks based on DMARC syntax requirements
            if (strpos($part, 'v=DMARC1') === false) {
                $invalidSyntax = true;
                $syntaxErrorDetails[] = "Missing 'v=DMARC1' in DMARC record.";
            }
        }

        if ($invalidSyntax) {
            $passedChecks[] = [
                "ID" => 484,
                "Name" => "DMARC Syntax",
                "Info" => "The DMARC record contains syntax errors.",
                "PublicDescription" => "The DMARC record has invalid syntax. Please review the format and ensure it follows DMARC specifications.",
                "IsExcludedByUser" => false,
                "Details" => implode("\n", $syntaxErrorDetails),
            ];
        } else {
            $passedChecks[] = [
                "ID" => 484,
                "Name" => "DMARC Syntax",
                "Info" => "The DMARC record is valid and contains no syntax errors.",
                "PublicDescription" => "The DMARC record was parsed correctly and contains no syntax errors.",
                "IsExcludedByUser" => false,
            ];
        }

        return $passedChecks;
    }


    private function getWarningDmarcChecks($dmarcRecord, $reportingNameServer)
    {
        // Initialize an array to hold warning checks
        $warningChecks = [];

        // Split the DMARC record into parts
        $parts = explode(';', $dmarcRecord);

        // Count different DMARC tags
        $pCount = 0; // Policy tags (p=)
        $spCount = 0; // Subdomain policy tags (sp=)
        $aspfCount = 0; // Alignment mode for SPF (aspf=)
        $adkimCount = 0; // Alignment mode for DKIM (adkim=)
        $pctCount = 0; // Percentage tag (pct=)
        $policy = null; // DMARC policy (p=)
        $spPolicy = null; // Subdomain policy (sp=)

        // Track if 'rua' or 'ruf' tags are found
        $ruaFound = false;
        $rufFound = false;

        // Loop through the parts to count mechanisms and check for rua/ruf
        foreach ($parts as $part) {
            $part = trim($part); // Clean up any whitespace
            if (strpos($part, 'p=') === 0) {
                $pCount++;
            } elseif (strpos($part, 'sp=') === 0) {
                $spCount++;
            } elseif (strpos($part, 'aspf=') === 0) {
                $aspfCount++;
            } elseif (strpos($part, 'adkim=') === 0) {
                $adkimCount++;
            } elseif (strpos($part, 'pct=') === 0) {
                $pctCount++;
            } elseif (strpos($part, 'rua=') === 0) {
                $ruaFound = true;
                $this->checkExternalValidation($part, $warningChecks, $reportingNameServer); // Check rua validation
            } elseif (strpos($part, 'p=') === 0) {
                $policy = substr($part, 2); // Extract the policy value after 'p='
            } elseif (strpos($part, 'sp=') === 0) {
                $spPolicy = substr($part, 3); // Extract subdomain policy value after 'sp='
            }
        }

        // Check for various warning conditions
        if ($pCount === 0) {
            $warningChecks[] = [
                "ID" => 600,
                "Name" => "DMARC Policy Missing Warning",
                "Info" => "No policy (p=) tag found in the DMARC record.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        if ($spCount > 1) {
            $warningChecks[] = [
                "ID" => 601,
                "Name" => "DMARC Subdomain Policy Warning",
                "Info" => "More than one subdomain policy (sp=) tag found.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        if ($aspfCount > 1) {
            $warningChecks[] = [
                "ID" => 602,
                "Name" => "DMARC SPF Alignment Warning",
                "Info" => "More than one alignment mode for SPF (aspf=) tag found.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        if ($adkimCount > 1) {
            $warningChecks[] = [
                "ID" => 603,
                "Name" => "DMARC DKIM Alignment Warning",
                "Info" => "More than one alignment mode for DKIM (adkim=) tag found.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        if ($pctCount > 1) {
            $warningChecks[] = [
                "ID" => 604,
                "Name" => "DMARC Percentage Warning",
                "Info" => "More than one percentage (pct=) tag found.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        if (!$ruaFound && !$rufFound) {
            $warningChecks[] = [
                "ID" => 605,
                "Name" => "DMARC Reporting Addresses Missing",
                "Info" => "No rua or ruf tags found in the DMARC record.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Check if no policy tag is found
        if ($policy === null) {
            $warningChecks[] = [
                "ID" => 600,
                "Name" => "DMARC Policy Missing Warning",
                "Info" => "DMARC Quarantine/Reject policy not enabled",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Check if the policy is too lenient (p=none)
        if ($policy === 'none') {
            $warningChecks[] = [
                "ID" => 605,
                "Name" => "DMARC Policy Not Enabled",
                "Info" => "DMARC policy is set to 'none', which means the domain is not protected against phishing or spoofing threats.",
                "PublicDescription" => "To protect the domain against phishing or spoofing, set the DMARC policy to 'quarantine' or 'reject'.",
                "IsExcludedByUser" => false
            ];
        }

        // Optionally, check the subdomain policy (sp=) if it's set
        if ($spPolicy === 'none') {
            $warningChecks[] = [
                "ID" => 606,
                "Name" => "DMARC Subdomain Policy Not Enabled",
                "Info" => "Subdomain policy (sp=none) is set, meaning subdomains are not protected against phishing or spoofing threats.",
                "PublicDescription" => "Consider setting the subdomain policy to 'quarantine' or 'reject' to protect subdomains.",
                "IsExcludedByUser" => false
            ];
        }

        return $warningChecks;
    }

    /**
     * Helper function to validate external destinations for DMARC reporting (rua/ruf).
     */
    private function checkExternalValidation($reportingTag, &$warningChecks, $reportingNameServer)
    {
        // Extract the email addresses from the rua or ruf tag
        preg_match_all('/mailto:([^,]+)/', $reportingTag, $matches);
        $emailAddresses = $matches[1];

        // Loop through each email address to check if it's an external domain
        foreach ($emailAddresses as $email) {
            // Extract the domain from the email address
            $domain = substr(strrchr($email, "@"), 1);

            // Check if this domain requires external verification
            // (In practice, you'd perform a DNS lookup or validation check here)
            $isValid = $this->validateExternalDmarcDomain($domain, $reportingNameServer); // Placeholder for actual validation

            // If the domain is not verified, add a warning
            if (!$isValid) {
                $warningChecks[] = [
                    "ID" => 606,
                    "Name" => "DMARC External Validation Warning",
                    "Info" => "External Domains in your DMARC are not giving permission for your reports to be sent to them",
                    "PublicDescription" => "One of the 'rua' or 'ruf' email addresses does not have a DNS TXT record verifying that they wish to receive DMARC reports for your domain.",
                    "IsExcludedByUser" => false
                ];
            }
        }
    }

    /**
     * Function to validate external DMARC domains by checking DNS TXT records.
     * @param string $domain The external domain to validate (e.g., 'mxtoolbox.com').
     * @param string $reportingDomain The domain making the DMARC request (e.g., 'example.com').
     * @return bool True if the external domain is authorized to receive DMARC reports for the reporting domain.
     */
    private function validateExternalDmarcDomain($domain, $reportingDomain)
    {
        // Build the required DNS query for the external validation:
        // The format is: yourdomain._report._dmarc.externaldomain.com
        $dmarcCheckDomain = "{$reportingDomain}._report._dmarc.{$domain}";

        // Perform a DNS TXT record lookup for the constructed domain
        $dnsRecords = dns_get_record($dmarcCheckDomain, DNS_TXT);

        // Check if any TXT record contains "v=DMARC1"
        foreach ($dnsRecords as $record) {
            if (isset($record['txt']) && strpos($record['txt'], 'v=DMARC1') !== false) {
                // The domain is authorized to receive DMARC reports
                return true;
            }
        }

        // If no valid DMARC TXT record is found, return false
        return false;
    }


    private function getFailedDmarcChecks($dmarcData, $domain) 
    {
        // Initialize an array to hold failed checks
        $failedChecks = [];

        // Check if the SPF record is empty
        if (empty(trim($dmarcData))) {
            $failedChecks[] = [
                "ID" => 600,
                "Name" => "DMARC Record Missing",
                "Info" => "No DMARC record found.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
            return ["Failed" => $failedChecks];
        }

        // Check if DMARC record has a valid syntax
        if (!$this->isValidDmarcSyntax($dmarcData)) {
            $failedChecks[] = [
                "ID" => 601,
                "Name" => "DMARC Syntax Error",
                "Info" => "The DMARC record has invalid syntax.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Check if there are multiple DMARC records for the domain
        // Assuming we have a function getDmarcRecordsForDomain() that fetches all SPF records for a domain
        $allDmarcRecords = $this->getDmarcRecordsForDomain($domain);
        if (count($allDmarcRecords) > 1) {
            $failedChecks[] = [
                "ID" => 602,
                "Name" => "Multiple DMARC Records Found",
                "Info" => "More than one DMARC record found for the domain.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        if (!preg_match('/\bp=(none|quarantine|reject)\b/', $dmarcData)) {
            $failedChecks[] = [
                "ID" => 701,
                "Name" => "DMARC Policy Missing",
                "Info" => "The DMARC record must include a policy ('p') value.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        if (preg_match('/\bp=p=.*?\b/', $dmarcData, $matches)) {
            if (!in_array(trim($matches[0]), ['p=none', 'p=quarantine', 'p=reject'])) {
                $failedChecks[] = [
                    "ID" => 702,
                    "Name" => "Invalid DMARC Policy Value",
                    "Info" => "The 'p' value must be 'none', 'quarantine', or 'reject'.",
                    "PublicDescription" => null,
                    "IsExcludedByUser" => false
                ];
            }
        }

        if (preg_match_all('/\bp=p=.*?\b/', $dmarcData, $matches) > 1) {
            $failedChecks[] = [
                "ID" => 705,
                "Name" => "Multiple DMARC Policies Detected",
                "Info" => "Only one 'p' policy should be defined in the DMARC record.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        if (preg_match('/\bpct=(\d{1,3})\b/', $dmarcData, $matches)) {
            if (intval($matches[1]) < 0 || intval($matches[1]) > 100) {
                $failedChecks[] = [
                    "ID" => 704,
                    "Name" => "Invalid DMARC Percentage Value",
                    "Info" => "The 'pct' value must be between 0 and 100.",
                    "PublicDescription" => null,
                    "IsExcludedByUser" => false
                ];
            }
        }

        if (!preg_match('/\bru[a]?=mailto:[\w\.-]+@[\w\.-]+/', $dmarcData) && 
            !preg_match('/\bruf=mailto:[\w\.-]+@[\w\.-]+/', $dmarcData)) {
            $failedChecks[] = [
                "ID" => 703,
                "Name" => "Missing DMARC Reporting URIs",
                "Info" => "At least one reporting URI ('rua' or 'ruf') must be included in the DMARC record.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }


        // Return the failed checks
        return $failedChecks;
    }  

    function performMxLookup($domain) {
        // Use the PHP dns_get_record function to retrieve MX records for the domain
        $mxRecords = dns_get_record($domain, DNS_MX);
    
        // Initialize an empty array to store the MX hostnames
        $mxHosts = [];
    
        // Loop through the MX records and extract the hostnames
        if (!empty($mxRecords)) {
            foreach ($mxRecords as $mx) {
                if (isset($mx['target'])) {
                    $mxHosts[] = $mx['target'];
                }
            }
        }
    
        return $mxHosts; // Return the list of MX hostnames
    }

    function performDnsLookup($mxHost, $recordType) {
        // Use the PHP dns_get_record function to retrieve A or AAAA records
        $dnsRecords = dns_get_record($mxHost, constant('DNS_' . strtoupper($recordType)));
    
        // Initialize an empty array to store the resolved IP addresses
        $ipAddresses = [];
    
        // Loop through the DNS records and extract the IP addresses
        if (!empty($dnsRecords)) {
            foreach ($dnsRecords as $record) {
                if (isset($record['ip']) || isset($record['ipv6'])) {
                    // Depending on the type of record (A or AAAA), we store the IP
                    if ($recordType === 'A' && isset($record['ip'])) {
                        $ipAddresses[] = $record['ip'];
                    } elseif ($recordType === 'AAAA' && isset($record['ipv6'])) {
                        $ipAddresses[] = $record['ipv6'];
                    }
                }
            }
        }
    
        return $ipAddresses; // Return the list of IP addresses (A or AAAA)
    }


    private function isValidSpfSyntax($spfData) {
        // Regular expression pattern for validating SPF syntax
        $spfPattern = '/^v=spf1\s+((?:(?:include|a|mx|ptr|ip4|ip6|exists|all)(?::[^\s;]+)?|\s+|;[^\n]*)*)-?all\s*$/';
    
        // Check if the provided SPF record matches the pattern
        if (preg_match($spfPattern, $spfData)) {
            return true; // If valid
        } else {
            return false; // If invalid
        }
    }

    private function isValidDmarcSyntax($dmarcData) {
        // Regular expression pattern for validating SPF syntax
        $dmarcPattern = '/^v=DMARC1;\s*p=(none|quarantine|reject);\s*pct=(\d{1,3});\s*rua=mailto:[\w\.-]+@[\w\.-]+;\s*ruf=mailto:[\w\.-]+@[\w\.-]+;\s*$/';
    
        // Check if the provided SPF record matches the pattern
        if (preg_match($dmarcPattern, $dmarcData)) {
            return true; // If valid
        } else {
            return false; // If invalid
        }
    }

    private function getDnsLookup($domain) {
        $dns = new Dns();

        $records = $dns->getRecords($domain); // returns all available dns records

        $domainInfo = [];

        foreach ($records as $record) {
            $recordArray = $record->toArray(); // Convert record to array

            // Base information common to all records
            $info = [
                'Host' => $recordArray['host'],
                'TTL' => $recordArray['ttl'],
                'Class' => $recordArray['class'],
                'Type' => $recordArray['type']
            ];

            // Add specific fields depending on the record type
            if (isset($recordArray['ip'])) {
                $info['IP'] = $recordArray['ip'];
            }

            if (isset($recordArray['target'])) {
                $info['Target'] = $recordArray['target'];
            }

            if (isset($recordArray['txt'])) {
                $info['TXT'] = $recordArray['txt'];
            }

            if (isset($recordArray['pri'])) {
                $info['Priority'] = $recordArray['pri'];
            }
            
            // Add the Name column with static text descriptions
            switch ($recordArray['type']) {
                case 'A':
                    $info['Name'] = 'IPv4 Address';
                    $info['IP'] = $recordArray['ip'];
                    break;
                case 'NS':
                    $info['Name'] = 'Name Server';
                    $info['Target'] = $recordArray['target'];
                    break;
                case 'SOA':
                    $info['Name'] = 'Start of Authority';
                    // Add SOA specific details
                    $info['MName'] = $recordArray['mname'];
                    $info['RName'] = $recordArray['rname'];
                    $info['Serial'] = $recordArray['serial'];
                    $info['Refresh'] = $recordArray['refresh'];
                    $info['Retry'] = $recordArray['retry'];
                    $info['Expire'] = $recordArray['expire'];
                    $info['MinimumTTL'] = $recordArray['minimum_ttl'];
                    break;
                case 'MX':
                    $info['Name'] = 'Mail Exchange';
                    $info['Priority'] = $recordArray['pri'];
                    $info['Target'] = $recordArray['target'];
                    break;
                case 'TXT':
                    $info['Name'] = 'Text Record';
                    $info['TXT'] = $recordArray['txt'];
                    break;
                default:
                    $info['Name'] = 'Unknown Record Type';
                    break;
            }

            // Add the record to the result set
            $domainInfo[] = $info;
        }

        return $domainInfo;
    }

    private function getSpfRecordsForDomain($domain) {
        // Initialize an array to hold SPF records
        $spfRecords = [];
    
        // Fetch DNS records of type 'TXT' for the specified domain
        $dnsRecords = dns_get_record($domain, DNS_TXT);
    
        // Loop through the DNS records to find SPF records
        foreach ($dnsRecords as $record) {
            if (isset($record['txt'])) {
                // Check if the TXT record is an SPF record
                if (preg_match('/^v=spf1/', $record['txt'])) {
                    $spfRecords[] = $record['txt'];
                }
            }
        }
    
        return $spfRecords;
    }

    private function getDmarcRecordsForDomain($domain) {
        // Initialize an array to hold SPF records
        $spfRecords = [];
    
        // Fetch DNS records of type 'TXT' for the specified domain
        $dnsRecords = dns_get_record('_dmarc.' . $domain, DNS_TXT);;
    
        // Loop through the DNS records to find SPF records
        foreach ($dnsRecords as $record) {
            if (isset($record['txt'])) {
                // Check if the TXT record is an SPF record
                if (preg_match('/^v=DMARC1/', $record['txt'])) {
                    $spfRecords[] = $record['txt'];
                }
            }
        }
    
        return $spfRecords;
    }

    private function getSpfInfo($spfData)
    {
        if ($spfData) {
            // Assuming $record is the SPF record string
            // Assume the record format is: "v=spf1 include:example.com ~all"
            $parts = explode(' ', trim($spfData));

            foreach ($parts as $part) {
                $info = [
                    "Prefix" => "",
                    "Type" => "",
                    "Value" => "",
                    "PrefixDesc" => "",
                    "Description" => "",
                ];

                // Determine the type and value of each part
                if (preg_match('/^v=spf1/', $part)) {
                    $info["Type"] = "record";
                    $info["Value"] = "txt";
                    $info["Description"] = $spfData; // The whole SPF record
                    $info["RecordNum"] = "1";
                } elseif (preg_match('/^(include|a|mx|ip4|ip6|all|redirect):(.+)$/', $part, $matches)) {
                    // Handle SPF mechanisms like include, a, mx, etc.
                    $info["Prefix"] = ($info["Type"] == "include") ? "+" : ($info["Type"] == "all" ? "-" : "+");
                    $info["Type"] = $matches[1];
                    $info["Value"] = $matches[2];
                    $info["PrefixDesc"] = ($info["Type"] == "include") ? "Pass" : ($info["Type"] == "all" ? "Fail" : "Neutral");
                    $info["Description"] = "The specified domain is searched for an &#39;allow&#39;.";
                } elseif (preg_match('/^([-+]?)(.+)$/', $part, $matches)) {
                    // Handle prefix and value (e.g., +, -, ~)
                    $info["Prefix"] = $matches[1];
                    $info["Type"] = $matches[2];
                    $info["PrefixDesc"] = ($info["Type"] == "include") ? "Pass" : ($info["Type"] == "all" ? "Fail" : "Neutral");
                    $info["Description"] = "Always matches. It goes at the end of your record.";
                }

                // Only add populated info
                if (!empty($info["Type"])) {
                    $information[] = $info;
                }
            }
        }

        return $information;
    }

    private function getDmarcInfo($dmarcData)
    {
        $information = []; // Array to hold DMARC information

        if ($dmarcData) {
            // Assuming the DMARC record is in the format: "v=DMARC1; p=none; pct=100; rua=mailto:dmarc@hub-score.com; ruf=mailto:dmarc_authfail@mails-tourmag.com;"
            $parts = explode(';', trim($dmarcData)); // Split the record by semicolon

            $info = [
                "Tag" => "",
                "TagValue" => "",
                "Name" => "",
                "Description" => "",
            ];
            foreach ($parts as $part) {
                // Trim the part to avoid leading/trailing whitespace
                $part = trim($part);

                // Determine the type and value of each part
                if ($part == "") {
                    $info["Tag"] = "";
                    $info["TagValue"] = "txt";
                    $info["Name"] = "Record";
                    $info["Description"] = $dmarcData; // The whole DMARC record
                } elseif (preg_match('/^v=DMARC1/', $part, $matches)) {
                    $info["Tag"] = "v";
                    $info["TagValue"] = "DMARC1";
                    $info["Name"] = "Version";
                    $info["Description"] = "Identifies the record retrieved as a DMARC record. It must be the first tag in the list.";
                } elseif (preg_match('/^p=(none|quarantine|reject)/', $part, $matches)) {
                    $info["Tag"] = "p";
                    $info["TagValue"] = $matches[1];
                    $info["Name"] = "Policy";
                    $info["Description"] = "The policy applied to the domain's mail.";
                } elseif (preg_match('/^pct=(\d{1,3})/', $part, $matches)) {
                    $info["Tag"] = "pct";
                    $info["TagValue"] = $matches[1];
                    $into["Name"] = "Percentage";
                    $info["Description"] = "Percentage of messages subjected to filtering.";
                } elseif (preg_match('/^(rua|ruf)=mailto:(.+)/', $part, $matches)) {
                    $info["Tag"] = $matches[1]; // rua or ruf
                    $info["TagValue"] = $matches[2];
                    $info["Name"] = $matches[1]=="rua" ? "Receivers" : "Forensic Receivers";
                    $info["Description"] = "Reporting URI for aggregate reports (rua) or failure reports (ruf).";
                }

                // Only add populated info
                if (!empty($info["Name"])) {
                    $information[] = $info;
                }
            }
        }

        return $information;
    }

    /**
     * Function to parse and extract information from a DKIM record.
     * @param string $dkimData The DKIM record data to be parsed.
     * @return array An array containing DKIM information with tags, tag values, names, and descriptions.
     */
    private function getDkimInfo($dkimData)
    {
        $information = []; // Array to hold DKIM information

        if ($dkimData) {
            // Assuming the DKIM record is in the format: "v=DKIM1; k=rsa; p=key-data;"
            $parts = explode(';', trim($dkimData)); // Split the record by semicolon

            $info = [
                "Tag" => "",
                "TagValue" => "",
                "Name" => "",
                "Description" => "",
            ];
            foreach ($parts as $part) {
                // Trim the part to avoid leading/trailing whitespace
                $part = trim($part);

                // Determine the type and value of each part
                if ($part == "") {
                    $info["Tag"] = "";
                    $info["TagValue"] = "txt";
                    $info["Name"] = "Record";
                    $info["Description"] = $dkimData; // The whole DKIM record
                } elseif (preg_match('/^v=DKIM1/', $part, $matches)) {
                    $info["Tag"] = "v";
                    $info["TagValue"] = "DKIM1";
                    $info["Name"] = "Version";
                    $info["Description"] = "Identifies the record retrieved as a DKIM record. It must be the first tag in the list.";
                } elseif (preg_match('/^k=(rsa|ed25519)/', $part, $matches)) {
                    $info["Tag"] = "k";
                    $info["TagValue"] = $matches[1];
                    $info["Name"] = "Key Type";
                    $info["Description"] = "The type of cryptographic key used (e.g., rsa or ed25519).";
                } elseif (preg_match('/^p=(.+)/', $part, $matches)) {
                    $info["Tag"] = "p";
                    $info["TagValue"] = substr($matches[1], 0, 30) . "..."; // Display partial key for brevity
                    $info["Name"] = "Public Key";
                    $info["Description"] = "The base64-encoded public key used for verifying signatures.";
                } elseif (preg_match('/^s=email/', $part, $matches)) {
                    $info["Tag"] = "s";
                    $info["TagValue"] = "email";
                    $info["Name"] = "Service Type";
                    $info["Description"] = "The service type for which the key is authorized (e.g., email).";
                } elseif (preg_match('/^h=(.+)/', $part, $matches)) {
                    $info["Tag"] = "h";
                    $info["TagValue"] = $matches[1];
                    $info["Name"] = "Signed Headers";
                    $info["Description"] = "List of headers included in the DKIM signature.";
                }

                // Only add populated info
                if (!empty($info["Name"])) {
                    $information[] = $info;
                }
            }
        }

        return $information;
    }

    private function getInfoMxToolbox($domain) {
        try {
            $test = new MxToolbox();
            $test
            // path to the dig tool - required
            ->setDig('/usr/bin/dig')
            // set dns resolver - required
            //->setDnsResolver('8.8.8.8')
            //->setDnsResolver('8.8.4.4')
            ->setDnsResolver('127.0.0.1')
            // load default blacklists for dnsbl check - optional
            ->setBlacklists();
            $infoEmailService = [$test->getDomainInformation($domain)];
            return $infoEmailService;
            //return $test->getDomainInformation($domain);
            } catch (MxToolboxRuntimeException $e) {
                echo $e->getMessage();
            } catch (MxToolboxLogicException $e) {
                echo $e->getMessage();
            }
    }

    private function generateSpfTranscript($domain, $spfData, $dnsLookupResults)
    {
        // Start the transcript with domain and initial text
        $transcript = "- - - txt:$domain\r\n\r\n";

        // Example DNS lookup results added to the transcript
        $transcript .= "&emsp; 1 e.gtld-servers.net 192.12.94.30 NON-AUTH 17 ms Received 2 Referrals, rcode=NO_ERROR &emsp; ";

        // Check if dnsLookupResults is an array and contains elements
        if (is_array($dnsLookupResults) && !empty($dnsLookupResults)) {
            foreach ($dnsLookupResults as $index => $result) {
                // Format and extract relevant information from each record
                $formattedResult = "Host: {$result['Host']}, ";
                $formattedResult .= "TTL: {$result['TTL']}, ";
                $formattedResult .= "Class: {$result['Class']}, ";
                $formattedResult .= "Type: {$result['Type']}, ";

                // Add additional fields if they exist
                if (isset($result['IP'])) {
                    $formattedResult .= "IP: {$result['IP']}, ";
                }
                if (isset($result['Target'])) {
                    $formattedResult .= "Target: {$result['Target']}, ";
                }
                if (isset($result['Name'])) {
                    $formattedResult .= "Name: {$result['Name']}";
                }

                // Trim trailing comma and space, then add to transcript
                $transcript .= "&emsp; " . rtrim($formattedResult, ', ') . "\r\n";
            }
        } else {
            $transcript .= "&emsp; No DNS lookup results found.\r\n";
        }

        // Add SPF records to the transcript
        $spfRecords = $this->getSpfRecord($domain); // Fetch the SPF records again if needed
        if (!empty($spfRecords['records'])) {
            foreach ($spfRecords['records'] as $index => $record) {
                $transcript .= "&emsp; " . ($index + 2) . " $record IN TXT\t$spfData\t\r\n";
            }
        } else {
            $transcript .= "&emsp; No SPF records found for this domain.\r\n";
        }

        // Include results of the SPF checks
        $transcript .= "- - Results\r\n";
        $spfValidationResults = $this->checkSpfSyntax($domain); // Simulate the check results
        if (is_array($spfValidationResults)) {
            foreach ($spfValidationResults as $result) {
                // Ensure each result is a string
                $transcript .= "TXT:$result = " . ($this->isValidResult($result) ? 'Pass' : 'Fail') . "\r\n";
            }
        } else {
            $transcript .= "No SPF validation results available.\r\n";
        }

        // Adding final touch with lookup server response time
        $transcript .= "LookupServer 3513ms\r\n";
        
        $transcriptInfo[] = ["Transcript" => $transcript];

        return $transcriptInfo;
    }
    
    private function generateDmarcTranscript($domain, $dmarcData, $dnsLookupResults)
    {
        // Start the transcript with the domain in the appropriate format
        $transcript = "- - - dmarc:_dmarc.$domain\r\n\r\n";
        
        // Check if dnsLookupResults is an array and contains elements
        if (is_array($dnsLookupResults) && !empty($dnsLookupResults)) {
            foreach ($dnsLookupResults as $index => $result) {
                // Combine results into a single formatted string for each lookup result
                $formattedResult = "{$result['Host']}.\t{$result['TTL']}\tIN\t{$result['Type']}\t{$result['Class']},";
                
                // Add additional fields if they exist (like IP, Target, Name)
                if (isset($result['IP'])) {
                    $formattedResult .= "{$result['IP']}, ";
                }
                if (isset($result['Target'])) {
                    $formattedResult .= "{$result['Target']}, ";
                }
                if (isset($result['Name'])) {
                    $formattedResult .= "{$result['Name']}";
                }

                // Trim trailing comma and space, then add to the transcript
                $transcript .= "&emsp; " . rtrim($formattedResult, ', ') . "\r\n";
            }
        } else {
            $transcript .= "&emsp; No DNS lookup results found.\r\n";
        }

        // Add DMARC records to the transcript
        $dmarcRecords = $this->getDmarcRecord($domain); // Fetch the DMARC records again if needed
        if (!empty($dmarcRecords['records'])) {
            foreach ($dmarcRecords['records'] as $index => $record) {
                $transcript .= "&emsp; " . ($index + 2) . " _dmarc.$domain.\t3600\tIN\tTXT\t$record,\r\n";
            }
            $transcript .= "Record returned is an RFC 7489 TXT record.<br/>\r\n";
        } else {
            $transcript .= "&emsp; No DMARC records found for this domain.\r\n";
        }

        // Simulate results of DMARC checks (failed verifications)
        $dmarcValidationResults = $this->checkDmarcSyntax($domain); // Simulate the check results
        $failedVerifications = [];
        
        if (is_array($dmarcValidationResults)) {
            foreach ($dmarcValidationResults as $result) {
                if (!$this->isValidResult($result)) {
                    $failedVerifications[] = $result;
                }
            }
            if (!empty($failedVerifications)) {
                $transcript .= "Failed External Verifications\r\n";
                foreach ($failedVerifications as $failed) {
                    $transcript .= "mailto:$failed\r\n";
                }
            }
        } else {
            $transcript .= "No DMARC validation results available.\r\n";
        }

        // Adding final touch with lookup server response time
        $transcript .= "LookupServer 552ms\r\n";

        // Prepare the transcript array to return
        $transcriptInfo[] = ["Transcript" => $transcript];

        return $transcriptInfo;
    }

    private function generateDkimTranscript($domain, $dkimData, $dnsLookupResults, $selector)
    {
        // Start the transcript with the DKIM selector and domain in the appropriate format
        $transcript = "- - - dkim:$selector._domainkey.$domain\r\n\r\n";
        
        // Check if dnsLookupResults is an array and contains elements
        if (is_array($dnsLookupResults) && !empty($dnsLookupResults)) {
            foreach ($dnsLookupResults as $index => $result) {
                // Combine results into a single formatted string for each lookup result
                $formattedResult = "{$result['Host']}.\t{$result['TTL']}\tIN\t{$result['Type']}\t{$result['Class']},";
                
                // Add additional fields if they exist (like IP, Target, Name)
                if (isset($result['IP'])) {
                    $formattedResult .= "{$result['IP']}, ";
                }
                if (isset($result['Target'])) {
                    $formattedResult .= "{$result['Target']}, ";
                }
                if (isset($result['Name'])) {
                    $formattedResult .= "{$result['Name']}";
                }

                // Trim trailing comma and space, then add to the transcript
                $transcript .= "&emsp; " . rtrim($formattedResult, ', ') . "\r\n";
            }
        } else {
            $transcript .= "&emsp; No DNS lookup results found.\r\n";
        }

        // Add DKIM record to the transcript
        $dkimRecord = $this->getDkimRecord($domain, $selector); // Fetch the DKIM record for the given selector
        if (!empty($dkimRecord['record'])) {
            $transcript .= "&emsp; " . "hub._domainkey.$domain.\t3600\tIN\tTXT\t{$dkimRecord['record']},\r\n";
            $transcript .= "Record returned is an RFC 6376 TXT record.<br/>\r\n";
        } else {
            $transcript .= "&emsp; No DKIM records found for this domain.\r\n";
        }

        // Simulate results of DKIM checks (failed verifications)
        $dkimValidationResults = $this->checkDkimSyntax($domain, $dkimData); // Simulate the check results
        $failedVerifications = [];
        
        if (is_array($dkimValidationResults)) {
            foreach ($dkimValidationResults as $result) {
                if (!$this->isValidResult($result)) {
                    $failedVerifications[] = $result;
                }
            }
            if (!empty($failedVerifications)) {
                $transcript .= "Failed External Verifications\r\n";
                foreach ($failedVerifications as $failed) {
                    $transcript .= "mailto:$failed\r\n";
                }
            }
        } else {
            $transcript .= "No DKIM validation results available.\r\n";
        }

        // Adding final touch with lookup server response time
        $transcript .= "LookupServer 552ms\r\n";

        // Prepare the transcript array to return
        $transcriptInfo[] = ["Transcript" => $transcript];

        return $transcriptInfo;
    }

    private function getFailedDkimChecks($dkimRecord, $domain, $dkimSelector)
    {
        // Initialize an array to hold failed checks
        $failedChecks = [];

        // Check if the DKIM record is empty
        if (empty(trim($dkimRecord))) {
            $failedChecks[] = [
                "ID" => 700,
                "Name" => "DKIM Record Missing",
                "Info" => "No DKIM record found for the domain.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
            return ["Failed" => $failedChecks];
        }

        // Validate DKIM syntax (assuming isValidDkimSyntax() exists)
        if (!$this->isValidDkimSyntax($dkimRecord)) {
            $failedChecks[] = [
                "ID" => 701,
                "Name" => "DKIM Syntax Error",
                "Info" => "The DKIM record has invalid syntax.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Check if there are multiple DKIM records for the domain
        $allDkimRecords = $this->getDkimRecordsForDomain($domain, $dkimSelector); // Assuming this function fetches all DKIM records
        if (count($allDkimRecords) > 1) {
            $failedChecks[] = [
                "ID" => 702,
                "Name" => "Multiple DKIM Records Found",
                "Info" => "More than one DKIM record found for the domain.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Check for the presence of 'v=DKIM1' tag
        if (strpos($dkimRecord, 'v=DKIM1') === false) {
            $failedChecks[] = [
                "ID" => 703,
                "Name" => "DKIM Version Missing",
                "Info" => "The DKIM record does not specify the version 'v=DKIM1'.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Return failed checks
        return $failedChecks;
    }

    private function getPassedDkimChecks($dkimRecord, $domain, $selector)
    {
        $passedChecks = [];

        // Check if the DKIM version tag is present
        if (strpos($dkimRecord, 'v=DKIM1') !== false) {
            $passedChecks[] = [
                "ID" => 750,
                "Name" => "DKIM Version Check",
                "Info" => "The DKIM record specifies 'v=DKIM1'.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Validate DKIM signature length (assuming validateDkimSignatureLength() exists)
        if ($this->validateDkimSignatureLength($dkimRecord)) {
            $passedChecks[] = [
                "ID" => 751,
                "Name" => "DKIM Signature Length",
                "Info" => "The DKIM signature length is valid.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        // Check for correct selector (assuming validateDkimSelector() exists)
        if ($this->validateDkimSelector($domain, $selector)) {
            $passedChecks[] = [
                "ID" => 752,
                "Name" => "DKIM Selector",
                "Info" => "The DKIM record contains a valid selector.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        return $passedChecks;
    }

    private function getWarningDkimChecks($dkimRecord)
    {
        // Initialize an array to hold warning checks
        $warningChecks = [];

        // Check for weak algorithms (assuming validateDkimAlgorithm() exists)
        if (!$this->validateDkimAlgorithm($dkimRecord)) {
            $warningChecks[] = [
                "ID" => 780,
                "Name" => "Weak DKIM Algorithm",
                "Info" => "The DKIM record uses a weak signing algorithm.",
                "PublicDescription" => "It is recommended to use 'rsa-sha256' for stronger security.",
                "IsExcludedByUser" => false
            ];
        }

        // Check for optional 'g=' tag usage
        if (strpos($dkimRecord, 'g=') !== false) {
            $warningChecks[] = [
                "ID" => 781,
                "Name" => "DKIM Granularity Warning",
                "Info" => "The 'g=' tag is present, which can limit the use of the DKIM signature.",
                "PublicDescription" => "Consider removing the 'g=' tag for broader DKIM applicability.",
                "IsExcludedByUser" => false
            ];
        }

        // Check if the DKIM key length is too short (assuming getDkimKeyLength() exists)
        $keyLength = $this->getDkimKeyLength($dkimRecord);
        if ($keyLength < 2048) {
            $warningChecks[] = [
                "ID" => 782,
                "Name" => "DKIM Key Length Warning",
                "Info" => "The DKIM key length is shorter than 2048 bits.",
                "PublicDescription" => "A DKIM key length of at least 2048 bits is recommended for security.",
                "IsExcludedByUser" => false
            ];
        }

        return $warningChecks;
    }

    // Checks if DKIM syntax is valid by verifying the format of the DKIM string
    public function isValidDkimSyntax($dkimConfig)
    {
        // Syntax should have "k=" for algorithm, "p=" for public key
        if (preg_match('/k=rsa; p=[A-Za-z0-9+\/=]+/', $dkimConfig)) {
            return true;
        }
        return false;
    }

    // Retrieve DKIM records for a domain
    public function getDkimRecordsForDomain($domain, $dkimSelector)
    {
        $dkimDnsRecord = dns_get_record($dkimSelector . '._domainkey.' . $domain, DNS_TXT);

        if (!empty($dkimDnsRecord)) {
            return $dkimDnsRecord;
        }
        return false;
    }

    // Validate the DKIM signature length (public key)
    public function validateDkimSignatureLength($dkimConfig)
    {
        if (preg_match('/p=([A-Za-z0-9+\/=]+)/', $dkimConfig, $matches)) {
            $publicKey = $matches[1];
            $keyLength = strlen(base64_decode($publicKey)) * 8; // Convert base64 to binary and calculate length

            if ($keyLength >= 1024) {
                return true;
            }
        }
        return false;
    }

    // Validate DKIM selector
    public function validateDkimSelector($domain, $selector)
    {
        $dkimDnsRecord = dns_get_record($selector . '._domainkey.' . $domain, DNS_TXT);
        
        return !empty($dkimDnsRecord);
    }

    // Validate DKIM algorithm (currently RSA supported)
    public function validateDkimAlgorithm($dkimConfig)
    {
        if (preg_match('/k=(rsa);/', $dkimConfig, $matches)) {
            $algorithm = $matches[1];
            return $algorithm === 'rsa';
        }
        return false;
    }

    // Extract the DKIM public key length from the DKIM record
    public function getDkimKeyLength($dkimConfig)
    {
        if (preg_match('/p=([A-Za-z0-9+\/=]+)/', $dkimConfig, $matches)) {
            $publicKey = $matches[1];
            $keyLength = strlen(base64_decode($publicKey)) * 8; // Convert base64 to binary and calculate length
            return $keyLength;
        }
        return 0;
    }

    private function isValidResult($result)
    {
        // Simple logic to determine if the SPF check passed or failed
        return strpos($result, 'fail') === false; // Example logic
    }

    public function checkDKIM(string $domain, string $selector)
    {
        { 
            $startTime = microtime(true);
            // Variables to track timeouts, errors, and whether an error occurred
            $timeout = false;
            $isError = false;
            $errorMessage = [];
            $timeoutThreshold = 5; // seconds
            try {
                // Perform DNS lookup and DKIM analysis
                $dkimData = $this->getDkimRecord($domain, $selector);
                $reportingNameServer = $this->getReportingNameServer($domain);
                $dnsLookupResults = $this->getDnsLookup($domain); // Fetch related DNS lookups
        
                // End timing
                $endTime = microtime(true);
        
                // Check for timeout (if execution time exceeds threshold)
                $executionTime = ($endTime - $startTime);
                if ($executionTime > $timeoutThreshold) {
                    $timeout = true;
                    throw new \Exception("Request timed out after $timeoutThreshold seconds.");
                }
        
            } catch (\Exception $e) {
                // Handle any error that occurs during the process
                $isError = true;
                $errorMessage = ["error"=>$e->getMessage()];
                // Set default values in case of an error
                $dkimData = null;
                $reportingNameServer = null;
            }
            // Calculate time to complete in milliseconds
            $timeToComplete = ($endTime - $startTime) * 1000;
            // Structure the response
            $response = [
                "UID" => Uuid::uuid4()->toString(),
                "ArgumentType" => "domain",
                "Command" => "dkim",
                "CommandArgument" => $domain,
                "TimeRecorded" => (new \DateTime())->format(\DateTime::ATOM),
                "ReportingNameServer" => $reportingNameServer,
                "TimeToComplete" => round($timeToComplete, 2),
                "RelatedIP" => $this->getRelatedIP($domain),
                "ResourceRecordType" => 16,
                "IsEmptySubDomain" => $this->getIsEmptySubDomain($domain),
                "IsEndpoint" => $this->getIsEndpoint($domain),
                "HasSubscriptions" => $this->getHasSubscriptions($domain),
                "Failed" => $this->getFailedDkimChecks($dkimData, $domain, $selector),
                "Warnings" => $this->getWarningDkimChecks($dkimData, $reportingNameServer),
                "Passed" => $this->getPassedDkimChecks($dkimData, $domain, $selector),
                "Timeouts" => $timeout,
                "Errors" => $errorMessage,
                "IsError" => $isError,
                "Information" => $this->getDkimInfo($dkimData),
                "Transcript" => $this->generateDkimTranscript($domain, $dkimData, $dnsLookupResults, $selector),
                "EmailServiceProvider" => $this->getInfoMxToolbox($domain),
                "DnsServiceProvider" => $this->getDnsServiceProvider($domain),
                "RelatedLookups" => $this->getDnsLookup($domain)
            ];
            return $response;
            
        }
    }

    public function checkDMARC(string $domain)
    { 
        $startTime = microtime(true);
        // Variables to track timeouts, errors, and whether an error occurred
        $timeout = false;
        $isError = false;
        $errorMessage = [];
        $timeoutThreshold = 5; // seconds
        try {
            // Perform DNS lookup and DMARC analysis
            $dmarcData = $this->getDmarcRecord($domain);
            $reportingNameServer = $this->getReportingNameServer($domain);
            $dnsLookupResults = $this->getDnsLookup($domain); // Fetch related DNS lookups
    
            // End timing
            $endTime = microtime(true);
    
            // Check for timeout (if execution time exceeds threshold)
            $executionTime = ($endTime - $startTime);
            if ($executionTime > $timeoutThreshold) {
                $timeout = true;
                throw new \Exception("Request timed out after $timeoutThreshold seconds.");
            }
    
        } catch (\Exception $e) {
            // Handle any error that occurs during the process
            $isError = true;
            $errorMessage = ["error"=>$e->getMessage()];
            // Set default values in case of an error
            $dmarcData = null;
            $reportingNameServer = null;
        }
        // Calculate time to complete in milliseconds
        $timeToComplete = ($endTime - $startTime) * 1000;
        // Structure the response
        $response = [
            "UID" => Uuid::uuid4()->toString(),
            "ArgumentType" => "domain",
            "Command" => "dmarc",
            "CommandArgument" => $domain,
            "TimeRecorded" => (new \DateTime())->format(\DateTime::ATOM),
            "ReportingNameServer" => $reportingNameServer,
            "TimeToComplete" => round($timeToComplete, 2),
            "RelatedIP" => $this->getRelatedIP($domain),
            "ResourceRecordType" => 16,
            "IsEmptySubDomain" => $this->getIsEmptySubDomain($domain),
            "IsEndpoint" => $this->getIsEndpoint($domain),
            "HasSubscriptions" => $this->getHasSubscriptions($domain),
            "Failed" => $this->getFailedDmarcChecks($dmarcData, $domain),
            "Warnings" => $this->getWarningDmarcChecks($dmarcData, $reportingNameServer),
            "Passed" => $this->getPassedDmarcChecks($dmarcData),
            "Timeouts" => $timeout,
            "Errors" => $errorMessage,
            "IsError" => $isError,
            "Information" => $this->getDmarcInfo($dmarcData),
            "Transcript" => $this->generateDmarcTranscript($domain, $dmarcData, $dnsLookupResults),
            "EmailServiceProvider" => $this->getInfoMxToolbox($domain),
            "DnsServiceProvider" => $this->getDnsServiceProvider($domain),
            "RelatedLookups" => $this->getDnsLookup($domain)
        ];
        return $response;
        
    }

    private function getDmarcRecord(string $domain)
    {
        // Use DNS functions to fetch SPF record
        $records = dns_get_record('_dmarc.' . $domain, DNS_TXT);
        foreach ($records as $record) {
            if (strpos($record['txt'], 'v=DMARC1') !== false) {
                return $record['txt'];
            }
        }
        return null;
    } 

    private function getDkimRecord(string $domain, string $selector)
    {
        // Use DNS functions to fetch SPF record
        $records = dns_get_record($selector . '._domainkey.' . $domain, DNS_TXT);
        foreach ($records as $record) {
            if (strpos($record['txt'], 'k=rsa') !== false) {
                return $record['txt'];
            }
        }
        return null;
    } 

    function getMailDomainsUnderPrincipal(string $principalDomain): array
    {
        // Initialize the result array
        $domains = [];

        //$output = shell_exec('dig +short MX ' . escapeshellarg($principalDomain));
        /*$output = shell_exec("dig ". $principalDomain ."AAAA 2>&1"); 
        var_dump(explode("\n", trim($output)));*/

        $whois = Factory::get()->createWhois();;
        $result = $whois->lookupDomain($principalDomain);
        //var_dump($result->text);

        // Get DNS records for the principal domain
        $dnsRecords = dns_get_record($principalDomain, DNS_MX | DNS_A | DNS_CNAME);
        //var_dump($dnsRecords);

        if (!$dnsRecords) {
            return ["error" => "No DNS records found for the domain"];
        }

        // Loop through DNS records to identify MX (Mail Exchange) records
        foreach ($dnsRecords as $record) {
            if (isset($record['type'])) {
                $status = 'inactive';  // Default status

                switch ($record['type']) {
                    case 'MX':  // MX record: Used for mail exchanges
                        $mailServer = $record['target'];
                        
                        // Check if the SMTP server is active
                        if ($this->isMailServerActive($mailServer)) {
                            $status = 'active';
                        }

                        $domains[] = [
                            'domain' => $record['host'],
                            'type' => 'MX',
                            'priority' => $record['pri'] ?? null,
                            'status' => $status,
                            'mail_server' => $mailServer,
                        ];
                        break;

                    case 'A':   // A record: Maps a domain to an IP address
                    case 'CNAME': // CNAME record: Canonical name (alias)
                        $ipAddress = $record['ip'] ?? $record['target'];
                        
                        // Check if the mail server is reachable
                        if ($this->isMailServerActive($ipAddress)) {
                            $status = 'active';
                        }

                        $domains[] = [
                            'domain' => $record['host'],
                            'type' => $record['type'],
                            'ip' => $ipAddress,
                            'status' => $status,
                        ];
                        break;

                    default:
                        // Handle any other record types if necessary
                        break;
                }
            }
        }

        return $domains;
    }

    function isMailServerActive(string $mailServer): bool
    {
        $port = 25; // Default SMTP port (can also check 587 or 465 for SMTP over TLS/SSL)
        $timeout = 5; // Timeout in seconds

        // Attempt to open a connection to the mail server
        $connection = @fsockopen($mailServer, $port, $errno, $errstr, $timeout);

        if ($connection) {
            // Close the connection if successful
            fclose($connection);
            return true;
        }

        return false;
    }
}
