<?php

namespace App\Service;

use MxToolbox\MxToolbox;
use MxToolbox\Exceptions\MxToolboxRuntimeException;
use MxToolbox\Exceptions\MxToolboxLogicException;
use Ramsey\Uuid\Uuid;

use Iodev\Whois\Factory;

use League\Uri\Components\Query;
use League\Uri\Modifier;
use League\Uri\Uri;
use Mika56\SPFCheck\DNS\DNSRecordGetter;
use Mika56\SPFCheck\SPFCheck;
use Spatie\Dns\Dns;
use SPFLib\Checker;

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
            "TimeToComplete" => round($timeToComplete, 2),
            "RelatedIP" => $this->getRelatedIP($domain),
            "ResourceRecordType" => 16,
            "IsEmptySubDomain" => $this->getIsEmptySubDomain($domain),
            "IsEndpoint" => $this->getIsEndpoint($domain),
            "HasSubscriptions" => $this->getHasSubscriptions($domain),
            "AlertgroupSubscriptionsId" => $this->getAlertgroupSubscriptionsId($domain),//
            "Failed" => $this->getFailedChecks($spfData, $domain),
            "Warnings" => $this->getWarningsChecks($spfData),
            "Passed" => $this->getPassedChecks($spfData),
            "Timeouts" => $timeout,
            "Errors" => $errorMessage,
            "IsError" => $isError,
            "Information" => $this->getSpfInfo($spfData),
            "MultiInformation" => $this->getMultiSpfInfo($spfData),//
            "Transcript" => $this->generateSpfTranscript($domain, $spfData, $dnsLookupResults),
            "MxRep" => 0,//
            "EmailServiceProvider" => $this->getSpfInfoMxToolbox($domain),
            "DnsServiceProvider" => $this->getDnsServiceProvider($domain),//
            "DnsServiceProviderIdentifier" => $this->getDnsServiceProviderIdentifier($domain),//
            "RelatedLookups" => $this->getDnsLookup($domain)
        ];
        //var_dump($this->checkSpfSyntax($domain));
        //var_dump($this->checkIps($domain));
        //var_dump($this->getDomainHttpsInfo($domain));
        //var_dump($this->getRecords($domain));
        //var_dump($this->getDnsPhpChecks($domain));
        //var_dump($this->getcheckSpfLib($spfData, $domain));
        //var_dump($this->getSpfCheckLib($spfData, $domain));
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

    private function getAlertgroupSubscriptionsId(string $domain): ?int
    {
        // Example logic: this would be a query to a database in a real-world scenario
        // You could check if the domain is subscribed to any alert groups

        // For now, return null as we don't have an actual data source for alert subscriptions
        return null;
    }

    private function getMultiSpfInfo(string $spfRecord) {
        return [];
    }

    private function getDnsServiceProvider(string $spfRecord) {
        return null;
    }

    private function getDnsServiceProviderIdentifier(string $spfRecord) {
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


    private function getPassedChecks($spfData)
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
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
            ];

            // Check for multiple records
            $passedChecks[] = [
                "ID" => 358,
                "Name" => "SPF Multiple Records",
                "Info" => $spfCount < 2 ? "Less than two records found" : "Multiple records found",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
                //"Result" => $spfCount < 2 ? "pass" : "fail",
            ];
        }

        // Check for characters after ALL
        $allCheck = !preg_match('/\s+\S/', trim(substr($spfData, strrpos($spfData, '-all'))));
        if ($allCheck) {
            $passedChecks[] = [
                "ID" => 477,
                "Name" => "SPF Contains characters after ALL",
                "Info" => $allCheck ? "No items after 'ALL'." : "Items found after 'ALL'.",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
            ];   
        }

        // Check for SPF Syntax
        $isValid = $this->isValidSpfSyntax($spfData); // Assume you have a function to check SPF syntax
        if ($isValid) {
            $passedChecks[] = [
                "ID" => 356,
                "Name" => "SPF Syntax Check",
                "Info" => $isValid ? "The record is valid" : "The record contains syntax errors",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
            ];
        }

        // Check for included lookups (maximum 10)
        $includedLookups = array_filter($spfRecords, function ($record) {
            return $record['Type'] === 'include';
        });
        if ($includedLookups <= 10) {
            $passedChecks[] = [
                "ID" => 421,
                "Name" => "SPF Included Lookups",
                "Info" => count($includedLookups) <= 10 ? "Number of included lookups is OK" : "Too many included lookups",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
                //"Result" => count($includedLookups) <= 10 ? "pass" : "warning",
            ];
        }

        // Check for type PTR
        $ptrCheck = true; // Assume you have logic to determine if PTR records are found
        if ($ptrCheck) {
            $passedChecks[] = [
                "ID" => 509,
                "Name" => "SPF Type PTR Check",
                "Info" => !$ptrCheck ? "No type PTR found" : "Type PTR found",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
            ];
        }

        // Check for void lookups
        $voidLookupsCheck = $this->checkForVoidLookups($spfData); // Call the new function
        if ($voidLookupsCheck) {
            $passedChecks[] = [
                "ID" => 511,
                "Name" => "SPF Void Lookups",
                "Info" => !$voidLookupsCheck ? "Number of void lookups is OK" : "Void lookups found",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
            ];
        }

        // Check for MX Resource Records
        $mxCheck = true; // Logic to determine MX Resource Records
        if ($mxCheck) {
            $passedChecks[] = [
                "ID" => 420,
                "Name" => "SPF MX Resource Records",
                "Info" => !$mxCheck ? "Number of MX Resource Records is OK" : "MX Resource Records found",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
            ];
        }

        // Check for null DNS Lookups
        $nullCheck = $this->checkForNullDnsLookups($spfRecords); // Call the new function
        if ($nullCheck) {
            $passedChecks[] = [
                "ID" => 418,
                "Name" => "SPF Record Null Value",
                "Info" => !$nullCheck ? "No Null DNS Lookups found" : "Null DNS Lookups found",
                "PublicDescription" => null,
                "IsExcludedByUser" => false,
            ];
        }

        return $passedChecks;
    }

    // Function to check for void lookups
    private function checkForVoidLookups($spfData)
    {
        // Logic to determine void lookups (e.g., exceeding DNS lookup limits)
        // Placeholder logic: return true if void lookups are found
        $voidLookups = preg_match('/\bvoid\b/', $spfData); // Example logic
        return $voidLookups > 0;
    }

    // Function to check for null DNS lookups
    private function checkForNullDnsLookups($spfRecords)
    {
        // Logic to determine null DNS lookups
        // Placeholder logic: return true if null lookups are found
        foreach ($spfRecords as $record) {
            if (empty($record['Value'])) {
                return true;
            }
        }
        return false;
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

    private function getWarningsChecks($spfRecord) {
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

    private function getFailedChecks($spfRecord, $domain) 
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
                    "RecordNum" => null,
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
                    $info["RecordNum"] = null; // Set the record number for all entries
                    $information[] = $info;
                }
            }
        }

        return $information;
    }

    private function getSpfInfoMxToolbox($domain) {
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


    private function isValidResult($result)
    {
        // Simple logic to determine if the SPF check passed or failed
        return strpos($result, 'fail') === false; // Example logic
    }

    public function checkDKIM(string $domain)
    {
        // PHPMailer can be used for DKIM validation
        // Extract DKIM TXT records
        return dns_get_record('_domainkey.' . $domain, DNS_TXT);
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
            "AlertgroupSubscriptionsId" => $this->getAlertgroupSubscriptionsId($domain),//
            "Failed" => $this->getFailedChecks($dmarcData, $domain),
            "Warnings" => $this->getWarningsChecks($dmarcData),
            "Passed" => $this->getPassedChecks($dmarcData),
            "Timeouts" => $timeout,
            "Errors" => $errorMessage,
            "IsError" => $isError,
            //"Information" => $this->getDmarcInfo($dmarcData),
            //"MultiInformation" => $this->getMultiDmarcInfo($dmarcData),//
            //"Transcript" => $this->generateDmarcTranscript($domain, $dmarcData, $dnsLookupResults),
            "MxRep" => 0,//
            //"EmailServiceProvider" => $this->getDmarcInfoMxToolbox($domain),
            "DnsServiceProvider" => $this->getDnsServiceProvider($domain),//
            "DnsServiceProviderIdentifier" => $this->getDnsServiceProviderIdentifier($domain),//
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

    private function getcheckSpfLib(string $spfData, string $domain) {
        /*$environment = new \SPFLib\Check\Environment("51.38.29.111", "mails-tourmag.com", "newsletter@mails-tourmag.com");
        $checker = new Checker();
        $checkResult = $checker->check($environment);
        return $checkResult;*/
        $decoder = new \SPFLib\Decoder();
        try {
            $record = $decoder->getRecordFromDomain($domain);
            return $record;
        } catch (\SPFLib\Exception $x) {
            // Problems retrieving the SPF record from example.com,
            // or problems decoding it
            return;
        }
    }

    private function getSpfCheckLib(string $spfData, string $domain) {
        $checker = new SPFCheck(new DNSRecordGetter());
        return $checker->getDomainSPFRecords($domain);
    }
}
