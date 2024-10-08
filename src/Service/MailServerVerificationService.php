<?php

namespace App\Service;

use MxToolbox\MxToolbox;
use MxToolbox\Exceptions\MxToolboxRuntimeException;
use MxToolbox\Exceptions\MxToolboxLogicException;
use Ramsey\Uuid\Uuid;

use Egulias\EmailValidator\EmailValidator;
use Egulias\EmailValidator\Validation\DNSCheckValidation;
use Egulias\EmailValidator\Validation\MultipleValidationWithAnd;
use Egulias\EmailValidator\Validation\RFCValidation;

use Iodev\Whois\Factory;

use League\Uri\Components\Query;
use League\Uri\Modifier;
use League\Uri\Uri;

use Spatie\Dns\Dns;
use Spatie\Dns\Records\A;

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
            //$this->getCheckRecords($spfData),  // Example time
            "Failed" => $this->getFailedChecks($spfData),//
            "Warnings" => $this->getWarningsChecks($spfData),//
            "Passed" => $this->getPassedChecks($spfData),//
            "Timeouts" => $timeout,
            "Errors" => $errorMessage,
            "IsError" => $isError,
            "Information" => $this->getSpfInfo($spfData),//
            "MultiInformation" => $this->getSpfInfoMxToolbox($domain),//
            "Transcript" => $this->getSpfTranscript($spfData),//
            "MxRep" => 0,
            "EmailServiceProvider" => $this->getSpfInfoMxToolbox($domain),//
            "DnsServiceProvider" => null,
            "DnsServiceProviderIdentifier" => null,
            "RelatedLookups" => $this->getDnsLookup($domain)
        ];
        //var_dump($this->checkSpfSyntax($domain));
        //var_dump($this->checkIps($domain));
        //var_dump($this->getDomainHttpsInfo($domain));
        //var_dump($this->getRecords($domain));
        //var_dump($this->getDnsPhpChecks($domain));
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

    private function getCheckRecords($domain) {
        $failed = [];
        $warnings[] = [];
        $passed = [];
        $spfRecord = dns_get_record($domain, DNS_TXT);
        $hasSpf = false;
        foreach ($spfRecord as $record) {
            if (strpos($record['txt'], 'v=spf1') !== false) {
                $hasSpf = true;
                break;
            }
        }

        if ($hasSpf) {
            $passed[] = [
                "ID" => 361,
                "Name" => "SPF Record Published",
                "Info" => "SPF Record found",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Record-Published?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        } else {
            $failed[] = [
                "ID" => 361,
                "Name" => "SPF Record Published",
                "Info" => "No SPF record found",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Record-Published?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }
        $isDeprecated = false;
        foreach ($spfRecord as $record) {
            if (strpos($record['txt'], '+all') !== false) {
                $isDeprecated = true;
                break;
            }
        }

        if ($isDeprecated) {
            $warnings[] = [
                "ID" => 355,
                "Name" => "SPF Record Deprecated",
                "Info" => "Deprecated records found",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Record-Deprecated?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        } else {
            $passed[] = [
                "ID" => 355,
                "Name" => "SPF Record Deprecated",
                "Info" => "No deprecated records found",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Record-Deprecated?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }
        $isValidSyntax = $this->checkSpfSyntax($spfRecord); // Assume a function that checks syntax

        if ($isValidSyntax) {
            $passed[] = [
                "ID" => 356,
                "Name" => "SPF Syntax Check",
                "Info" => "The record is valid",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Syntax-Check?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        } else {
            $failed[] = [
                "ID" => 356,
                "Name" => "SPF Syntax Check",
                "Info" => "The record is not valid",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Syntax-Check?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }

        $spfCount = 0;
        foreach ($spfRecord as $record) {
            if (strpos($record['txt'], 'v=spf1') !== false) {
                $spfCount++;
            }
        }

        if ($spfCount > 1) {
            $warnings[] = [
                "ID" => 358,
                "Name" => "SPF Multiple Records",
                "Info" => "More than one SPF record found",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Multiple-Records?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        } else {
            $passed[] = [
                "ID" => 358,
                "Name" => "SPF Multiple Records",
                "Info" => "Less than two records found",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Multiple-Records?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }
        $hasCharactersAfterAll = false;
        foreach ($spfRecord as $record) {
            if (preg_match('/all.*[^\s]$/', $record['txt'])) {
                $hasCharactersAfterAll = true;
                break;
            }
        }

        if ($hasCharactersAfterAll) {
            $warnings[] = [
                "ID" => 477,
                "Name" => "SPF Contains characters after ALL",
                "Info" => "Items found after 'ALL'.",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Contains-characters-after-ALL?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        } else {
            $passed[] = [
                "ID" => 477,
                "Name" => "SPF Contains characters after ALL",
                "Info" => "No items after 'ALL'.",
                "Url" => "https://templatetwiginfo.com/Problem/spf/SPF-Contains-characters-after-ALL?page=prob_spf&showlogin=1&hidetoc=1&action=spf:" . $domain,
                "PublicDescription" => null,
                "IsExcludedByUser" => false
            ];
        }
        return [
            "Failed" => $failed,
            "Warnings" => $warnings,
            "Passed" => $passed
        ];
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
        return true;
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

    private function getRecords($domain) {
        $dns = new Dns();

        $dns->getRecords($domain); // returns all available dns records

        $dns->getRecords('spatie.be', 'A'); // returns only A records

        //return $dns->getRecords($domain, 'TXT'); // return spf configuration
        return $dns->getRecords($domain);
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

    private function getPassedChecks($dnsRecords)
    {
        // Logic to determine which checks have passed
        return [
            [
                "ID" => 361,
                "Name" => "SPF Record Published",
                "Info" => "SPF Record found",
                "Url" => "https://example.com/Problem/spf/SPF-Record-Published"
            ],
            // Add other checks as needed
        ];
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
                'Type' => $recordArray['type'],
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

            // Add the record to the result set
            $domainInfo[] = $info;
        }

        return $domainInfo;
    }

    private function getWarningsChecks($dnsRecords)
    {
        // Logic to determine which checks have passed
        return [
            [
                "ID" => 361,
                "Name" => "SPF Record Published",
                "Info" => "SPF Record found",
                "Url" => "https://example.com/Problem/spf/SPF-Record-Published"
            ],
            // Add other checks as needed
        ];
    }

    private function getFailedChecks($dnsRecords)
    {
        // Logic to determine which checks have passed
        return [
            [
                "ID" => 361,
                "Name" => "SPF Record Published",
                "Info" => "SPF Record found",
                "Url" => "https://example.com/Problem/spf/SPF-Record-Published"
            ],
            // Add other checks as needed
        ];
    }

    private function getSpfInfo($dnsRecords)
    {
        // Extract SPF-related information from DNS records
        return [
            [
                "Prefix" => "",
                "Type" => "record",
                "Value" => "txt",
                "Description" => $dnsRecords ?: "No SPF record found",
            ]
        ];
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
            return $test->getDomainInformation($domain);
            //return $test->getDomainInformation($domain);
            } catch (MxToolboxRuntimeException $e) {
                echo $e->getMessage();
            } catch (MxToolboxLogicException $e) {
                echo $e->getMessage();
            }
    }

    private function getSpfTranscript($dnsRecords)
    {
        // Create transcript of the DNS resolution process
        return [
            ["Transcript" => "Received referrals, rcode=NO_ERROR for domain TXT record"]
        ];
    }

    public function checkDKIM(string $domain)
    {
        // PHPMailer can be used for DKIM validation
        // Extract DKIM TXT records
        return dns_get_record('_domainkey.' . $domain, DNS_TXT);
    }

    public function checkDMARC(string $domain)
    {
        return dns_get_record('_dmarc.' . $domain, DNS_TXT);
    }
}
