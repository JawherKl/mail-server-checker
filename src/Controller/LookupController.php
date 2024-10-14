<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use App\Service\MailServerVerificationService;
use Symfony\Component\HttpFoundation\Request;

class LookupController extends AbstractController
{
    private $mailServerVerification;

    public function __construct(MailServerVerificationService $mailServerVerification)
    {
        $this->mailServerVerification = $mailServerVerification;
    }

    #[Route('/api/v1/lookup', methods: ['GET'])]
    public function lookup(Request $request): JsonResponse
    {
        // Extract parameters from the query string
        $command = $request->query->get('command');
        $argument = $request->query->get('argument');
        
        // Check if command and argument are provided
        if (!$command || !$argument) {
            return new JsonResponse(['error' => 'Missing command or argument'], 400);
        }

        // Initialize response variable
        $response = [];

        switch ($command) {
            case 'spf':
                $response = $this->mailServerVerification->checkSPF($argument);
                break;
            case 'dkim':
                // For DKIM, the argument should be in the format domain:selector
                // Split the argument into domain and selector
                $parts = explode(':', $argument);
    
                // Check if both domain and selector are provided
                if (count($parts) !== 2) {
                    return new JsonResponse(['error' => 'Invalid DKIM argument format. Expected format: domain:selector'], 400);
                }
    
                $domain = $parts[0];
                $selector = $parts[1];
    
                // Perform the DKIM check
                $response = $this->mailServerVerification->checkDKIM($domain, $selector);
                break;
            case 'dmarc':
                $response = $this->mailServerVerification->checkDMARC($argument);
                break;
            default:
                return new JsonResponse(['error' => 'Invalid command'], 400);
        }

        return new JsonResponse($response);
    }

    #[Route('/api/v1/domains', methods: ['GET'])]
    public function domains(Request $request): JsonResponse
    {
        $argument = $request->query->get('argument');
        
        // Check if command and argument are provided
        if (!$argument) {
            return new JsonResponse(['error' => 'Missing command or argument'], 400);
        }

        $response = $this->mailServerVerification->getMailDomainsUnderPrincipal($argument);
        return new JsonResponse($response);
    }
}
