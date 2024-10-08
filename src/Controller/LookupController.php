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
                $response = $this->mailServerVerification->checkDKIM($argument);
                break;
            case 'dmarc':
                $response = $this->mailServerVerification->checkDMARC($argument);
                break;
            default:
                return new JsonResponse(['error' => 'Invalid command'], 400);
        }

        return new JsonResponse($response);
    }
}
