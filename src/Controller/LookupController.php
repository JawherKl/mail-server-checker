<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use App\Service\MailServerVerificationService;

class LookupController extends AbstractController
{
    private $mailServerVerification;

    public function __construct(MailServerVerificationService $mailServerVerification)
    {
        $this->mailServerVerification = $mailServerVerification;
    }

    #[Route('/api/v1/lookup/{protocol}/{domain}', methods: ['GET'])]
    public function lookup(string $protocol, string $domain): JsonResponse
    {
        $response = [];

        switch ($protocol) {
            case 'spf':
                $response['spf'] = $this->mailServerVerification->checkSPF($domain);
                break;
            case 'dkim':
                $response['dkim'] = $this->mailServerVerification->checkDKIM($domain);
                break;
            case 'dmarc':
                $response['dmarc'] = $this->mailServerVerification->checkDMARC($domain);
                break;
            default:
                return new JsonResponse(['error' => 'Invalid protocol'], 400);
        }

        return new JsonResponse($response);
    }
}
