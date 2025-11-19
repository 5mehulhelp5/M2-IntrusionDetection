<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Observer;

use Magento\Sales\Api\Data\OrderPaymentInterface;

trait _PaymentExtract
{
    private function extractBin(?string $panMasked): ?string
    {
        if (!$panMasked) return null;
        // try to find first 6 digits in masked pan like 411111******1111
        if (preg_match('/\b(\d{6})\D*\*+/', $panMasked, $m)) {
            return $m[1];
        }
        // sometimes we only have last4; BIN unknown
        return null;
    }

    private function pullAvsCvv(OrderPaymentInterface $payment): array
    {
        $ai = (array)$payment->getAdditionalInformation();
        $keys = [
            'avs' => ['avs_result', 'avsResult', 'avsResultCode', 'avs_code', 'avs_response', 'avsCv2'],
            'cvv' => ['cvv_result', 'cvvResult', 'cvvResultCode', 'cvv_code', 'cvc_result', 'cv2result'],
        ];
        $avs = null; $cvv = null;
        foreach ($keys['avs'] as $k) { if (isset($ai[$k])) { $avs = (string)$ai[$k]; break; } }
        foreach ($keys['cvv'] as $k) { if (isset($ai[$k])) { $cvv = (string)$ai[$k]; break; } }
        // Some gateways pack both in 'avsCv2' like 'MATCHED/MATCHED' or similar
        if (!$avs && isset($ai['avsCv2']) && is_string($ai['avsCv2']) && str_contains($ai['avsCv2'], '/')) {
            [$avs, $cvv] = array_map('trim', explode('/', $ai['avsCv2'], 2));
        }
        return [$avs, $cvv];
    }

    private function extractMaskedPanFromPayment(OrderPaymentInterface $payment): ?string
    {
        $ai = (array)$payment->getAdditionalInformation();
        // common keys for masked pan
        foreach (['cc_last4_masked','maskedPan','cardNumber','cc_masked'] as $k) {
            if (!empty($ai[$k]) && is_string($ai[$k])) return $ai[$k];
        }
        // fallbacks
        if ($payment->getCcLast4()) {
            return '******' . (string)$payment->getCcLast4();
        }
        return null;
    }
}
