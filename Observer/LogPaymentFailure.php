<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Observer;

use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;
use Magento\Quote\Api\CartRepositoryInterface;
use Merlin\IntrusionDetection\Model\PaymentAttemptFactory;
use Merlin\IntrusionDetection\Model\ResourceModel\PaymentAttempt as AttemptResource;
use Magento\Framework\App\Request\Http as HttpRequest;

class LogPaymentFailure implements ObserverInterface
{
    use _PaymentExtract;

    public function __construct(
        private readonly PaymentAttemptFactory $attemptFactory,
        private readonly AttemptResource $attemptResource,
        private readonly CartRepositoryInterface $cartRepo,
        private readonly HttpRequest $request
    ) {}

    public function execute(Observer $observer): void
    {
        $quote = $observer->getData('quote');
        if (!$quote) return;

        $payment = $quote->getPayment();
        $method  = $payment ? (string)$payment->getMethod() : '';
        $last4   = $payment ? (string)$payment->getCcLast4() : '';
        $masked  = $payment ? $this->extractMaskedPanFromPayment($payment) : null;
        $bin6    = $this->extractBin($masked);
        $avs = $cvv = null;
        if ($payment) {
            [$avs, $cvv] = $this->pullAvsCvv($payment);
        }

        $attempt = $this->attemptFactory->create();
        $attempt->setData([
            'ip'              => (string)($this->request->getServer('REMOTE_ADDR') ?? ''),
            'customer_id'     => (int)($quote->getCustomerId() ?: 0),
            'email'           => (string)$quote->getCustomerEmail(),
            'payment_method'  => $method,
            'bin6'            => $bin6,
            'last4'           => $last4,
            'avs_result'      => $avs,
            'cvv_result'      => $cvv,
            'status'          => 'failed',
            'order_increment' => null,
            'quote_id'        => (int)$quote->getId(),
        ]);
        try { $this->attemptResource->save($attempt); } catch (\Throwable $e) {}
    }
}
