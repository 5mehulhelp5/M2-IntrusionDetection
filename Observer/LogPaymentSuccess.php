<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Observer;

use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;
use Magento\Sales\Model\Order\Payment as OrderPayment;
use Merlin\IntrusionDetection\Model\PaymentAttemptFactory;
use Merlin\IntrusionDetection\Model\ResourceModel\PaymentAttempt as AttemptResource;
use Magento\Framework\App\Request\Http as HttpRequest;

class LogPaymentSuccess implements ObserverInterface
{
    use _PaymentExtract;

    public function __construct(
        private readonly PaymentAttemptFactory $attemptFactory,
        private readonly AttemptResource $attemptResource,
        private readonly HttpRequest $request
    ) {}

    public function execute(Observer $observer): void
    {
        /** @var OrderPayment $payment */
        $payment = $observer->getData('payment');
        $order   = $payment ? $payment->getOrder() : null;
        if (!$order) return;

        $masked = $this->extractMaskedPanFromPayment($payment);
        $bin6   = $this->extractBin($masked);
        [$avs, $cvv] = $this->pullAvsCvv($payment);

        $attempt = $this->attemptFactory->create();
        $attempt->setData([
            'ip'              => (string)($this->request->getServer('REMOTE_ADDR') ?? ''),
            'customer_id'     => (int)($order->getCustomerId() ?: 0),
            'email'           => (string)$order->getCustomerEmail(),
            'payment_method'  => (string)$payment->getMethod(),
            'bin6'            => $bin6,
            'last4'           => (string)$payment->getCcLast4(),
            'avs_result'      => $avs,
            'cvv_result'      => $cvv,
            'status'          => 'success',
            'order_increment' => (string)$order->getIncrementId(),
            'quote_id'        => (int)$order->getQuoteId(),
        ]);
        try { $this->attemptResource->save($attempt); } catch (\Throwable $e) {}
    }
}
