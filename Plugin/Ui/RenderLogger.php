<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Plugin\Ui;

use Magento\Ui\Controller\Index\Render;
use Magento\Framework\App\RequestInterface;
use Merlin\IntrusionDetection\Logger\IdsLogger;

class RenderLogger {
    private $logger; private $request;
    public function __construct(IdsLogger $logger, RequestInterface $request){ $this->logger=$logger; $this->request=$request; }
    public function aroundExecute(Render $subject, \Closure $proceed){
        $params = $this->request->getParams();
        $ns = (is_array($params) && isset($params['namespace'])) ? $params['namespace'] : null;
        $this->logger->debug('[UI:render] start', ['namespace'=>$ns,'filters'=>$params['filters']??null,'paging'=>$params['paging']??null]);
        try{ $res=$proceed(); $this->logger->debug('[UI:render] success', ['namespace'=>$ns]); return $res; }
        catch(\Throwable $e){ $this->logger->error('[UI:render] FAILED', ['namespace'=>$ns,'error'=>$e->getMessage(),'trace'=>$e->getTraceAsString()]); throw $e; }
    }
}
