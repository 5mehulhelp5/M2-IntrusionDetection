<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Logger;

use Magento\Framework\Logger\Handler\Base as BaseHandler;
use Monolog\Logger;

class Handler extends BaseHandler {
    protected $fileName = '/var/log/merlin_ids.log';
    protected $loggerType = Logger::DEBUG;
}
