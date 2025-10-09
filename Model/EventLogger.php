<?php
declare(strict_types=1);
namespace Merlin\IntrusionDetection\Model;
class EventLogger {
    private $factory; private $resource;
    public function __construct(\Merlin\IntrusionDetection\Model\EventLogFactory $factory, \Merlin\IntrusionDetection\Model\ResourceModel\EventLog $resource){ $this->factory=$factory; $this->resource=$resource; }
    public function log(string $detector, string $severity, string $ip, string $path, string $ua = null, ?string $details = null): void {
        $m = $this->factory->create();
        $m->setData(['detector'=>$detector,'severity'=>$severity,'ip'=>$ip,'path'=>$path,'user_agent'=>$ua,'details'=>$details]);
        try { $this->resource->save($m); } catch (\Exception $e) {}
    }
}
