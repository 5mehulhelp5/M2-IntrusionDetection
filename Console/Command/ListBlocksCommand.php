<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Console\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Merlin\IntrusionDetection\Api\BlockServiceInterface;

class ListBlocksCommand extends Command {
    private $svc;
    public function __construct(BlockServiceInterface $svc){ $this->svc=$svc; parent::__construct(); }
    protected function configure(){ $this->setName('merlin:ids:list-blocks')->setDescription('List blocked IPs'); parent::configure(); }
    protected function execute(InputInterface $in, OutputInterface $out): int {
        $rows = $this->svc->listBlocks();
        if (!$rows){ $out->writeln('<comment>No blocks.</comment>'); return Command::SUCCESS; }
        foreach ($rows as $r) { $out->writeln(sprintf('%-15s | %-19s | %s', $r['ip'], (string)$r['expires_at'], (string)$r['reason'])); }
        return Command::SUCCESS;
    }
}
