<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Console\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Merlin\IntrusionDetection\Api\BlockServiceInterface;

class UnblockIpCommand extends Command {
    private $svc;
    public function __construct(BlockServiceInterface $svc){ $this->svc=$svc; parent::__construct(); }
    protected function configure(){
        $this->setName('merlin:ids:unblock')->setDescription('Unblock an IP')
            ->addArgument('ip', InputArgument::REQUIRED);
        parent::configure();
    }

    protected function execute(InputInterface $in, OutputInterface $out): int {
        $ip=(string)$in->getArgument('ip'); $this->svc->unblock($ip);
        $out->writeln("<info>Unblocked {$ip}.</info>"); return Command::SUCCESS;
    }
}

