<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Console\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Merlin\IntrusionDetection\Api\BlockServiceInterface;

class BlockIpCommand extends Command {
    private $svc;
    public function __construct(BlockServiceInterface $svc){ $this->svc=$svc; parent::__construct(); }
    protected function configure(){
        $this->setName('merlin:ids:block')->setDescription('Block an IP')
            ->addArgument('ip', InputArgument::REQUIRED)
            ->addArgument('minutes', InputArgument::OPTIONAL, 'Duration minutes', '60');
        parent::configure();
    }

    protected function execute(InputInterface $in, OutputInterface $out): int {
        $ip=(string)$in->getArgument('ip'); $minutes=(int)$in->getArgument('minutes');
        $this->svc->block($ip, 'CLI', $minutes); $out->writeln("<info>Blocked {$ip} for {$minutes} minutes.</info>");
        return Command::SUCCESS;
    }
}
