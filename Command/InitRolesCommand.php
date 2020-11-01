<?php

/*
 * This file is part of the Klipper package.
 *
 * (c) François Pluchino <francois.pluchino@klipper.dev>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Klipper\Component\DataLoaderSecurity\Command;

use Klipper\Component\DataLoader\Command\AbstractDataLoaderCommand;
use Klipper\Component\DataLoader\DataLoaderInterface;
use Klipper\Component\DataLoader\Entity\YamlUniqueSystemNameableEntityLoader;
use Klipper\Component\Security\Model\RoleInterface;

/**
 * Init the system roles.
 *
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class InitRolesCommand extends AbstractDataLoaderCommand
{
    protected function configure(): void
    {
        $this
            ->setName('init:roles')
            ->setDescription('Init the system roles')
        ;
    }

    protected function getDataLoader(): DataLoaderInterface
    {
        return new YamlUniqueSystemNameableEntityLoader($this->domainManager->get(RoleInterface::class));
    }

    protected function getFindFileNames(): array
    {
        return [
            'security_roles.yaml',
            'security_roles_*.yaml',
        ];
    }

    protected function getEmptyMessage(): string
    {
        return 'No system roles are defined';
    }

    protected function getInitializedMessage(): string
    {
        return 'The system roles have been initialized';
    }

    protected function getUpToDateMessage(): string
    {
        return 'The system roles are already up to date';
    }
}
