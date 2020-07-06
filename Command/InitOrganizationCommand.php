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

use Doctrine\ORM\EntityManagerInterface;
use Klipper\Component\Console\Command\RequiredCommandsInterface;
use Klipper\Component\DataLoader\Exception\ConsoleResourceException;
use Klipper\Component\Model\Traits\EmailableInterface;
use Klipper\Component\Resource\Domain\DomainManagerInterface;
use Klipper\Component\Resource\ResourceItem;
use Klipper\Component\Security\Model\OrganizationInterface;
use Klipper\Component\Security\Model\OrganizationUserInterface;
use Klipper\Component\Security\Model\Traits\RoleableInterface;
use Klipper\Component\Security\Model\UserInterface;
use Klipper\Contracts\Model\LabelableInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;

/**
 * Init the organization system with user super admin.
 *
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class InitOrganizationCommand extends Command implements RequiredCommandsInterface
{
    public const ORGANIZATION_NAME = 'org-admin';
    public const ORGANIZATION_LABEL = 'Organization Admin';
    public const USERNAME = 'admin';
    public const USER_EMAIL = 'admin@example.tld';
    public const USER_PASSWORD = 'password';

    private EntityManagerInterface $em;

    private DomainManagerInterface $domainManager;

    private ValidatorInterface $validator;

    private UserPasswordEncoderInterface $passwordEncoder;

    public function __construct(
        EntityManagerInterface $em,
        DomainManagerInterface $domainManager,
        ValidatorInterface $validator,
        UserPasswordEncoderInterface $passwordEncoder
    ) {
        parent::__construct();

        $this->em = $em;
        $this->domainManager = $domainManager;
        $this->validator = $validator;
        $this->passwordEncoder = $passwordEncoder;
    }

    public function getRequiredCommands(): array
    {
        return [
            'init:roles',
            'init:permissions',
        ];
    }

    protected function configure(): void
    {
        $this
            ->setName('init:organization:system')
            ->setDescription('Init the organization system with the user super admin')
        ;
    }

    /**
     * @throws \Throwable
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $domainUser = $this->domainManager->get(UserInterface::class);
        $domainOrg = $this->domainManager->get(OrganizationInterface::class);
        $domainOrgUser = $this->domainManager->get(OrganizationUserInterface::class);

        $count = (int) $domainOrg->createQueryBuilder('o')
            ->select('count(o)')
            ->getQuery()
            ->getSingleScalarResult()
        ;

        if ($count > 0) {
            $output->writeln('  The organization system and the super admin user are already created');

            return 0;
        }

        $this->em->beginTransaction();

        try {
            /** @var OrganizationInterface $org */
            $org = $domainOrg->newInstance();
            $org->setName(self::ORGANIZATION_NAME);

            if ($org instanceof LabelableInterface) {
                $org->setLabel(self::ORGANIZATION_LABEL);
            }

            $this->validate($org);

            /** @var UserInterface $user */
            $user = $domainUser->newInstance();
            $user
                ->setUsername(self::USERNAME)
                ->setPassword($this->passwordEncoder->encodePassword($user, self::USER_PASSWORD))
                ->addRole('ROLE_SUPER_ADMIN')
            ;

            if ($user instanceof EmailableInterface) {
                $user->setEmail(self::USER_EMAIL);
            }

            $this->validate($user);

            /** @var OrganizationUserInterface $orgUser */
            $orgUser = $domainOrgUser->newInstance();
            $orgUser
                ->setOrganization($org)
                ->setUser($user)
            ;

            if ($orgUser instanceof RoleableInterface) {
                $orgUser->addRole('ROLE_ADMIN');
            }

            $this->validate($orgUser);

            $this->em->persist($org);
            $this->em->persist($user);
            $this->em->persist($orgUser);

            $this->em->flush();
            $this->em->commit();
        } catch (\Throwable $e) {
            $this->em->rollback();

            throw $e;
        }

        $output->writeln('  The organization system and the super admin user are created');

        return 0;
    }

    protected function validate($entity): void
    {
        $res = $this->validator->validate($entity);

        if ($res->count() > 0) {
            throw new ConsoleResourceException(new ResourceItem($entity, $res));
        }
    }
}
