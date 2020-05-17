<?php

/*
 * This file is part of the Klipper package.
 *
 * (c) François Pluchino <francois.pluchino@klipper.dev>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Klipper\Component\DataLoaderSecurity\Permission;

use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Processor;

/**
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class PermissionProcessor
{
    protected Processor $processor;

    /**
     * Constructor.
     *
     * @param null|Processor $processor The config processor
     */
    public function __construct(?Processor $processor = null)
    {
        $this->processor = $processor ?? new Processor();
    }

    /**
     * Processes an array of configurations.
     *
     * @param ConfigurationInterface $configuration The configuration class
     * @param array[]                $configs       An array of configuration items to process
     *
     * @return array The processed configuration
     */
    public function process(ConfigurationInterface $configuration, array $configs): array
    {
        $config = $this->processor->processConfiguration($configuration, $configs);
        $templates = $config['permission_templates'];

        unset($config['permission_templates']);
        $this->includeTemplateValues($templates, $config['permissions']);

        foreach ($config['permission_classes'] as $class => &$classConfig) {
            $this->includeTemplateValues($templates, $classConfig['permissions']);

            foreach ($classConfig['fields'] as $field => &$fieldConfig) {
                $this->includeTemplateValues($templates, $fieldConfig['permissions']);
            }
        }

        return $config;
    }

    /**
     * Include the template values in permission configs.
     *
     * @param array $templates   The template values
     * @param array $permissions The permission configs
     */
    private function includeTemplateValues(array $templates, array &$permissions): void
    {
        foreach ($permissions as $permission => &$config) {
            if (isset($templates[$permission])) {
                $tplValues = $templates[$permission];

                foreach (array_keys($tplValues) as $key) {
                    if (!empty($tplValues[$key])
                            && (!\array_key_exists($key, $config) || empty($config[$key]))) {
                        $config[$key] = $tplValues[$key];
                    }
                }
            }
        }
    }
}
