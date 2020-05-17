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

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class PermissionConfiguration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('klipper_permissions');
        /** @var ArrayNodeDefinition $rootNode */
        $rootNode = $treeBuilder->getRootNode();
        $rootNode
            ->addDefaultsIfNotSet()
            ->children()
            ->append($this->buildPermissionsNode('permission_templates'))
            ->append($this->buildPermissionsNode('permissions'))
            ->append($this->getClassesNode())
            ->end()
        ;

        return $treeBuilder;
    }

    /**
     * Get classes node.
     */
    private function getClassesNode(): ArrayNodeDefinition
    {
        $treeBuilder = new TreeBuilder('permission_classes');
        /** @var ArrayNodeDefinition $rootNode */
        $rootNode = $treeBuilder->getRootNode();
        $rootNode
            ->requiresAtLeastOneElement()
            ->useAttributeAsKey('class')
            ->normalizeKeys(false)
            ->prototype('array')
            ->addDefaultsIfNotSet()
            ->children()
            ->append($this->buildPermissionsNode('permissions'))
            ->arrayNode('fields')
            ->requiresAtLeastOneElement()
            ->useAttributeAsKey('field')
            ->normalizeKeys(false)
            ->prototype('array')
            ->beforeNormalization()
            ->ifTrue(static function ($v) {
                return !isset($v['permissions']);
            })
            ->then(static function ($v) {
                return ['permissions' => $v];
            })
            ->end()
            ->children()
            ->append($this->buildPermissionsNode('permissions'))
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
        ;

        return $rootNode;
    }

    /**
     * Get permissions node.
     *
     * @param string $name The name
     */
    private function buildPermissionsNode(string $name): ArrayNodeDefinition
    {
        $treeBuilder = new TreeBuilder($name);
        /** @var ArrayNodeDefinition $node */
        $node = $treeBuilder->getRootNode();
        $node
            ->requiresAtLeastOneElement()
            ->useAttributeAsKey('operation')
            ->normalizeKeys(false)
            ->prototype('array')
            ->addDefaultsIfNotSet()
            ->beforeNormalization()
            ->ifTrue(static function ($v) {
                return !(!empty($v) && array_keys($v) !== range(0, \count($v) - 1));
            })
            ->then(static function ($v) {
                return ['attached_roles' => $v];
            })
            ->end()
            ->children()
            ->scalarNode('label')->defaultNull()->end()
            ->scalarNode('detail_label')->defaultNull()->end()
            ->scalarNode('translation_domain')->defaultNull()->end()
            ->arrayNode('contexts')
            ->prototype('scalar')->end()
            ->end()
            ->arrayNode('attached_roles')
            ->prototype('scalar')->end()
            ->end()
            ->end()
            ->end()
        ;

        return $node;
    }
}
