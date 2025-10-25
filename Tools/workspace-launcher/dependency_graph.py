#!/usr/bin/env python3
"""
Dependency Graph - Service dependency resolution and startup ordering

Provides topological sorting for service startup order based on dependencies.
"""

import logging
from typing import Dict, List
from collections import defaultdict, deque
from config_loader import ServiceConfig


logger = logging.getLogger('workspace_manager.dependencies')


class DependencyGraph:
    """
    Manage service dependencies and execution order

    Uses topological sorting (Kahn's algorithm) to determine safe startup order.
    Services are grouped into "tiers" where services in the same tier have no
    dependencies on each other and can be started in parallel.
    """

    def __init__(self, services: Dict[str, ServiceConfig]):
        """
        Initialize dependency graph

        Args:
            services: Dictionary of service configurations
        """
        self.services = services
        self.graph = self._build_graph()

    def _build_graph(self) -> Dict[str, List[str]]:
        """
        Build adjacency list representation of dependency graph

        Returns:
            Dict mapping each service to list of services that depend on it
        """
        graph = defaultdict(list)

        for service_key, service in self.services.items():
            # For each dependency, add this service as a dependent
            for dependency in service.depends_on:
                graph[dependency].append(service_key)

        logger.debug(f"Built dependency graph: {dict(graph)}")
        return graph

    def topological_sort(self, service_keys: List[str]) -> List[List[str]]:
        """
        Return services grouped by dependency tier using Kahn's algorithm

        Services in the same tier can start in parallel as they have no
        dependencies on each other.

        Args:
            service_keys: List of service keys to sort

        Returns:
            List of tiers, where each tier is a list of service keys
            Example: [['redis'], ['mcp-orchestrator'], ['mcp-dashboard']]

        Raises:
            ValueError: If circular dependency detected
        """
        # Build in-degree map for requested services
        in_degree = defaultdict(int)
        relevant_graph = defaultdict(list)

        # Filter graph to only include requested services and their dependencies
        for service_key in service_keys:
            service = self.services.get(service_key)
            if not service:
                logger.warning(f"Service '{service_key}' not found in configuration")
                continue

            # Count dependencies (in-degree)
            for dep in service.depends_on:
                if dep in service_keys:
                    relevant_graph[dep].append(service_key)
                    in_degree[service_key] += 1
                elif dep in self.services:
                    # Dependency exists but not in requested list - add it automatically
                    logger.info(f"Auto-adding dependency '{dep}' for service '{service_key}'")
                    service_keys.append(dep)
                    relevant_graph[dep].append(service_key)
                    in_degree[service_key] += 1
                else:
                    logger.warning(f"Service '{service_key}' depends on undefined service '{dep}'")

            # Ensure service is in in_degree map (even if no dependencies)
            if service_key not in in_degree:
                in_degree[service_key] = 0

        # Kahn's algorithm for topological sort
        tiers = []
        queue = deque([key for key in service_keys if in_degree[key] == 0])

        if not queue and service_keys:
            # All services have dependencies - possible cycle
            raise ValueError(
                f"No services without dependencies found. "
                f"Possible circular dependency in: {service_keys}"
            )

        processed = 0
        while queue:
            # Current tier: all services with no remaining dependencies
            current_tier = list(queue)
            queue.clear()
            tiers.append(current_tier)

            logger.debug(f"Tier {len(tiers)}: {current_tier}")

            # Process current tier
            for service_key in current_tier:
                processed += 1

                # Reduce in-degree for all dependents
                for neighbor in relevant_graph[service_key]:
                    in_degree[neighbor] -= 1
                    if in_degree[neighbor] == 0:
                        queue.append(neighbor)

        # Check for cycles
        if processed < len(service_keys):
            # Some services weren't processed - circular dependency exists
            unprocessed = [s for s in service_keys if in_degree[s] > 0]
            raise ValueError(
                f"Circular dependency detected involving: {unprocessed}"
            )

        logger.info(
            f"Topological sort complete: {len(tiers)} tiers, {processed} services",
            extra={'tier_count': len(tiers), 'service_count': processed}
        )

        return tiers

    def get_startup_order(self, profile_services: List[str]) -> List[List[str]]:
        """
        Get startup order for a profile's services

        Args:
            profile_services: List of service keys in profile

        Returns:
            List of tiers for startup order

        Raises:
            ValueError: If circular dependency detected
        """
        try:
            tiers = self.topological_sort(profile_services)

            logger.info(
                f"Startup order computed: {len(tiers)} tiers",
                extra={
                    'tier_count': len(tiers),
                    'services': profile_services,
                    'tiers': [[s for s in tier] for tier in tiers]
                }
            )

            return tiers

        except ValueError as e:
            logger.error(f"Failed to compute startup order: {e}")
            raise

    def get_dependencies(self, service_key: str) -> List[str]:
        """
        Get direct dependencies for a service

        Args:
            service_key: Service to get dependencies for

        Returns:
            List of service keys that this service depends on
        """
        service = self.services.get(service_key)
        if not service:
            return []

        return service.depends_on

    def get_dependents(self, service_key: str) -> List[str]:
        """
        Get services that depend on this service

        Args:
            service_key: Service to get dependents for

        Returns:
            List of service keys that depend on this service
        """
        return self.graph.get(service_key, [])

    def has_cycles(self) -> bool:
        """
        Check if dependency graph contains cycles

        Returns:
            True if cycles exist, False otherwise
        """
        visited = set()
        rec_stack = set()

        def has_cycle_util(service_key: str) -> bool:
            """DFS helper to detect cycles"""
            visited.add(service_key)
            rec_stack.add(service_key)

            # Check all dependencies
            service = self.services.get(service_key)
            if service:
                for dep in service.depends_on:
                    if dep not in visited:
                        if has_cycle_util(dep):
                            return True
                    elif dep in rec_stack:
                        # Found cycle
                        logger.warning(f"Cycle detected: {service_key} -> {dep}")
                        return True

            rec_stack.remove(service_key)
            return False

        # Check all services
        for service_key in self.services:
            if service_key not in visited:
                if has_cycle_util(service_key):
                    return True

        return False

    def visualize(self) -> str:
        """
        Create text visualization of dependency graph

        Returns:
            Multi-line string showing dependency relationships
        """
        lines = ["Dependency Graph:", "=" * 60]

        for service_key, service in self.services.items():
            if service.depends_on:
                deps = ", ".join(service.depends_on)
                lines.append(f"{service_key} depends on: {deps}")
            else:
                lines.append(f"{service_key} (no dependencies)")

            dependents = self.get_dependents(service_key)
            if dependents:
                deps_str = ", ".join(dependents)
                lines.append(f"  └─> required by: {deps_str}")

        lines.append("=" * 60)
        return "\n".join(lines)


# Example usage and testing
if __name__ == '__main__':
    import sys
    from pathlib import Path
    from config_loader import ConfigLoader

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Load configuration
    config_file = Path(__file__).parent / 'workspace-config.yaml'

    if not config_file.exists():
        print(f"Configuration file not found: {config_file}")
        sys.exit(1)

    print("Loading configuration...")
    loader = ConfigLoader(config_file)

    if not loader.load():
        print("[ERROR] Failed to load configuration")
        sys.exit(1)

    # Create dependency graph
    print("\nBuilding dependency graph...")
    dep_graph = DependencyGraph(loader.get_services())

    # Check for cycles
    print("\nChecking for circular dependencies...")
    if dep_graph.has_cycles():
        print("[ERROR] Circular dependencies detected!")
    else:
        print("[OK] No circular dependencies")

    # Visualize graph
    print("\n" + dep_graph.visualize())

    # Test startup order for each profile
    print("\nStartup Orders by Profile:")
    print("=" * 60)

    for profile_key, profile in loader.get_profiles().items():
        all_services = profile.services + profile.projects

        print(f"\nProfile: {profile.name}")
        print(f"Services: {', '.join(all_services)}")

        try:
            tiers = dep_graph.get_startup_order(all_services)

            print(f"Startup Order ({len(tiers)} tiers):")
            for i, tier in enumerate(tiers, 1):
                tier_str = ', '.join(tier)
                print(f"  Tier {i}: {tier_str}")

        except ValueError as e:
            print(f"  [ERROR] {e}")

    print("\n" + "=" * 60)
    print("Dependency graph testing complete!")
