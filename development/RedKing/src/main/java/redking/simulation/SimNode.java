package redking.simulation;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a node in the simulated P2P network.
 * Each node has a unique ID and a virtual location in the addressing space.
 */
public class SimNode {
    private final String id;
    private int location;
    private final SecureRandom random;

    public SimNode() {
        this.id = UUID.randomUUID().toString().substring(0, 8);
        this.random = new SecureRandom();
        this.location = random.nextInt(1000000); // Random initial location
    }

    public SimNode(int initialLocation) {
        this.id = UUID.randomUUID().toString().substring(0, 8);
        this.random = new SecureRandom();
        this.location = initialLocation;
    }

    public String getId() {
        return id;
    }

    public int getLocation() {
        return location;
    }

    public void setLocation(int location) {
        this.location = location;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SimNode simNode = (SimNode) o;
        return Objects.equals(id, simNode.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "SimNode{id='" + id + "', location=" + location + '}';
    }
}
