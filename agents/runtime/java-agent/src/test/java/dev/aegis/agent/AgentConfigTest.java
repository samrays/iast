package dev.aegis.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AgentConfigTest {

    @Test
    void blockingDefaultsOffAndCrossesTheBootstrapBoundaryWhenEnabled() {
        AgentConfig defaults = AgentConfig.fromAgentArgs("");
        AgentConfig enabled = AgentConfig.fromAgentArgs("blocking=true");

        assertFalse(defaults.blockingEnabled());
        assertEquals("false", defaults.toMap().get("blocking"));
        assertTrue(enabled.blockingEnabled());
        assertEquals("true", enabled.toMap().get("blocking"));
    }
}
