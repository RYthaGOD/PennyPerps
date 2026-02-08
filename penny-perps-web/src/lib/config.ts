export const CONFIG = {
    MATCHER_URL: 'ws://localhost:8080',
    // This public key MUST match the server's private key.
    // In our simulation, the server generates a random key on startup, 
    // so strictly speaking we'd need a handshake or a fixed key.
    // For now, we will use the fixed key we saw in logs or a known hardcoded one if we fixed the server seed.
    // But wait, the server generates a NEW key every time.
    // AUDIT FIX: We need the server to broadcast its PubKey on connect, OR use a fixed seed.
    // Let's use a placeholder here and fix the server to be deterministic or broadcast it.
    // AUDIT FIX: We use a deterministic key derived from "DarkMatcherSecretSeedForSimulationModeOnly"
    MATCHER_PUBKEY: "3bftR1sLgYHPi45gVywrhw2CDotx7mYBJQvZsbjRfPdE"
};
