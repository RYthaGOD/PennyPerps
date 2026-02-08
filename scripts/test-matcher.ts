import WebSocket from 'ws';

const ws = new WebSocket('ws://localhost:8080');

ws.on('open', () => {
    console.log('Connected to Dark Matcher');

    // 1. Auth
    ws.send(JSON.stringify({
        type: 'auth',
        pubKey: 'GhostKeyToTheMoon'
    }));

    // 2. Send Intent
    setTimeout(() => {
        console.log('Sending Intent...');
        ws.send(JSON.stringify({
            type: 'post_intent',
            encrypted: {
                nonce: '123',
                ciphertext: 'abc'
            }
        }));
    }, 1000);
});

ws.on('message', (data) => {
    const msg = JSON.parse(data.toString());
    console.log('Received:', msg);

    if (msg.type === 'fill_report') {
        console.log('✅ Trade Filled!');
        ws.close();
        process.exit(0);
    }
});

ws.on('error', (err) => {
    console.error('Socket Error:', err);
    process.exit(1);
});
