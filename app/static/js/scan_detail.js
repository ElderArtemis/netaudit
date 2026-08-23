(function () {
    const scanId = window.SCAN_ID;
    const initialStatus = window.SCAN_STATUS;
    const statusEl = document.getElementById('status');
    const progressBar = document.getElementById('progress-bar');
    const msgEl = document.getElementById('progress-msg');

    if (['completed', 'failed', 'cancelled'].includes(initialStatus)) {
        return; // nada que escuchar
    }

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${window.location.host}/api/scans/ws/${scanId}`;

    let reconnectAttempts = 0;
    let ws;

    function connect() {
        ws = new WebSocket(wsUrl);

        ws.onmessage = (ev) => {
            let data;
            try { data = JSON.parse(ev.data); } catch { return; }
            if (data.type === 'ping') return;

            if (typeof data.progress === 'number') {
                progressBar.style.width = `${data.progress}%`;
            }
            if (data.status) {
                statusEl.textContent = data.status;
                statusEl.className = `badge badge-${data.status}`;
            }
            if (data.message) {
                msgEl.textContent = `> ${data.message}`;
            }
            if (['completed', 'failed', 'cancelled'].includes(data.status)) {
                ws.close();
                setTimeout(() => window.location.reload(), 1500);
            }
        };

        ws.onclose = () => {
            if (reconnectAttempts < 5) {
                reconnectAttempts += 1;
                setTimeout(connect, 1500 * reconnectAttempts);
            }
        };
    }

    connect();
})();
