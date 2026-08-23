document.getElementById('scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const status = document.getElementById('form-status');
    const fd = new FormData(form);
    const payload = {
        name: fd.get('name'),
        target_cidr: fd.get('target_cidr'),
        ports: fd.get('ports') || '1-65535',
        masscan_rate: parseInt(fd.get('masscan_rate'), 10),
        nmap_scripts: fd.get('nmap_scripts') || 'vuln,auth,default',
    };

    status.textContent = '> enviando a la cola...';
    try {
        const res = await fetch('/api/scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            status.textContent = `! error: ${err.detail || res.statusText}`;
            return;
        }
        const scan = await res.json();
        status.textContent = `> escaneo #${scan.id} encolado, redirigiendo...`;
        setTimeout(() => { window.location.href = `/scans/${scan.id}`; }, 600);
    } catch (err) {
        status.textContent = `! error de red: ${err.message}`;
    }
});
