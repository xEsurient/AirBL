"""Debug page HTML generator."""

def get_debug_html() -> str:
    """Generate the debug page HTML."""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Debug - AirBL</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #0a0e27;
            --bg-secondary: #141b2d;
            --bg-card: #1a2332;
            --bg-hover: #252f43;
            --text-primary: #e4e7eb;
            --text-secondary: #9ca3af;
            --accent: #3b82f6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --border: #2d3748;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 20px 0;
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        h1 {
            font-size: 1.5rem;
            color: var(--text-primary);
        }
        
        .nav-links {
            display: flex;
            gap: 20px;
        }
        
        .nav-links a {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 4px;
            transition: all 0.2s;
        }
        
        .nav-links a:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }
        
        .nav-links a.active {
            color: var(--accent);
            background: var(--bg-hover);
        }
        
        .debug-controls {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.2s;
            font-weight: 500;
        }
        
        .btn-primary {
            background: var(--accent);
            color: white;
        }
        
        .btn-primary:hover {
            background: #2563eb;
        }
        
        .btn-secondary {
            background: var(--bg-card);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }
        
        .btn-secondary:hover {
            background: var(--bg-hover);
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-danger:hover {
            background: #dc2626;
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-success:hover {
            background: #059669;
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .log-container {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            height: 600px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
        }
        
        .log-entry {
            padding: 4px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            word-wrap: break-word;
        }
        
        .log-entry:last-child {
            border-bottom: none;
        }
        
        .log-timestamp {
            color: var(--text-secondary);
            margin-right: 10px;
        }
        
        .log-level {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.75rem;
            font-weight: bold;
            margin-right: 8px;
            min-width: 50px;
            text-align: center;
        }
        
        .log-level.DEBUG {
            background: #3b82f6;
            color: white;
        }
        
        .log-level.INFO {
            background: #10b981;
            color: white;
        }
        
        .log-level.WARNING {
            background: #f59e0b;
            color: white;
        }
        
        .log-level.ERROR {
            background: #ef4444;
            color: white;
        }
        
        .log-level.CRITICAL {
            background: #dc2626;
            color: white;
        }
        
        .log-message {
            color: var(--text-primary);
        }
        
        .log-paused {
            opacity: 0.6;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 5px;
        }
        
        .stat-value {
            color: var(--text-primary);
            font-size: 1.5rem;
            font-weight: bold;
        }
        
    </style>
</head>
<body>
    <header>
        <div class="container header-content">
            <h1>Debug - AirBL</h1>
            <nav class="nav-links">
                <a href="/">Dashboard</a>
                <a href="/debug" class="active">Debug</a>
                <a href="/settings">Settings</a>
            </nav>
        </div>
    </header>
    
    <main class="container">
        <div class="debug-controls">
            <button class="btn btn-primary" id="pauseBtn" onclick="togglePause()">Pause</button>
            <button class="btn btn-secondary" onclick="clearLogs()">Clear Logs</button>
            <button class="btn btn-success" onclick="exportLogs()">Export Logs</button>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Log Entries</div>
                <div class="stat-value" id="logCount">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Status</div>
                <div class="stat-value" id="logStatus">Active</div>
            </div>
        </div>
        
        <div class="log-container" id="logContainer">
            <div class="log-entry">
                <span class="log-timestamp">--:--:--</span>
                <span class="log-level INFO">INFO</span>
                <span class="log-message">Debug log initialized. Waiting for log entries...</span>
            </div>
        </div>
    </main>
    
    <script>
        let ws = null;
        let isPaused = false;
        let logs = [];
        
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
            
            ws.onopen = () => {
                console.log('WebSocket connected');
                loadLogs();
            };
            
            ws.onmessage = (event) => {
                const msg = JSON.parse(event.data);
                if (msg.type === 'debug_log') {
                    addLogEntry(msg.data);
                }
            };
            
            ws.onclose = () => {
                setTimeout(connectWebSocket, 3000);
            };
        }
        
        async function loadLogs() {
            try {
                const response = await fetch('/api/debug/logs');
                const data = await response.json();
                logs = data.logs || [];
                isPaused = data.paused || false;
                updatePauseButton();
                renderLogs();
            } catch (e) {
                console.error('Failed to load logs:', e);
            }
        }
        
        function addLogEntry(entry) {
            if (isPaused) return;
            
            logs.push(entry);
            // Keep only last 1000 entries
            if (logs.length > 1000) {
                logs.shift();
            }
            renderLogs();
        }
        
        function renderLogs() {
            const container = document.getElementById('logContainer');
            container.innerHTML = '';
            
            logs.forEach(entry => {
                const logEntry = document.createElement('div');
                logEntry.className = 'log-entry' + (isPaused ? ' log-paused' : '');
                
                const timestamp = new Date(entry.timestamp).toLocaleTimeString();
                const level = entry.level || 'INFO';
                const message = entry.message || '';
                
                logEntry.innerHTML = `
                    <span class="log-timestamp">${timestamp}</span>
                    <span class="log-level ${level}">${level}</span>
                    <span class="log-message">${message}</span>
                `;
                
                container.appendChild(logEntry);
            });
            
            // Auto-scroll to bottom
            container.scrollTop = container.scrollHeight;
            
            // Update stats
            document.getElementById('logCount').textContent = logs.length;
            document.getElementById('logStatus').textContent = isPaused ? 'Paused' : 'Active';
        }
        
        async function togglePause() {
            try {
                const response = await fetch('/api/debug/pause', { method: 'POST' });
                const data = await response.json();
                isPaused = data.paused;
                updatePauseButton();
                document.getElementById('logStatus').textContent = isPaused ? 'Paused' : 'Active';
                renderLogs();
            } catch (e) {
                alert('Failed to toggle pause: ' + e.message);
            }
        }
        
        function updatePauseButton() {
            const btn = document.getElementById('pauseBtn');
            btn.textContent = isPaused ? 'Resume' : 'Pause';
            btn.className = isPaused ? 'btn btn-success' : 'btn btn-primary';
        }
        
        async function clearLogs() {
            if (!confirm('Clear all log entries?')) return;
            
            try {
                await fetch('/api/debug/clear', { method: 'POST' });
                logs = [];
                renderLogs();
            } catch (e) {
                alert('Failed to clear logs: ' + e.message);
            }
        }
        
        
        function exportLogs() {
            const logText = logs.map(entry => {
                const timestamp = new Date(entry.timestamp).toISOString();
                return `[${timestamp}] ${entry.level} - ${entry.message}`;
            }).join('\\n');
            
            const blob = new Blob([logText], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `airbl-debug-${new Date().toISOString().split('T')[0]}.log`;
            a.click();
            URL.revokeObjectURL(url);
        }
        
        // Initialize
        connectWebSocket();
    </script>
</body>
</html>'''

