/**
 * AirBL Dashboard Application Logic
 */

// Polyfill to prevent crashes when app.js accesses DOM elements that are split across Overview/Servers pages.
const originalGetElementById = document.getElementById.bind(document);
document.getElementById = function(id) {
    const el = originalGetElementById(id);
    if (el) return el;
    
    const safeIds = [
        'resultsContainer', 'filterCountry', 'filterStatus', 'filterMaxLoad', 'filterMaxPing',
        'filterMinDownload', 'filterMinUpload', 'filterMinScore', 'filterMinDev',
        'serverModal', 'modalServerName', 'modalServerInfo', 'modalPerformance', 'modalSpeedtest',
        'modalIPs', 'modalSpeedtestBtn',
        'scanStatus', 'scanProgress', 'nextStep', 'nextScan', 'progressContainer', 'progressFill',
        'summaryServers', 'summaryClean', 'summaryBlocked', 'summaryIPs',
        'scanBtn', 'stopBtn', 'pauseBtn', 'restartBtn', 'baselineDisplay', 'baselineText'
    ];
    
    if (safeIds.includes(id)) {
        return { 
            style: {}, 
            classList: { add: ()=>{}, remove: ()=>{} }, 
            textContent: '', 
            innerHTML: '', 
            value: '', 
            disabled: false,
            appendChild: ()=>{},
            focus: ()=>{}
        };
    }
    return null;
};
let ws = null;
let nextScanTime = null;
let allResults = null;
let scoringThresholds = { signal_good_threshold: 80, signal_medium_threshold: 50 };  // Defaults, updated from API

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => console.log('WebSocket connected');
    ws.onmessage = (event) => handleMessage(JSON.parse(event.data));
    ws.onclose = () => setTimeout(connectWebSocket, 3000);
}

function handleMessage(msg) {
    switch (msg.type) {
        case 'status':
            updateStatus(msg.data);
            // Restore progress if available
            if (msg.data.progress) {
                updateProgress(msg.data.progress);
            }
            // Restore summary stats if available
            if (msg.data.summary) {
                updateSummary(msg.data.summary);
                if (!allResults) {
                    allResults = msg.data.summary;
                    populateCountryFilter(msg.data.summary);
                    // Apply filters (defaults to clean only)
                    applyFilters();
                }
            }
            break;
        case 'progress':
            updateProgress(msg.data);
            break;
        case 'scan_started':
            updateStatus({ is_scanning: true, is_paused: false });
            document.getElementById('progressContainer').style.display = 'block';
            document.getElementById('nextStep').textContent = '-';
            // Initialize empty results for incremental updates
            allResults = { servers_by_country: {}, servers: [] };
            document.getElementById('resultsContainer').innerHTML = '';
            // Reset summary to zeros
            document.getElementById('summaryServers').textContent = '0';
            document.getElementById('summaryClean').textContent = '0';
            document.getElementById('summaryBlocked').textContent = '0';
            document.getElementById('summaryIPs').textContent = '0';
            break;
        case 'server_complete':
            // Add/update this server in results incrementally
            if (!allResults) {
                allResults = msg.data.summary || { servers_by_country: {}, servers: [] };
            } else {
                // Merge the new server into existing results
                const server = msg.data.server;
                const countryCode = server.country_code;

                if (!allResults.servers_by_country) {
                    allResults.servers_by_country = {};
                }
                if (!allResults.servers_by_country[countryCode]) {
                    allResults.servers_by_country[countryCode] = [];
                }

                // Remove existing server if present (update)
                allResults.servers_by_country[countryCode] =
                    allResults.servers_by_country[countryCode].filter(
                        s => s.server_name !== server.server_name
                    );
                allResults.servers_by_country[countryCode].push(server);

                // Update servers array
                if (!allResults.servers) {
                    allResults.servers = [];
                }
                allResults.servers = allResults.servers.filter(
                    s => s.server_name !== server.server_name
                );
                allResults.servers.push(server);

                // Fix: Update summary stats from the full summary, but preserve our merged data
                if (msg.data.summary) {
                    allResults.total_servers = msg.data.summary.total_servers;
                    allResults.clean_servers_count = msg.data.summary.clean_servers_count;
                    allResults.blocked_servers_count = msg.data.summary.blocked_servers_count;
                    allResults.total_ips_scanned = msg.data.summary.total_ips_scanned;
                    allResults.total_responsive = msg.data.summary.total_responsive;
                    allResults.total_blocked = msg.data.summary.total_blocked;
                }
            }

            // Update display incrementally
            updateSummary(allResults);
            populateCountryFilter(allResults);

            // Always apply filters (status filter defaults to "clean")
            applyFilters();
            break;
        case 'baseline_speedtest_started':
            console.log('Baseline speedtest started');
            break;
        case 'baseline_speedtest_complete':
            if (msg.data.baseline) {
                updateBaselineDisplay(msg.data.baseline);
            }
            break;
        case 'baseline_speedtest_error':
            console.error('Baseline speedtest error:', msg.data.error);
            break;
        case 'scan_complete':
            document.getElementById('scanStatus').textContent = 'Scan Complete';
            if (msg.data && (msg.data.total_servers !== undefined ||
                (msg.data.servers_by_country && Object.keys(msg.data.servers_by_country).length > 0))) {
                allResults = msg.data;
                updateSummary(msg.data);
                populateCountryFilter(msg.data);
                // Apply filters to respect current filter settings
                applyFilters();
                if (msg.data.next_scan_at) {
                    nextScanTime = new Date(msg.data.next_scan_at);
                }
            }
            // Fire page-level callback for reactive refresh
            if (typeof window.onScanComplete === 'function') {
                window.onScanComplete(msg.data);
            }
            break;
        case 'scan_error':
            document.getElementById('scanStatus').textContent = 'Error';
            document.getElementById('scanStatus').classList.remove('scanning');
            document.getElementById('scanBtn').disabled = false;
            alert('Scan error: ' + msg.data.error);
            break;
        case 'speedtest_queue':
            // Show speedtest queue notification
            console.log('Speedtest queue:', msg.data.message);
            // Ensure is_scanning is true when speedtests start
            updateStatus({ is_scanning: true, is_paused: false });
            if (msg.data.count) {
                document.getElementById('scanStatus').textContent = 'Speedtesting...';
                document.getElementById('scanStatus').classList.add('scanning');
                document.getElementById('progressContainer').style.display = 'block';
                // Initialize progress
                updateProgress({
                    phase: 'speedtesting',
                    current: 0,
                    total: msg.data.total || msg.data.count,
                    server: '',
                    country: '',
                    next: msg.data.next || 'Queueing speedtests...'
                });
            }
            break;
        case 'progress_update':
            // Update progress from state (used during burst waits and other updates)
            if (msg.data.progress) {
                updateProgress(msg.data.progress);
            }
            // If summary is included, update stats to ensure they're preserved during waits
            if (msg.data.summary && allResults) {
                // Preserve existing results but update summary stats
                allResults.total_servers = msg.data.summary.total_servers;
                allResults.clean_servers_count = msg.data.summary.clean_servers_count;
                allResults.blocked_servers_count = msg.data.summary.blocked_servers_count;
                allResults.total_ips_scanned = msg.data.summary.total_ips_scanned;
                updateSummary(allResults);
            }
            break;

        case 'speedtest_started':
            console.log('Speedtest started for:', msg.data.server);
            // Update progress card with current speedtest
            if (msg.data.current !== undefined && msg.data.total !== undefined) {
                const country = msg.data.country || '';
                const server = msg.data.server || '';
                updateProgress({
                    phase: 'speedtesting',
                    current: msg.data.current,
                    total: msg.data.total,
                    server: server,
                    country: country,
                    next: msg.data.next || ''
                });
                // Update status to show which server is being tested
                document.getElementById('scanStatus').textContent = `Speedtesting ${server}...`;
            }
            break;
        case 'speedtest_complete':
            // Update server with speedtest results
            if (msg.data.server && msg.data.summary) {
                const server = msg.data.server;
                const countryCode = server.country_code;

                if (!allResults) {
                    allResults = msg.data.summary;
                } else {
                    // Update the server in results
                    if (!allResults.servers_by_country) {
                        allResults.servers_by_country = {};
                    }
                    if (!allResults.servers_by_country[countryCode]) {
                        allResults.servers_by_country[countryCode] = [];
                    }

                    // Remove existing server if present (update)
                    allResults.servers_by_country[countryCode] =
                        allResults.servers_by_country[countryCode].filter(
                            s => s.server_name !== server.server_name
                        );
                    allResults.servers_by_country[countryCode].push(server);

                    // Update servers array
                    if (!allResults.servers) {
                        allResults.servers = [];
                    }
                    allResults.servers = allResults.servers.filter(
                        s => s.server_name !== server.server_name
                    );
                    allResults.servers.push(server);

                    // Update summary stats from the full summary
                    if (msg.data.summary) {
                        allResults.total_servers = msg.data.summary.total_servers;
                        allResults.clean_servers_count = msg.data.summary.clean_servers_count;
                        allResults.blocked_servers_count = msg.data.summary.blocked_servers_count;
                        allResults.total_ips_scanned = msg.data.summary.total_ips_scanned;
                    }
                }

                // Refresh display
                updateSummary(allResults);
                populateCountryFilter(allResults);
                // Apply filters (defaults to clean only)
                applyFilters();
            }
            break;
        case 'speedtest_all_complete':
            // All speedtests completed - now we can set is_scanning to false
            updateStatus({ is_scanning: false, is_paused: false });
            document.getElementById('scanStatus').textContent = 'Idle';
            document.getElementById('scanStatus').classList.remove('scanning');
            // Update progress if provided, otherwise reset to idle
            if (msg.data.progress) {
                updateProgress(msg.data.progress);
            } else {
                updateProgress({
                    phase: 'idle',
                    current: 0,
                    total: 0,
                    server: '',
                    country: '',
                    next: ''
                });
            }
            // Hide progress container when truly idle
            if (msg.data.progress && msg.data.progress.phase === 'idle') {
                document.getElementById('progressContainer').style.display = 'none';
            }
            if (msg.data && msg.data.summary) {
                // Validate summary has required fields
                const summary = msg.data.summary;
                if (summary.total_servers !== undefined ||
                    (summary.servers_by_country && Object.keys(summary.servers_by_country).length > 0)) {
                    allResults = summary;
                    updateSummary(summary);
                    populateCountryFilter(summary);
                    // Apply filters to respect current filter settings
                    applyFilters();
                }
            }
            break;
        case 'speedtest_error':
            console.error('Speedtest error for', msg.data.server, ':', msg.data.error);
            // Show error notification
            const errorMsg = `Speedtest failed for ${msg.data.server}: ${msg.data.error}`;
            // alert(errorMsg); // Removed alert to avoid annoyance during batch tests

            // Update the server in the UI to show error
            if (allResults && allResults.servers_by_country) {
                for (const countryCode in allResults.servers_by_country) {
                    const servers = allResults.servers_by_country[countryCode];
                    const server = servers.find(s => s.server_name === msg.data.server);
                    if (server) {
                        if (!server.speedtest) {
                            server.speedtest = {};
                        }
                        server.speedtest.error = msg.data.error;
                        // Apply filters (defaults to clean only)
                        applyFilters();
                        break;
                    }
                }
            }
            break;
        case 'scan_paused':
            updateStatus({ is_scanning: true, is_paused: true });
            break;
        case 'scan_resumed':
            updateStatus({ is_scanning: true, is_paused: false });
            break;
        case 'scan_cancelled':
        case 'scan_stopping':
            updateStatus({ is_scanning: false, is_paused: false });
            document.getElementById('scanStatus').textContent = 'Cancelled';
            document.getElementById('progressContainer').style.display = 'none';
            break;
    }
}

function updateStatus(data) {
    const scanBtn = document.getElementById('scanBtn');
    const stopBtn = document.getElementById('stopBtn');
    const pauseBtn = document.getElementById('pauseBtn');
    const restartBtn = document.getElementById('restartBtn');
    const statusEl = document.getElementById('scanStatus');

    if (data.is_scanning) {
        if (data.is_paused) {
            statusEl.textContent = 'Paused';
            statusEl.classList.add('scanning');
            pauseBtn.textContent = 'Resume';
        } else {
            statusEl.textContent = 'Scanning...';
            statusEl.classList.add('scanning');
            pauseBtn.textContent = 'Pause';
        }
        scanBtn.disabled = true;
        scanBtn.style.display = 'none';
        stopBtn.style.display = 'inline-block';
        pauseBtn.style.display = 'inline-block';
        restartBtn.style.display = 'inline-block';
    } else {
        statusEl.textContent = 'Idle';
        statusEl.classList.remove('scanning');
        scanBtn.disabled = false;
        scanBtn.style.display = 'inline-block';
        stopBtn.style.display = 'none';
        pauseBtn.style.display = 'none';
        restartBtn.style.display = 'none';
    }
}

function updateProgress(data) {
    const pct = data.total > 0 ? (data.current / data.total * 100) : 0;
    document.getElementById('progressFill').style.width = pct + '%';

    // Format: "Country - Server - phase (current/total)"
    let progressText = '';
    if (data.phase === 'speedtesting') {
        // Special format for speedtesting
        if (data.country && data.server) {
            progressText = `Speedtesting ${data.country} - ${data.server} (${data.current}/${data.total})`;
        } else if (data.server) {
            progressText = `Speedtesting ${data.server} (${data.current}/${data.total})`;
        } else {
            progressText = `Speedtesting (${data.current}/${data.total})`;
        }
    } else {
        const displayPhase = data.phase ? data.phase.charAt(0).toUpperCase() + data.phase.slice(1) : '';
        
        if (data.country && data.server) {
            progressText = `${data.country} - ${data.server} - ${displayPhase} (${data.current}/${data.total})`;
        } else if (data.server) {
            progressText = `${data.server} - ${displayPhase} (${data.current}/${data.total})`;
        } else {
            progressText = `${displayPhase} (${data.current}/${data.total})`;
        }
    }
    document.getElementById('scanProgress').textContent = progressText;

    // Update next step
    document.getElementById('nextStep').textContent = data.next || '-';
}

function updateSummary(data) {
    document.getElementById('summaryServers').textContent = data.total_servers || 0;
    document.getElementById('summaryClean').textContent = data.clean_servers_count || 0;
    document.getElementById('summaryBlocked').textContent = data.blocked_servers_count || 0;
    document.getElementById('summaryIPs').textContent = data.total_ips_scanned || 0;
}

function updateBaselineDisplay(baseline) {
    if (!baseline) return;
    const display = document.getElementById('baselineDisplay');
    const text = document.getElementById('baselineText');
    if (display && text && baseline.download_mbps && baseline.upload_mbps && baseline.ping_ms) {
        text.textContent = `Baseline: ↓ ${baseline.download_mbps.toFixed(1)} Mbps | ↑ ${baseline.upload_mbps.toFixed(1)} Mbps | ${baseline.ping_ms.toFixed(0)}ms ping`;
        display.style.display = 'block';
    }
}

// Load baseline on page load
async function loadBaseline() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        if (data.baseline_speedtest) {
            updateBaselineDisplay(data.baseline_speedtest);
        }
    } catch (e) {
        console.error('Failed to load baseline:', e);
    }
}

function populateCountryFilter(data) {
    const select = document.getElementById('filterCountry');
    const currentValue = select.value;
    select.innerHTML = '<option value="">All Countries</option>';

    if (data.servers_by_country) {
        const countries = Object.keys(data.servers_by_country).sort();
        for (const code of countries) {
            const servers = data.servers_by_country[code];
            if (servers && servers.length > 0) {
                const name = servers[0].country_name;
                const opt = document.createElement('option');
                opt.value = code;
                opt.textContent = `${getFlagEmoji(code)} ${name} (${servers.length})`;
                select.appendChild(opt);
            }
        }
    }

    select.value = currentValue;
}

function applyFilters() {
    if (!allResults) return;

    const country = document.getElementById('filterCountry').value;
    const status = document.getElementById('filterStatus').value;
    const maxLoad = document.getElementById('filterMaxLoad').value;
    const maxPing = document.getElementById('filterMaxPing').value;
    const minDownload = document.getElementById('filterMinDownload').value;
    const minUpload = document.getElementById('filterMinUpload').value;
    const minScore = document.getElementById('filterMinScore').value;
    const minDev = document.getElementById('filterMinDev').value;

    // Build query params
    const params = new URLSearchParams();
    if (country) params.set('country', country);
    if (status) params.set('status', status);
    if (maxLoad) params.set('max_load', maxLoad);
    if (maxPing) params.set('max_ping', maxPing);
    if (minDownload) params.set('min_download', minDownload);
    if (minUpload) params.set('min_upload', minUpload);
    if (minScore) params.set('min_score', minScore);
    if (minDev) params.set('min_dev', minDev);

    fetch('/api/servers?' + params.toString())
        .then(r => r.json())
        .then(data => {
            renderFilteredResults(data.countries || []);
        });
}

function resetFilters() {
    document.getElementById('filterCountry').value = '';
    document.getElementById('filterStatus').value = 'clean';  // Default to clean only
    document.getElementById('filterMaxLoad').value = '';
    document.getElementById('filterMaxPing').value = '';
    document.getElementById('filterMinDownload').value = '';
    document.getElementById('filterMinUpload').value = '';
    document.getElementById('filterMinScore').value = '';
    document.getElementById('filterMinDev').value = '';

    // Always apply filters (status defaults to clean)
    applyFilters();
}

let renderTimeout = null;
let pendingRenderData = null;

function renderResults(data) {
    // Debounce rendering to prevent UI from becoming unresponsive during speedtests
    pendingRenderData = data;

    if (renderTimeout) {
        clearTimeout(renderTimeout);
    }

    renderTimeout = setTimeout(() => {
        _renderResultsImmediate(pendingRenderData);
        pendingRenderData = null;
        renderTimeout = null;
    }, 150); // 150ms debounce
}

function _renderResultsImmediate(data) {
    const container = document.getElementById('resultsContainer');

    if (!data.servers_by_country || Object.keys(data.servers_by_country).length === 0) {
        container.innerHTML = '<div class="empty-state"><h2>No Servers Found</h2><p>Make sure config files are in the conf/ directory.</p></div>';
        return;
    }

    let html = '<div class="countries-grid">';
    const countries = Object.keys(data.servers_by_country).sort();

    for (const countryCode of countries) {
        const servers = data.servers_by_country[countryCode];
        if (!servers || servers.length === 0) continue;
        html += renderCountryCard(countryCode, servers);
    }

    html += '</div>';
    container.innerHTML = html;
}

function renderFilteredResults(countries) {
    const container = document.getElementById('resultsContainer');

    if (!countries || countries.length === 0) {
        container.innerHTML = '<div class="empty-state"><h2>No Matching Servers</h2><p>Try adjusting your filters.</p></div>';
        return;
    }

    let html = '<div class="countries-grid">';

    for (const country of countries) {
        html += renderCountryCard(country.country_code, country.servers);
    }

    html += '</div>';
    container.innerHTML = html;
}

function renderCountryCard(countryCode, servers) {
    const countryName = servers[0].country_name;
    const cleanCount = servers.filter(s => s.is_clean).length;
    const blockedCount = servers.length - cleanCount;

    let html = `
        <div class="country-card">
            <div class="country-header">
                <span class="country-name">${getFlagEmoji(countryCode)} ${countryName}</span>
                <div class="country-stats">
                    <span class="stat ok">✓ ${cleanCount}</span>
                    <span class="stat blocked">✗ ${blockedCount}</span>
                </div>
            </div>
            <div class="server-list">
    `;

    for (const server of servers) {
        const statusClass = server.is_clean ? 'clean' : 'blocked';
        const loadClass = getLoadClass(server.load_percent);
        // Check if speedtest exists and is valid
        const hasSpeedtest = server.speedtest &&
            !server.speedtest.error &&
            (server.speedtest.download_mbps > 0 || server.speedtest.upload_mbps > 0);

        // Get config ping (now separated to Entry 1 and Entry 3 logic)
        const e1Ping = server.entry1_ping?.latency_ms || null;
        const e3Ping = server.entry3_ping?.latency_ms || null;
        let bestEntryPing = e1Ping;
        if (e3Ping !== null && (bestEntryPing === null || e3Ping < bestEntryPing)) {
            bestEntryPing = e3Ping;
        }

        // Get exit ping
        const exitPing = server.exit_ping?.latency_ms || null;

        // Get speedtest values
        const speedtestPing = hasSpeedtest && server.speedtest.ping_ms ? server.speedtest.ping_ms : null;
        const download = hasSpeedtest ? server.speedtest.download_mbps : null;
        const upload = hasSpeedtest ? server.speedtest.upload_mbps : null;
        const devianceScore = hasSpeedtest && server.speedtest.deviation_score !== undefined ? server.speedtest.deviation_score : null;

        const serverScore = server.score || 0;

        html += `
            <div class="server-item ${statusClass}" onclick="showServerDetails('${server.server_name}')">
                <div class="server-info">
                    <div class="server-name">
                        ${getSignalBarsHtml(server)}
                        ${server.server_name}
                    </div>
                    <div class="server-location">${server.location}</div>
                </div>
                <div class="server-metrics">
                    <!-- Row 1: Entry1 ping, Exit ping, upload, deviation, load -->
                    <div class="metrics-row" style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px;">
                        <div class="metric">
                            <span class="metric-value ${e1Ping ? getPingClass(e1Ping) : ''}">${e1Ping ? Math.round(e1Ping) + 'ms' : '-'}</span>
                            <span class="metric-label">Entry 1</span>
                        </div>
                        <div class="metric">
                            <span class="metric-value ${exitPing ? getPingClass(exitPing) : ''}">${exitPing ? Math.round(exitPing) + 'ms' : '-'}</span>
                            <span class="metric-label">Exit</span>
                        </div>
                        <div class="metric">
                            <span class="metric-value" style="color: var(--accent);">${upload ? '↑ ' + upload.toFixed(1) : '-'}</span>
                            <span class="metric-label">Up</span>
                        </div>
                        <div class="metric">
                            <span class="metric-value" style="color: ${devianceScore !== null ? (devianceScore >= 100 ? 'var(--success)' : devianceScore >= 50 ? 'var(--warning)' : 'var(--danger)') : 'var(--text-secondary)'};">${devianceScore !== null ? devianceScore.toFixed(1) + '%' : '-'}</span>
                            <span class="metric-label">Dev</span>
                        </div>
                        <div class="metric">
                            <span class="metric-value ${loadClass}">${server.load_percent}%</span>
                            <span class="metric-label">Load</span>
                        </div>
                    </div>
                    
                    <!-- Row 2: Entry 3 ping, Speedtest ping, download, (empty space), Score -->
                    <div class="metrics-row" style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-top: 10px;">
                        <div class="metric">
                            <span class="metric-value ${e3Ping ? getPingClass(e3Ping) : ''}">${e3Ping ? Math.round(e3Ping) + 'ms' : '-'}</span>
                            <span class="metric-label">Entry 3</span>
                        </div>
                        <div class="metric">
                            <span class="metric-value ${speedtestPing ? getPingClass(speedtestPing) : ''}">${speedtestPing ? Math.round(speedtestPing) + 'ms' : '-'}</span>
                            <span class="metric-label">ST Ping</span>
                        </div>
                        <div class="metric">
                            <span class="metric-value" style="color: var(--accent);">${download ? '↓ ' + download.toFixed(1) : '-'}</span>
                            <span class="metric-label">Down</span>
                        </div>
                        <div class="metric">
                            <!-- Empty spacer -->
                        </div>
                        <div class="metric">
                            <span class="metric-value">${serverScore.toFixed(1)}</span>
                            <span class="metric-label">Score</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    html += '</div></div>';
    return html;
}

let currentModalServer = null;

function showServerDetails(serverName) {
    // Find server in allResults
    if (!allResults || !allResults.servers_by_country) {
        console.error('No results available');
        return;
    }

    let server = null;
    for (const countryCode in allResults.servers_by_country) {
        const servers = allResults.servers_by_country[countryCode];
        server = servers.find(s => s.server_name === serverName);
        if (server) break;
    }

    if (!server) {
        console.error('Server not found:', serverName);
        return;
    }

    currentModalServer = server;

    // Populate header
    document.getElementById('modalServerName').textContent = server.server_name;

    // Populate Server Info section
    const statusText = server.is_clean ? '✓ Clean' : '✗ Blocked';
    const statusClass = server.is_clean ? 'success' : 'danger';

    document.getElementById('modalServerInfo').innerHTML = `
        <div class="info-item">
            <span class="info-label">Status</span>
            <span class="info-value ${statusClass}">${statusText}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Country</span>
            <span class="info-value">${getFlagEmoji(server.country_code)} ${server.country_name}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Location</span>
            <span class="info-value">${server.location || '-'}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Score</span>
            <span class="info-value accent">${(server.score || 0).toFixed(1)}</span>
        </div>
    `;

    // Populate Performance section
    const entry1Ping = server.entry1_ping?.latency_ms;
    const entry3Ping = server.entry3_ping?.latency_ms;
    const exitPing = server.exit_ping?.latency_ms;
    const load = server.load_percent;

    document.getElementById('modalPerformance').innerHTML = `
        <div class="info-item">
            <span class="info-label">Entry 1 Ping</span>
            <span class="info-value ${entry1Ping ? getPingClass(entry1Ping) : ''}">${entry1Ping ? Math.round(entry1Ping) + ' ms' : '-'}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Entry 3 Ping</span>
            <span class="info-value ${entry3Ping ? getPingClass(entry3Ping) : ''}">${entry3Ping ? Math.round(entry3Ping) + ' ms' : '-'}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Exit Ping</span>
            <span class="info-value ${exitPing ? getPingClass(exitPing) : ''}">${exitPing ? Math.round(exitPing) + ' ms' : '-'}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Server Load</span>
            <span class="info-value ${getLoadClass(load)}">${load}%</span>
        </div>
        <div class="info-item">
            <span class="info-label">IPs Scanned</span>
            <span class="info-value">${server.responsive_count || 0} / ${server.total_ips || 0}</span>
        </div>
    `;

    // Populate Speedtest section
    const st = server.speedtest;
    const hasSpeedtest = st && !st.error && (st.download_mbps > 0 || st.upload_mbps > 0);

    if (hasSpeedtest) {
        const devScore = st.deviation_score;
        const devClass = devScore !== undefined && devScore !== null
            ? (devScore >= 100 ? 'success' : devScore >= 50 ? 'warning' : 'danger')
            : '';

        document.getElementById('modalSpeedtest').innerHTML = `
            ${st.vpn_port ? `
            <div class="info-item">
                <span class="info-label">Port</span>
                <span class="info-value">${st.vpn_port}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Entry</span>
                <span class="info-value">${st.vpn_entry || '-'}</span>
            </div>
            ` : ''}
            <div class="info-item">
                <span class="info-label">Download</span>
                <span class="info-value accent">↓ ${st.download_mbps.toFixed(1)} Mbps</span>
            </div>
            <div class="info-item">
                <span class="info-label">Upload</span>
                <span class="info-value accent">↑ ${st.upload_mbps.toFixed(1)} Mbps</span>
            </div>
            <div class="info-item">
                <span class="info-label">Ping</span>
                <span class="info-value ${st.ping_ms ? getPingClass(st.ping_ms) : ''}">${st.ping_ms ? Math.round(st.ping_ms) + ' ms' : '-'}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Deviation</span>
                <span class="info-value ${devClass}">${devScore !== undefined && devScore !== null ? devScore.toFixed(1) + '%' : '-'}</span>
            </div>
        `;
    } else if (st && st.error) {
        document.getElementById('modalSpeedtest').innerHTML = `
            <div class="info-item" style="grid-column: span 2;">
                <span class="info-label">Error</span>
                <span class="info-value danger">${st.error}</span>
            </div>
        `;
    } else {
        document.getElementById('modalSpeedtest').innerHTML = `
            <div class="info-item" style="grid-column: span 2;">
                <span class="info-value" style="color: var(--text-secondary);">No speedtest results available</span>
            </div>
        `;
    }

    // Populate IP Addresses section
    const ips = server.exit_ips || [];
    if (ips.length > 0) {
        document.getElementById('modalIPs').innerHTML = ips.map(ip => {
            const isResponsive = ip.is_responsive;
            const isBlocked = ip.blocked_count > 0;
            const itemClass = isBlocked ? 'blocked' : (isResponsive ? 'responsive' : '');

            return `
                <div class="ip-item ${itemClass}">
                    <span class="ip-address">${ip.ip}</span>
                    <div class="ip-status">
                        ${ip.latency_ms ? `<span class="ping">${Math.round(ip.latency_ms)} ms</span>` : ''}
                        ${isBlocked ? `<span class="blocked">Blocked</span>` : ''}
                        ${!isResponsive && !isBlocked ? `<span>Unresponsive</span>` : ''}
                    </div>
                </div>
            `;
        }).join('');
    } else {
        document.getElementById('modalIPs').innerHTML = `
            <div style="color: var(--text-secondary); padding: 10px;">No IP addresses available</div>
        `;
    }

    // Update speedtest button state
    const speedtestBtn = document.getElementById('modalSpeedtestBtn');
    if (server.is_clean) {
        speedtestBtn.style.display = 'inline-block';
        speedtestBtn.disabled = false;
    } else {
        speedtestBtn.style.display = 'none';
    }

    // Show modal
    document.getElementById('serverModal').style.display = 'flex';
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    document.getElementById('serverModal').style.display = 'none';
    document.body.style.overflow = '';
    currentModalServer = null;
}

async function runServerSpeedtest() {
    if (!currentModalServer) return;

    const btn = document.getElementById('modalSpeedtestBtn');
    btn.disabled = true;
    btn.textContent = 'Running...';

    try {
        const response = await fetch(`/api/speedtest/${encodeURIComponent(currentModalServer.server_name)}`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.error) {
            alert('Error: ' + data.error);
        } else {
            btn.textContent = 'Queued!';
            setTimeout(() => {
                btn.textContent = 'Run Speedtest';
                btn.disabled = false;
            }, 2000);
        }
    } catch (e) {
        alert('Failed to queue speedtest: ' + e.message);
        btn.textContent = 'Run Speedtest';
        btn.disabled = false;
    }
}

// Close modal with Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.getElementById('serverModal').style.display === 'flex') {
        closeModal();
    }
});

function getFlagEmoji(countryCode) {
    const codePoints = countryCode.toUpperCase().split('').map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}

function getPingClass(ping) {
    if (!ping) return '';
    if (ping < 50) return 'good';
    if (ping < 150) return 'medium';
    return 'bad';
}

function getLoadClass(load) {
    if (load < 50) return 'good';
    if (load < 80) return 'medium';
    return 'bad';
}

async function startScan() {
    try {
        const response = await fetch('/api/scan/start', { method: 'POST' });
        const data = await response.json();
        if (data.error) alert(data.error);
    } catch (e) {
        alert('Failed to start scan: ' + e.message);
    }
}

async function stopScan() {
    if (!confirm('Are you sure you want to stop the current scan?')) {
        return;
    }
    try {
        const response = await fetch('/api/scan/stop', { method: 'POST' });
        const data = await response.json();
        if (data.error) alert(data.error);
    } catch (e) {
        alert('Failed to stop scan: ' + e.message);
    }
}

async function pauseScan() {
    try {
        const response = await fetch('/api/scan/pause', { method: 'POST' });
        const data = await response.json();
        if (data.error) alert(data.error);
    } catch (e) {
        alert('Failed to pause/resume scan: ' + e.message);
    }
}

async function restartScan() {
    if (!confirm('Are you sure you want to restart the scan? This will stop the current scan and start a new one.')) {
        return;
    }
    try {
        const response = await fetch('/api/scan/restart', { method: 'POST' });
        const data = await response.json();
        if (data.error) alert(data.error);
    } catch (e) {
        alert('Failed to restart scan: ' + e.message);
    }
}

function updateCountdown() {
    const el = document.getElementById('nextScan');
    if (!nextScanTime) { el.textContent = '--:--'; return; }

    const now = new Date();
    const diff = nextScanTime - now;

    if (diff <= 0) { el.textContent = 'Now'; return; }

    const mins = Math.floor(diff / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    el.textContent = `${mins}:${secs.toString().padStart(2, '0')}`;
}

document.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
    setInterval(updateCountdown, 1000);
    loadBaseline();

    // Load results and status on page load
    Promise.all([
        fetch('/api/status').then(r => r.json()),
        fetch('/api/results').then(r => r.json())
    ]).then(([status, results]) => {
        updateStatus(status);
        if (status.progress) updateProgress(status.progress);

        // Restore progress bar visibility on refresh if a scan/speedtest is active
        if (status.is_scanning && status.progress && status.progress.phase !== 'idle') {
            document.getElementById('progressContainer').style.display = 'block';
        }

        // Load scoring thresholds from API
        if (status.scoring) {
            scoringThresholds = status.scoring;
        }
        // Load next scan time
        if (status.next_scan_at) {
            nextScanTime = new Date(status.next_scan_at);
        }

        if (results.summary) {
            allResults = results.summary;
            updateSummary(allResults);
            populateCountryFilter(allResults);
            applyFilters();
        }
    });
});

function getSignalBarsHtml(server) {
    let quality = 'offline';

    // Determine quality based on responsiveness and score
    if (server.responsive_count === 0) {
        quality = 'offline';
    } else {
        const score = server.score || 0;
        const goodThreshold = scoringThresholds.signal_good_threshold || 80;
        const mediumThreshold = scoringThresholds.signal_medium_threshold || 50;
        if (score >= goodThreshold) quality = 'good';
        else if (score >= mediumThreshold) quality = 'medium';
        else quality = 'bad';
    }

    return `
    <div class="signal-bars signal-${quality}" title="Quality: ${quality}">
        <div class="signal-bar"></div>
        <div class="signal-bar"></div>
        <div class="signal-bar"></div>
    </div>`;
}
