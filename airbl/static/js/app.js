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

// True only for elements actually on this page (getElementById returns stubs for dashboard ids)
function hasEl(id) { return !!originalGetElementById(id); }

// One shared /api/status request per page load (app.js + base.html)
let _statusPromise = null;
function getStatusOnce() {
    if (!_statusPromise) {
        _statusPromise = fetch('/api/status').then(r => r.json());
        _statusPromise.catch(() => { _statusPromise = null; });
    }
    return _statusPromise;
}

// Idle status text unless a scan is running (stop button visible)
function resetScanStatusText() {
    const stopBtn = document.getElementById('stopBtn');
    if (stopBtn.style.display === 'inline-block') return;
    const el = document.getElementById('scanStatus');
    el.textContent = 'Idle';
    el.classList.remove('scanning');
}

// Page hooks (index.html) for refreshing after scans/speedtests
function firePageRefresh(hook, data) {
    if (typeof window[hook] === 'function') window[hook](data);
}

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
        case 'scan_started':
            updateStatus({ is_scanning: true, is_paused: false });
            if (msg.data && msg.data.next_scan_at) {
                nextScanTime = new Date(msg.data.next_scan_at);
            }
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
            {
                const summary = msg.data && msg.data.summary;
                if (summary && (summary.total_servers !== undefined ||
                    (summary.servers_by_country && Object.keys(summary.servers_by_country).length > 0))) {
                    allResults = summary;
                    updateSummary(summary);
                    populateCountryFilter(summary);
                    // Apply filters to respect current filter settings
                    applyFilters();
                }
                if (msg.data && msg.data.next_scan_at) {
                    nextScanTime = new Date(msg.data.next_scan_at);
                }
            }
            // Fire page-level callback for reactive refresh
            firePageRefresh('onScanComplete', msg.data);
            break;
        case 'scan_error':
            updateStatus({ is_scanning: false, is_paused: false });
            document.getElementById('scanStatus').textContent = 'Error';
            document.getElementById('progressContainer').style.display = 'none';
            showToast('Scan error: ' + ((msg.data && msg.data.error) || 'unknown error'), 'error');
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
                // The scan task's final reset arrives here, not via speedtest_all_complete
                // (speedtest_all_complete never arrives with speedtests off / no clean servers)
                if (msg.data.progress.phase === 'idle') {
                    document.getElementById('progressContainer').style.display = 'none';
                    updateStatus({ is_scanning: false, is_paused: false });
                }
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
            firePageRefresh('onSpeedtestsComplete', msg.data);
            break;
        case 'discovery_combo_complete':
        case 'discovery_scan_complete':
        case 'discovery_finalized':
            // Settings page re-renders discovery status/results (if open and no unsaved edits)
            if (typeof window.onDiscoveryUpdate === 'function') window.onDiscoveryUpdate(msg.type);
            if (msg.type === 'discovery_finalized' && msg.data) {
                const outcome = msg.data.outcome || '';
                showToast(outcome.startsWith('inconclusive') ? `Discovery finished: ${outcome}` : `Discovery finished: best port/entry ${outcome.replace('/', ' / ')}`,
                    outcome.startsWith('inconclusive') ? 'info' : 'success');
            }
            break;
        case 'network_job_waiting':
            showToast(`⏳ ${msg.data.job} is waiting for ${msg.data.owner || 'another job'} to finish using the VPN`, 'info');
            break;
        case 'speedtest_manual_done': {
            const d = msg.data || {};
            if (d.ok) {
                const fmt = (v, unit) => (v != null ? v.toFixed(1) + ' ' + unit : '-');
                showToast(`✅ Speedtest ${d.server}: ↓ ${fmt(d.download_mbps, 'Mbps')} | ↑ ${fmt(d.upload_mbps, 'Mbps')} | ${fmt(d.ping_ms, 'ms')}`, 'success');
            } else {
                showToast(`❌ Speedtest ${d.server} failed: ${d.error || 'unknown error'}`, 'error');
            }
            resetScanStatusText();
            firePageRefresh('onSpeedtestsComplete', d);
            break;
        }
        case 'server_disabled': {
            const d = msg.data || {};
            showToast(`🚫 ${d.server || d.server_name || 'Server'} was disabled${d.reason ? ': ' + d.reason : ''}`, 'info');
            break;
        }
        case 'settings_changed':
            // Refresh thresholds/next scan time; pages with forms handle their own reloads
            fetch('/api/status').then(r => r.json()).then(st => {
                if (st.scoring) scoringThresholds = st.scoring;
                if (st.next_scan_at) nextScanTime = new Date(st.next_scan_at);
            }).catch(() => {});
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
            updateStatus({ is_scanning: false, is_paused: false });
            if (hasEl('scanStatus')) document.getElementById('scanStatus').textContent = 'Cancelled';
            if (hasEl('progressContainer')) document.getElementById('progressContainer').style.display = 'none';
            // The live view held a partial scan; the backend kept the previous complete results
            if (hasEl('resultsContainer')) {
                fetch('/api/results').then(r => r.json()).then(results => {
                    if (results && results.servers_by_country) {
                        allResults = results;
                        updateSummary(allResults);
                        populateCountryFilter(allResults);
                        applyFilters();
                    }
                }).catch(() => {});
            }
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
    // Unverified servers are neither clean nor blocked; show them on the blocked card's tooltip
    document.getElementById('summaryBlocked').title = data.unknown_servers_count
        ? `${data.unknown_servers_count} more server(s) unverified (DroneBL lookup failed or no exit IPs)` : '';
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
        const data = await getStatusOnce();
        if (data.baseline_speedtest) {
            updateBaselineDisplay(data.baseline_speedtest);
        }
    } catch (e) {
        console.error('Failed to load baseline:', e);
    }
}

function populateCountryFilter(data) {
    if (!hasEl('filterCountry')) return;
    const select = document.getElementById('filterCountry');
    const currentValue = select.value;
    let found = false;
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
                if (code === currentValue) found = true;
            }
        }
    }

    // Keep the chosen country selected while a scan rebuilds the list
    if (currentValue && !found) {
        const opt = document.createElement('option');
        opt.value = currentValue;
        opt.textContent = `${getFlagEmoji(currentValue)} ${currentValue} (0)`;
        select.appendChild(opt);
    }
    select.value = currentValue;
}

let applyFiltersTimer = null;
let applyFiltersSeq = 0;

// Debounced; scan events call this often
function applyFilters() {
    if (!allResults || !hasEl('resultsContainer')) return;
    clearTimeout(applyFiltersTimer);
    applyFiltersTimer = setTimeout(_applyFiltersNow, 200);
}

function _applyFiltersNow() {
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

    const seq = ++applyFiltersSeq;
    fetch('/api/servers?' + params.toString())
        .then(r => r.json())
        .then(data => {
            if (seq !== applyFiltersSeq) return;  // a newer request is in flight
            renderFilteredResults(data.countries || []);
        })
        .catch(e => console.error('Failed to load servers:', e));
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
    const blockedCount = servers.filter(s => !s.is_clean && s.reputation === 'blocked').length;
    const unknownCount = servers.filter(s => !s.is_clean && s.reputation === 'unknown').length;

    let html = `
        <div class="country-card">
            <div class="country-header">
                <span class="country-name">${getFlagEmoji(countryCode)} ${escapeHtml(countryName)}</span>
                <div class="country-stats">
                    <span class="stat ok">✓ ${cleanCount}</span>
                    <span class="stat blocked">✗ ${blockedCount}</span>
                    ${unknownCount ? `<span class="stat unknown" title="Unverified">? ${unknownCount}</span>` : ''}
                </div>
            </div>
            <div class="server-list">
    `;

    for (const server of servers) {
        const statusClass = server.is_clean ? 'clean' : (server.reputation === 'unknown' ? 'unknown' : 'blocked');
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
            <div class="server-item ${statusClass}" data-server-name="${escapeHtml(server.server_name)}" onclick="showServerDetails(this.dataset.serverName)">
                <div class="server-info">
                    <div class="server-name">
                        ${getSignalBarsHtml(server)}
                        ${escapeHtml(server.server_name)}
                    </div>
                    <div class="server-location">${escapeHtml(server.location ?? '')}</div>
                </div>
                <div class="server-metrics">
                    <!-- Row 1: Entry1 ping, Exit ping, upload, deviation, load -->
                    <div class="metrics-row" style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px;">
                        <div class="metric" title="${pingTitle(server.entry1_ping)}">
                            <span class="metric-value ${e1Ping ? getPingClass(e1Ping) : ''}">${e1Ping ? Math.round(e1Ping) + 'ms' : '-'}</span>
                            <span class="metric-label">Entry 1</span>
                        </div>
                        <div class="metric" title="${pingTitle(server.exit_ping)}">
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
                            <span class="metric-value ${loadClass}">${escapeHtml(server.load_percent ?? '-')}%</span>
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
    const isUnknown = server.reputation === 'unknown';
    const statusText = server.is_clean ? '✓ Clean' : (isUnknown ? '? Unverified' : '✗ Blocked');
    const statusClass = server.is_clean ? 'success' : (isUnknown ? 'warning' : 'danger');

    document.getElementById('modalServerInfo').innerHTML = `
        <div class="info-item">
            <span class="info-label">Status</span>
            <span class="info-value ${statusClass}" title="${escapeHtml(server.reputation_note || '')}">${statusText}</span>
        </div>
        ${isUnknown ? `<div class="info-item" style="grid-column: span 2;">
            <span class="info-label">Why unverified</span>
            <span class="info-value warning">${escapeHtml(server.reputation_note || 'No verified DroneBL result')}. Not used for clean-only exports until a scan verifies it.</span>
        </div>` : ''}
        <div class="info-item">
            <span class="info-label">Country</span>
            <span class="info-value">${getFlagEmoji(server.country_code)} ${escapeHtml(server.country_name ?? '')}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Location</span>
            <span class="info-value">${escapeHtml(server.location || '-')}</span>
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
        <div class="info-item" title="${pingTitle(server.entry1_ping)}">
            <span class="info-label">Entry 1 Ping</span>
            <span class="info-value ${entry1Ping ? getPingClass(entry1Ping) : ''}">${entry1Ping ? Math.round(entry1Ping) + ' ms' : '-'}</span>
        </div>
        <div class="info-item" title="${pingTitle(server.entry3_ping)}">
            <span class="info-label">Entry 3 Ping</span>
            <span class="info-value ${entry3Ping ? getPingClass(entry3Ping) : ''}">${entry3Ping ? Math.round(entry3Ping) + ' ms' : '-'}</span>
        </div>
        <div class="info-item" title="${pingTitle(server.exit_ping)}">
            <span class="info-label">Exit Ping</span>
            <span class="info-value ${exitPing ? getPingClass(exitPing) : ''}">${exitPing ? Math.round(exitPing) + ' ms' : '-'}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Server Load</span>
            <span class="info-value ${getLoadClass(load)}">${load}%</span>
        </div>
        <div class="info-item">
            <span class="info-label">IPs Scanned</span>
            <span class="info-value">${server.responsive_count || 0} / ${server.total_ips_scanned || 0}</span>
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
                <span class="info-value">${escapeHtml(st.vpn_port)}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Entry</span>
                <span class="info-value">${escapeHtml(st.vpn_entry || '-')}</span>
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
                <span class="info-value danger">${escapeHtml(st.error)}</span>
            </div>
        `;
    } else {
        document.getElementById('modalSpeedtest').innerHTML = `
            <div class="info-item" style="grid-column: span 2;">
                <span class="info-value" style="color: var(--text-secondary);">No speedtest results available</span>
            </div>
        `;
    }

    // Populate Block Notes (DroneBL listings from the last scan)
    const blockedIps = (server.exit_ips || []).filter(ip => ip.is_blocked);
    document.getElementById('modalBlockNotesSection').style.display = blockedIps.length ? '' : 'none';
    document.getElementById('modalBlockNotes').innerHTML = blockedIps.map(ip => {
        const checked = ip.dronebl_checked_at ? new Date(ip.dronebl_checked_at).toLocaleString() : 'unknown';
        const code = ip.dronebl_code != null ? ` (code ${ip.dronebl_code})` : '';
        return `
            <div class="ip-item blocked" style="flex-direction: column; align-items: flex-start; gap: 4px;">
                <div style="display: flex; justify-content: space-between; width: 100%;">
                    <span class="ip-address">${escapeHtml(ip.ip)}</span>
                    <a href="https://dronebl.org/lookup?ip=${encodeURIComponent(ip.ip)}" target="_blank" rel="noopener noreferrer"
                        style="color: var(--accent); font-size: 0.85rem;">DroneBL lookup ↗</a>
                </div>
                <span style="color: var(--danger);">${escapeHtml(ip.dronebl_reason || 'Listed')}${code}</span>
                <span style="color: var(--text-secondary); font-size: 0.8rem;">Checked ${escapeHtml(checked)}</span>
            </div>
        `;
    }).join('');

    // Populate IP Addresses section
    const ips = server.exit_ips || [];
    if (ips.length > 0) {
        document.getElementById('modalIPs').innerHTML = ips.map(ip => {
            const isResponsive = ip.is_responsive;
            const isBlocked = ip.is_blocked;
            const itemClass = isBlocked ? 'blocked' : (isResponsive ? 'responsive' : '');

            return `
                <div class="ip-item ${itemClass}">
                    <span class="ip-address">${escapeHtml(ip.ip)}</span>
                    <div class="ip-status">
                        ${ip.latency_ms ? `<span class="ping" title="${pingTitle(ip)}">${Math.round(ip.latency_ms)} ms</span>` : ''}
                        ${isBlocked ? `<span class="blocked" title="${escapeHtml(ip.dronebl_reason || '')}">Blocked</span>` : ''}
                        ${!isBlocked && ip.reputation_verified === false ? `<span style="color: var(--warning);" title="${escapeHtml(ip.dronebl_error || '')}">Unverified</span>` : ''}
                        ${!isResponsive && !isBlocked ? `<span>No ping reply</span>` : ''}
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
            showToast('❌ ' + data.error, 'error');
            btn.textContent = 'Run Speedtest';
            btn.disabled = false;
        } else {
            showToast(`⏳ Speedtest queued for ${currentModalServer.server_name}. This takes a few minutes; you'll get a message when it finishes.`, 'info');
            btn.textContent = 'Queued!';
            setTimeout(() => {
                btn.textContent = 'Run Speedtest';
                btn.disabled = false;
            }, 2000);
        }
    } catch (e) {
        showToast('❌ Failed to queue speedtest: ' + e.message, 'error');
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

// Small transient notification (bottom right); created on first use
function showToast(message, kind = 'info') {
    let box = document.getElementById('appToastBox');
    if (!box) {
        box = document.createElement('div');
        box.id = 'appToastBox';
        box.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:10000;display:flex;flex-direction:column;gap:8px;max-width:420px;';
        document.body.appendChild(box);
    }
    const colors = { success: 'var(--success)', error: 'var(--danger)', info: 'var(--accent)' };
    const el = document.createElement('div');
    el.textContent = message;
    el.style.cssText = `background:var(--bg-secondary, #1e1e2e);color:var(--text-primary, #fff);border-left:4px solid ${colors[kind] || colors.info};padding:10px 14px;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,.3);font-size:.9rem;`;
    box.appendChild(el);
    setTimeout(() => el.remove(), kind === 'error' ? 12000 : 8000);
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Tooltip showing both probes; the displayed value is the lower of the two.
function pingTitle(p) {
    if (!p) return '';
    const fmt = v => (v != null ? Math.round(v) + ' ms' : 'no reply');
    return `ICMP: ${fmt(p.icmp_ms)} | TCP: ${fmt(p.tcp_ms)} (showing lowest)`;
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
    // Dashboard work only on Overview/Servers
    const isDashboard = hasEl('resultsContainer') || hasEl('scanStatus');
    if (!isDashboard) return;
    setInterval(updateCountdown, 1000);
    loadBaseline();

    // Load results and status on page load
    Promise.all([
        getStatusOnce(),
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

        // /api/results returns the summary itself ({error} when no scan yet)
        const loaded = results && results.servers_by_country ? results : status.summary;
        if (loaded) {
            allResults = loaded;
            updateSummary(allResults);
            populateCountryFilter(allResults);
            applyFilters();
        }
    }).catch(e => console.error('Failed to load status/results:', e));
});

// Chart.js comes from a CDN; when it fails to load, show a note instead of the charts
function chartsUnavailable() {
    if (typeof Chart !== 'undefined') return false;
    document.querySelectorAll('.chart-container').forEach(c => {
        if (c.querySelector('.charts-offline-note')) return;
        const note = document.createElement('p');
        note.className = 'setting-description charts-offline-note';
        note.style.cssText = 'text-align:center;padding:40px 0;';
        note.textContent = 'Charts unavailable (Chart.js could not be loaded, offline?)';
        c.appendChild(note);
    });
    return true;
}

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
