/**
 * RupeeShield - Advanced Model Layer
 */

function formatMoney(lakhs) {
    if (lakhs >= 100) return `₹${(lakhs / 100).toFixed(2)} Cr`;
    return `₹${lakhs.toFixed(0)} L`;
}

// --- 1. DATA MODEL ---
const MODEL = {
    BASE: 410,
    LO: 320,
    HI: 510,
    DELAY_PENALTY_RATE: 0.04, // 0.04 Cr (4L) per day penalty
    
    SVC: [
        { id: 'core', name: 'Core Banking', base: 150 },
        { id: 'upi', name: 'UPI & Payments', base: 110 },
        { id: 'net', name: 'Net Banking', base: 70 },
        { id: 'cloud', name: 'Cloud Data Platform', base: 50 },
        { id: 'corp', name: 'Corporate IT', base: 30 }
    ],

    SCN: [
        { id: 'ran', name: 'Ransomware', base: 172 },
        { id: 'brc', name: 'Data breach', base: 115 },
        { id: 'bec', name: 'BEC', base: 70 },
        { id: '3rd', name: 'Third-party disruption', base: 53 }
    ],

    A: [
        { id: 'c1', name: 'MFA & SSO (Enterprise)', service: 'Corporate IT', c: 15, f: 0.15, asset: 'Endpoints', ref: 'NIST CSF PR.AC-1' },
        { id: 'c2', name: 'EDR / XDR Deployment', service: 'Core Banking', c: 25, f: 0.20, asset: 'Servers', ref: 'CIS Control 8' },
        { id: 'c3', name: 'Cloud CSPM', service: 'Cloud Data Platform', c: 10, f: 0.12, asset: 'Cloud Env', ref: 'ISO 27001 A.13' },
        { id: 'c4', name: 'Zero Trust Network Architecture', service: 'Net Banking', c: 40, f: 0.25, asset: 'Network', ref: 'NIST SP 800-207' },
        { id: 'c5', name: 'WAF & DDoS Protection', service: 'UPI & Payments', c: 12, f: 0.10, asset: 'API Gateway', ref: 'PCI DSS 6.6' },
        { id: 'c6', name: 'Privileged Access Management', service: 'Core Banking', c: 18, f: 0.18, asset: 'DB', ref: 'RBI Cyber Sec' },
        { id: 'c7', name: 'Data Loss Prevention (DLP)', service: 'Cloud Data Platform', c: 22, f: 0.15, asset: 'Data Lake', ref: 'SEBI CSCRF' },
        { id: 'c8', name: 'Next-Gen SIEM Upgrade', service: 'All', c: 30, f: 0.22, asset: 'SOC', ref: 'CIS Control 17' },
        { id: 'c9', name: 'Third-party Risk Mgmt', service: 'Corporate IT', c: 8, f: 0.08, asset: 'Vendors', ref: 'RBI Cyber Sec' },
        { id: 'c10', name: 'Immutable Backups', service: 'Core Banking', c: 15, f: 0.12, asset: 'Storage', ref: 'NIST CSF PR.IP-4' }
    ],

    DRIVERS: [
        { id: 'd1', finding: 'CVE-2023-44487', label: 'Payment API Exploit', asset: 'API Gateway', service: 'UPI & Payments', scenario: 'Data breach', likelihood: 0.22, magnitude: 390, c: 'c5' },
        { id: 'd2', finding: 'Missing MFA', label: 'Vendor Ransomware', asset: 'Third-party', service: 'Corporate IT', scenario: 'Third-party disruption', likelihood: 0.15, magnitude: 386, c: 'c9' },
        { id: 'd3', finding: 'Open S3 Bucket', label: 'Cloud Misconfiguration', asset: 'Cloud Env', service: 'Cloud Data Platform', scenario: 'Data breach', likelihood: 0.12, magnitude: 350, c: 'c3' },
        { id: 'd4', finding: 'Phishing Campaign', label: 'Endpoint BEC', asset: 'Endpoints', service: 'Corporate IT', scenario: 'BEC', likelihood: 0.18, magnitude: 172, c: 'c1' }
    ],

    COMPLIANCE: [
        { fw: 'ISO/IEC 27001', req: 'A.9 Access Control', status: 'Fail', weakness: 'Missing MFA on privileged accounts', asset: 'DB', exposure: 85 },
        { fw: 'NIST CSF', req: 'PR.IP-4 Backups', status: 'Partial', weakness: 'Backups not immutable', asset: 'Storage', exposure: 120 },
        { fw: 'RBI Cyber Sec', req: 'Baseline Controls', status: 'Fail', weakness: 'Lack of PAM for core systems', asset: 'Core Banking', exposure: 150 },
        { fw: 'SEBI CSCRF', req: 'Data Security', status: 'Partial', weakness: 'DLP incomplete in cloud', asset: 'Data Lake', exposure: 60 }
    ]
};

// --- 2. CORE FUNCTIONS ---

function getSelectedControls(selectionIds) {
    return MODEL.A.filter(c => selectionIds.has(c.id));
}

function residual(selectionIds, delayDays = 0) {
    const controls = getSelectedControls(selectionIds);
    const multiplier = controls.reduce((acc, c) => acc * (1 - c.f), 1);
    const delayCostLakhs = delayDays * (MODEL.DELAY_PENALTY_RATE * 100);
    return (MODEL.BASE * multiplier) + delayCostLakhs;
}

function avoided(selectionIds) {
    // Avoided loss is BASE - residual (excluding delay penalty for pure ROI calc on controls)
    const currentResidual = residual(selectionIds, 0); 
    return MODEL.BASE - currentResidual;
}

function cost(selectionIds) {
    const controls = getSelectedControls(selectionIds);
    return controls.reduce((acc, c) => acc + c.c, 0);
}

// Exhaustive search (2^10 = 1024) to find best controls under budget
function best(budget) {
    let bestSet = new Set();
    let maxAvoided = -1;
    
    const n = MODEL.A.length;
    for (let i = 0; i < (1 << n); i++) {
        let currentSet = new Set();
        for (let j = 0; j < n; j++) {
            if (i & (1 << j)) {
                currentSet.add(MODEL.A[j].id);
            }
        }
        
        let c = cost(currentSet);
        if (c <= budget) {
            let a = avoided(currentSet);
            if (a > maxAvoided) {
                maxAvoided = a;
                bestSet = currentSet;
            }
        }
    }
    return bestSet;
}

// --- 3. STATE ---
let activeTab = 'view-dashboard';
let currentBudget = 50;
let currentDelay = 0;
let optimizedSelection = new Set();

// --- 4. UI RENDERING ---

function renderNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            // Update active nav class
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            e.currentTarget.classList.add('active');
            
            // Switch view
            activeTab = e.currentTarget.getAttribute('data-target');
            document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
            document.getElementById(activeTab).classList.add('active');

            if (activeTab === 'view-optimization') renderOptimizationCurve();
        });
    });
}

function renderDrivers() {
    const container = document.getElementById('drivers-container');
    container.innerHTML = '';
    
    const drivers = MODEL.DRIVERS.map(d => ({
        ...d,
        exposure: d.likelihood * d.magnitude
    })).sort((a, b) => b.exposure - a.exposure);

    drivers.forEach((driver, idx) => {
        let riskClass = idx === 0 ? 'critical' : (idx === 1 ? 'high' : 'medium');
        const el = document.createElement('div');
        el.className = `driver-item ${riskClass}`;
        el.innerHTML = `
            <div>
                <div class="driver-name">${driver.label}</div>
                <div class="driver-asset">${driver.service} &bull; ${driver.asset}</div>
            </div>
            <div class="driver-value">${formatMoney(driver.exposure)}</div>
        `;
        container.appendChild(el);
    });
}

function renderScenarioChart(currentResidual) {
    const container = document.getElementById('scenario-chart');
    container.innerHTML = '';
    
    MODEL.SCN.forEach(scn => {
        const prop = scn.base / MODEL.BASE;
        const value = currentResidual * prop;
        const heightPct = Math.min(100, Math.max(5, (value / 180) * 100));

        const wrapper = document.createElement('div');
        wrapper.className = 'bar-wrapper';
        wrapper.innerHTML = `
            <div class="bar-value">${formatMoney(value)}</div>
            <div class="bar" style="height: ${heightPct}%"></div>
            <div class="bar-label">${scn.name.split(' ')[0]}</div>
        `;
        container.appendChild(wrapper);
    });
}

function renderTechnicalTable() {
    const tbody = document.getElementById('technical-table-body');
    tbody.innerHTML = '';
    
    MODEL.DRIVERS.forEach(d => {
        const exposure = d.likelihood * d.magnitude;
        const control = MODEL.A.find(c => c.id === d.c);
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${d.finding}</code></td>
            <td>${d.asset} / ${d.service}</td>
            <td>${d.scenario}</td>
            <td>${(d.likelihood*100).toFixed(0)}%</td>
            <td>${formatMoney(d.magnitude)}</td>
            <td class="status-red">${formatMoney(exposure)}</td>
            <td>${control ? control.name : '--'}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderComplianceTable() {
    const tbody = document.getElementById('compliance-table-body');
    tbody.innerHTML = '';
    
    MODEL.COMPLIANCE.forEach(c => {
        const statusClass = c.status === 'Fail' ? 'status-red' : 'status-green';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${c.fw}</strong></td>
            <td>${c.req}</td>
            <td class="${statusClass}">${c.status}</td>
            <td>${c.weakness}</td>
            <td>${c.asset}</td>
            <td class="status-red">${formatMoney(c.exposure)}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderControlsList() {
    const container = document.getElementById('controls-container');
    container.innerHTML = '';

    // Sort so selected controls show at the top
    const sorted = [...MODEL.A].sort((a,b) => {
        const aSel = optimizedSelection.has(a.id);
        const bSel = optimizedSelection.has(b.id);
        return aSel === bSel ? 0 : aSel ? -1 : 1;
    });

    sorted.forEach(control => {
        const isSelected = optimizedSelection.has(control.id);
        const el = document.createElement('div');
        el.className = `control-item ${isSelected ? 'selected' : ''}`;
        
        el.innerHTML = `
            <div class="control-info">
                <div class="control-name">${control.name}</div>
                <div class="control-meta">
                    <span>Cost: ${formatMoney(control.c)}</span>
                    <span>Risk Reduction: ${(control.f * 100).toFixed(0)}%</span>
                </div>
            </div>
            <label class="toggle-switch">
                <input type="checkbox" disabled ${isSelected ? 'checked' : ''}>
                <span class="slider"></span>
            </label>
        `;
        container.appendChild(el);
    });
}

function renderOptimizationCurve() {
    const container = document.getElementById('roi-curve');
    if (!container) return;

    // Generate points
    const points = [];
    for(let b = 0; b <= 150; b += 10) {
        let bestSet = best(b);
        let a = avoided(bestSet);
        points.push({x: b, y: a});
    }

    // Map to SVG coordinates
    const w = container.clientWidth || 400;
    const h = container.clientHeight || 250;
    const padding = 20;
    
    const maxX = 150;
    const maxY = Math.max(...points.map(p=>p.y));

    const mapX = val => padding + (val / maxX) * (w - padding * 2);
    const mapY = val => h - padding - (val / maxY) * (h - padding * 2);

    let pathData = `M ${mapX(points[0].x)} ${mapY(points[0].y)}`;
    points.forEach((p, i) => {
        if(i > 0) pathData += ` L ${mapX(p.x)} ${mapY(p.y)}`;
    });

    // Current point
    const curA = avoided(optimizedSelection);
    const curC = cost(optimizedSelection);
    const curX = mapX(curC);
    const curY = mapY(curA);

    container.innerHTML = `
        <svg class="roi-svg" viewBox="0 0 ${w} ${h}">
            <line x1="${padding}" y1="${h-padding}" x2="${w-padding}" y2="${h-padding}" class="roi-axes"/>
            <line x1="${padding}" y1="${padding}" x2="${padding}" y2="${h-padding}" class="roi-axes"/>
            <path d="${pathData}" class="roi-line"/>
            <circle cx="${curX}" cy="${curY}" r="6" class="roi-point"/>
            <text x="${curX}" y="${curY - 15}" fill="white" font-size="12" text-anchor="middle">Current</text>
        </svg>
    `;
}

function updateDashboard() {
    // 1. Calculate Core Numbers based on Delay & Budget
    optimizedSelection = best(currentBudget);
    
    const currentCost = cost(optimizedSelection);
    const currentAvoided = avoided(optimizedSelection);
    const currentResidual = residual(optimizedSelection, currentDelay);
    
    const var95 = currentResidual * 2.5; // Simple VaR multiple assumption
    
    // 2. Update Executive Dashboard
    document.getElementById('total-exposure').innerText = formatMoney(currentResidual);
    document.getElementById('var-exposure').innerText = formatMoney(var95);
    
    // Adjust risk score
    const score = Math.max(10, 100 - (currentResidual / MODEL.BASE * 40) - (currentDelay * 0.5));
    document.getElementById('header-risk-score').innerText = `${score.toFixed(0)}/100`;

    const ratio = currentResidual / MODEL.BASE;
    const currentLo = MODEL.LO * ratio;
    const currentHi = MODEL.HI * ratio;
    
    const bar = document.getElementById('eal-range-fill');
    // Visual bar shift
    bar.style.left = `${Math.max(0, 20 * ratio)}%`;
    bar.style.right = `${Math.max(0, 100 - (80 * ratio))}%`;

    // 3. Update Optimizer View
    document.getElementById('opt-cost').innerText = formatMoney(currentCost);
    document.getElementById('opt-avoided').innerText = formatMoney(currentAvoided);
    
    const rosiEl = document.getElementById('opt-rosi');
    if (currentCost > 0) {
        const rosi = ((currentAvoided - currentCost) / currentCost) * 100;
        rosiEl.innerText = `${rosi.toFixed(0)}%`;
    } else {
        rosiEl.innerText = '--';
    }

    renderControlsList();
    if (activeTab === 'view-optimization') {
        renderOptimizationCurve();
    }
    renderScenarioChart(currentResidual);
}

// --- 5. EVENT LISTENERS ---

document.getElementById('budget-slider').addEventListener('input', (e) => {
    currentBudget = parseInt(e.target.value);
    document.getElementById('budget-display').innerText = formatMoney(currentBudget);
    updateDashboard();
});

document.getElementById('delay-slider').addEventListener('input', (e) => {
    currentDelay = parseInt(e.target.value);
    document.getElementById('delay-display').innerText = `${currentDelay} Days`;
    updateDashboard();
});

// AI Copilot Logic
document.getElementById('chat-send').addEventListener('click', handleChat);
document.getElementById('chat-input').addEventListener('keypress', (e) => {
    if(e.key === 'Enter') handleChat();
});

function handleChat() {
    const input = document.getElementById('chat-input');
    const msg = input.value.trim();
    if (!msg) return;

    const win = document.getElementById('chat-window');
    
    // User Message
    const userDiv = document.createElement('div');
    userDiv.className = 'chat-msg user-msg';
    userDiv.innerText = msg;
    win.appendChild(userDiv);

    input.value = '';
    
    // Simulated Response
    setTimeout(() => {
        const aiDiv = document.createElement('div');
        aiDiv.className = 'chat-msg ai-msg';
        
        const query = msg.toLowerCase();
        
        if (query.includes('highest') && (query.includes('risk') || query.includes('financial'))) {
            aiDiv.innerHTML = `Based on the latest telemetry, your highest financial risk is the <strong>Payment API Exploit</strong> (₹85 L exposure), driven by vulnerability CVE-2023-44487 in the API Gateway.`;
        } else if (query.includes('mfa')) {
            aiDiv.innerHTML = `Implementing Enterprise MFA costs <strong>₹15 L</strong> and would reduce overall Expected Annual Loss by <strong>15%</strong> (Approx ₹61.5 L avoided loss), yielding a ROSI of >300%.`;
        } else if (query.includes('delay') || query.includes('30 days')) {
            aiDiv.innerHTML = `Delaying remediation by 30 days adds a time-decay penalty of ₹0.04 Cr per day, increasing your Expected Annual Loss by exactly <strong>₹1.20 Cr</strong>.`;
        } else {
            aiDiv.innerHTML = `I can help with financial risk quantification. Try asking about "highest risk", "MFA simulation", or "remediation delay".`;
        }

        win.appendChild(aiDiv);
        win.scrollTop = win.scrollHeight;
    }, 600);
}

// --- 6. INIT ---
document.addEventListener('DOMContentLoaded', () => {
    renderNavigation();
    renderDrivers();
    renderTechnicalTable();
    renderComplianceTable();
    updateDashboard();
});
