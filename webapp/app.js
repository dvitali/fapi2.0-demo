// S2S M2M Client App
let s2sState = null;

const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');
const btnResetKeys = document.getElementById('btnResetKeys');

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  loadS2SStatus();
  initStage1Token();
  initStage2Operations();
  initAttackSimulator();

  btnResetKeys.addEventListener('click', async () => {
    if (!confirm('Regenerate client asymmetric keys?')) return;
    try {
      await fetch('/api/s2s/reset-keys', { method: 'POST' });
      alert('Keys regenerated!');
      window.location.reload();
    } catch (e) {
      alert('Error: ' + e.message);
    }
  });
});

function initTabs() {
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.style.display = 'none');

      btn.classList.add('active');
      const targetId = 'tab-' + btn.getAttribute('data-tab');
      const target = document.getElementById(targetId);
      if (target) target.style.display = 'block';

      if (btn.getAttribute('data-tab') === 'keys') {
        renderKeysTab();
      }
    });
  });
}

async function loadS2SStatus() {
  try {
    const res = await fetch('/api/s2s/status');
    s2sState = await res.json();
    renderKeysTab();
  } catch (e) {
    console.error('Failed to load S2S status:', e);
  }
}

function renderKeysTab() {
  const container = document.getElementById('keysContainer');
  if (!container || !s2sState) return;

  container.innerHTML = `
    <div class="card" style="margin: 0;">
      <div class="panel-header">
        <span class="badge badge-info">Authentication</span>
        <h3>Client Assertion Key (ES256)</h3>
        <p class="panel-desc">${s2sState.keys.authKey.purpose}</p>
      </div>
      <div class="inspect-field">
        <label>RFC 7638 Thumbprint (jkt):</label>
        <code class="code-value highlight-val">${s2sState.keys.authKey.thumbprint}</code>
      </div>
      <div class="inspect-field" style="margin-top: 0.75rem;">
        <label>Public JWK:</label>
        <pre class="code-block">${JSON.stringify(s2sState.keys.authKey.publicJwk, null, 2)}</pre>
      </div>
    </div>

    <div class="card" style="margin: 0;">
      <div class="panel-header">
        <span class="badge badge-success">DPoP Proof-of-Possession</span>
        <h3>Client DPoP Key (ES256)</h3>
        <p class="panel-desc">${s2sState.keys.dpopKey.purpose}</p>
      </div>
      <div class="inspect-field">
        <label>RFC 7638 Thumbprint (jkt):</label>
        <code class="code-value highlight-val">${s2sState.keys.dpopKey.thumbprint}</code>
      </div>
      <div class="inspect-field" style="margin-top: 0.75rem;">
        <label>Public JWK:</label>
        <pre class="code-block">${JSON.stringify(s2sState.keys.dpopKey.publicJwk, null, 2)}</pre>
      </div>
    </div>
  `;
}

function initStage1Token() {
  const btn = document.getElementById('btnAcquireToken');
  const chkNonce = document.getElementById('chkEnforceAsNonce');
  const output = document.getElementById('tokenOutput');
  const nonceAlert = document.getElementById('tokenNonceAlert');

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Acquiring M2M Token...';

    try {
      const res = await fetch('/api/s2s/run-token-exchange', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enforceNonce: chkNonce.checked })
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error_description || data.error);

      document.getElementById('tClientJkt').textContent = data.clientDpopThumbprint;
      document.getElementById('tTokenPayload').textContent = JSON.stringify(data.tokenResponse.decodedAccessToken.payload, null, 2);

      nonceAlert.style.display = data.nonceNegotiated ? 'block' : 'none';
      output.style.display = 'block';

      btn.disabled = false;
      btn.textContent = '⚡ Re-Acquire Token (Success)';
      
      // Auto trigger first treasury call
      document.getElementById('btnCallTreasury').click();
    } catch (e) {
      alert('Token Acquisition Failed: ' + e.message);
      btn.disabled = false;
      btn.textContent = '⚡ Execute Automated Token Exchange';
    }
  });
}

function initStage2Operations() {
  const btnTreasury = document.getElementById('btnCallTreasury');
  const btnPayroll = document.getElementById('btnCallPayroll');
  const btnFx = document.getElementById('btnCallFx');
  const chkNonce = document.getElementById('chkEnforceRsNonce');
  const output = document.getElementById('b2bOutput');
  const rsNonceAlert = document.getElementById('rsNonceAlert');

  async function executeCall(action) {
    try {
      const res = await fetch('/api/s2s/run-b2b-call', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, enforceNonce: chkNonce.checked })
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message || data.error);

      rsNonceAlert.style.display = data.nonceNegotiated ? 'block' : 'none';

      // Render Security Audit
      const auditContainer = document.getElementById('b2bAuditChecklist');
      auditContainer.innerHTML = data.bankResponse.fapiSecurityAudit.checks.map(c => `
        <div class="audit-item ${c.status === 'PASS' ? 'pass' : 'fail'}">
          <div>
            <strong>${c.name}</strong>
            <div class="small text-muted">${c.details || c.error}</div>
          </div>
          <div class="audit-status">${c.status === 'PASS' ? '✅ PASS' : '❌ FAIL'}</div>
        </div>
      `).join('');

      renderDataDisplay(action, data.bankResponse);
      document.getElementById('b2bRawData').textContent = JSON.stringify(data.bankResponse, null, 2);

      output.style.display = 'block';
    } catch (e) {
      alert('B2B Call Failed: ' + e.message);
    }
  }

  btnTreasury.addEventListener('click', () => executeCall('treasury'));
  btnPayroll.addEventListener('click', () => executeCall('payroll'));
  btnFx.addEventListener('click', () => executeCall('fx'));
}

function renderDataDisplay(action, response) {
  const container = document.getElementById('b2bDataDisplay');

  if (action === 'treasury') {
    container.innerHTML = response.data.map(pos => `
      <div class="account-card">
        <div>
          <h4>${pos.name} (${pos.accountNumber})</h4>
          <div class="small text-muted">Yield: ${pos.interestYield} • Reserved for Payroll: € ${pos.reservedForPayroll.toLocaleString()}</div>
        </div>
        <div class="account-balance">${pos.currency} ${pos.availableLiquidity.toLocaleString('en-US', { minimumFractionDigits: 2 })}</div>
      </div>
    `).join('');
  } else if (action === 'payroll') {
    const b = response.payrollBatch;
    container.innerHTML = `
      <div class="alert alert-success">
        <h4>💼 Bulk Payroll Batch Settled</h4>
        <p><strong>Batch ID:</strong> ${b.batchId}</p>
        <p><strong>Total Disbursed:</strong> € ${b.totalAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })} EUR across ${b.employeeCount} employees</p>
        <p><strong>Clearing Network:</strong> ${b.clearingNetwork}</p>
        <p><strong>Status:</strong> ${b.status}</p>
      </div>
    `;
  } else if (action === 'fx') {
    const q = response.quote;
    container.innerHTML = `
      <div class="alert alert-info">
        <h4>💱 Wholesale FX Rate Quote</h4>
        <p><strong>Quote ID:</strong> ${q.quoteId} (${q.pair})</p>
        <p><strong>Base Amount:</strong> € ${q.baseAmount.toLocaleString()} EUR @ Rate ${q.rate}</p>
        <p><strong>Target Amount:</strong> $ ${q.targetAmount.toLocaleString()} USD</p>
        <p><strong>Guaranteed Expiry:</strong> ${q.expiresInSeconds}s (${q.validUntil})</p>
      </div>
    `;
  }
}

function initAttackSimulator() {
  const box = document.getElementById('attackResultBox');
  const title = document.getElementById('attackResultTitle');
  const badge = document.getElementById('attackResultBadge');
  const explanation = document.getElementById('attackResultExplanation');
  const details = document.getElementById('attackResultDetails');

  async function runAttack(attackType) {
    try {
      const res = await fetch('/api/s2s/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attackType })
      });
      const data = await res.json();

      if (data.error && !data.attackType) {
        alert(data.error);
        return;
      }

      box.style.display = 'block';
      box.scrollIntoView({ behavior: 'smooth' });

      title.textContent = `Simulation: ${data.attackType}`;
      if (data.blocked) {
        badge.className = 'badge badge-success';
        badge.textContent = '🛡️ BLOCKED BY FAPI S2S GATEWAY';
      } else {
        badge.className = 'badge badge-danger';
        badge.textContent = '🚨 ATTACK SUCCEEDED (VULNERABLE)';
      }

      explanation.textContent = data.explanation;
      details.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      alert('Attack simulation error: ' + e.message);
    }
  }

  document.getElementById('btnAttackBearer').addEventListener('click', () => runAttack('exfiltrated_bearer'));
  document.getElementById('btnAttackRogue').addEventListener('click', () => runAttack('rogue_service_key'));
  document.getElementById('btnAttackNonce').addEventListener('click', () => runAttack('stale_nonce'));
}
