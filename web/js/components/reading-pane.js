/**
 * Apple WWDC 2018 Designing Fluid Interfaces — Reading Pane
 * Renders decrypted email content, quantum verification badges, and attachments.
 */

export class ReadingPane {
  /**
   * @param {HTMLElement} containerEl
   * @param {Object} options
   * @param {Function} options.onInspectEnvelope - Opens crypto inspector modal
   */
  constructor(containerEl, options = {}) {
    this.container = containerEl;
    this.options = options;
    this.currentEmail = null;
  }

  setEmail(email) {
    this.currentEmail = email;
    this.render();
  }

  render() {
    if (!this.currentEmail) {
      this.container.innerHTML = `
        <div class="empty-reading-state">
          <div class="empty-icon">🛡️</div>
          <h3>Select a message to view</h3>
          <p>End-to-end post-quantum encryption & verification details will appear here.</p>
        </div>
      `;
      return;
    }

    const e = this.currentEmail;
    const v = e.verification;

    let verificationHtml = '';
    if (v && v.verified) {
      const isL3 = v.level === 'L3';
      const isL25 = v.level === 'L2.5';
      const badgeClass = isL3 ? 'verified-l3' : (isL25 ? 'verified-l25' : 'verified-l2');

      const keyChips = (v.keyIds || []).map(k => `<span class="key-id-chip">${k}</span>`).join(' ');

      verificationHtml = `
        <div class="quantum-verified-banner ${badgeClass}">
          <div class="verified-header">
            <div class="verified-title-row">
              <span class="verified-check">✓</span>
              <span class="verified-title">QUANTUM VERIFIED</span>
            </div>
            <span class="verified-badge-pill">${e.securityLevelName}</span>
          </div>
          <div class="verified-method">${v.methodTitle}</div>
          <div class="verified-detail">${v.methodDetail}</div>
          <div class="verified-meta-row">
            ${v.keyIds?.length ? `<div class="verified-keys"><span class="meta-label">Key IDs:</span> ${keyChips}</div>` : ''}
            ${v.aadAuthenticated ? `<div class="verified-aad"><span>AAD Authenticated</span> <span class="check-mark">✓</span></div>` : ''}
          </div>
        </div>
      `;
    }

    const attachmentsHtml = (e.attachments || []).map(att => `
      <div class="attachment-chip" role="button" tabindex="0">
        <span class="attachment-icon">📎</span>
        <div class="attachment-info">
          <span class="attachment-name">${att.filename}</span>
          <span class="attachment-size">${att.size}</span>
        </div>
        <span class="attachment-dl-icon">↓</span>
      </div>
    `).join('');

    this.container.innerHTML = `
      <div class="reading-pane-toolbar">
        <div class="toolbar-actions-left">
          <button class="btn-tool" title="Reply"><span class="icon">↩</span> Reply</button>
          <button class="btn-tool" title="Reply All"><span class="icon">⮁</span> Reply All</button>
          <button class="btn-tool" title="Forward"><span class="icon">↪</span> Forward</button>
          <button class="btn-tool btn-danger" title="Delete"><span class="icon">🗑</span></button>
        </div>
        <div class="toolbar-actions-right">
          ${e.envelopeHeader ? `<button class="btn-inspect-envelope" id="btn-inspect"><span class="icon">🔍</span> Envelope</button>` : ''}
        </div>
      </div>

      <div class="reading-pane-content">
        <div class="email-meta-header">
          <div class="email-sender-line">
            <span class="email-sender-name">${e.from}</span>
            <span class="email-date">${e.date}</span>
          </div>
          <div class="email-recipient-line">
            To: ${e.to.join(', ')}
          </div>
          <h1 class="email-subject">${e.subject}</h1>
        </div>

        ${verificationHtml}

        <div class="email-body-text">
          ${e.bodyText.replace(/\n/g, '<br>')}
        </div>

        ${e.attachments?.length ? `
          <div class="email-attachments-section">
            <div class="attachments-header">Attachments (${e.attachments.length}):</div>
            <div class="attachments-grid">
              ${attachmentsHtml}
            </div>
          </div>
        ` : ''}
      </div>
    `;

    // Hook envelope inspector button
    const inspectBtn = this.container.querySelector('#btn-inspect');
    if (inspectBtn && this.options.onInspectEnvelope) {
      inspectBtn.addEventListener('click', () => {
        this.options.onInspectEnvelope(e);
      });
    }
  }
}
