/**
 * QuMail Fluid Web Client — Main Application Controller
 * Orchestrates physics, components, state management, and gesture events.
 */

import { MOCK_EMAILS, INITIAL_KEY_BANK } from './mock-data.js';
import { KeyBankGauge } from './components/key-gauge.js';
import { SwipeableEmailItem } from './components/email-item.js';
import { ReadingPane } from './components/reading-pane.js';
import { ComposeSheet } from './components/compose-sheet.js';
import { InspectorModal } from './components/inspector-modal.js';

// Subtle Web Audio Click Synthesizer for tactile confirmation (Principle 13)
class AudioHaptics {
  constructor() {
    this.ctx = null;
  }
  _init() {
    if (!this.ctx) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) this.ctx = new AudioCtx();
    }
  }
  click() {
    try {
      this._init();
      if (!this.ctx || this.ctx.state === 'suspended') {
        this.ctx?.resume();
      }
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(800, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(300, this.ctx.currentTime + 0.02);
      gain.gain.setValueAtTime(0.04, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.02);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.025);
    } catch (_) {}
  }
}

class QuMailApp {
  constructor() {
    this.emails = [...MOCK_EMAILS];
    this.currentFilter = 'all';
    this.searchQuery = '';
    this.selectedEmailId = this.emails[0]?.id || null;
    this.haptics = new AudioHaptics();

    this.listContainer = document.getElementById('email-list-container');
    this.readingPaneContainer = document.getElementById('reading-pane-container');
    this.composeOverlay = document.getElementById('compose-overlay');
    this.composeSheetEl = document.getElementById('compose-sheet');
    this.inspectorOverlay = document.getElementById('inspector-overlay');
    this.inspectorModalEl = document.getElementById('inspector-modal');

    this._init();
  }

  _init() {
    // 1. Initialize Key Bank Gauge
    const gaugeEl = document.getElementById('key-gauge-container');
    this.gauge = new KeyBankGauge(gaugeEl, INITIAL_KEY_BANK);

    // 2. Initialize Inspector Modal
    this.inspector = new InspectorModal(this.inspectorOverlay, this.inspectorModalEl);

    // 3. Initialize Reading Pane
    this.readingPane = new ReadingPane(this.readingPaneContainer, {
      onInspectEnvelope: (email) => {
        this.haptics.click();
        this.inspector.open(email);
      },
    });

    // 4. Initialize Compose Sheet
    this.composeSheet = new ComposeSheet(this.composeOverlay, this.composeSheetEl, {
      onSend: (newMail) => {
        this._handleSendEmail(newMail);
      },
    });

    const openComposeBtn = document.getElementById('btn-open-compose');
    if (openComposeBtn) {
      openComposeBtn.addEventListener('click', () => {
        this.haptics.click();
        this.composeSheet.open(openComposeBtn);
      });
    }

    // 5. Search & Filters
    this._bindSearchAndFilters();

    // 6. Render Emails & initial view
    this.renderEmailList();
    if (this.selectedEmailId) {
      const email = this.emails.find(e => e.id === this.selectedEmailId);
      if (email) this.readingPane.setEmail(email);
    }
  }

  _bindSearchAndFilters() {
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase().trim();
        this.renderEmailList();
      });
    }

    const filterBtns = document.querySelectorAll('.filter-pill');
    filterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        this.haptics.click();
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.currentFilter = btn.dataset.filter;
        this.renderEmailList();
      });
    });
  }

  renderEmailList() {
    this.listContainer.innerHTML = '';

    const filtered = this.emails.filter(e => {
      const matchesFilter = this.currentFilter === 'all' || e.securityLevel === this.currentFilter;
      const matchesSearch = !this.searchQuery ||
        e.subject.toLowerCase().includes(this.searchQuery) ||
        e.from.toLowerCase().includes(this.searchQuery) ||
        e.snippet.toLowerCase().includes(this.searchQuery);
      return matchesFilter && matchesSearch;
    });

    if (filtered.length === 0) {
      this.listContainer.innerHTML = `
        <div style="padding: 30px; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
          No quantum messages found.
        </div>
      `;
      return;
    }

    filtered.forEach(email => {
      const itemEl = document.createElement('div');
      itemEl.className = `email-item-container ${email.id === this.selectedEmailId ? 'selected' : ''}`;
      itemEl.dataset.id = email.id;

      const levelClass = email.securityLevel.replace('.', '');

      itemEl.innerHTML = `
        <div class="swipe-action-left">
          <span>${email.isUnread ? 'Mark Read' : 'Unread'}</span>
        </div>
        <div class="swipe-action-right">
          <span>Archive</span>
        </div>
        <div class="email-card-content">
          <div class="email-row-top">
            <div class="sender-wrapper">
              ${email.isUnread ? '<div class="unread-dot"></div>' : ''}
              <span class="email-sender">${email.senderName || email.from}</span>
            </div>
            <span class="email-item-date">${email.date}</span>
          </div>
          <div class="email-row-middle">
            <span class="email-item-subject">${email.subject}</span>
            <span class="security-badge-pill ${levelClass}">${email.securityLevelName}</span>
          </div>
          <div class="email-item-snippet">${email.snippet}</div>
        </div>
      `;

      // Instantiate fluid gesture controller on this row
      new SwipeableEmailItem(itemEl, email, {
        onSelect: (selectedEmail) => {
          this.haptics.click();
          this.selectedEmailId = selectedEmail.id;
          selectedEmail.isUnread = false;
          this.readingPane.setEmail(selectedEmail);
          this.renderEmailList();
        },
        onToggleRead: (targetEmail) => {
          this.haptics.click();
          targetEmail.isUnread = !targetEmail.isUnread;
          this.renderEmailList();
        },
        onArchive: (targetEmail) => {
          this.haptics.click();
          this.emails = this.emails.filter(e => e.id !== targetEmail.id);
          if (this.selectedEmailId === targetEmail.id) {
            this.selectedEmailId = this.emails[0]?.id || null;
            const next = this.emails.find(e => e.id === this.selectedEmailId);
            this.readingPane.setEmail(next || null);
          }
          this.renderEmailList();
        },
      });

      this.listContainer.appendChild(itemEl);
    });

    // Update unread count
    const unreadCount = this.emails.filter(e => e.isUnread).length;
    const badge = document.getElementById('inbox-count-badge');
    if (badge) badge.textContent = unreadCount.toString();
  }

  _handleSendEmail({ to, subject, body, level }) {
    this.haptics.click();

    let secName = "L2.5 Hybrid PQC";
    let slotsConsumed = 1;
    if (level === 'L3') {
      secName = "L3 Quantum OTP";
      slotsConsumed = Math.ceil(((body || '').length + 32) / 1024) || 1;
    } else if (level === 'L2') {
      secName = "L2 Q-AES";
      slotsConsumed = 1;
    } else if (level === 'L1') {
      secName = "L1 Baseline";
      slotsConsumed = 0;
    }

    if (slotsConsumed > 0) {
      this.gauge.consumeKeys(slotsConsumed);
    }

    const newMailObj = {
      id: `msg-${Date.now()}`,
      folder: "inbox",
      from: "officer.sac@isro.gov.in",
      senderName: "Space Applications Centre (SAC)",
      to: [to],
      date: "Just now",
      subject: subject || "(No Subject)",
      snippet: (body || "").slice(0, 80) + "...",
      bodyText: body || "(No body text provided)",
      securityLevel: level,
      securityLevelName: secName,
      isUnread: true,
      verification: {
        verified: true,
        level,
        methodTitle: `${secName} — Outgoing Quantum Sealed`,
        methodDetail: `Encrypted via SAC node key allocation #${slotsConsumed}`,
        keyIds: Array.from({ length: slotsConsumed }, (_, i) => `isro-qkd-key-${Math.floor(1000 + Math.random() * 9000)}`),
        aadAuthenticated: true,
        timestampEpochSecs: Math.floor(Date.now() / 1000),
      },
      envelopeHeader: {
        version: 1,
        security_level: level === 'L3' ? 'QuantumOtp' : (level === 'L2.5' ? 'HybridPqc' : (level === 'L2' ? 'Qaes' : 'Baseline')),
        message_id: crypto.randomUUID ? crypto.randomUUID() : `msg-uuid-${Date.now()}`,
        sender_sae: 1,
        recipient_sae: 2,
        key_ids: [`isro-qkd-key-${Math.floor(1000 + Math.random() * 9000)}`],
        timestamp_epoch_secs: Math.floor(Date.now() / 1000),
        tag_b64: "Poly1305_AuthTag_Generated==",
        nonce_b64: "96bit_CSPRNG_Random_Nonce==",
        pqc_ciphertext_b64: level === 'L2.5' ? "MLKEM768_Shared_Secret_B64==" : null,
      },
      attachments: [],
    };

    this.emails.unshift(newMailObj);
    this.selectedEmailId = newMailObj.id;
    this.readingPane.setEmail(newMailObj);
    this.renderEmailList();
  }
}

// Start application when DOM is ready
window.addEventListener('DOMContentLoaded', () => {
  new QuMailApp();
});
