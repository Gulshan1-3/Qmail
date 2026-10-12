/**
 * Apple WWDC 2018 Designing Fluid Interfaces — Cryptographic Envelope Inspector
 * Interactive inspector for raw QuMail quantum envelope headers and cryptographic context.
 */

import { Spring } from '../physics/spring.js';

export class InspectorModal {
  /**
   * @param {HTMLElement} overlayEl - Scrim container
   * @param {HTMLElement} modalEl - Modal card
   */
  constructor(overlayEl, modalEl) {
    this.overlay = overlayEl;
    this.modal = modalEl;
    this.contentEl = modalEl.querySelector('.inspector-json-content');

    this.isOpen = false;

    // Scale & opacity spring
    this.scaleSpring = new Spring({
      damping: 0.9,
      response: 0.3,
      initialValue: 0.85,
    });

    this.scaleSpring.onUpdate = (scale) => {
      this.modal.style.transform = `scale(${scale})`;
      this.modal.style.opacity = Math.min(1, Math.max(0, (scale - 0.8) / 0.2)).toString();
    };

    this.scaleSpring.onComplete = (scale) => {
      if (scale < 0.9) {
        this.overlay.style.display = 'none';
        this.isOpen = false;
      }
    };

    this._bindEvents();
  }

  open(email) {
    if (!email || !email.envelopeHeader) return;
    this.isOpen = true;
    this.overlay.style.display = 'flex';
    this.contentEl.textContent = JSON.stringify(email.envelopeHeader, null, 2);

    this.scaleSpring.snapTo(0.85);
    this.scaleSpring.to(1.0);
  }

  close() {
    this.scaleSpring.to(0.8);
  }

  _bindEvents() {
    this.overlay.addEventListener('click', (e) => {
      if (e.target === this.overlay) {
        this.close();
      }
    });

    const closeBtn = this.modal.querySelector('.btn-close-inspector');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.close());
    }
  }
}
