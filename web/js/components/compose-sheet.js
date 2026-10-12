/**
 * Apple WWDC 2018 Designing Fluid Interfaces — Fluid Modal Sheet
 * Interruptible drag-to-dismiss, momentum throw, rubber-banding, and origin anchoring.
 */

import { Spring } from '../physics/spring.js';
import { PanGestureRecognizer } from '../physics/gesture.js';
import { project, rubberband } from '../physics/projection.js';

export class ComposeSheet {
  /**
   * @param {HTMLElement} overlayEl - Scrim backdrop
   * @param {HTMLElement} sheetEl - Draggable modal sheet container
   * @param {Object} options
   * @param {Function} options.onSend - Callback when message is sent
   */
  constructor(overlayEl, sheetEl, options = {}) {
    this.overlay = overlayEl;
    this.sheet = sheetEl;
    this.handle = sheetEl.querySelector('.sheet-grab-handle') || sheetEl;
    this.options = options;

    this.isOpen = false;
    this.sheetHeight = 600;

    // Y-axis spring (damping 0.82 for subtle Apple sheet bounce when thrown)
    this.spring = new Spring({
      damping: 0.85,
      response: 0.35,
      initialValue: 800, // starts off-screen below
    });

    this.spring.onUpdate = (y) => {
      this.sheet.style.transform = `translate3d(0, ${Math.max(-50, y)}px, 0)`;
      // Fade scrim dynamically as sheet moves down
      const progress = Math.max(0, Math.min(1, 1 - (y / this.sheetHeight)));
      this.overlay.style.opacity = progress.toString();
    };

    this.spring.onComplete = (y) => {
      if (y >= this.sheetHeight - 50) {
        this.overlay.style.display = 'none';
        this.isOpen = false;
      }
    };

    this._initGesture();
    this._initForm();
  }

  open(triggerElement = null) {
    this.sheetHeight = this.sheet.offsetHeight || 600;
    this.overlay.style.display = 'flex';
    this.isOpen = true;

    // Spring open from bottom
    this.spring.snapTo(this.sheetHeight);
    this.spring.to(0, -600); // initial upward boost
  }

  close(velocity = 0) {
    this.spring.to(this.sheetHeight + 50, velocity);
  }

  _initGesture() {
    this.pan = new PanGestureRecognizer(this.handle, {
      axis: 'vertical',
      threshold: 6,

      onDown: () => {
        // Interrupt ongoing spring in flight immediately
        if (!this.spring.isSettled) {
          this.spring.stop();
        }
      },

      onMove: ({ dy }) => {
        let y = dy;
        // Rubberband upward overshoot if dragged above rest (y < 0)
        if (y < 0) {
          y = rubberband(y, 250, 0.55);
        }
        this.spring.snapTo(y);
      },

      onEnd: ({ dy, vy }) => {
        // Momentum Projection: determine landing point
        const projectedY = dy + project(vy, 0.995);
        const dismissThreshold = this.sheetHeight * 0.4;

        if (projectedY > dismissThreshold || vy > 700) {
          // User threw or dragged the sheet down -> Dismiss with release velocity
          this.close(Math.max(vy, 400));
        } else {
          // Snap back to open (y = 0) with release velocity
          this.spring.to(0, vy);
        }
      },

      onCancel: () => {
        this.spring.to(0, 0);
      },
    });

    // Close when tapping backdrop
    this.overlay.addEventListener('click', (e) => {
      if (e.target === this.overlay) {
        this.close(300);
      }
    });

    // Close button
    const closeBtn = this.sheet.querySelector('.btn-close-sheet');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.close(400));
    }
  }

  _initForm() {
    const secSelect = this.sheet.querySelector('#compose-sec-level');
    const keyReqNotice = this.sheet.querySelector('#key-requirement-badge');
    const bodyInput = this.sheet.querySelector('#compose-body');

    const updateKeyEstimates = () => {
      if (!secSelect || !keyReqNotice) return;
      const level = secSelect.value;
      const textLen = (bodyInput?.value || '').length;

      if (level === 'L3') {
        const neededBytes = textLen + 32;
        const slotsNeeded = Math.ceil(neededBytes / 1024) || 1;
        keyReqNotice.textContent = `Requires ${slotsNeeded} QKD key slot (${slotsNeeded * 1024} bytes Vernam Pad + MAC)`;
        keyReqNotice.className = 'key-estimate-pill l3-badge';
      } else if (level === 'L2.5') {
        keyReqNotice.textContent = 'Requires 1 QKD key slot (1024B) + ML-KEM-768 lattice encapsulation';
        keyReqNotice.className = 'key-estimate-pill l25-badge';
      } else if (level === 'L2') {
        keyReqNotice.textContent = 'Requires 1 QKD key slot (1024B) for AES-256-GCM derivation';
        keyReqNotice.className = 'key-estimate-pill l2-badge';
      } else {
        keyReqNotice.textContent = 'No QKD key material required (Standard TLS transport)';
        keyReqNotice.className = 'key-estimate-pill l1-badge';
      }
    };

    if (secSelect) secSelect.addEventListener('change', updateKeyEstimates);
    if (bodyInput) bodyInput.addEventListener('input', updateKeyEstimates);
    updateKeyEstimates();

    // Form submission
    const form = this.sheet.querySelector('#compose-form');
    if (form) {
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const to = this.sheet.querySelector('#compose-to')?.value;
        const subject = this.sheet.querySelector('#compose-subject')?.value;
        const body = bodyInput?.value;
        const level = secSelect?.value || 'L2.5';

        if (this.options.onSend) {
          this.options.onSend({ to, subject, body, level });
        }
        this.close(500);
      });
    }
  }
}
