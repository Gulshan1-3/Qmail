/**
 * Apple WWDC 2018 Designing Fluid Interfaces — Key Bank Gauge
 * Spring-driven visualizer of ISRO 100x1Kb symmetric key bank and ETSI QKD 014 link.
 */

import { Spring } from '../physics/spring.js';

export class KeyBankGauge {
  /**
   * @param {HTMLElement} containerEl - Container element
   * @param {Object} initialStatus - KeyBankStatus data
   */
  constructor(containerEl, initialStatus) {
    this.container = containerEl;
    this.status = { ...initialStatus };

    this.meterFill = containerEl.querySelector('.gauge-bar-fill');
    this.countLabel = containerEl.querySelector('.gauge-count-label');
    this.capacityLabel = containerEl.querySelector('.gauge-capacity-label');
    this.syncButton = containerEl.querySelector('.btn-sync-inbox');

    // Spring for smooth gauge percentage animation (critically damped)
    this.spring = new Spring({
      damping: 1.0,
      response: 0.4,
      initialValue: (this.status.stored_keys / this.status.max_keys) * 100,
    });

    this.spring.onUpdate = (pct) => {
      if (this.meterFill) {
        this.meterFill.style.width = `${Math.max(0, Math.min(100, pct))}%`;
      }
    };

    this._bindEvents();
    this.render();
  }

  render() {
    if (this.countLabel) {
      this.countLabel.textContent = `${this.status.stored_keys}/${this.status.max_keys}`;
    }
    if (this.capacityLabel) {
      const kb = ((this.status.stored_keys * (this.status.key_size_bits / 8)) / 1024).toFixed(1);
      this.capacityLabel.textContent = `Capacity: ${kb} KB available`;
    }
    const targetPct = (this.status.stored_keys / this.status.max_keys) * 100;
    this.spring.to(targetPct);
  }

  consumeKeys(count = 1) {
    this.status.stored_keys = Math.max(0, this.status.stored_keys - count);
    this.render();
  }

  refillKeys() {
    this.status.stored_keys = this.status.max_keys;
    // Slight bounce when refreshed from QKD link
    this.spring.setParams(0.85, 0.35);
    this.render();
    setTimeout(() => {
      this.spring.setParams(1.0, 0.4);
    }, 1000);
  }

  _bindEvents() {
    if (this.syncButton) {
      this.syncButton.addEventListener('click', () => {
        this.syncButton.classList.add('syncing');
        setTimeout(() => {
          this.refillKeys();
          this.syncButton.classList.remove('syncing');
        }, 600);
      });
    }
  }
}
