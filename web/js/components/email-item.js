/**
 * Apple WWDC 2018 Designing Fluid Interfaces — Swipeable Email Item
 * Implements 1:1 direct tracking, rubberbanding, momentum projection, and velocity handoff.
 */

import { Spring } from '../physics/spring.js';
import { PanGestureRecognizer } from '../physics/gesture.js';
import { project, rubberband } from '../physics/projection.js';

export class SwipeableEmailItem {
  /**
   * @param {HTMLElement} element - Row DOM container
   * @param {Object} email - Email data object
   * @param {Object} callbacks
   * @param {Function} callbacks.onSelect - Triggered on tap
   * @param {Function} callbacks.onToggleRead - Triggered on swipe right commit
   * @param {Function} callbacks.onArchive - Triggered on swipe left commit
   */
  constructor(element, email, callbacks = {}) {
    this.container = element;
    this.email = email;
    this.callbacks = callbacks;

    this.card = element.querySelector('.email-card-content');
    this.actionLeft = element.querySelector('.swipe-action-left');   // e.g. Mark Read/Unread
    this.actionRight = element.querySelector('.swipe-action-right'); // e.g. Archive

    this.actionThreshold = 80; // px needed to engage action
    this.maxActionWidth = 100;

    // Fluid spring controlling card horizontal offset
    this.spring = new Spring({
      damping: 0.85,  // Slight physical bounce for tactile feedback
      response: 0.32, // Snappy settle
      initialValue: 0,
    });

    this.spring.onUpdate = (x) => {
      this.card.style.transform = `translate3d(${x}px, 0, 0)`;
      this._updateActionVisuals(x);
    };

    this.spring.onComplete = () => {
      if (this.spring.targetValue === 0) {
        this.container.classList.remove('swiping');
      }
    };

    this._initGesture();
    this._initClick();
  }

  _initClick() {
    this.card.addEventListener('click', (e) => {
      // Don't trigger select if was just swiped
      if (Math.abs(this.spring.currentValue) > 5) return;
      if (this.callbacks.onSelect) {
        this.callbacks.onSelect(this.email);
      }
    });
  }

  _initGesture() {
    this.pan = new PanGestureRecognizer(this.card, {
      axis: 'horizontal',
      threshold: 8,

      onDown: () => {
        // Interrupt any ongoing animation instantly
        if (!this.spring.isSettled) {
          this.spring.stop();
        }
      },

      onStart: () => {
        this.container.classList.add('swiping');
      },

      onMove: ({ dx }) => {
        let x = dx;
        // Rubberband if dragged beyond action widths
        if (x > this.maxActionWidth) {
          const overshoot = x - this.maxActionWidth;
          x = this.maxActionWidth + rubberband(overshoot, 150, 0.55);
        } else if (x < -this.maxActionWidth) {
          const overshoot = x - (-this.maxActionWidth);
          x = -this.maxActionWidth + rubberband(overshoot, 150, 0.55);
        }

        // 1:1 direct tracking
        this.spring.snapTo(x);
      },

      onEnd: ({ dx, vx }) => {
        // Momentum Projection: project resting point using velocity
        const projectedX = dx + project(vx, 0.992);

        if (projectedX > this.actionThreshold || vx > 600) {
          // Commit Swipe Right Action (Toggle Read)
          this._triggerAction('right', vx);
        } else if (projectedX < -this.actionThreshold || vx < -600) {
          // Commit Swipe Left Action (Archive)
          this._triggerAction('left', vx);
        } else {
          // Spring back to rest (0) with release velocity handoff
          this.spring.to(0, vx);
        }
      },

      onCancel: () => {
        this.spring.to(0, 0);
      },
    });
  }

  _updateActionVisuals(x) {
    if (x > 0) {
      if (this.actionLeft) {
        this.actionLeft.style.opacity = Math.min(1, x / 40);
        this.actionLeft.style.transform = `scale(${Math.min(1.1, 0.8 + (x / 100) * 0.3)})`;
      }
      if (this.actionRight) this.actionRight.style.opacity = '0';
    } else if (x < 0) {
      const absX = Math.abs(x);
      if (this.actionRight) {
        this.actionRight.style.opacity = Math.min(1, absX / 40);
        this.actionRight.style.transform = `scale(${Math.min(1.1, 0.8 + (absX / 100) * 0.3)})`;
      }
      if (this.actionLeft) this.actionLeft.style.opacity = '0';
    } else {
      if (this.actionLeft) this.actionLeft.style.opacity = '0';
      if (this.actionRight) this.actionRight.style.opacity = '0';
    }
  }

  _triggerAction(direction, releaseVelocity) {
    // Provide tactile commit feedback
    if (direction === 'right') {
      if (this.callbacks.onToggleRead) this.callbacks.onToggleRead(this.email);
    } else if (direction === 'left') {
      if (this.callbacks.onArchive) this.callbacks.onArchive(this.email);
    }

    // Spring gracefully back to center with velocity
    this.spring.to(0, releaseVelocity);
  }
}
