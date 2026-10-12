/**
 * Apple WWDC 2018 Designing Fluid Interfaces — Gesture Recognizer
 * 1:1 direct pointer tracking with velocity buffer, hysteresis, and pointer capture.
 */

export class PanGestureRecognizer {
  /**
   * @param {HTMLElement} element - Target element to attach listener to
   * @param {Object} options
   * @param {'horizontal'|'vertical'|'both'} [options.axis='both']
   * @param {number} [options.threshold=8] - Hysteresis threshold in pixels
   * @param {Function} [options.onDown] - Fires on pointer-down (instant feedback)
   * @param {Function} [options.onStart] - Fires when gesture passes hysteresis threshold
   * @param {Function} [options.onMove] - Fires on pointer-move during active drag
   * @param {Function} [options.onEnd] - Fires on pointer-up with release velocity
   * @param {Function} [options.onCancel] - Fires on pointer-cancel
   */
  constructor(element, options = {}) {
    this.element = element;
    this.axis = options.axis ?? 'both';
    this.threshold = options.threshold ?? 8;

    this.onDown = options.onDown ?? null;
    this.onStart = options.onStart ?? null;
    this.onMove = options.onMove ?? null;
    this.onEnd = options.onEnd ?? null;
    this.onCancel = options.onCancel ?? null;

    this.isActive = false;
    this.isDragging = false;
    this.pointerId = null;

    this.startX = 0;
    this.startY = 0;
    this.grabOffsetX = 0;
    this.grabOffsetY = 0;

    // Rolling history for velocity calculation (last 100ms)
    this.history = [];

    this._onPointerDown = this._onPointerDown.bind(this);
    this._onPointerMove = this._onPointerMove.bind(this);
    this._onPointerUp = this._onPointerUp.bind(this);
    this._onPointerCancel = this._onPointerCancel.bind(this);

    this.attach();
  }

  attach() {
    this.element.addEventListener('pointerdown', this._onPointerDown, { passive: false });
  }

  detach() {
    this.element.removeEventListener('pointerdown', this._onPointerDown);
    this._cleanup();
  }

  _onPointerDown(e) {
    // Only respond to primary button (left click or primary touch)
    if (e.button !== 0) return;

    this.pointerId = e.pointerId;
    this.isActive = true;
    this.isDragging = false;

    const rect = this.element.getBoundingClientRect();
    this.startX = e.clientX;
    this.startY = e.clientY;
    this.grabOffsetX = e.clientX - rect.left;
    this.grabOffsetY = e.clientY - rect.top;

    const now = performance.now();
    this.history = [{ x: e.clientX, y: e.clientY, time: now }];

    // Bind document listeners
    window.addEventListener('pointermove', this._onPointerMove, { passive: false });
    window.addEventListener('pointerup', this._onPointerUp);
    window.addEventListener('pointercancel', this._onPointerCancel);

    if (this.onDown) {
      this.onDown({
        pointerId: e.pointerId,
        x: e.clientX,
        y: e.clientY,
        grabOffsetX: this.grabOffsetX,
        grabOffsetY: this.grabOffsetY,
        nativeEvent: e,
      });
    }
  }

  _onPointerMove(e) {
    if (!this.isActive || e.pointerId !== this.pointerId) return;

    const now = performance.now();
    const dx = e.clientX - this.startX;
    const dy = e.clientY - this.startY;

    // Push into rolling history and prune older than 120ms
    this.history.push({ x: e.clientX, y: e.clientY, time: now });
    while (this.history.length > 2 && now - this.history[0].time > 120) {
      this.history.shift();
    }

    if (!this.isDragging) {
      const dist = Math.hypot(dx, dy);
      if (dist >= this.threshold) {
        // Axis check
        if (this.axis === 'horizontal' && Math.abs(dx) < Math.abs(dy)) {
          // Primarily vertical when horizontal requested -> abort
          this._cleanup();
          return;
        }
        if (this.axis === 'vertical' && Math.abs(dy) < Math.abs(dx)) {
          this._cleanup();
          return;
        }

        // Capture pointer to maintain continuous tracking
        try {
          this.element.setPointerCapture(this.pointerId);
        } catch (_) {}

        this.isDragging = true;
        if (this.onStart) {
          this.onStart({
            dx,
            dy,
            startX: this.startX,
            startY: this.startY,
            grabOffsetX: this.grabOffsetX,
            grabOffsetY: this.grabOffsetY,
            nativeEvent: e,
          });
        }
      }
    }

    if (this.isDragging) {
      // Prevent browser scroll/pull-to-refresh
      if (e.cancelable) e.preventDefault();

      if (this.onMove) {
        this.onMove({
          dx,
          dy,
          clientX: e.clientX,
          clientY: e.clientY,
          nativeEvent: e,
        });
      }
    }
  }

  _computeVelocity() {
    if (this.history.length < 2) return { vx: 0, vy: 0 };
    const latest = this.history[this.history.length - 1];
    const earliest = this.history[0];
    const dt = (latest.time - earliest.time) / 1000;
    if (dt <= 0.001) return { vx: 0, vy: 0 };

    return {
      vx: (latest.x - earliest.x) / dt, // px/sec
      vy: (latest.y - earliest.y) / dt,
    };
  }

  _onPointerUp(e) {
    if (!this.isActive || e.pointerId !== this.pointerId) return;

    const { vx, vy } = this._computeVelocity();
    const dx = e.clientX - this.startX;
    const dy = e.clientY - this.startY;
    const wasDragging = this.isDragging;

    this._cleanup();

    if (wasDragging && this.onEnd) {
      this.onEnd({
        dx,
        dy,
        vx,
        vy,
        clientX: e.clientX,
        clientY: e.clientY,
        nativeEvent: e,
      });
    }
  }

  _onPointerCancel(e) {
    if (!this.isActive || e.pointerId !== this.pointerId) return;
    this._cleanup();
    if (this.onCancel) this.onCancel({ nativeEvent: e });
  }

  _cleanup() {
    this.isActive = false;
    this.isDragging = false;
    if (this.pointerId !== null) {
      try {
        this.element.releasePointerCapture(this.pointerId);
      } catch (_) {}
      this.pointerId = null;
    }
    window.removeEventListener('pointermove', this._onPointerMove);
    window.removeEventListener('pointerup', this._onPointerUp);
    window.removeEventListener('pointercancel', this._onPointerCancel);
  }
}
