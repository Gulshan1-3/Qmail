/**
 * Apple WWDC 2018 Designing Fluid Interfaces — Analytical Spring Simulation
 * Solves the mass-spring-damper differential equation analytically for
 * zero numerical drift, arbitrary dt steps, and clean interruptibility.
 */

const raf = typeof requestAnimationFrame !== 'undefined'
  ? requestAnimationFrame
  : (cb) => setTimeout(() => cb(performance.now()), 16);
const cancelRaf = typeof cancelAnimationFrame !== 'undefined'
  ? cancelAnimationFrame
  : (id) => clearTimeout(id);

export class Spring {
  /**
   * @param {Object} options
   * @param {number} [options.damping=1.0] - Damping ratio (1.0 = critically damped, 0.8 = slight bounce)
   * @param {number} [options.response=0.35] - Response time in seconds (lower = snappier)
   * @param {number} [options.initialValue=0] - Initial value
   * @param {number} [options.initialVelocity=0] - Initial velocity (px/sec)
   * @param {number} [options.precision=0.05] - Distance threshold to consider settled
   * @param {number} [options.velocityThreshold=0.5] - Velocity threshold to consider settled
   */
  constructor(options = {}) {
    this.damping = options.damping ?? 1.0;
    this.response = options.response ?? 0.35;
    this.precision = options.precision ?? 0.05;
    this.velocityThreshold = options.velocityThreshold ?? 0.5;

    this.currentValue = options.initialValue ?? 0;
    this.targetValue = this.currentValue;
    this.currentVelocity = options.initialVelocity ?? 0;

    this.isSettled = true;
    this.onUpdate = null;
    this.onComplete = null;

    // Internal state for analytical evaluation
    this.startTime = 0;
    this.startPos = this.currentValue;
    this.startVel = this.currentVelocity;
    this._rafId = null;
  }

  setParams(damping, response) {
    this.damping = damping;
    this.response = response;
  }

  /**
   * Set target value. If moving, smoothly blends velocity without discontinuity.
   * @param {number} target - New target value
   * @param {number} [velocityOverride] - Optional velocity override (px/sec), e.g. from pointer release
   */
  to(target, velocityOverride = null) {
    this.targetValue = target;
    this.startPos = this.currentValue;
    this.startVel = velocityOverride !== null ? velocityOverride : this.currentVelocity;
    this.startTime = performance.now();
    this.isSettled = false;

    this._startLoop();
  }

  /**
   * Sets value instantly without animation (e.g. during 1:1 direct dragging).
   */
  snapTo(value, velocity = 0) {
    this.stop();
    this.currentValue = value;
    this.targetValue = value;
    this.currentVelocity = velocity;
    this.startPos = value;
    this.startVel = velocity;
    this.isSettled = true;
    if (this.onUpdate) this.onUpdate(this.currentValue, this.currentVelocity);
  }

  stop() {
    if (this._rafId !== null) {
      cancelRaf(this._rafId);
      this._rafId = null;
    }
    this.isSettled = true;
  }

  _startLoop() {
    if (this._rafId !== null) return;
    const tick = (now) => {
      this._step(now);
      if (!this.isSettled) {
        this._rafId = raf(tick);
      } else {
        this._rafId = null;
        if (this.onComplete) this.onComplete(this.currentValue);
      }
    };
    this._rafId = raf(tick);
  }

  _step(now) {
    const t = Math.max(0, (now - this.startTime) / 1000);
    const { val, vel } = this.evaluateAt(t);

    this.currentValue = val;
    this.currentVelocity = vel;

    const dist = Math.abs(this.currentValue - this.targetValue);
    const speed = Math.abs(this.currentVelocity);

    if (dist < this.precision && speed < this.velocityThreshold && t > 0.05) {
      this.currentValue = this.targetValue;
      this.currentVelocity = 0;
      this.isSettled = true;
    }

    if (this.onUpdate) {
      this.onUpdate(this.currentValue, this.currentVelocity);
    }
  }

  /**
   * Analytical evaluation of position and velocity at time t (seconds).
   */
  evaluateAt(t) {
    const omega = (2 * Math.PI) / Math.max(0.01, this.response);
    const zeta = this.damping;
    const x0 = this.startPos - this.targetValue;
    const v0 = this.startVel;

    if (zeta >= 0.999 && zeta <= 1.001) {
      // Critically Damped
      const c1 = x0;
      const c2 = v0 + omega * x0;
      const decay = Math.exp(-omega * t);
      const val = this.targetValue + (c1 + c2 * t) * decay;
      const vel = (c2 - omega * (c1 + c2 * t)) * decay;
      return { val, vel };
    } else if (zeta < 0.999) {
      // Underdamped (bouncy)
      const omegaD = omega * Math.sqrt(1 - zeta * zeta);
      const c1 = x0;
      const c2 = (v0 + zeta * omega * x0) / omegaD;
      const decay = Math.exp(-zeta * omega * t);
      const sinT = Math.sin(omegaD * t);
      const cosT = Math.cos(omegaD * t);
      const val = this.targetValue + decay * (c1 * cosT + c2 * sinT);
      const vel = decay * ((c2 * omegaD - c1 * zeta * omega) * cosT - (c1 * omegaD + c2 * zeta * omega) * sinT);
      return { val, vel };
    } else {
      // Overdamped
      const gamma = omega * Math.sqrt(zeta * zeta - 1);
      const r1 = -zeta * omega + gamma;
      const r2 = -zeta * omega - gamma;
      const c2 = (v0 - r1 * x0) / (r2 - r1);
      const c1 = x0 - c2;
      const exp1 = Math.exp(r1 * t);
      const exp2 = Math.exp(r2 * t);
      const val = this.targetValue + c1 * exp1 + c2 * exp2;
      const vel = c1 * r1 * exp1 + c2 * r2 * exp2;
      return { val, vel };
    }
  }
}

/**
 * 2D Spring animating independent X and Y axes.
 * Avoids desync when X and Y carry different initial velocities.
 */
export class Spring2D {
  constructor(options = {}) {
    this.x = new Spring(options);
    this.y = new Spring(options);
    this.onUpdate = null;
    this.onComplete = null;

    const checkComplete = () => {
      if (this.x.isSettled && this.y.isSettled && this.onComplete) {
        this.onComplete(this.x.currentValue, this.y.currentValue);
      }
    };

    this.x.onUpdate = () => {
      if (this.onUpdate) this.onUpdate(this.x.currentValue, this.y.currentValue);
    };
    this.y.onUpdate = () => {
      if (this.onUpdate) this.onUpdate(this.x.currentValue, this.y.currentValue);
    };

    this.x.onComplete = checkComplete;
    this.y.onComplete = checkComplete;
  }

  to(targetX, targetY, velX = null, velY = null) {
    this.x.to(targetX, velX);
    this.y.to(targetY, velY);
  }

  snapTo(x, y, velX = 0, velY = 0) {
    this.x.snapTo(x, velX);
    this.y.snapTo(y, velY);
  }

  stop() {
    this.x.stop();
    this.y.stop();
  }

  get isSettled() {
    return this.x.isSettled && this.y.isSettled;
  }
}
