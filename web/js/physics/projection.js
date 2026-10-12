/**
 * Apple WWDC 2018 Designing Fluid Interfaces — Projection & Rubberbanding
 * Mathematical models for momentum projection and boundary resistance.
 */

/**
 * Projects a gesture's landing point based on exponential velocity decay.
 * Exactly mirrors Apple's scroll deceleration and flick throw equation.
 * 
 * @param {number} initialVelocity - Velocity at pointer release in px/second
 * @param {number} decelerationRate - Decay coefficient (0.998 default for iOS scroll, 0.99 for snappier)
 * @returns {number} Projected offset from release point in pixels
 */
export function project(initialVelocity, decelerationRate = 0.998) {
  if (Math.abs(initialVelocity) < 1) return 0;
  return (initialVelocity / 1000) * decelerationRate / (1 - decelerationRate);
}

/**
 * Hyperbolic rubber-banding resistance function.
 * Smoothly decelerates movement past boundaries without hitting a hard wall.
 * 
 * @param {number} overshoot - Distance dragged beyond the boundary in px (signed)
 * @param {number} dimension - Length/height of the boundary dimension in px
 * @param {number} constant - Resistance coefficient (0.55 Apple standard)
 * @returns {number} Visually attenuated distance
 */
export function rubberband(overshoot, dimension, constant = 0.55) {
  if (overshoot === 0 || dimension <= 0) return 0;
  const sign = Math.sign(overshoot);
  const absOvershoot = Math.abs(overshoot);
  return sign * ((absOvershoot * dimension * constant) / (dimension + constant * absOvershoot));
}

/**
 * Restricts value within bounds [min, max].
 */
export function clamp(val, min, max) {
  return Math.min(Math.max(val, min), max);
}
