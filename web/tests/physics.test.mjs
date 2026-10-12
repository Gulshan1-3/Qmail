/**
 * Automated test suite for QuMail Fluid Physics Engine
 */

import assert from 'node:assert/strict';
import { project, rubberband, clamp } from '../js/physics/projection.js';
import { Spring } from '../js/physics/spring.js';

console.log('🧪 Running QuMail Fluid Physics Engine Test Suite...\n');

// 1. Momentum Projection
{
  const v = 1000; // 1000 px/s
  const p = project(v, 0.998);
  // (1000 / 1000) * 0.998 / (1 - 0.998) = 1 * 0.998 / 0.002 = 499
  assert(Math.abs(p - 499) < 0.1, `Expected projected distance ~499, got ${p}`);
  console.log('✓ project() computes correct exponential momentum decay');

  // Zero velocity projects 0
  assert.equal(project(0), 0);
  console.log('✓ project(0) yields 0');
}

// 2. Rubber-banding Boundary Resistance
{
  const dim = 100;
  const c = 0.55;
  const rb50 = rubberband(50, dim, c);
  const rb100 = rubberband(100, dim, c);
  const rb500 = rubberband(500, dim, c);

  // Growth must be sub-linear (slowing down as overshoot increases)
  assert(rb50 > 0 && rb100 > rb50 && rb500 > rb100);
  assert(rb500 < dim, `Rubberbanded overshoot must not exceed dimension bound, got ${rb500}`);
  assert.equal(rubberband(0, dim), 0);
  console.log('✓ rubberband() exhibits progressive boundary resistance');
}

// 3. Critically Damped Spring Solver (zeta = 1.0)
{
  const s = new Spring({ damping: 1.0, response: 0.35, initialValue: 0 });
  s.to(100);

  // At t=0, val should be 0
  const at0 = s.evaluateAt(0);
  assert(Math.abs(at0.val - 0) < 0.001);

  // Over time, position monotonically approaches 100 without overshooting
  let lastVal = 0;
  let overshot = false;
  for (let t = 0.05; t <= 1.0; t += 0.05) {
    const { val } = s.evaluateAt(t);
    if (val > 100.01) overshot = true;
    assert(val >= lastVal - 0.001, `Critically damped spring must not oscillate backwards: ${val} vs ${lastVal}`);
    lastVal = val;
  }
  assert(!overshot, 'Critically damped spring (damping 1.0) must not overshoot target');
  console.log('✓ Spring(damping: 1.0) is strictly critically damped with 0 overshoot');
}

// 4. Underdamped Spring (zeta = 0.8)
{
  const s = new Spring({ damping: 0.8, response: 0.35, initialValue: 0 });
  s.to(100);

  // Should overshoot target slightly
  let maxVal = 0;
  for (let t = 0.01; t <= 1.0; t += 0.01) {
    const { val } = s.evaluateAt(t);
    if (val > maxVal) maxVal = val;
  }
  assert(maxVal > 100, `Underdamped spring must exhibit slight overshoot, got max ${maxVal}`);
  assert(maxVal < 115, `Underdamped spring (0.8) overshoot should be subtle (~10%), got ${maxVal}`);
  console.log(`✓ Spring(damping: 0.8) exhibits authentic physical bounce (overshoot: ${maxVal.toFixed(1)}px)`);
}

// 5. Retargeting & Interruption
{
  const s = new Spring({ damping: 1.0, response: 0.35, initialValue: 0 });
  s.to(100);
  // Mid-flight at 0.15s
  const mid = s.evaluateAt(0.15);
  // Interrupt: snap to mid position and retarget to 0 with blended velocity
  s.snapTo(mid.val, mid.vel);
  s.to(0, mid.vel);
  const next = s.evaluateAt(0.01);
  // Must start from mid.val smoothly
  assert(Math.abs(next.val - mid.val) < 2.0, `Interruption must start from current presentation value`);
  console.log('✓ Interruption smoothly retargets without position jump');
}

console.log('\n🎉 All QuMail Fluid Physics Engine Tests Passed!');
