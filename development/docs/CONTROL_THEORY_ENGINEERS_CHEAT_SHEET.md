# Control Theory Engineer's Cheat Sheet
## One-Page Quick Reference for Daily Engineering Work

---

## CRITICAL FORMULAS

### Second-Order System
```
T(s) = ωₙ²/(s² + 2ζωₙs + ωₙ²)
Poles: s = -ζωₙ ± jωₙ√(1-ζ²)
```

### Time Response
```
%OS = exp(-πζ/√(1-ζ²)) × 100%        [Overshoot]
tp = π/(ωₙ√(1-ζ²))                   [Peak time]
ts ≈ 4/(ζωₙ)                         [Settling time, 2%]
tr ≈ 1.8/ωₙ                          [Rise time]
```

### Frequency Domain
```
GM(dB) = -20log₁₀|G(jωpc)|           [ω where ∠G = -180°]
PM = 180° + ∠G(jωgc)                 [ω where |G| = 0 dB]
ζ ≈ PM(degrees)/100                  [Quick estimate]
```

---

## STANDARD DESIGN VALUES

### Damping Ratio (ζ) Selection
| ζ | %OS | Application |
|---|-----|-------------|
| 0.5 | 16% | ITAE optimal |
| **0.6** | **10%** | **Typical target** |
| 0.7 | 5% | Conservative |
| 1.0 | 0% | Critical (fastest without overshoot) |

### Stability Margins (Industry Standard)
```
GM > 6 dB          [Factor of 2 gain tolerance]
PM > 45-60°        [45° classical, 60° robust]
```

---

## SPECIFICATION TRANSLATION

### Given: %OS, ts → Find: ζ, ωₙ
```
1. ζ = -ln(%OS/100) / √(π² + [ln(%OS/100)]²)
2. ωₙ = 4/(ζ·ts)   [Using ts formula]
3. Poles: s = -ζωₙ ± jωₙ√(1-ζ²)
```

**Example:** ts < 2s, %OS < 10%
- ζ ≥ 0.6, ωₙ ≥ 3.33 rad/s → **Design: ζ=0.6, ωₙ=3.5**

---

## STABILITY QUICK CHECKS

### Routh-Hurwitz
**2nd-order:** s² + bs + c → Stable if **b > 0 AND c > 0**
**3rd-order:** s³ + as² + bs + c → Stable if **a,b,c > 0 AND ab > c**

### Pole Locations
```
LHP (Re < 0): Stable
Imaginary axis: Marginal (sustained oscillation)
RHP (Re > 0): UNSTABLE
```

---

## BODE PLOT QUICK SLOPES

| Element | Magnitude Slope | Phase |
|---------|----------------|-------|
| Integrator (1/s) | -20 dB/dec | -90° |
| Pole (1/(τs+1)) | -20 dB/dec above ωc | 0° → -90° |
| Zero ((τs+1)) | +20 dB/dec above ωc | 0° → +90° |
| 2nd-order pole | -40 dB/dec above ωₙ | 0° → -180° |

**Corner frequency (ωc):** -3 dB point, phase = ±45°

---

## PID TUNING (ZIEGLER-NICHOLS)

### Closed-Loop Method
1. Set Ki = Kd = 0, find ultimate gain Ku (sustained oscillation)
2. Record ultimate period Pu
3. Apply:
```
P:   Kp = 0.5Ku
PI:  Kp = 0.45Ku, Ti = 0.83Pu, Ki = Kp/Ti
PID: Kp = 0.6Ku, Ti = 0.5Pu, Td = 0.125Pu
```

### Starting Values (No Test)
```
Kp = 1.0, Ki = 0.1, Kd = 0   [Conservative start]
```
Increase Kp until oscillation → Reduce to 50%
Add Ki to eliminate steady-state error
Add Kd if overshoot excessive (small, 0.1×Kp max)

---

## SYSTEM TYPE (STEADY-STATE ERROR)

| Type | Integrators | Step Error | Ramp Error | Use Case |
|------|------------|------------|------------|----------|
| 0 | 0 | Finite | ∞ | Simple P control |
| 1 | 1 (PI) | 0 | Finite | **Most industrial** |
| 2 | 2 | 0 | 0 | Tracking (satellites) |

---

## METHOD SELECTION FLOWCHART

```
Stability analysis?
  → Open-loop stable? → YES: Bode (easiest, GM/PM)
                      → NO: Nyquist (handles RHP poles)
  → Parameter range? → Routh-Hurwitz (algebraic, fast)

Design controller?
  → SISO? → YES: PID tuning or Root Locus
          → NO (MIMO): State-space (LQR, pole placement)

Need constraints? → MPC
Large uncertainty? → H-infinity
Parameters vary? → Adaptive control
```

---

## COMPENSATOR QUICK REFERENCE

### Lead (Phase Boost)
```
Gc(s) = K(s+z)/(s+p),  z < p
Max phase: φmax = sin⁻¹((1-α)/(1+α)), α = z/p
Occurs at: ωm = √(zp)
```
**Use:** Improve PM (add 30-60° phase)

### Lag (DC Gain Boost)
```
Gc(s) = K(s+z)/(s+p),  z > p
DC gain: z/p (typically 5-20)
```
**Use:** Reduce steady-state error without affecting PM

---

## DISCRETIZATION (DIGITAL CONTROL)

### Sample Rate
```
fs ≥ 10 × Bandwidth    [Typical]
fs ≥ 30 × ωₙ           [Conservative]
```

### Tustin Transformation (Recommended)
```
s → 2(z-1)/(T(z+1))    [T = sample period]
```

---

## COMMON DESIGN VALUES BY APPLICATION

### Aerospace
- Inner loops: ωₙ > 100 rad/s, ζ = 0.7-0.9, GM > 6 dB, PM > 45°

### Automotive Suspension
- Comfort: ωₙ ≈ 9 rad/s, ζ = 0.2-0.4
- Sport: ωₙ ≈ 9 rad/s, ζ = 0.5-0.7

### Process Control (Reactors)
- ωₙ ≈ 0.01 rad/s, ζ = 1.0, ts < 5 min

### Robotics
- Position loop: 20-50 Hz, ζ = 0.7-0.9, zero overshoot

### CNC Machining
- Position: ±1 mm to ±4 μm, ts = 0.05-0.1 s, ζ = 1.0

---

## TROUBLESHOOTING GUIDE

| Problem | Likely Cause | Fix |
|---------|--------------|-----|
| Excessive overshoot | ζ too low | Increase ζ to 0.6-0.7 |
| Slow response | ωₙ too low | Increase ωₙ |
| Sustained oscillation | Poles on jω axis | Add damping |
| Instability | RHP poles | Reduce gain, check margins |
| SS error large | Type 0 system | Add integrator (Type 1) |
| Noisy control | High bandwidth/Kd | Filter derivative, reduce BW |

---

## MATLAB/PYTHON ONE-LINERS

### MATLAB
```matlab
sys = tf([num],[den]);             % Transfer function
step(sys); stepinfo(sys)           % Time response
bode(sys); [GM,PM]=margin(sys)     % Frequency response
rlocus(sys)                        % Root locus
pole(sys); zero(sys)               % Pole-zero locations
```

### Python
```python
import control as ct
sys = ct.TransferFunction([num],[den])
t,y = ct.step_response(sys)
ct.bode_plot(sys)
ct.root_locus(sys)
```

---

## CRITICAL CHECKS BEFORE DEPLOYMENT

- [ ] All poles in LHP (stability)
- [ ] GM > 6 dB, PM > 45° (robustness)
- [ ] Step response meets specs (ts, %OS)
- [ ] Anti-windup implemented (if integrator)
- [ ] Derivative filtered (if PID)
- [ ] Actuator limits respected (no saturation)
- [ ] Sample rate adequate (fs ≥ 10×BW)
- [ ] Tested across operating conditions

---

## CONVERSION FACTORS

```
Frequency: f (Hz) = ω (rad/s) / (2π)
Time constant: τ (s) → ωc = 1/τ (rad/s)
Damping: PM ≈ 100ζ (degrees)
Bandwidth: BW × tr ≈ 0.35-0.5
```

---

## WHEN TO ESCALATE

**Use advanced methods (MPC, robust, adaptive) if:**
- MIMO with strong interactions
- Constraints critical (saturation, limits)
- Large parameter uncertainty (±30%+)
- Economic optimization significant
- Simple PID insufficient after tuning

**Otherwise:** Classical PID + Bode margins sufficient (85-95% of cases)

---

## GOLDEN RULES

1. **Start simple:** Try PID before advanced methods
2. **Check margins:** GM > 6 dB, PM > 45° minimum
3. **Test robustness:** ±20% parameter variation
4. **Respect physics:** Actuator limits, sensor noise
5. **Validate:** Simulation → Bench test → Field test

---

**Keep this sheet accessible during design work!**

---

## QUICK EXAMPLE: FULL DESIGN IN 5 STEPS

**Spec:** "ts < 2s, %OS < 10%"

**Step 1:** Translate specs
- %OS < 10% → ζ ≥ 0.6
- ts = 4/(ζωₙ) ≤ 2 → ζωₙ ≥ 2 → ωₙ ≥ 3.33 (for ζ=0.6)

**Step 2:** Choose design
- ζ = 0.6, ωₙ = 3.5 rad/s (margin)
- Poles: s = -2.1 ± j2.8

**Step 3:** Design controller
- Root locus: Add compensator to achieve poles
- Or PID: Tune for ζ, ωₙ response

**Step 4:** Verify
- Bode: Check GM > 6 dB, PM > 45°
- Step response: Confirm ts, %OS

**Step 5:** Implement
- Discretize (fs ≥ 35 Hz for ωₙ=3.5)
- Add anti-windup, filters
- Test!

---

**END OF CHEAT SHEET**
