# Control Theory Master Formula Sheet
## Complete Engineering Quick Reference

**Generated:** 2025-10-09
**Source:** Control Theory Extracted Documents
**Purpose:** All key equations in one place for rapid engineering reference

---

## SECOND-ORDER SYSTEM FUNDAMENTALS

### Canonical Transfer Function
```
T(s) = ωₙ²/(s² + 2ζωₙs + ωₙ²)
```

### Pole Locations
```
s = -ζωₙ ± jωₙ√(1-ζ²)    [Underdamped: 0 < ζ < 1]
s = -ωₙ                   [Critically damped: ζ = 1]
s = -ζωₙ ± ωₙ√(ζ²-1)      [Overdamped: ζ > 1]
```

### Physical System Parameters
```
ζ = b/(2√(km))            [Damping ratio from physical parameters]
ωₙ = √(k/m)               [Natural frequency]
ωd = ωₙ√(1-ζ²)            [Damped natural frequency]
```

---

## TIME-DOMAIN SPECIFICATIONS

### Rise Time
```
tr ≈ 1.8/ωₙ               [Second-order, 0.3 < ζ < 0.8]
tr = 2.2τ                 [First-order, τ = time constant]
tr = (π - cos⁻¹(ζ))/(ωₙ√(1-ζ²))  [Precise second-order]
```

### Peak Time
```
tp = π/(ωₙ√(1-ζ²))        [Time to first overshoot]
```

### Percent Overshoot
```
%OS = exp(-πζ/√(1-ζ²)) × 100%
```

**Inverse (find ζ from overshoot):**
```
ζ = -ln(%OS/100) / √(π² + [ln(%OS/100)]²)
```

### Settling Time
```
ts ≈ 4/(ζωₙ)              [2% criterion]
ts ≈ 3/(ζωₙ)              [5% criterion]
```

### Delay Time
```
td ≈ (1 + 0.7ζ)/ωₙ        [50% final value]
```

---

## FREQUENCY-DOMAIN SPECIFICATIONS

### Bandwidth
```
Bandwidth × Rise Time ≈ 0.35 to 0.5
```

### Resonance Peak (for ζ < 0.707)
```
ωr = ωₙ√(1-2ζ²)           [Resonance frequency]
Mr = 1/(2ζ√(1-ζ²))        [Peak magnitude]
```

### Gain Margin
```
GM(dB) = -20log₁₀|G(jωpc)|    [Where ∠G(jωpc) = -180°]
```

### Phase Margin
```
PM = 180° + ∠G(jωgc)      [Where |G(jωgc)| = 0 dB]
```

### Approximate Damping Ratio from Phase Margin
```
ζ ≈ PM(degrees)/100       [Rule of thumb]
```

---

## STABILITY CRITERIA

### Routh-Hurwitz
**Necessary condition:** All coefficients of characteristic equation same sign

**Sufficient condition:** Zero sign changes in first column of Routh array

### Gain and Phase Margin Guidelines
```
GM > 6 dB                 [Industry standard]
PM > 45° to 60°           [45° classical, 60° robust]
```

### Nyquist Criterion
```
Z = N + P
```
Where:
- Z = number of unstable closed-loop poles
- N = number of clockwise encirclements of (-1,0)
- P = number of unstable open-loop poles

**For stability:** Z = 0 → N = -P

---

## STEADY-STATE ERROR

### Error Constants

**Position Error Constant:**
```
Kp = lim(s→0) G(s)
ess(step) = 1/(1+Kp)
```

**Velocity Error Constant:**
```
Kv = lim(s→0) sG(s)
ess(ramp) = 1/Kv
```

**Acceleration Error Constant:**
```
Ka = lim(s→0) s²G(s)
ess(parabola) = 1/Ka
```

### System Type Classification

| Type | Integrators | Step Error | Ramp Error | Parabola Error |
|------|------------|------------|------------|----------------|
| 0    | 0          | 1/(1+Kp)   | ∞          | ∞              |
| 1    | 1          | 0          | 1/Kv       | ∞              |
| 2    | 2          | 0          | 0          | 1/Ka           |

---

## FIRST-ORDER SYSTEMS

### Transfer Function
```
H(s) = K/(τs + 1)
```

### Time Response
```
y(t) = K(1 - e^(-t/τ))    [Step response]
```

### Frequency Response
```
|H(jω)| = K/√(1 + (ωτ)²)
∠H(jω) = -tan⁻¹(ωτ)
ωc = 1/τ                  [Corner frequency, -3dB point]
```

---

## LAPLACE TRANSFORM PAIRS

| Time Domain f(t) | Laplace F(s) |
|------------------|--------------|
| δ(t) [impulse]   | 1            |
| u(t) [step]      | 1/s          |
| t [ramp]         | 1/s²         |
| e^(-at)          | 1/(s+a)      |
| sin(ωt)          | ω/(s²+ω²)    |
| cos(ωt)          | s/(s²+ω²)    |
| e^(-at)sin(ωt)   | ω/[(s+a)²+ω²]|

### Laplace Properties
```
L{df/dt} = sF(s) - f(0⁻)  [Differentiation]
L{∫f(τ)dτ} = F(s)/s       [Integration]
```

---

## BLOCK DIAGRAM ALGEBRA

### Series Connection
```
G(s) = G₁(s) · G₂(s)
```

### Parallel Connection
```
G(s) = G₁(s) + G₂(s)
```

### Negative Feedback
```
T(s) = G(s)/(1 + G(s)H(s))
```

### Unity Feedback
```
T(s) = G(s)/(1 + G(s))
```

---

## BODE PLOT ASYMPTOTES

### First-Order Pole: 1/(τs+1)
**Magnitude:**
- ω < ωc: 0 dB (flat)
- ω > ωc: -20 dB/decade
- At ωc: -3 dB

**Phase:**
- ω < 0.1ωc: 0°
- 0.1ωc to 10ωc: 0° to -90°
- ω > 10ωc: -90°
- At ωc: -45°

### First-Order Zero: (τs+1)
**Magnitude:**
- ω < ωc: 0 dB
- ω > ωc: +20 dB/decade
- At ωc: +3 dB

**Phase:**
- ω < 0.1ωc: 0°
- 0.1ωc to 10ωc: 0° to +90°
- ω > 10ωc: +90°
- At ωc: +45°

### Integrator: 1/s
**Magnitude:** -20 dB/decade slope through 0 dB at ω=1
**Phase:** Constant -90°

### Differentiator: s
**Magnitude:** +20 dB/decade slope through 0 dB at ω=1
**Phase:** Constant +90°

### Second-Order Pole
**Magnitude:**
- ω < ωₙ: 0 dB
- ω > ωₙ: -40 dB/decade
- At ωₙ: Depends on ζ (resonance peak if ζ < 0.707)

**Phase:**
- Transitions from 0° to -180° over ~2 decades
- At ωₙ: -90°
- Sharper transition for lower ζ

---

## PID CONTROLLER

### Standard Form
```
Gc(s) = Kp + Ki/s + Kd·s
```

### Parallel Form
```
Gc(s) = Kp(1 + 1/(Ti·s) + Td·s)
```
Where Ti = Kp/Ki, Td = Kd/Kp

### Derivative with Filter
```
Gc(s) = Kp + Ki/s + Kd·s/(1+s/N)
```
N = 10 to 100 (filter coefficient)

---

## LEAD-LAG COMPENSATORS

### Lead Compensator (Phase Boost)
```
Gc(s) = Kc(s+z)/(s+p)     [z < p]
```

**Maximum phase boost:**
```
φmax = sin⁻¹((1-α)/(1+α))
```
Where α = z/p < 1

**Occurs at:**
```
ωm = √(zp)
```

### Lag Compensator (DC Gain Boost)
```
Gc(s) = Kc(s+z)/(s+p)     [z > p]
```

**DC gain increase:**
```
Gain = z/p
```

---

## ROOT LOCUS RULES

### Basic Properties
1. Number of branches = number of open-loop poles
2. Start at open-loop poles (K=0)
3. End at open-loop zeros or ∞ (K→∞)
4. Real axis segments where odd number of poles+zeros to right
5. Asymptotes at angles: θa = ±180°(2k+1)/(P-Z), k=0,1,2...
6. Centroid: σa = (Σpoles - Σzeros)/(P-Z)
7. Breakaway points where dK/ds = 0

---

## SPECIFICATION CONVERSION FORMULAS

### Given: Overshoot %OS, Find ζ
```
ζ = -ln(%OS/100) / √(π² + [ln(%OS/100)]²)
```

### Given: Settling Time ts and ζ, Find ωₙ
```
ωₙ = 4/(ζ·ts)             [2% criterion]
ωₙ = 3/(ζ·ts)             [5% criterion]
```

### Given: Rise Time tr, Find ωₙ
```
ωₙ ≈ 1.8/tr               [Second-order, typical ζ]
```

### Given: Phase Margin, Estimate ζ
```
ζ ≈ PM(degrees)/100
```

---

## DISCRETE-TIME EQUIVALENTS

### Sample Rate Selection
```
fs ≥ 10 × Bandwidth
fs ≥ 30 × ωₙ
```

### Tustin (Bilinear) Transformation
```
s → 2(z-1)/(T(z+1))
```
Where T = sample period

---

## POLE LOCATION GUIDELINES

### Dominant Pole Placement
```
Real part: σ = ζωₙ        [Controls settling time]
Imag part: ωd = ωₙ√(1-ζ²) [Controls oscillation frequency]
```

### Additional Poles
Place 5-10× farther left than dominant poles to maintain dominant pole approximation

---

## PHYSICAL INTERPRETATIONS

### Pole in LHP: s = -σ
```
Time response: Ce^(-σt)   [Exponential decay]
```

### Complex Poles: s = -ζωₙ ± jωd
```
Time response: Ae^(-ζωₙt)sin(ωdt + φ)  [Damped oscillation]
```

### Pole on Imaginary Axis: s = ±jω
```
Time response: Asin(ωt + φ)  [Sustained oscillation, marginal stability]
```

### Pole in RHP: s = +σ
```
Time response: Ce^(+σt)   [Exponential growth, UNSTABLE]
```

---

## QUICK STABILITY CHECKS

### Second-Order
```
s² + bs + c: Stable if b > 0 AND c > 0
```

### Third-Order
```
s³ + as² + bs + c: Stable if a,b,c > 0 AND ab > c
```

---

## COMMON DESIGN TRADEOFFS

### Speed vs. Overshoot
- High ωₙ → fast response BUT low ζ → high overshoot
- Solution: ζ = 0.5-0.7 balances both

### Accuracy vs. Stability
- More integrators → better accuracy BUT more phase lag → lower margins
- Solution: Add lead compensation for phase boost

### Bandwidth vs. Noise
- Wide bandwidth → fast tracking BUT amplifies noise
- Solution: Bandwidth just wide enough for specs, add sensor filtering

---

## NUMERICAL EXAMPLES

### Example 1: Translate Specs to Parameters
**Given:** ts < 2 sec, %OS < 10%

**Solution:**
```
%OS < 10% → ζ ≥ 0.6
ts = 4/(ζωₙ) ≤ 2 → ζωₙ ≥ 2
For ζ = 0.6: ωₙ ≥ 3.33 rad/s

Design: ζ = 0.6-0.7, ωₙ = 3.5-4.0 rad/s
Poles: s = -2.1 ± j2.8
```

### Example 2: Verify Stability from Routh Array
**Given:** s³ + 10s² + 31s + (30+K) = 0

**Routh Array:**
```
s³ |  1         31
s² | 10      (30+K)
s¹ | (280-K)/10  0
s⁰ | 30+K
```

**Stability:** (280-K)/10 > 0 AND 30+K > 0
**Result:** -30 < K < 280

---

## MATLAB/PYTHON QUICK COMMANDS

### MATLAB
```matlab
sys = tf([num], [den])              % Create transfer function
step(sys)                           % Step response
bode(sys)                           % Bode plot
rlocus(sys)                         % Root locus
[GM,PM,Wcg,Wcp] = margin(sys)       % Margins
pole(sys)                           % Poles
stepinfo(sys)                       % Rise time, overshoot, etc.
```

### Python
```python
import control as ct
sys = ct.TransferFunction([num], [den])
t, y = ct.step_response(sys)
ct.bode_plot(sys)
ct.root_locus(sys)
poles = ct.poles(sys)
```

---

## UNITS AND NOTATION

| Symbol | Meaning | Units |
|--------|---------|-------|
| ζ | Damping ratio | dimensionless |
| ωₙ | Natural frequency | rad/s |
| ωd | Damped natural frequency | rad/s |
| ωr | Resonance frequency | rad/s |
| τ | Time constant | s |
| K | Gain | varies |
| tr | Rise time | s |
| tp | Peak time | s |
| ts | Settling time | s |
| %OS | Percent overshoot | % |
| GM | Gain margin | dB |
| PM | Phase margin | degrees |
| Mr | Resonance peak | dimensionless |

---

## REFERENCES
- Ogata, "Modern Control Engineering"
- Dorf & Bishop, "Modern Control Systems"
- Franklin, Powell, Emami-Naeini, "Feedback Control of Dynamic Systems"

**End of Master Formula Sheet**
