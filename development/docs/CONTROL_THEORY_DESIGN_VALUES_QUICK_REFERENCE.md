# Control Theory Design Values Quick Reference
## Common Engineering Design Parameters

**Generated:** 2025-10-09
**Purpose:** Standard design values for daily control system engineering work

---

## DAMPING RATIO (ζ) COMMON VALUES

### Overshoot-Based Selection

| ζ Value | %OS | Application | Reasoning |
|---------|-----|-------------|-----------|
| **0.3** | 37% | Fast response where overshoot tolerable | Aggressive, minimal damping |
| **0.4** | 25% | Moderate speed with acceptable overshoot | Balanced for speed |
| **0.5** | 16% | Optimal for ITAE criterion | Often-optimal mathematically |
| **0.6** | 9.5% | **TYPICAL DESIGN TARGET** | **Industry standard** |
| **0.7** | 4.6% | Conservative, minimal overshoot | Low overshoot needed |
| **0.8** | 1.5% | Very conservative | Safety-critical |
| **1.0** | 0% | Critical damping | Fastest without overshoot |
| **> 1.0** | 0% | Overdamped | Sluggish but guaranteed no overshoot |

### Application-Specific Recommendations

**Aerospace (Aircraft Autopilots):**
- Inner rate-damping loop: ζ = 0.7-0.9 (high damping, no oscillation)
- Middle attitude loop: ζ = 0.6-0.7 (balanced)
- Outer guidance loop: ζ = 0.5-0.6 (acceptable overshoot for speed)

**Automotive (Suspension):**
- Comfort mode: ζ = 0.2-0.4 (soft ride, body motion acceptable)
- Performance mode: ζ = 0.5-0.7 (reduced roll/pitch during transients)

**Industrial (Hydraulic Servos):**
- Position control: ζ = 0.6-0.8 (micron-level accuracy, zero overshoot)
- Force control: ζ = 0.5-0.7 (fast response with some overshoot acceptable)

**Process Control (Chemical):**
- Temperature loops: ζ = 1.0 (critical, no overshoot for safety)
- Flow/pressure loops: ζ = 0.6-0.8 (faster response acceptable)

**Robotics:**
- Joint position: ζ = 0.7-0.9 (precision, minimal oscillation)
- Trajectory tracking: ζ = 0.6-0.8 (balance speed and accuracy)

**Door Closers (Automotive/Building):**
- ζ = 1.0 (critical damping: no slam, no bounce)

---

## NATURAL FREQUENCY (ωₙ) TYPICAL RANGES

### By Application Speed Class

**Very Fast (< 0.1 second settling):**
- ωₙ > 40 rad/s
- Examples: Robotic arms, aerospace control surfaces, high-speed servos

**Fast (0.1-1 second settling):**
- ωₙ = 4-40 rad/s
- Examples: CNC machines, precision positioning, automotive suspension

**Moderate (1-10 seconds settling):**
- ωₙ = 0.4-4 rad/s
- Examples: Ship steering, building HVAC zones, some chemical processes

**Slow (10-300 seconds settling):**
- ωₙ = 0.013-0.4 rad/s
- Examples: Large reactor vessels, thermal processes, batch manufacturing

**Very Slow (> 300 seconds settling):**
- ωₙ < 0.013 rad/s
- Examples: Large building thermal control, certain geological processes

### Calculation from Settling Time
For 2% settling criterion:
```
ωₙ = 4/(ζ·ts)
```

**Example:**
- ts = 2 sec, ζ = 0.6 → ωₙ = 4/(0.6×2) = 3.33 rad/s

---

## GAIN MARGIN (GM) STANDARDS

### Industry Guidelines

| GM (dB) | Classification | Application |
|---------|---------------|-------------|
| **< 3 dB** | Inadequate | Unstable or marginally stable |
| **3-6 dB** | Poor | Avoid, insufficient robustness |
| **6-10 dB** | **Acceptable** | **Industry minimum standard** |
| **10-20 dB** | Good | Recommended for most applications |
| **> 20 dB** | Conservative | Very robust, may sacrifice performance |

**Aerospace Mandate:** GM > 6 dB (regulatory requirement)

**Safety-Critical Systems:** GM > 10 dB recommended

---

## PHASE MARGIN (PM) STANDARDS

### Industry Guidelines

| PM (degrees) | Classification | Approximate ζ | Application |
|--------------|---------------|---------------|-------------|
| **< 30°** | Inadequate | < 0.3 | Oscillatory, poor robustness |
| **30-45°** | Marginal | 0.3-0.45 | Minimum acceptable |
| **45-60°** | **Good** | 0.45-0.6 | **Classical standard** |
| **60-90°** | **Excellent** | 0.6-0.9 | **Modern robust design** |
| **> 90°** | Conservative | > 0.9 | May be overdamped |

**Aerospace Standard:** PM > 45° (minimum), 60° (preferred)

**Rule of Thumb:**
```
ζ ≈ PM(degrees)/100
```

**Example:** PM = 60° → ζ ≈ 0.6

---

## RESONANCE PEAK (Mr) LIMITS

### Frequency Response Design Targets

| Mr | Implications | Design Action |
|----|--------------|---------------|
| **< 1.1** | Excellent damping (ζ > 0.7) | Well-damped system |
| **1.1-1.5** | Good damping (0.4 < ζ < 0.7) | **Typical target** |
| **1.5-2.0** | Moderate damping (0.3 < ζ < 0.4) | Acceptable if speed needed |
| **> 2.0** | Lightly damped (ζ < 0.3) | Likely excessive overshoot |

**Maximally Flat:** Mr = 1.0 occurs at ζ = 0.707

---

## BANDWIDTH TARGETS

### Bandwidth vs. Rise Time
```
BW × tr ≈ 0.35 to 0.5
```

**Example:**
- tr = 0.1 sec → BW ≈ 3.5-5 Hz

### Application-Specific Bandwidths

**Aerospace:**
- Inner loops: 100+ Hz
- Middle loops: 1-10 Hz
- Outer loops: 0.1-1 Hz

**Industrial Servo:**
- Velocity loop: 100-500 Hz
- Position loop: 20-50 Hz

**Process Control:**
- Flow loops: 1-10 Hz
- Temperature loops: 0.01-0.1 Hz
- Composition loops: 0.001-0.01 Hz

---

## SYSTEM TYPE SELECTION

| Application | Required Type | Reason |
|-------------|--------------|--------|
| **Position tracking (constant setpoint)** | Type 1 | Zero steady-state error to steps |
| **Velocity tracking (constant rate)** | Type 2 | Zero error to ramps |
| **Simple proportional control** | Type 0 | Finite error acceptable |
| **Most industrial applications** | Type 1 | PI control standard |

---

## SAMPLE RATE SELECTION (DIGITAL CONTROL)

### Minimum Sample Rates

**Conservative:**
```
fs ≥ 30 × ωₙ
```

**Typical:**
```
fs ≥ 10 × Bandwidth
```

**Aggressive (use with caution):**
```
fs ≥ 5 × Bandwidth
```

### Application Examples

**Fast Servos:**
- ωₙ = 40 rad/s → fs ≥ 1200 Hz (30×) or fs ≥ 190 Hz (10×BW)
- **Typical choice:** 500-1000 Hz

**Process Control:**
- ωₙ = 0.01 rad/s → fs ≥ 0.3 Hz
- **Typical choice:** 1-10 Hz (oversampled for noise filtering)

---

## PID TUNING STARTING VALUES

### Ziegler-Nichols Closed-Loop Method

1. Set Ki = Kd = 0, increase Kp until sustained oscillation
2. Record ultimate gain Ku and ultimate period Pu
3. Apply rules:

**P Controller:**
```
Kp = 0.5Ku
```

**PI Controller:**
```
Kp = 0.45Ku
Ti = 0.83Pu
Ki = Kp/Ti
```

**PID Controller:**
```
Kp = 0.6Ku
Ti = 0.5Pu
Td = 0.125Pu
Ki = Kp/Ti
Kd = Kp·Td
```

### Cohen-Coon Method (Process Dead Time)

For first-order + dead time model: K/(τs+1) with delay L

**PI Controller:**
```
Kp = (0.9/K)(τ/L)
Ti = 3L
```

**PID Controller:**
```
Kp = (1.35/K)(τ/L)
Ti = 2.5L
Td = 0.37L
```

---

## COMPENSATOR DESIGN VALUES

### Lead Compensator

**Purpose:** Phase boost for improved PM

**Typical α values:**
```
α = 0.1 to 0.5
```

**Phase boost:**
```
φmax = sin⁻¹((1-α)/(1+α))
```

**Example:**
- α = 0.25 → φmax ≈ 42°

**Place maximum boost 5-12° above crossover frequency** (account for phase droop)

### Lag Compensator

**Purpose:** DC gain boost for improved steady-state accuracy

**Typical attenuation:**
```
β = 5 to 20  (where β = p/z)
```

**Place corner frequencies (z, p) one decade below crossover** to avoid phase degradation at crossover

---

## POLE PLACEMENT GUIDELINES

### Dominant Pole Separation

**Additional poles should be 5-10× farther left than dominant poles**

**Example:**
- Dominant poles: s = -2 ± j3
- Third pole: s = -10 to -20

### Zero Influence

**Zeros within 10× of dominant pole real part:** Significantly affect transient response

**Zeros > 10× farther left:** Negligible transient effect, treat as dominant second-order

---

## ACTUATOR SATURATION LIMITS

### Design for Realistic Control Effort

**Typical actuator slew rates:**
- Hydraulic valves: 10-100 mm/s
- Electric motors: Limited by voltage and inductance
- Control valves: 0.1-10% per second

**Anti-Windup:** Essential when actuator saturates

---

## SENSOR NOISE FILTERING

### Low-Pass Filter for Derivative Term

**Filter cutoff:**
```
ωf = 5 to 10 × ωₙ
```

**Filter form:**
```
1/(1 + s/ωf)
```

**Or limit derivative gain:**
```
Kd = 0 to 0.1·Kp
```

---

## ENVIRONMENTAL FACTORS

### Temperature Effects

**Compensation needed if:**
- Component values drift > 20%
- Operating range > 50°C

### Noise Levels

**High-noise environments:**
- Reduce bandwidth
- Increase filtering
- Use Kalman filter for optimal estimation

---

## PERFORMANCE METRICS SUMMARY

### Excellent Performance
- %OS < 5%
- ts < required (with 50% margin)
- GM > 10 dB
- PM > 60°
- Mr < 1.2

### Good Performance
- %OS < 10%
- ts meets requirement
- GM > 6 dB
- PM > 45°
- Mr < 1.5

### Acceptable Performance
- %OS < 20%
- ts within 20% of requirement
- GM > 3 dB
- PM > 30°
- Mr < 2.0

---

## AEROSPACE SPECIFIC VALUES

### NASA GRACE-FO Satellite

**Attitude Control:**
- Arc-second accuracy requirements
- ζ = 1.0 target (critical damping)
- Natural frequency from orbital mechanics (~0.001 Hz for orbit rate)

**Boeing 777X Fly-by-Wire:**
- GM > 6 dB (regulatory)
- PM > 45° (minimum)
- Three-loop architecture (rate/attitude/guidance)

---

## AUTOMOTIVE SPECIFIC VALUES

### Mercedes-Benz Active Body Control

**Body Motion (Bounce):**
- ωₙ ≈ 1.5 Hz (9.4 rad/s)
- ζ = 0.2-0.4 (comfort mode)
- ζ = 0.5-0.7 (sport mode)

**Wheel Hop:**
- ωₙ ≈ 10 Hz (62.8 rad/s)
- Higher damping to prevent resonance

**Magnetorheological Dampers:**
- Stiffness range: 5,500 to 25,000 N/m
- Response time: milliseconds

---

## PROCESS CONTROL SPECIFIC VALUES

### Chemical Reactors

**Temperature Control:**
- Accuracy: ±0.5°C typical
- Settling time: < 5 minutes
- ζ = 1.0 (no overshoot for safety)
- Type 1 system (PI control)

**Pressure Control:**
- Accuracy: ±1% of setpoint
- Settling time: < 1 minute
- ζ = 0.6-0.8

### Power Grid AGC

**Frequency Regulation:**
- Accuracy: ±0.1 Hz (60 Hz system)
- Settling time: < 30 seconds
- Type 1 system
- Optimized PID reduces settling from 83s to 30s

---

## CNC MACHINING VALUES

**Position Accuracy:**
- Standard: ±1 mm
- High-end: ±4 μm

**Settling Time:**
- Standard: 0.1 seconds
- High-speed: 0.05 seconds

**Control Loop Hierarchy:**
- Position loop: 20-50 Hz
- Velocity loop: 100-500 Hz
- Current loop: 1-5 kHz

**Design:**
- ζ = 1.0 (no overshoot, prevents tool chatter)
- Type 1 (zero position error)

---

## COST-EFFECTIVENESS THRESHOLDS

### Manufacturing Automation ROI

**Small Manufacturers (< 100 employees):**
- Cost-effective if: < $9,285 per affected employee
- Highest ROI: CNC stone cutting systems

**Chemical Process Optimization:**
- Typical ROI: €1.3 million/year (lubrication oil)
- Payback: < 1 year for MPC implementations

---

## TROUBLESHOOTING QUICK GUIDE

### Problem: Excessive Overshoot
- **Check:** ζ too low
- **Fix:** Increase damping ratio (target 0.6-0.7)

### Problem: Slow Response
- **Check:** ωₙ too low or ζ too high
- **Fix:** Increase ωₙ or reduce ζ (if overshoot acceptable)

### Problem: Sustained Oscillation
- **Check:** Poles on imaginary axis or insufficient damping
- **Fix:** Add damping, check stability margins

### Problem: Instability
- **Check:** Poles in RHP, inadequate margins
- **Fix:** Reduce gain, add compensator, verify Routh array

### Problem: Large Steady-State Error
- **Check:** System type insufficient
- **Fix:** Add integrator (upgrade to Type 1 or Type 2)

### Problem: Noisy Control Signal
- **Check:** Excessive derivative gain or wide bandwidth
- **Fix:** Filter derivative term, reduce bandwidth

---

## REFERENCES

**Industry Standards:**
- Aerospace: DO-178C (software), ARP4754A (systems)
- Automotive: ISO 26262 (functional safety)
- Process Control: ISA-5.1 (instrumentation symbols)

**Textbook Values:**
- Ogata, "Modern Control Engineering" - Tables in Chapters 5-7
- Dorf & Bishop, "Modern Control Systems" - Design guidelines
- Franklin et al., "Feedback Control" - Application examples

---

**End of Design Values Quick Reference**
