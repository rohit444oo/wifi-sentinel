# 🛡️ Wi-Fi Sentinel

### Wireless Security Assessment & Rogue Access Point Detection Platform

Wi-Fi Sentinel is a professional wireless security assessment platform designed to
identify unauthorized or suspicious wireless infrastructure through evidence-based
analysis.

The platform discovers nearby access points, maintains an authorized wireless
baseline, analyzes SSID/BSSID and security characteristics, evaluates risk, records
security evidence, and presents findings through a modern security operations
dashboard.

> **Core Principle: Unknown ≠ Malicious**
>
> An access point is not classified as malicious simply because it is unknown.
> Wi-Fi Sentinel uses multiple security indicators and historical evidence before
> assigning elevated risk or generating a security event.

---

## 🎯 Project Objective

Organizations may operate multiple wireless access points across offices,
laboratories, campuses, and other environments. Unauthorized or modified wireless
infrastructure can introduce security risks.

Wi-Fi Sentinel provides a centralized assessment workflow to:

- Discover nearby wireless access points
- Maintain an authorized AP inventory
- Compare observations against the authorized baseline
- Analyze SSID and BSSID characteristics
- Evaluate wireless security configuration
- Maintain wireless fingerprints
- Identify meaningful behavioral changes
- Calculate evidence-based risk
- Generate security events when sufficient evidence exists
- Track incidents and supporting evidence
- Assess overall wireless security posture
- Maintain assessment history
- Generate CSV and PDF reports

---

# 🚀 Key Capabilities

## 1. Wireless Discovery

Discovers available wireless access points using the capabilities exposed by the
operating system, wireless adapter, and installed tooling.

Collected information may include:

- SSID
- BSSID
- Signal strength
- Channel
- Security configuration
- Network characteristics
- Wireless fingerprint attributes

The platform does not fabricate telemetry when a platform or adapter does not
expose a particular capability.

---

## 2. Authorized Access Point Baseline

Wi-Fi Sentinel maintains an inventory of known-good wireless infrastructure.

Authorized AP records can contain:

- SSID
- BSSID
- Security configuration
- Location / operational note

Observed infrastructure is compared against this authorized baseline.

### Classification

| State | Meaning |
|---|---|
| Authorized | AP matches the approved baseline |
| Unverified | AP has been observed but is not in the authorized inventory |
| Elevated Risk | Additional security evidence indicates increased concern |

> An unverified AP is not automatically considered malicious.

---

## 3. Rogue Access Point Detection

The platform evaluates wireless observations for indicators that may suggest
unauthorized or suspicious infrastructure.

Detection can consider:

- BSSID identity
- SSID characteristics
- Authorized baseline comparison
- Security configuration
- Configuration changes
- Wireless fingerprint changes
- Historical behavior
- Risk indicators

The system separates **observation** from **security classification** to reduce
false positives.

---

## 4. SSID & BSSID Analysis

Each observed access point is analyzed using its wireless identity.

Analysis includes:

- SSID identification
- BSSID identification
- Baseline comparison
- First-seen state
- Historical observation
- Identity consistency
- Configuration comparison

This allows the platform to distinguish ordinary new observations from potentially
meaningful wireless changes.

---

## 5. Wireless Fingerprinting

Wi-Fi Sentinel maintains wireless characteristics that can be used to compare
current observations with historical observations.

Fingerprint information may include:

- BSSID
- SSID
- Channel
- Security configuration
- Band/radio characteristics
- Historical observation data

Fingerprint changes can contribute to behavioral analysis and risk assessment.

---

# 📊 Risk Assessment Engine

Wi-Fi Sentinel uses an evidence-based risk model.

Risk is not determined solely by whether an AP is authorized.

Potential risk factors include:

- Unauthorized or unverified identity
- Security configuration weaknesses
- Configuration changes
- Wireless fingerprint changes
- Behavioral anomalies
- Suspicious identity relationships
- Historical evidence

### Risk Philosophy

```text
Observation
     │
     ▼
Evidence Collection
     │
     ▼
Baseline Comparison
     │
     ▼
Behavioral / Configuration Analysis
     │
     ▼
Risk Assessment
     │
     ├── Low / Informational
     ├── Moderate
     ├── High
     └── Critical
