# Tri-Layer Smart Mobile Phone Detection System

An ESP32-based embedded system that detects unauthorized mobile phone usage in restricted environments (e.g., exam halls, classrooms) using a three-layer sensing approach: RF detection, WiFi/BLE scanning, and MAC-based whitelisting.

## Overview

Mobile phones emit detectable RF signatures and wireless traffic even when idle. This project combines three independent detection layers running on a dual-core ESP32 to reliably flag the presence of phones while minimizing false positives from authorized devices.

## Key Features

- **Dual-core FreeRTOS architecture** — RF sensing runs on Core 1, WiFi/BLE scanning runs on Core 0, allowing continuous parallel monitoring without blocking.
- **RF Front-End Sensing** — CA3130-based RF detector circuit with median filtering and debounce logic to reduce noise-triggered false positives.
- **WiFi/BLE MAC Whitelisting** — Scans for nearby WiFi and Bluetooth Low Energy devices; authorized MAC addresses are whitelisted and persisted in EEPROM across reboots.
- **802.11 Promiscuous Mode Sniffing** — Captures WiFi management/probe frames to detect nearby active devices, including those not connected to any network.
- **Weighted Threat Scoring** — Combines signals from all three layers into a 0–100% confidence score, mapped to SAFE / WARNING / CRITICAL threat levels.
- **Baseline Calibration** — A teacher/admin device can be used to calibrate the system's baseline RF and wireless environment before monitoring begins.
- **Cloud Logging** — Detection events and threat scores are uploaded to ThingSpeak via HTTP for remote monitoring and historical logging.

## Repository Structure

```
tri-layer-mobile-phone-radiation-detector/
├── README.md
├── LICENSE
├── .gitignore
├── firmware/
│   └── tri_layer_detector/
│       ├── tri_layer_detector.ino   # main sketch (setup/loop, dual-core tasks)
│       ├── config.h                 # pins, credentials, thresholds
│       ├── whitelist.h              # EEPROM-backed MAC whitelist
│       ├── threat_score.h           # weighted scoring engine
│       └── libraries.txt            # required Arduino libraries
├── docs/
│   ├── hardware.md                  # circuit notes, BOM, pin mapping, calibration
│   └── threat_scoring.md            # scoring formula & false-positive mitigation
└── images/                          # circuit photos / diagrams (add your own)
```

## Hardware

- ESP32 (dual-core, WiFi + BLE)
- CA3130 op-amp based RF front-end detector
- Antenna (connected at Pin 3 for improved RF pickup range)
- Series resistor + filter capacitor for noise suppression
- Detection range: ~5–30 cm (tuned via component placement and antenna addition)

## Software Architecture

```
Core 0 (WiFi/BLE Task)          Core 1 (RF Sensing Task)
 ├─ WiFi promiscuous sniffer     ├─ ADC sampling from CA3130
 ├─ BLE scanner                 ├─ Median filter
 ├─ MAC whitelist check         ├─ Debounce logic
 └─ EEPROM persistence          └─ RF signal scoring
              \                        /
               \                      /
            Weighted Threat Scoring Engine
                        |
              SAFE / WARNING / CRITICAL
                        |
                ThingSpeak HTTP Upload
```

## Threat Scoring Logic

Each detection layer contributes a weighted score:
- RF signal strength & consistency
- Number of non-whitelisted WiFi/BLE devices detected
- Persistence of detection over time (debounce window)

Combined score (0–100%) determines the alert level shown on the system and logged to the cloud dashboard.

## Setup

1. Clone this repo and open `firmware/tri_layer_detector/tri_layer_detector.ino` in the Arduino IDE (or `arduino-cli`).
2. Install the libraries listed in `firmware/tri_layer_detector/libraries.txt`.
3. Edit `firmware/tri_layer_detector/config.h` — set your WiFi SSID/password and ThingSpeak write API key, and adjust pin numbers if your wiring differs.
4. Select board **ESP32 Dev Module**, select the correct COM port, and flash.
5. Wire the circuit per `docs/hardware.md` (BOM + pin mapping included).
6. Power on the teacher/admin device, hold the calibration button to set the RF baseline and whitelist the admin device's MAC address.
7. Deploy — the system begins continuous monitoring, local OLED/LED/buzzer alerts, and ThingSpeak cloud logging.

See `docs/threat_scoring.md` for how the SAFE/WARNING/CRITICAL score is calculated.

## Tech Stack

- **Platform:** ESP32 (Arduino framework)
- **RTOS:** FreeRTOS (dual-core task distribution)
- **Protocols:** WiFi (802.11 promiscuous mode), BLE, HTTP
- **Cloud:** ThingSpeak
- **Storage:** EEPROM (MAC whitelist persistence)

## Future Improvements

- Machine learning-based RF signature classification
- Web dashboard for real-time multi-room monitoring
- Configurable sensitivity profiles per deployment environment

## License

MIT
