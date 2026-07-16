# Hardware & Circuit Notes

## RF Front-End (CA3130-based detector)

The RF sensing layer uses a CA3130 op-amp configured as a high-gain RF energy
detector. Key practical fixes made during development:

- **Capacitor placement** — decoupling capacitor moved close to the CA3130
  supply pins to eliminate high-frequency supply noise that was causing
  false triggers.
- **Antenna** — a short wire antenna added to Pin 3 (non-inverting input)
  extended usable detection range from a few cm to approximately **5–30 cm**.
- **Noise suppression** — a series resistor + filter capacitor stage added
  between the RF front-end output and the ESP32 ADC input to remove
  high-frequency ripple before sampling.
- **Output** — the conditioned analog signal feeds ESP32 ADC1_CH6 (GPIO34).

## Bill of Materials

| Component                  | Notes                                   |
|-----------------------------|------------------------------------------|
| ESP32 Dev Board             | Dual-core, WiFi + BLE                    |
| CA3130 Op-Amp                | RF energy detection front-end            |
| Wire antenna                 | Soldered to CA3130 Pin 3                 |
| Series resistor (RF path)    | Noise suppression, tune experimentally   |
| Filter capacitor (RF path)   | Noise suppression, tune experimentally   |
| SSD1306 OLED (I2C, 128x64)   | Status display                           |
| Push button                  | Calibration trigger                      |
| Buzzer                       | CRITICAL alert                           |
| 3x LED (any color)           | SAFE / WARNING / CRITICAL indicators     |
| Breadboard / perfboard, wires| Assembly                                 |

## Pin Mapping

See `firmware/tri_layer_detector/config.h` for the authoritative pin list.
Summary:

| Signal              | ESP32 Pin |
|---------------------|-----------|
| RF sensor input      | GPIO34 (ADC1_CH6) |
| OLED SDA              | GPIO21 |
| OLED SCL              | GPIO22 |
| Buzzer                | GPIO25 |
| LED - SAFE             | GPIO26 |
| LED - WARNING           | GPIO27 |
| LED - CRITICAL          | GPIO14 |
| Calibration button      | GPIO32 |

## Calibration Procedure

1. Power on the system in the target room with no phones present.
2. Hold the calibration button while the teacher/admin device (a phone whose
   MAC address should be whitelisted) is nearby.
3. The RF baseline is set from the current filtered ADC reading, and the
   admin device's WiFi/BLE MAC addresses can be added to the whitelist via
   the calibration routine.
4. Release the button — the system returns to normal monitoring using the
   new baseline.
