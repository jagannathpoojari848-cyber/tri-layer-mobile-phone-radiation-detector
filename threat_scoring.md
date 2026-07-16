# Threat Scoring Design

Each of the three sensing layers produces an independent confidence score
from 0-100, which are combined into a single weighted score.

## Layer Scores

| Layer | Signal source                                   | Weight |
|-------|--------------------------------------------------|--------|
| RF    | CA3130 front-end, median-filtered + debounced     | 40%    |
| WiFi  | 802.11 promiscuous sniffing, non-whitelisted MACs | 35%    |
| BLE   | BLE advertisement scan, non-whitelisted MACs      | 25%    |

RF is weighted highest because it can detect a phone's RF emissions even
when WiFi/BLE radios are off or the phone is in airplane mode with radios
disabled; WiFi and BLE add corroborating evidence and help reduce false
positives from environmental RF noise.

## Combined Score

```
combined = (rfScore * 40 + wifiScore * 35 + bleScore * 25) / 100
```

The combined score is then exponentially smoothed (60% previous / 40% new)
to avoid flicker between states on the display and in the cloud log.

## Classification

| Score range | Level     |
|-------------|-----------|
| 0–34        | SAFE      |
| 35–64       | WARNING   |
| 65–100      | CRITICAL  |

Thresholds are configurable in `config.h` (`THRESHOLD_WARNING`,
`THRESHOLD_CRITICAL`) and should be re-tuned per deployment room, since RF
noise floor and WiFi/BLE device density vary by environment.

## False-Positive Mitigation

- **Median filtering** (RF layer) removes single-sample spikes.
- **Debounce counter** (RF layer) requires sustained detection over several
  sampling windows before contributing to the score.
- **MAC whitelisting** (WiFi/BLE layers) excludes known/authorized devices
  (teacher laptops, approved admin phones) from scoring entirely.
- **Exponential smoothing** (combined score) prevents momentary spikes in
  any single layer from flipping the displayed alert level.
