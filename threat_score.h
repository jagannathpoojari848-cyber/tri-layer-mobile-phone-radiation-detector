#ifndef THREAT_SCORE_H
#define THREAT_SCORE_H

#include <Arduino.h>
#include "config.h"

enum ThreatLevel { SAFE, WARNING, CRITICAL };

class ThreatScorer {
public:
  // Each sub-score is 0-100 representing confidence from that layer.
  int compute(int rfScore, int wifiScore, int bleScore) {
    long weighted = (long)rfScore * WEIGHT_RF
                   + (long)wifiScore * WEIGHT_WIFI
                   + (long)bleScore * WEIGHT_BLE;
    int combined = weighted / 100;
    if (combined > 100) combined = 100;
    if (combined < 0) combined = 0;

    // Exponential smoothing so the displayed score doesn't jitter wildly
    smoothed = (smoothed * 0.6f) + (combined * 0.4f);
    return (int)smoothed;
  }

  ThreatLevel classify(int score) {
    if (score >= THRESHOLD_CRITICAL) return CRITICAL;
    if (score >= THRESHOLD_WARNING) return WARNING;
    return SAFE;
  }

  const char* levelName(ThreatLevel level) {
    switch (level) {
      case CRITICAL: return "CRITICAL";
      case WARNING:  return "WARNING";
      default:       return "SAFE";
    }
  }

private:
  float smoothed = 0;
};

#endif // THREAT_SCORE_H
