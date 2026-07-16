#ifndef WHITELIST_H
#define WHITELIST_H

#include <Arduino.h>
#include <EEPROM.h>
#include "config.h"

// Simple EEPROM-backed MAC address whitelist.
// Layout: [count(1 byte)] [mac1(6 bytes)] [mac2(6 bytes)] ...

class Whitelist {
public:
  void begin() {
    EEPROM.begin(EEPROM_SIZE);
    count = EEPROM.read(0);
    if (count > MAX_WHITELIST_ENTRIES) count = 0; // guard against uninitialized flash
    for (int i = 0; i < count; i++) {
      for (int b = 0; b < 6; b++) {
        entries[i][b] = EEPROM.read(1 + i * 6 + b);
      }
    }
  }

  bool isWhitelisted(const uint8_t *mac) {
    for (int i = 0; i < count; i++) {
      if (memcmp(entries[i], mac, 6) == 0) return true;
    }
    return false;
  }

  bool add(const uint8_t *mac) {
    if (isWhitelisted(mac)) return true;
    if (count >= MAX_WHITELIST_ENTRIES) return false;
    memcpy(entries[count], mac, 6);
    count++;
    persist();
    return true;
  }

  void clear() {
    count = 0;
    persist();
  }

  int size() { return count; }

private:
  uint8_t entries[MAX_WHITELIST_ENTRIES][6];
  uint8_t count = 0;

  void persist() {
    EEPROM.write(0, count);
    for (int i = 0; i < count; i++) {
      for (int b = 0; b < 6; b++) {
        EEPROM.write(1 + i * 6 + b, entries[i][b]);
      }
    }
    EEPROM.commit();
  }
};

#endif // WHITELIST_H
