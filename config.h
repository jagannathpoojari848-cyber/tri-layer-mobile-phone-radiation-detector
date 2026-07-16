#ifndef CONFIG_H
#define CONFIG_H

// ==================== WiFi / Cloud Credentials ====================
#define WIFI_SSID          "YOUR_WIFI_SSID"
#define WIFI_PASSWORD      "YOUR_WIFI_PASSWORD"
#define THINGSPEAK_API_KEY "YOUR_THINGSPEAK_WRITE_API_KEY"
#define THINGSPEAK_CHANNEL_ID 0000000UL   // your channel ID

// ==================== Pin Definitions ====================
#define RF_SENSOR_PIN      34    // ADC1_CH6 - CA3130 RF front-end output
#define BUZZER_PIN         25
#define LED_SAFE_PIN       26
#define LED_WARNING_PIN    27
#define LED_CRITICAL_PIN   14
#define CALIBRATION_BTN_PIN 32

// OLED (I2C)
#define OLED_SDA           21
#define OLED_SCL           22
#define OLED_WIDTH         128
#define OLED_HEIGHT        64
#define OLED_RESET         -1
#define OLED_I2C_ADDR      0x3C

// ==================== RF Sensing Parameters ====================
#define RF_SAMPLE_WINDOW_MS     50     // sampling interval on Core 1
#define RF_MEDIAN_FILTER_SIZE   7      // odd number, samples used for median filter
#define RF_DEBOUNCE_COUNT       3      // consecutive triggers required before flagging
#define RF_BASELINE_MARGIN      120    // ADC counts above baseline to count as a hit

// ==================== WiFi/BLE Scan Parameters ====================
#define WIFI_SCAN_CHANNEL_HOP_MS 300   // time spent per channel in promiscuous mode
#define BLE_SCAN_DURATION_S      4
#define BLE_SCAN_INTERVAL_MS     6000
#define MAX_WHITELIST_ENTRIES    20
#define EEPROM_SIZE               (MAX_WHITELIST_ENTRIES * 6 + 4) // 6 bytes/MAC + 4 byte count

// ==================== Threat Scoring Weights ====================
// Must sum to 100
#define WEIGHT_RF          40
#define WEIGHT_WIFI         35
#define WEIGHT_BLE          25

#define THRESHOLD_WARNING   35   // score >= this -> WARNING
#define THRESHOLD_CRITICAL  65   // score >= this -> CRITICAL

// ==================== Timing ====================
#define THINGSPEAK_UPLOAD_INTERVAL_MS 16000   // ThingSpeak free tier: >= 15s between updates
#define SCORE_DECAY_MS                 2000   // how often the score decays back toward 0

#endif // CONFIG_H
