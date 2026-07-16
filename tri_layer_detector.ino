/*
 * Tri-Layer Smart Mobile Phone Detection System
 * ------------------------------------------------
 * ESP32 dual-core FreeRTOS firmware.
 *
 *  Core 1: RF energy sensing (CA3130 front-end) -> median filter -> debounce
 *  Core 0: WiFi 802.11 promiscuous sniffing + BLE scanning -> MAC whitelist check
 *
 * Both layers feed a weighted threat-scoring engine whose output (0-100%,
 * SAFE / WARNING / CRITICAL) is shown on an OLED and pushed to ThingSpeak.
 *
 * Hardware: ESP32 dev board, CA3130-based RF detector, SSD1306 OLED,
 *           buzzer + 3 status LEDs, calibration push button.
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#include "config.h"
#include "whitelist.h"
#include "threat_score.h"

// ---------------------------------------------------------------------
// Globals shared between cores (protected by mutex where written/read
// from both tasks)
// ---------------------------------------------------------------------
Adafruit_SSD1306 display(OLED_WIDTH, OLED_HEIGHT, &Wire, OLED_RESET);
Whitelist whitelist;
ThreatScorer scorer;

SemaphoreHandle_t scoreMutex;

volatile int g_rfScore = 0;      // 0-100, written by Core 1
volatile int g_wifiScore = 0;    // 0-100, written by Core 0
volatile int g_bleScore = 0;     // 0-100, written by Core 0
volatile int g_combinedScore = 0;
volatile ThreatLevel g_level = SAFE;
volatile bool g_calibrationMode = false;

int rfBaseline = 1800; // updated during calibration

// ---------------------------------------------------------------------
// RF Sensing (Core 1)
// ---------------------------------------------------------------------
int medianFilter(int *buf, int n) {
  int tmp[RF_MEDIAN_FILTER_SIZE];
  memcpy(tmp, buf, n * sizeof(int));
  // simple insertion sort - n is small (7)
  for (int i = 1; i < n; i++) {
    int key = tmp[i], j = i - 1;
    while (j >= 0 && tmp[j] > key) { tmp[j + 1] = tmp[j]; j--; }
    tmp[j + 1] = key;
  }
  return tmp[n / 2];
}

void rfSensingTask(void *param) {
  int samples[RF_MEDIAN_FILTER_SIZE];
  int sampleIdx = 0;
  int debounceCounter = 0;

  for (;;) {
    samples[sampleIdx % RF_MEDIAN_FILTER_SIZE] = analogRead(RF_SENSOR_PIN);
    sampleIdx++;

    if (sampleIdx >= RF_MEDIAN_FILTER_SIZE) {
      int filtered = medianFilter(samples, RF_MEDIAN_FILTER_SIZE);

      if (g_calibrationMode) {
        rfBaseline = filtered; // teacher/admin device sets the ambient baseline
      }

      int delta = filtered - rfBaseline;
      bool hit = delta > RF_BASELINE_MARGIN;

      if (hit) {
        debounceCounter++;
      } else {
        debounceCounter = max(0, debounceCounter - 1);
      }
      debounceCounter = min(debounceCounter, RF_DEBOUNCE_COUNT * 2);

      int score = 0;
      if (debounceCounter >= RF_DEBOUNCE_COUNT) {
        // scale confidence with how far past the debounce threshold we are
        score = map(constrain(debounceCounter, RF_DEBOUNCE_COUNT, RF_DEBOUNCE_COUNT * 2),
                    RF_DEBOUNCE_COUNT, RF_DEBOUNCE_COUNT * 2, 60, 100);
      }

      xSemaphoreTake(scoreMutex, portMAX_DELAY);
      g_rfScore = score;
      xSemaphoreGive(scoreMutex);
    }

    vTaskDelay(pdMS_TO_TICKS(RF_SAMPLE_WINDOW_MS));
  }
}

// ---------------------------------------------------------------------
// WiFi 802.11 Promiscuous Sniffing (Core 0)
// ---------------------------------------------------------------------
volatile int g_unknownWifiDevices = 0;

typedef struct {
  uint8_t frame_ctrl[2];
  uint8_t duration[2];
  uint8_t addr1[6]; // receiver
  uint8_t addr2[6]; // sender / transmitter
  uint8_t addr3[6];
} wifi_hdr_t;

void IRAM_ATTR wifiSnifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_hdr_t *hdr = (wifi_hdr_t *)pkt->payload;

  // Only interested in probe requests / association-related frames from
  // the sender address (addr2), which identifies the transmitting device.
  if (!whitelist.isWhitelisted(hdr->addr2)) {
    g_unknownWifiDevices++;
  }
}

void wifiScanTask(void *param) {
  const uint8_t channels[] = {1, 6, 11}; // common channels, hop between them
  int chIdx = 0;

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);

  TickType_t lastDecay = xTaskGetTickCount();

  for (;;) {
    esp_wifi_set_channel(channels[chIdx], WIFI_SECOND_CHAN_NONE);
    chIdx = (chIdx + 1) % (sizeof(channels) / sizeof(channels[0]));

    vTaskDelay(pdMS_TO_TICKS(WIFI_SCAN_CHANNEL_HOP_MS));

    // Every full channel sweep, convert unknown-device count into a score
    // and decay the counter so it reflects a rolling window, not a
    // lifetime total.
    if (chIdx == 0) {
      int count = g_unknownWifiDevices;
      g_unknownWifiDevices = 0;

      int score = constrain(map(count, 0, 8, 0, 100), 0, 100);

      xSemaphoreTake(scoreMutex, portMAX_DELAY);
      g_wifiScore = score;
      xSemaphoreGive(scoreMutex);
    }
  }
}

// ---------------------------------------------------------------------
// BLE Scanning (Core 0, cooperatively scheduled with WiFi task)
// ---------------------------------------------------------------------
class BleCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) override {
    uint8_t mac[6];
    memcpy(mac, advertisedDevice.getAddress().getNative(), 6);
    if (!whitelist.isWhitelisted(mac)) {
      unknownCount++;
    }
  }
public:
  int unknownCount = 0;
};

void bleScanTask(void *param) {
  BLEDevice::init("");
  BLEScan *pBLEScan = BLEDevice::getScan();
  BleCallbacks cb;
  pBLEScan->setAdvertisedDeviceCallbacks(&cb);
  pBLEScan->setActiveScan(true);

  for (;;) {
    cb.unknownCount = 0;
    pBLEScan->start(BLE_SCAN_DURATION_S, false);
    pBLEScan->clearResults();

    int score = constrain(map(cb.unknownCount, 0, 6, 0, 100), 0, 100);

    xSemaphoreTake(scoreMutex, portMAX_DELAY);
    g_bleScore = score;
    xSemaphoreGive(scoreMutex);

    vTaskDelay(pdMS_TO_TICKS(BLE_SCAN_INTERVAL_MS));
  }
}

// ---------------------------------------------------------------------
// ThingSpeak Upload
// ---------------------------------------------------------------------
void uploadToThingSpeak(int rf, int wifi, int ble, int combined, ThreatLevel level) {
  if (WiFi.status() != WL_CONNECTED) return;

  HTTPClient http;
  String url = "http://api.thingspeak.com/update?api_key=" + String(THINGSPEAK_API_KEY)
             + "&field1=" + String(rf)
             + "&field2=" + String(wifi)
             + "&field3=" + String(ble)
             + "&field4=" + String(combined)
             + "&field5=" + String(level);
  http.begin(url);
  http.GET();
  http.end();
}

// ---------------------------------------------------------------------
// OLED Display
// ---------------------------------------------------------------------
void updateDisplay(int rf, int wifi, int ble, int combined, ThreatLevel level) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.printf("RF:%3d  WiFi:%3d  BLE:%3d\n", rf, wifi, ble);

  display.setTextSize(2);
  display.setCursor(0, 16);
  display.printf("%s", scorer.levelName(level));

  display.setTextSize(1);
  display.setCursor(0, 40);
  display.printf("Score: %d%%\n", combined);

  display.drawRect(0, 52, 128, 10, SSD1306_WHITE);
  int fillWidth = map(combined, 0, 100, 0, 126);
  display.fillRect(1, 53, fillWidth, 8, SSD1306_WHITE);

  display.display();
}

void updateIndicators(ThreatLevel level) {
  digitalWrite(LED_SAFE_PIN, level == SAFE);
  digitalWrite(LED_WARNING_PIN, level == WARNING);
  digitalWrite(LED_CRITICAL_PIN, level == CRITICAL);
  digitalWrite(BUZZER_PIN, level == CRITICAL);
}

// ---------------------------------------------------------------------
// Setup / Loop (run on Core 1's Arduino loop task by default)
// ---------------------------------------------------------------------
void setup() {
  Serial.begin(115200);

  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(LED_SAFE_PIN, OUTPUT);
  pinMode(LED_WARNING_PIN, OUTPUT);
  pinMode(LED_CRITICAL_PIN, OUTPUT);
  pinMode(CALIBRATION_BTN_PIN, INPUT_PULLUP);
  analogReadResolution(12);

  Wire.begin(OLED_SDA, OLED_SCL);
  display.begin(SSD1306_SWITCHCAPVCC, OLED_I2C_ADDR);
  display.clearDisplay();
  display.display();

  whitelist.begin();
  scoreMutex = xSemaphoreCreateMutex();

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to WiFi");
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 10000) {
    delay(300);
    Serial.print(".");
  }
  Serial.println(WiFi.status() == WL_CONNECTED ? " connected" : " continuing offline");

  // Pin RF sensing task to Core 1, WiFi/BLE task to Core 0
  xTaskCreatePinnedToCore(rfSensingTask, "RFSense", 4096, NULL, 2, NULL, 1);
  xTaskCreatePinnedToCore(wifiScanTask,  "WiFiScan", 4096, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(bleScanTask,   "BLEScan",  8192, NULL, 1, NULL, 0);

  Serial.println("Tri-layer detection system online.");
}

void loop() {
  // Calibration: hold the button on boot/runtime to set current RF
  // reading + treat currently visible devices as the whitelist baseline.
  g_calibrationMode = (digitalRead(CALIBRATION_BTN_PIN) == LOW);

  int rf, wifi, ble;
  xSemaphoreTake(scoreMutex, portMAX_DELAY);
  rf = g_rfScore;
  wifi = g_wifiScore;
  ble = g_bleScore;
  xSemaphoreGive(scoreMutex);

  int combined = scorer.compute(rf, wifi, ble);
  ThreatLevel level = scorer.classify(combined);

  updateDisplay(rf, wifi, ble, combined, level);
  updateIndicators(level);

  static uint32_t lastUpload = 0;
  if (millis() - lastUpload > THINGSPEAK_UPLOAD_INTERVAL_MS) {
    uploadToThingSpeak(rf, wifi, ble, combined, level);
    lastUpload = millis();
  }

  Serial.printf("RF:%d WiFi:%d BLE:%d -> Combined:%d [%s]\n",
                rf, wifi, ble, combined, scorer.levelName(level));

  delay(500);
}
