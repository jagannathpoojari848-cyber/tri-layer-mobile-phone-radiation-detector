// ============================================================
//  Tri-Layer Smart Mobile Phone Detector — THINGSPEAK FIXED
//  ESP32-WROOM-32 | MGIT ECE Major Project
//  Using HTTP (not HTTPS) for more reliable uploads
// ============================================================

#include <WiFi.h>
#include <HTTPClient.h>  // Use HTTPClient instead of ThingSpeak library
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <EEPROM.h>
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

// ─── OLED ────────────────────────────────────────────────────
#define SCREEN_WIDTH  128
#define SCREEN_HEIGHT  64
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// ─── Pins ────────────────────────────────────────────────────
#define RF_PIN        34
#define BUZZER        25
#define ENROLL_BTN     4
#define BATTERY_PIN   35

// ─── WiFi Credentials ────────────────────────────────────────
const char* ssid      = "your ssid ";
const char* password  = "your password ";

// ─── ESP32 Hotspot ───────────────────────────────────────────
#define AP_SSID "ExamHall_Monitor"
#define AP_PASS "mgit1234"

// ─── ThingSpeak ─────────────────────────────────────────────
unsigned long CH_ID    = xxxxx;
const char* CH_WRITE = "xxxxxxxx";

#define TS_INTERVAL   15000
unsigned long lastUpload = 0;

// ─── BLE ─────────────────────────────────────────────────────
BLEScan* pBLEScan;

// ─── Whitelist ───────────────────────────────────────────────
#define MAX_WHITELIST  10
#define MAC_LEN        18
#define EEPROM_SIZE    512
String whitelist[MAX_WHITELIST];
int    whitelistCount = 0;

// ─── RF Settings ─────────────────────────────────────────────
#define RF_THRESHOLD        1800
#define RF_SAMPLES            20
#define RF_DEBOUNCE_COUNT      3
#define EXTRA_RF_THRESHOLD   150
#define GSM_BURST_MIN        180
#define GSM_BURST_MAX        250
#define RSSI_NEAR            -65

// ─── Promiscuous Sniffer ─────────────────────────────────────
#define MAX_SNIFFED    20
#define SNIFF_DURATION 3000
struct SniffedDevice { String mac; int rssi; unsigned long lastSeen; };
SniffedDevice     sniffBuffer[MAX_SNIFFED];
int               sniffCount = 0;
SemaphoreHandle_t sniffMutex;

// ─── Threat Score ────────────────────────────────────────────
struct ThreatScore { int score; String level; String reason; };

// ─── RF State ────────────────────────────────────────────────
struct RFState { int raw; int averaged; float burstRate; int debounceCount; bool confirmed; };
RFState rfState = {0, 0, 0, 0, false};

// ─── Baseline ────────────────────────────────────────────────
float teacherBaseline = 0;
bool  baselineSet     = false;

// ─── Shared Scan Results ─────────────────────────────────────
SemaphoreHandle_t resultMutex;
struct ScanResults {
  int  knownWiFi; int unknownWiFi;
  int  knownBLE;  int unknownBLE;
  int  sniffedUnknown; int sniffedKnown;
  bool teacherOnHotspot;
};
ScanResults scanResults = {0,0,0,0,0,0,false};

// ─── Statistics ──────────────────────────────────────────────
int           totalAlerts      = 0;
int           knownDevicesSeen = 0;
int           peakRF           = 0;
int           peakScore        = 0;
unsigned long teacherStartTime = 0;

// ─── State ───────────────────────────────────────────────────
bool   enrollMode  = false;
unsigned long enrollStart = 0;
bool   prevTeacher = false;
int    currentScore = 0;
String currentLevel = "SAFE";

// ============================================================
//  WiFi Promiscuous Sniffer
// ============================================================
typedef struct {
  uint8_t frame_ctrl[2]; uint8_t duration[2];
  uint8_t addr1[6]; uint8_t addr2[6]; uint8_t addr3[6]; uint8_t seq_ctrl[2];
} wifi_mac_hdr_t;
typedef struct { wifi_mac_hdr_t hdr; uint8_t payload[0]; } wifi_packet_t;

void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  wifi_promiscuous_pkt_t* pkt  = (wifi_promiscuous_pkt_t*)buf;
  wifi_packet_t* ipkt = (wifi_packet_t*)pkt->payload;
  wifi_mac_hdr_t* hdr  = &ipkt->hdr;
  int rssi = pkt->rx_ctrl.rssi;
  if (rssi < RSSI_NEAR)     return;
  if (hdr->addr2[0] & 0x01) return;
  if (hdr->addr2[0] & 0x02) return;
  char mac[18];
  sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X",
    hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
    hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);
  String macStr = String(mac);
  if (xSemaphoreTake(sniffMutex, 0) == pdTRUE) {
    bool found = false;
    for (int i=0;i<sniffCount;i++) {
      if (sniffBuffer[i].mac==macStr) { sniffBuffer[i].rssi=rssi; sniffBuffer[i].lastSeen=millis(); found=true; break; }
    }
    if (!found && sniffCount<MAX_SNIFFED)
      sniffBuffer[sniffCount++]={macStr,rssi,millis()};
    xSemaphoreGive(sniffMutex);
  }
}
void startSniffing() {
  if (xSemaphoreTake(sniffMutex,100)==pdTRUE){sniffCount=0;xSemaphoreGive(sniffMutex);}
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
}
void stopSniffing() { esp_wifi_set_promiscuous(false); }

// ============================================================
//  EEPROM Whitelist
// ============================================================
void saveWhitelist() {
  int addr=0; EEPROM.write(addr++,whitelistCount);
  for(int i=0;i<whitelistCount;i++){
    String mac=whitelist[i];
    for(int j=0;j<MAC_LEN;j++) EEPROM.write(addr++,j<(int)mac.length()?mac[j]:0);
  }
  EEPROM.commit();
}
void loadWhitelist() {
  int addr=0; int count=EEPROM.read(addr++);
  if(count<0||count>MAX_WHITELIST){whitelistCount=0;return;}
  whitelistCount=count;
  for(int i=0;i<whitelistCount;i++){
    String mac="";
    for(int j=0;j<MAC_LEN;j++){char c=EEPROM.read(addr++);if(c!=0)mac+=c;}
    whitelist[i]=mac;
  }
}
bool isWhitelisted(String mac) {
  mac.toUpperCase();
  for(int i=0;i<whitelistCount;i++) if(whitelist[i]==mac) return true;
  return false;
}
void addToWhitelist(String mac) {
  mac.toUpperCase();
  if(whitelistCount>=MAX_WHITELIST||isWhitelisted(mac)) return;
  whitelist[whitelistCount++]=mac; saveWhitelist();
}

// ============================================================
//  RF Functions
// ============================================================
int readRFAveraged() {
  int s[RF_SAMPLES];
  for(int i=0;i<RF_SAMPLES;i++){s[i]=analogRead(RF_PIN);delay(2);}
  for(int i=0;i<RF_SAMPLES-1;i++)
    for(int j=0;j<RF_SAMPLES-i-1;j++)
      if(s[j]>s[j+1]){int t=s[j];s[j]=s[j+1];s[j+1]=t;}
  return s[RF_SAMPLES/2];
}
float detectGSMBurst() {
  int count=0; unsigned long start=millis();
  while(millis()-start<1000){if(analogRead(RF_PIN)>RF_THRESHOLD)count++;delay(2);}
  return count;
}
bool checkRFDebounced() {
  int reading=readRFAveraged(); rfState.averaged=reading;
  if(reading>peakRF) peakRF=reading;
  if(reading>RF_THRESHOLD){
    rfState.debounceCount++;
    if(rfState.debounceCount>=RF_DEBOUNCE_COUNT) rfState.confirmed=true;
  } else { rfState.debounceCount=0; rfState.confirmed=false; }
  return rfState.confirmed;
}

// ============================================================
//  Hotspot Check
// ============================================================
bool isTeacherOnHotspot() {
  wifi_sta_list_t list; esp_wifi_ap_get_sta_list(&list);
  for(int i=0;i<list.num;i++){
    char mac[18];
    sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X",
      list.sta[i].mac[0],list.sta[i].mac[1],list.sta[i].mac[2],
      list.sta[i].mac[3],list.sta[i].mac[4],list.sta[i].mac[5]);
    if(isWhitelisted(String(mac))) return true;
  }
  return false;
}

// ============================================================
//  Confidence Scoring
// ============================================================
ThreatScore calculateThreat(
  bool rfConfirmed, float burstRate,
  int unknownWiFi, int knownWiFi,
  int unknownBLE,  int knownBLE,
  int sniffedUnknown, int sniffedKnown,
  bool teacherPresent, float rfDiff
) {
  ThreatScore t={0,"SAFE","No activity"};
  if(rfConfirmed)                                       {t.score+=30;t.reason="RF detected";}
  if(burstRate>=GSM_BURST_MIN&&burstRate<=GSM_BURST_MAX){t.score+=25;t.reason="GSM burst";}
  if(unknownWiFi>0)   {t.score+=30*unknownWiFi;t.reason="Unknown WiFi device";}
  if(unknownBLE>0)    {t.score+=20*unknownBLE; t.reason="Unknown BLE device";}
  if(sniffedUnknown>0){t.score+=25;            t.reason="Device sniffed";}
  if(baselineSet&&rfDiff>EXTRA_RF_THRESHOLD)  {t.score+=30;t.reason="Mobile data user";}
  if(rfConfirmed&&!teacherPresent&&unknownWiFi==0&&unknownBLE==0&&sniffedUnknown==0)
                                              {t.score+=20;t.reason="Unidentified RF";}
  if(teacherPresent&&knownWiFi>0) t.score-=15;
  if(teacherPresent&&knownBLE>0)  t.score-=10;
  if(sniffedKnown>0)              t.score-=10;
  t.score=constrain(t.score,0,100);
  if     (t.score>=80) t.level="CRITICAL";
  else if(t.score>=60) t.level="HIGH";
  else if(t.score>=40) t.level="MEDIUM";
  else if(t.score>=20) t.level="LOW";
  else                 t.level="SAFE";
  return t;
}

// ============================================================
//  ThingSpeak Upload - USING HTTPClient (MORE RELIABLE)
// ============================================================
void uploadToThingSpeak(ThreatScore threat, bool teacherPresent,
                        ScanResults res, float battV) {

  // Check WiFi
  if(WiFi.status() != WL_CONNECTED) {
    Serial.println("ThingSpeak: WiFi Offline - Skipping");
    return;
  }
  
  // Rate limit
  if(millis() - lastUpload < TS_INTERVAL) {
    return; 
  }

  int totalUnknown = res.unknownWiFi + res.unknownBLE + res.sniffedUnknown;
  int knownTotal = res.knownWiFi + res.knownBLE + res.sniffedKnown;
  int teacherVal = teacherPresent ? 1 : 0;
  
  // Build the URL with all 8 fields
  String url = "http://api.thingspeak.com/update?api_key=";
  url += CH_WRITE;
  url += "&field1=" + String(rfState.averaged);
  url += "&field2=" + String(threat.score);
  url += "&field3=" + String(totalUnknown);
  url += "&field4=" + String(teacherVal);
  url += "&field5=" + String((int)rfState.burstRate);
  url += "&field6=" + String(totalAlerts);
  url += "&field7=" + String(knownTotal);
  url += "&field8=" + String((int)(battV * 10));
  
  Serial.println("\n=== ThingSpeak Upload (HTTP Method) ===");
  Serial.println("URL: " + url);
  
  HTTPClient http;
  http.begin(url);  // Use HTTP (not HTTPS) for reliability
  
  int httpCode = http.GET();
  
  if(httpCode > 0) {
    String payload = http.getString();
    Serial.print("Response Code: ");
    Serial.println(httpCode);
    Serial.print("Response Body: ");
    Serial.println(payload);
    
    if(httpCode == 200) {
      Serial.println("✅ ThingSpeak UPLOAD SUCCESS!");
    } else {
      Serial.println("❌ ThingSpeak upload failed with HTTP code: " + String(httpCode));
    }
  } else {
    Serial.print("❌ HTTP GET failed, error: ");
    Serial.println(httpCode);
  }
  
  http.end();

  lastUpload = millis();
  Serial.println("=== End Upload ===\n");
}

// ============================================================
//  Alert
// ============================================================
void triggerAlert(String level, String reason) {
  totalAlerts++;
  Serial.println("ALERT ["+level+"]: "+reason);
  if     (level=="CRITICAL"){for(int i=0;i<10;i++){digitalWrite(BUZZER,HIGH);delay(80);digitalWrite(BUZZER,LOW);delay(50);}}
  else if(level=="HIGH")    {for(int i=0;i< 5;i++){digitalWrite(BUZZER,HIGH);delay(150);digitalWrite(BUZZER,LOW);delay(100);}}
  else if(level=="MEDIUM")  {for(int i=0;i< 3;i++){digitalWrite(BUZZER,HIGH);delay(200);digitalWrite(BUZZER,LOW);delay(150);}}
  else                      {                       digitalWrite(BUZZER,HIGH);delay(300);digitalWrite(BUZZER,LOW);}
}
void clearAlert(){digitalWrite(BUZZER,LOW);}

// ============================================================
//  OLED
// ============================================================
void showOLED(String l1,String l2,String l3,String l4){
  display.clearDisplay(); display.setTextSize(1); display.setTextColor(WHITE);
  display.setCursor(0, 0);display.println(l1);
  display.setCursor(0,16);display.println(l2);
  display.setCursor(0,32);display.println(l3);
  display.setCursor(0,48);display.println(l4);
  display.display();
}

void showMainDisplay(ThreatScore t,bool teacher,ScanResults res,float battV){
  display.clearDisplay(); display.setTextColor(WHITE);
  if(t.level!="SAFE"){
    display.setTextSize(2); display.setCursor(0,0);
    if     (t.level=="CRITICAL") display.print("CRITICAL");
    else if(t.level=="HIGH")     display.print("HIGH!");
    else if(t.level=="MEDIUM")   display.print("MEDIUM");
    else                         display.print("LOW");
  } else {
    display.setTextSize(1); display.setCursor(0,0);
    display.print("SAFE  RF:"); display.print(rfState.averaged);
  }
  display.setTextSize(1);
  display.setCursor(0,20);
  display.print("S:"); display.print(t.score);
  display.print("% [");
  int bars=map(t.score,0,100,0,8);
  for(int i=0;i<bars;i++)  display.print("#");
  for(int i=bars;i<8;i++) display.print(".");
  display.print("]");
  display.setCursor(0,32);
  int unk=res.unknownWiFi+res.unknownBLE+res.sniffedUnknown;
  display.print("Unknown:"); display.print(unk);
  display.print(teacher?" T:Y":" T:N");
  display.setCursor(0,48);
  display.print("Alrt:"); display.print(totalAlerts);
  display.print(" Bat:"); display.print(battV,1); display.print("V");
  display.display();
}

// ============================================================
//  Battery
// ============================================================
float readBattery(){
  return (analogRead(BATTERY_PIN)/4095.0)*3.3*2.0;
}

// ============================================================
//  Background Scan Task
// ============================================================
void scanTask(void* parameter){
  while(true){
    ScanResults results={0,0,0,0,0,0,false};
    results.teacherOnHotspot=isTeacherOnHotspot();

    int n=WiFi.scanNetworks(false,true);
    for(int i=0;i<n;i++){
      String mac=WiFi.BSSIDstr(i); int rssi=WiFi.RSSI(i); mac.toUpperCase();
      if(rssi>RSSI_NEAR){
        if(enrollMode){addToWhitelist(mac);enrollMode=false;}
        else if(isWhitelisted(mac)){results.knownWiFi++;knownDevicesSeen++;}
        else results.unknownWiFi++;
      }
    }
    WiFi.scanDelete();

    BLEScanResults* found=pBLEScan->start(2,false);
    for(int i=0;i<found->getCount();i++){
      BLEAdvertisedDevice dev=found->getDevice(i);
      String mac=String(dev.getAddress().toString().c_str()); mac.toUpperCase();
      if(dev.getRSSI()>RSSI_NEAR){
        if(enrollMode){addToWhitelist(mac);enrollMode=false;}
        else if(isWhitelisted(mac)) results.knownBLE++;
        else results.unknownBLE++;
      }
    }
    pBLEScan->clearResults();

    startSniffing();
    vTaskDelay(pdMS_TO_TICKS(SNIFF_DURATION));
    stopSniffing();

    if(xSemaphoreTake(sniffMutex,100)==pdTRUE){
      for(int i=0;i<sniffCount;i++){
        if(isWhitelisted(sniffBuffer[i].mac)) results.sniffedKnown++;
        else results.sniffedUnknown++;
      }
      xSemaphoreGive(sniffMutex);
    }

    if(xSemaphoreTake(resultMutex,100)==pdTRUE){scanResults=results;xSemaphoreGive(resultMutex);}

    if(WiFi.status()!=WL_CONNECTED){
      WiFi.begin(ssid,password);
      int tries=0;
      while(WiFi.status()!=WL_CONNECTED&&tries<10){vTaskDelay(pdMS_TO_TICKS(500));tries++;}
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

// ============================================================
//  SETUP
// ============================================================
void setup(){
  Serial.begin(115200);
  Serial.println("\n\n=== Tri-Layer Smart Detector ===");
  
  pinMode(BUZZER,OUTPUT); pinMode(ENROLL_BTN,INPUT_PULLUP);
  digitalWrite(BUZZER,LOW);
  sniffMutex=xSemaphoreCreateMutex(); resultMutex=xSemaphoreCreateMutex();

  if(!display.begin(SSD1306_SWITCHCAPVCC,0x3C)) Serial.println("OLED not found");
  showOLED("Smart Detector","MGIT ECE","Starting...","");
  delay(1500);

  EEPROM.begin(EEPROM_SIZE); loadWhitelist();

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID,AP_PASS);
  showOLED("Connecting WiFi",ssid,"Please wait...","");
  WiFi.begin(ssid,password);
  int tries=0;
  while(WiFi.status()!=WL_CONNECTED&&tries<20){delay(500);tries++;}

  if(WiFi.status()==WL_CONNECTED){
    Serial.println("✅ WiFi Connected!");
    Serial.print("IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("❌ WiFi Connection Failed!");
  }
  
  BLEDevice::init("ESP32_Detector");
  pBLEScan=BLEDevice::getScan();
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);

  showOLED("System Ready!",
           "AP: "+String(AP_SSID),
           "WiFi: "+String(WiFi.status()==WL_CONNECTED?"OK":"Offline"),
           "HTTP Upload Mode");
  delay(2000);

  xTaskCreatePinnedToCore(scanTask,"ScanTask",16384,NULL,1,NULL,0);
}

// ============================================================
//  MAIN LOOP
// ============================================================
void loop(){

  if(digitalRead(ENROLL_BTN)==LOW){
    delay(50);
    if(digitalRead(ENROLL_BTN)==LOW){
      enrollMode=true; enrollStart=millis();
      showOLED("ENROLL MODE","Bring teacher","phone near now","10 sec timeout");
      for(int i=0;i<3;i++){digitalWrite(BUZZER,HIGH);delay(100);digitalWrite(BUZZER,LOW);delay(100);}
    }
  }
  if(enrollMode&&millis()-enrollStart>10000){enrollMode=false;showOLED("Enroll timeout","","","");delay(1000);}

  bool rfConfirmed=checkRFDebounced();
  if(rfConfirmed) rfState.burstRate=detectGSMBurst();

  bool teacherNow=false;
  ScanResults results;
  if(xSemaphoreTake(resultMutex,50)==pdTRUE){teacherNow=scanResults.teacherOnHotspot;results=scanResults;xSemaphoreGive(resultMutex);}

  if(teacherNow&&!prevTeacher){
    teacherBaseline=readRFAveraged(); baselineSet=true;
    showOLED("Teacher found!","Baseline set!","RF:"+String((int)teacherBaseline),"");delay(1000);
  }
  if(!teacherNow&&prevTeacher&&baselineSet){baselineSet=false;teacherBaseline=0;}
  prevTeacher=teacherNow;

  float rfDiff=rfState.averaged-teacherBaseline;
  bool teacherPresent=teacherNow||results.knownWiFi>0||results.knownBLE>0||results.sniffedKnown>0;

  ThreatScore threat=calculateThreat(
    rfConfirmed,rfState.burstRate,
    results.unknownWiFi,results.knownWiFi,
    results.unknownBLE, results.knownBLE,
    results.sniffedUnknown,results.sniffedKnown,
    teacherPresent,rfDiff
  );

  if(threat.score>peakScore) peakScore=threat.score;
  currentScore=threat.score; currentLevel=threat.level;

  if(threat.level!="SAFE") triggerAlert(threat.level,threat.reason);
  else clearAlert();

  float battV=readBattery();
  showMainDisplay(threat,teacherPresent,results,battV);
  
  uploadToThingSpeak(threat, teacherPresent, results, battV);

  Serial.print("RF:"+String(rfState.averaged));
  Serial.print(" S:"+String(threat.score)+"%");
  Serial.print(" ["+threat.level+"]");
  Serial.print(" U:"+String(results.unknownWiFi+results.unknownBLE+results.sniffedUnknown));
  Serial.print(" T:"+String(teacherPresent?"Y":"N"));
  Serial.print(" A:"+String(totalAlerts));
  Serial.println();
  
  delay(1000);
}
