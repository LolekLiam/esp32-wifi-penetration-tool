#include "wifi_controller.h"

#include <stdio.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char* TAG = "wifi_controller";
/**
 * @brief Stores current state of Wi-Fi interface
 */
static bool wifi_init = false;
static uint8_t original_mac_ap[6];

static volatile int s_sta_status = -1; // -1 unknown, 0 failed, 1 connected

static void (*s_sta_connected_cb)(void) = NULL;
static void (*s_sta_disconnected_cb)(void) = NULL;

static volatile bool s_ignore_disconnect = false;

static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data){
    if(event_base == WIFI_EVENT){
        switch(event_id){
            case WIFI_EVENT_STA_CONNECTED:
                s_sta_status = 1;
                ESP_LOGD(TAG, "STA connected event");
                break;
            case WIFI_EVENT_STA_DISCONNECTED:
                if (!s_ignore_disconnect) {
                    s_sta_status = 0;
                }
                ESP_LOGD(TAG, "STA disconnected event");
                break;
            case WIFI_EVENT_AP_STACONNECTED:
                ESP_LOGI(TAG, "Client connected to AP");
                if (s_sta_connected_cb) s_sta_connected_cb();
                break;
            case WIFI_EVENT_AP_STADISCONNECTED:
                ESP_LOGI(TAG, "Client disconnected from AP");
                if (s_sta_disconnected_cb) s_sta_disconnected_cb();
                break;
            default:
                break;
        }
    } else if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_ASSIGNED_IP_TO_CLIENT) {
            ip_event_assigned_ip_to_client_t* event = (ip_event_assigned_ip_to_client_t*) event_data;
            ESP_LOGI(TAG, "IP assigned to client: %d.%d.%d.%d", 
                     (event->ip.addr >> 0) & 0xff,
                     (event->ip.addr >> 8) & 0xff,
                     (event->ip.addr >> 16) & 0xff,
                     (event->ip.addr >> 24) & 0xff);
        }
    }
}

/**
 * @brief Initializes Wi-Fi interface into APSTA mode and starts it.
 * 
 * @attention This function should be called only once.
 */
static void wifi_init_apsta(){
    ESP_ERROR_CHECK(esp_netif_init());

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ASSIGNED_IP_TO_CLIENT, &wifi_event_handler, NULL));

    // save original AP MAC address
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));

    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    wifi_init = true;
}

void wifictl_ap_start(wifi_config_t *wifi_config) {
    ESP_LOGD(TAG, "Starting AP...");
    if(!wifi_init){
        wifi_init_apsta();
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, wifi_config));
    ESP_LOGI(TAG, "AP started with SSID=%s", wifi_config->ap.ssid);
}

void wifictl_ap_stop(){
    ESP_LOGD(TAG, "Stopping AP...");
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_LOGD(TAG, "AP stopped");
}

void wifictl_mgmt_ap_start(){
    wifi_config_t mgmt_wifi_config = {
        .ap = {
            .ssid = CONFIG_MGMT_AP_SSID,
            .ssid_len = strlen(CONFIG_MGMT_AP_SSID),
            .password = CONFIG_MGMT_AP_PASSWORD,
            .max_connection = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .beacon_interval = 100
        },
    };
    wifictl_ap_start(&mgmt_wifi_config);
}

void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]){
    ESP_LOGD(TAG, "Connecting STA to AP...");
    if(!wifi_init){
        wifi_init_apsta();
    }

    wifi_config_t sta_wifi_config = {
        .sta = {
            .channel = ap_record->primary,
            .scan_method = WIFI_FAST_SCAN,
            .pmf_cfg.capable = false,
            .pmf_cfg.required = false,
            .bssid_set = true
        },
    };
    memcpy(sta_wifi_config.sta.ssid, ap_record->ssid, 32);
    memcpy(sta_wifi_config.sta.bssid, ap_record->bssid, 6);

    if(password != NULL){
        if(strlen(password) > 63) {
            ESP_LOGE(TAG, "Password is too long. Max supported length is 63");
            return;
        }
        memcpy(sta_wifi_config.sta.password, password, strlen(password) + 1);
    }

    ESP_LOGD(TAG, ".ssid=%s", sta_wifi_config.sta.ssid);

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());

}

void wifictl_sta_disconnect(){
    esp_err_t err = esp_wifi_disconnect();
    if (err != ESP_OK && err != ESP_FAIL) {
        ESP_ERROR_CHECK(err);
    }
}

bool wifictl_sta_check_password(const wifi_ap_record_t *ap_record, const char password[]){
    if (wifi_init) {
        s_ignore_disconnect = true;
        wifictl_sta_disconnect();
        vTaskDelay(pdMS_TO_TICKS(300)); // let disconnect settle
        s_ignore_disconnect = false;
    }
    s_sta_status = -1;
    wifictl_sta_connect_to_ap(ap_record, password);

    // Wait indefinitely for a definitive result
    while (true) {
        if (s_sta_status == 1) {
            s_ignore_disconnect = true;
            vTaskDelay(pdMS_TO_TICKS(100));
            wifictl_sta_disconnect();
            vTaskDelay(pdMS_TO_TICKS(100));
            s_ignore_disconnect = false;
            return true;
        }
        if (s_sta_status == 0) {
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void wifictl_set_ap_mac(const uint8_t *mac_ap){
    ESP_LOGD(TAG, "Changing AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, mac_ap));
}

void wifictl_get_ap_mac(uint8_t *mac_ap){
    esp_wifi_get_mac(WIFI_IF_AP, mac_ap);
}

void wifictl_restore_ap_mac(){
    ESP_LOGD(TAG, "Restoring original AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, original_mac_ap));
}

void wifictl_get_sta_mac(uint8_t *mac_sta){
    esp_wifi_get_mac(WIFI_IF_STA, mac_sta);
}

void wifictl_set_channel(uint8_t channel){
    if((channel == 0) || (channel >  13)){
        ESP_LOGE(TAG,"Channel out of range. Expected value from <1,13> but got %u", channel);
        return;
    }
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void wifictl_set_ap_sta_connected_cb(void (*cb)(void)) {
    s_sta_connected_cb = cb;
}

void wifictl_set_ap_sta_disconnected_cb(void (*cb)(void)) {
    s_sta_disconnected_cb = cb;
}