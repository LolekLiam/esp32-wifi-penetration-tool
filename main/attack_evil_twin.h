/**
 * @file attack_evil_twin.h
 * @author ravijol1 (liamstaric@gmail.com)
 * @date 2026-06-18
 * @copyright Copyright (c) 2026
 *
 * @brief Provides interface to control attacks on WPA evil twin AP
 */
#ifndef ATTACK_EVIL_TWIN_H
#define ATTACK_EVIL_TWIN_H

#include "attack.h"

/**
 * @brief Available methods that can be chosen for the attack.
 *
 */
typedef enum{
    ATTACK_EVIL_TWIN_DEFAULT,
} attack_evil_twin_methods_t;

/**
 * @brief Starts evil twin attack with given attack config.
 *
 * To stop evil twin attack, call attack_evil_twin_stop().
 *
 * @param attack_config attack config with valid ap_record and attack method chosen
 */
void attack_evil_twin_start(attack_config_t *attack_config);

/**
 * @brief Stops evil twin attack.
 *
 * This function stops everything that attack_evil_twin_start() started and resets all values to default state.
 */
void attack_evil_twin_stop();

/**
 * @brief Checks if entered password is correct for target AP.
 * 
 * @param password entered password
 * @return true if password is correct, false otherwise
 */
bool attack_evil_twin_check_password(const char *password);

const char *attack_evil_twin_get_ssid(void);

#endif