//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * @file att_manager_logger.h
 *
 * @brief Defines the logging behavior of the SDK.
 *
 * @note You MUST NOT use any symbols (macros, functions, structures, enums, etc.)
 * prefixed with an underscore ('_') directly in your application code. These symbols
 * are part of the SDK's internal implementation; we do not document these symbols
 * and they are subject to change in future versions of the SDK which would break your code.
 */
#ifndef _ATT_MANAGER_LOGGER_H
#define _ATT_MANAGER_LOGGER_H

#include "att_logger_exports.h"

/**
 * @brief Sets the listener function that will be invoked to report a MAA
 * SDK log message.
 * 
 * @param[in] listener The listener function to be called.
 */
void att_set_log_listener(PATT_LOGGER_FUNC listener);

/**
 * @brief Set the log level for the SDK.
 * 
 * @param[in] level The logging level to set.
 */
void att_set_log_level(att_log_level level);

/**
 * @brief Get the current log level for the SDK.
 * 
 * @return The current log level.
 */
att_log_level att_get_log_level();

#endif // __ATT_MANAGER_LOGGER_H