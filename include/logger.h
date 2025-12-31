//
// Created by fang on 23-12-19.
//

#ifndef QBDIRECORDER_LOGGER_H
#define QBDIRECORDER_LOGGER_H

#include <android/log.h>

#define LOG_TAG "FANGG3"
#define log_priority  ANDROID_LOG_DEBUG//ANDROID_LOG_SILENT


#define LOGI(fmt, ...)                                                \
  do {                                                                       \
    if (__predict_false(log_priority <= ANDROID_LOG_INFO))                \
      __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##__VA_ARGS__); \
  } while (0)
#define LOGW(fmt, ...)                                                \
  do {                                                                       \
    if (__predict_false(log_priority <= ANDROID_LOG_WARN))                \
      __android_log_print(ANDROID_LOG_WARN, LOG_TAG, fmt, ##__VA_ARGS__); \
  } while (0)
#define LOGE(fmt, ...)                                                \
  do {                                                                        \
    if (__predict_false(log_priority <= ANDROID_LOG_ERROR))                \
      __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__); \
  } while (0)

#define LOGD(fmt, ...)                                              \
  do {                                                                        \
    if (__predict_false(log_priority <= ANDROID_LOG_DEBUG))                \
      __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##__VA_ARGS__); \
  } while (0)

#define LOGS(fmt, ...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##__VA_ARGS__);


#endif //QBDIRECORDER_LOGGER_H
