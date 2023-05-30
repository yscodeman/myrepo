# Copyright (C) 2012 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_C_INCLUDES :=  \
    $(LOCAL_PATH)/include \
    external/curl/include

LOCAL_CFLAGS += -Wno-unused-parameter \
                -Wno-format-extra-args \
                -Wno-pointer-sign \
                -Wno-unused-variable \
                -Wno-unused-function

LOCAL_SRC_FILES := otaMain.c \
                   chint_downloader.c \
                   chintMd5.c \
                   ota_interface.c \
                   cJSON.c

LOCAL_MODULE := ota_c_service
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := liblog libcutils libcurl

include $(BUILD_EXECUTABLE)
