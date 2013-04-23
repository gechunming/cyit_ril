# Copyright 2006 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
ifeq ($(HAVE_CYIT_SOURCES),true)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES:= \
    $(LOCAL_PATH)/../../../../device/samsung/smdk_common/libaudio/
LOCAL_SRC_FILES:= \
    secril-client.cpp
    

LOCAL_SHARED_LIBRARIES := \
    libutils \
    libbinder \
    libcutils \
    libhardware_legacy


LOCAL_MODULE:= libsecril-client
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE_TAGS := optional


include $(BUILD_SHARED_LIBRARY)
else
    include $(CLEAR_VARS)
    LOCAL_MODULE := libsecril-client.so
    LOCAL_MODULE_TAGS := optional
    LOCAL_MODULE_CLASS := CYIT
    LOCAL_MODULE_PATH := $(TARGET_OUT)/lib
    LOCAL_SRC_FILES := ../../../../device/$(TARGET_PRODUCT)/sc630/apk/libsecril-client.so
    include $(BUILD_PREBUILT)
endif

