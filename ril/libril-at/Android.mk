# Copyright 2006 The Android Open Source Project

# XXX using libutils for simulator build only...
#
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    atparser.c \
    atchannel.c \
    misc.c \
    at_tok.c

LOCAL_SHARED_LIBRARIES := \
    libcutils libutils libril-cyit libnetutils

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE_TAGS := optional

# for asprinf
LOCAL_CFLAGS := -D_GNU_SOURCE
LOCAL_CFLAGS += -DUSE_CYIT_COMMANDS -DM_USAT_MODULE
#LOCAL_CFLAGS += -DUSE_PPP
#LOCAL_CFLAGS += -DUSE_MULT_AT_CHAN
LOCAL_CFLAGS += -DUSE_CYIT_FRAMEWORK
LOCAL_CFLAGS += -DUSE_RAWIP
LOCAL_CFLAGS += -DGSM_MUX_CHANNEL

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

ifeq ($(TARGET_DEVICE),sooner)
  LOCAL_CFLAGS += -DOMAP_CSMI_POWER_CONTROL -DUSE_TI_COMMANDS
endif

ifeq ($(TARGET_DEVICE),surf)
  LOCAL_CFLAGS += -DPOLL_CALL_STATE -DUSE_QMI
endif

ifeq ($(TARGET_DEVICE),dream)
  LOCAL_CFLAGS += -DPOLL_CALL_STATE -DUSE_QMI
endif

#build shared library
LOCAL_SHARED_LIBRARIES += \
     libcutils libutils
LOCAL_LDLIBS += -lpthread
LOCAL_CFLAGS += -DRIL_SHLIB
LOCAL_MODULE:= libril-at-cyit
include $(BUILD_SHARED_LIBRARY)
