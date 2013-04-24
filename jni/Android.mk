#
# Copyright (C) 2008 The Android Open Source Project
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
#

# This makefile supplies the rules for building a library of JNI code for
# use by our example of how to bundle a shared library with an APK.

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# This is the target being built.
LOCAL_MODULE:= libexec

# All of the source files that we will compile.
LOCAL_SRC_FILES:= \
  termExec.cpp

LOCAL_LDLIBS := -ldl -llog

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

lzma_SOURCES := \
	7zStream.c 7zFile.c Ppmd7Dec.c Ppmd7.c Bcj2.c \
	Bra86.c Bra.c Lzma2Dec.c LzmaDec.c 7zIn.c 7zDec.c \
	7zCrcOpt.c 7zCrc.c 7zBuf2.c 7zBuf.c 7zAlloc.c \
	CpuArch.c Util/7z/7zMain.c

LOCAL_MODULE := lzma
LOCAL_SRC_FILES := $(addprefix lzma/, $(lzma_SOURCES)) lzma.cpp
LOCAL_CFLAGS := -O2 -g -I$(LOCAL_PATH)/lzma -D_7ZIP_PPMD_SUPPPORT

include $(BUILD_SHARED_LIBRARY)
