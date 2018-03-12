# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

SGX_SSL ?= /opt/intel/sgxssl
SGX_SDK ?= /opt/intel/sgxsdk
SGX_DEBUG ?= 0
SGX_ARCH ?= x64

IAS_VERIFIER_SO_U ?= libiasverifier_u.so
IAS_VERIFIER_ARCHIVE_U ?= libiasverifier_u.a
IAS_VERIFIER_ARCHIVE_T ?= libiasverifier_t.a

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIB_DIR := $(SGX_SDK)/lib
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIB_DIR := $(SGX_SDK)/lib64
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

Cpp_Files := IAS_report_verifier.cpp

App_Include_Paths := -I$(SGX_SDK)/include -I../ -I../../
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -lcrypto -L$(SGX_LIB_DIR) -lpthread -Wl,-rpath=$(CURDIR)

Enclave_Include_Paths := -I$(SGX_SDK)/include -I../ -I../../ -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SSL)/include
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

App_Cpp_Objects := IAS_report_verifier_u.o
Enclave_Cpp_Objects := IAS_report_verifier_t.o


ifdef SIMULATE_IAS
ifeq ($(SIMULATE_IAS),1)
App_Cpp_Flags += -DSIMULATE_IAS
Enclave_Cpp_Flags += -DSIMULATE_IAS
endif
endif

.PHONY: all

all: $(IAS_VERIFIER_ARCHIVE_T) $(IAS_VERIFIER_ARCHIVE_U) #$(IAS_VERIFIER_SO_U)

IAS_report_verifier_u.o: IAS_report_verifier.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

IAS_report_verifier_t.o: IAS_report_verifier.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(IAS_VERIFIER_SO_U): $(App_Cpp_Objects)
	@$(CXX) $^ $(App_Link_Flags) -shared -o $@
	@echo "LINK =>  $@"

$(IAS_VERIFIER_ARCHIVE_U): $(App_Cpp_Objects)
	ar -cvq $@ $(App_Cpp_Objects)
	@echo "CONSTRUCT  =>  $@"

$(IAS_VERIFIER_ARCHIVE_T): $(Enclave_Cpp_Objects)
	ar -cvq $@ $(Enclave_Cpp_Objects)
	@echo "CONSTRUCT  =>  $@"
	
clean:
	@rm -f $(App_Cpp_Objects) $(Enclave_Cpp_Objects) $(IAS_VERIFIER_ARCHIVE_T) $(IAS_VERIFIER_ARCHIVE_U) $(IAS_VERIFIER_SO_U)
	