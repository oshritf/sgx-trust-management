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


TRUCE_CLIENT_LIB:=libtruce_client.so
TRUCE_CLIENT:=truce_client

SGX_SDK ?= /opt/intel/sgxsdk

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


Cpp_Files := truce_client.cpp client.cpp
Include_Paths := -I../ -I../aux_lib -IIAS_report_verifier -I$(SGX_SDK)/include

Cpp_Flags := $(Include_Paths) -fPIC -std=c++11

Cpp_Objects := $(Cpp_Files:.cpp=.o)

Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIB_DIR) -lsgx_tcrypto -lcurl -lcrypto -lpthread -L../aux_lib -laux_lib -LIAS_report_verifier -liasverifier_u -Wl,-rpath=$(CURDIR)


ifdef SIMULATE_IAS
SIM_VALUE ?= $(SIMULATE_IAS)
else
SIM_VALUE ?= 0
endif

ifdef SIMULATE_IAS
ifeq ($(SIMULATE_IAS),1)
Cpp_Flags += -DSIMULATE_IAS
endif
endif

.PHONY: all

all: ias_report_verifier $(TRUCE_CLIENT_LIB) $(TRUCE_CLIENT)

######## IAS_report_verifier ######

ias_report_verifier: 
	@echo "Building IAS_report_verifier"
	@cd IAS_report_verifier && make SIMULATE_IAS=$(SIM_VALUE) SGX_SDK=$(SGX_SDK) SGX_SSL=$(SGX_SSL)

####################################

./%.o: ./%.cpp
	@$(CXX) $(Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"


$(TRUCE_CLIENT_LIB): truce_client.o
	@$(CXX) $^ -shared -o $@ $(Link_Flags)
	@echo "LINK =>  $@"


$(TRUCE_CLIENT): $(Cpp_Objects)
	@$(CXX) $^ -L../aux_lib -laux_lib -o $@ $(Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean

clean:
	@cd IAS_report_verifier && make clean
	@rm -f $(Cpp_Objects) $(TRUCE_CLIENT_LIB) $(TRUCE_CLIENT)

