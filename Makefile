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


.PHONY: all

SGX_SDK ?= /opt/intel/sgxsdk
SSL_SGX ?= /opt/intel/sgxssl

ifdef SIMULATE_IAS
SIM_VALUE ?= $(SIMULATE_IAS)
else
SIM_VALUE ?= 0
endif

all: auxlib trucelib service_provider truce_client

auxlib:
	@echo "Building aux_lib"
	@cd aux_lib && make SIMULATE_IAS=$(SIM_VALUE)
	
trucelib: 
	@echo "Building application"
	@cd application && make SIMULATE_IAS=$(SIM_VALUE) SGX_SDK=$(SGX_SDK) SSL_SGX?=$(SSL_SGX)
	
service_provider: 
	@echo "Building service-provider"
	@cd service-provider && make SIMULATE_IAS=$(SIM_VALUE) SGX_SDK=$(SGX_SDK) SSL_SGX?=$(SSL_SGX)
	
truce_client: 
	@echo "Building client"
	@cd client && make SIMULATE_IAS=$(SIM_VALUE) SGX_SDK=$(SGX_SDK) SSL_SGX?=$(SSL_SGX)

.PHONY: clean
	
clean:
	@cd aux_lib && make clean
	@cd application && make clean
	@cd service-provider && make clean
	@cd client && make clean
