#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#


######## Server Settings ########


Server_Cpp_Files := server/server.cpp
Server_Include_Paths := -Iservice_provider -Isample_libcrypto

Server_C_Flags := -fPIC -Wno-attributes $(Server_Include_Paths)


Server_Cpp_Flags := $(Server_C_Flags) -std=c++11
Server_Link_Flags := -L. -lpthread -lservice_provider -Wl,-rpath=$(CURDIR)/sample_libcrypto -Wl,-rpath=$(CURDIR) -lsample_libcrypto -Lsample_libcrypto


Server_Cpp_Objects := $(Server_Cpp_Files:.cpp=.o)

Server_Name := truce_server

######## Service Provider Settings ########

ServiceProvider_Cpp_Files := service_provider/ecp.cpp service_provider/service_provider.cpp service_provider/ias_ra.cpp 
ServiceProvider_Include_Paths := -Isample_libcrypto

ServiceProvider_C_Flags := -fPIC -Wno-attributes $(ServiceProvider_Include_Paths)
ServiceProvider_Cpp_Flags := $(ServiceProvider_C_Flags) -std=c++11
ServiceProvider_Link_Flags :=  -shared -lsample_libcrypto -Lsample_libcrypto

ServiceProvider_Cpp_Objects := $(ServiceProvider_Cpp_Files:.cpp=.o)



.PHONY: all run


all: libservice_provider.so $(Server_Name) 




######## Server Objects ########


server/%.o: server/%.cpp
	@$(CXX) $(Server_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Server_Name):  $(Server_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Server_Link_Flags)
	@echo "LINK =>  $@"

######## Service Provider Objects ########


service_provider/%.o: service_provider/%.cpp
	@$(CXX) $(ServiceProvider_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

libservice_provider.so: $(ServiceProvider_Cpp_Objects)
	@$(CXX) $^ -o $@ $(ServiceProvider_Link_Flags)
	@echo "LINK =>  $@"



.PHONY: clean

clean:
	@rm -f $(Server_Name) $(Server_Cpp_Objects) libservice_provider.* $(ServiceProvider_Cpp_Objects)
