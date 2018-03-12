# Linux SGX Truce Library
## Introduction
Truce Library provides a simplified SDK for Intel SGX developers to implement attestation.
In the current version of Truce, there are 3 components: Applications, Clients and Service Provider.
Applications are the entities that contains SGX enclaves that should be attested, Clients are the entities that want to attest an SGX enclave of an application in order to provide secrets, and the Service Provider (can be seen as a cloud service) is the entity that communicate with the Intel Attestation Service (IAS) and stores all IAS reports of the Applications' SGX enclaves. Any enclave that should be attested need to sign in the Service Provider, and any client that wants to attest an SGX enclave should receive from the Service Provider the enclave's IAS report and verify it. 

## Pre-Request steps
* Download and install the latest packages of Intel SGX LINUX from https://01.org/intel-software-guard-extensions/downloads.
* Download and build SGX SSL located at the git repository https://github.com/intel/intel-sgx-ssl.
* Update the values of SGX_SDK and SGX_SSL in the Makefile.
* Download cpp-base64 from the git repository https://github.com/ReneNyffenegger/cpp-base64, and put it under the aux_lib folder.
* Install the following packages:
	- sudo apt-get install libssl-dev
	- sudo apt-get install libjsoncpp-dev
	- sudo apt-get install libcur14-openssl-dev
* In order to run the code in IAS Real mode, create a [developer account](https://software.intel.com/en-us/sgx). After the registration with a certificate (can be self-signed for development purposes), Intel will
respond with a SPID. Update defs.h with you SPID, certificate and the quote signing type.

## Compilation steps
* In order to compile in IAS simulation mode, type "make SIMULATE_IAS=1".
* In order to compile in IAS Real mode, type "make".
* A successful compilation should output the following files:
	- Under truce/application: libtruce_u.so, libtruce_t.a and app.
	- Under client: libtruce_client.so and truce_client.
	- Under service-provider: truce_server.

## Usage
* Application:
	- The untrusted part should use the API in app/truce_u.h and link with libtruce_u.so
	- The trusted part should import truce_enclave.edl and link with libtruce_t.a
	- truce_app/app.cpp is an example of the untrusted part of such application.
* Client:
	- Should use the API in truce_client.h and link with libtruce_client.so
	- client.cpp is an example of such client.
* Service-Provider:
	- Run truce_server.