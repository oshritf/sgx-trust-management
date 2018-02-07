Compiled and made for ubuntu 4.4.0-62
sgx v1.8

place under /opt/intel (i.e. /opt/intel/sgxssl) to align with Makefile ssl

in sgx_tsgx_ssl.edl tsdc import was commented out (conflict with edl imports, since no ifndef mechanism)
