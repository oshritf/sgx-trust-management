IBM Trusted Services libraries and reference

!! Under construction, come back later !!

Compilation steps:
- cd truce/application
- make
- cd ../client
- make
- cd ../service-provider
- make
- cd ../../sample/agent
- make
- cd ../client
- make
- cd ../../


In order to run, do the following steps:
PWD = current directory
- export LD_LIBRARY_PATH=$PWD/truce/application
- /truce/service-provider/truce_server &
- /sample/agent/agent 127.0.0.1 &
- export LD_LIBRARY_PATH=$PWD/truce/client
- (Writing a file): /sample/client/client 127.0.0.1 127.0.0.1 [finer_print_file_path] w
- (Reading and checking for a match): /sample/client/client 127.0.0.1 127.0.0.1 [finger_print_file_path] r
