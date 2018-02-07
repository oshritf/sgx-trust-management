
TRUCELIB_CL:=libtruce_client.so


Cpp_Files := truce_client.cpp
Include_Paths := -I.

Cpp_Flags := $(App_Include_Paths) -fPIC -std=c++11

Cpp_Objects := $(Cpp_Files:.cpp=.o)



./%.o: ./%.cpp
	@$(CXX) $(Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"


$(TRUCELIB_CL): truce_client.o
	@$(CXX) $^ -shared -o $@
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f $(Cpp_Objects) $(TRUCELIB_CL)

