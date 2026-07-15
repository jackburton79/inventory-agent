################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
LOCAL_CPP_SRCS = \
../http/HTTP.cpp \
../http/HTTPDefines.cpp \
../http/HTTPHeader.cpp \
../http/HTTPRequestHeader.cpp \
../http/HTTPResponseHeader.cpp \
../http/Socket.cpp \
../http/SocketGetter.cpp \
../http/SSLSocket.cpp \
../http/URL.cpp \
../http/Utils.cpp 

LOCALOBJECTS= $(addprefix ./http/, $(notdir $(LOCAL_CPP_SRCS:.cpp=.o)))
LOCALDEPS= $(addprefix ./http/, $(notdir $(LOCALOBJECTS:.o=.d)))

SOURCES+= $(LOCAL_CPP_SRCS)
OBJS += $(LOCALOBJECTS)
DEPS += $(LOCALDEPS)


# Each subdirectory must supply rules for building sources it contributes
http/%.o: http/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -DTIXML_USE_STL $(CXXFLAGS) -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


