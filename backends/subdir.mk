################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
LOCAL_CPP_SRCS = \
../backends/CPUInfoBackend.cpp \
../backends/DataBackend.cpp \
../backends/DMIDataBackend.cpp \
../backends/DMIDecodeBackend.cpp \
../backends/LSHWBackend.cpp \
../backends/MemInfoBackend.cpp \
../backends/OSInfoBackend.cpp \
../backends/UnameBackend.cpp \

LOCALOBJECTS= $(addprefix ./backends/, $(notdir $(LOCAL_CPP_SRCS:.cpp=.o)))
LOCALDEPS= $(addprefix ./backends/, $(notdir $(LOCALOBJECTS:.o=.d)))

SOURCES+= $(LOCAL_CPP_SRCS)
OBJS += $(LOCALOBJECTS)
DEPS += $(LOCALDEPS)

# Each subdirectory must supply rules for building sources it contributes
backends/%.o: backends/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -DTIXML_USE_STL $(CXXFLAGS) -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


