################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
LOCAL_CPP_SRCS = \
../Agent.cpp \
../AgentService.cpp \
../Components.cpp \
../Configuration.cpp \
../Inventory.cpp \
../Logger.cpp \
../NetworkInterface.cpp \
../NetworkRoster.cpp \
../ProcReader.cpp \
../ProcessRoster.cpp \
../Screens.cpp \
../Softwares.cpp \
../StorageRoster.cpp \
../Support.cpp \
../UsersRoster.cpp \
../VolumeRoster.cpp \
../WebServer.cpp \
../XML.cpp \
../ZLibCompressor.cpp

LOCAL_C_SRCS = \
../edid-decode.c

LOCALOBJECTS= $(addprefix ./, $(notdir $(LOCAL_CPP_SRCS:.cpp=.o)))
LOCALOBJECTS+= $(addprefix ./, $(notdir $(LOCAL_C_SRCS:.c=.o)))
LOCALDEPS= $(addprefix ./, $(notdir $(LOCALOBJECTS:.o=.d)))

SOURCES+= $(LOCALSOURCES)
OBJS += $(LOCALOBJECTS)
DEPS += $(LOCALDEPS)


# Each subdirectory must supply rules for building sources it contributes
%.o: ./%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ $(CXXFLAGS) -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


