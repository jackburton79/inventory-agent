################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables

C_SRCS += \
../libs/civetweb-1.16/src/civetweb.c

OBJS += \
./libs/civetweb-1.16/src/civetweb.o

C_DEPS += \
./libs/civetweb-1.16/src/civetweb.d

LOCAL_C_FLAGS = $(CFLAGS) -DUSE_SSL \
	-DOPENSSL_API_3_0

# Each subdirectory must supply rules for building sources it contributes

libs/civetweb-1.16/src/%.o: ../libs/civetweb-1.16/src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc $(LOCAL_C_FLAGS) -c -fmessage-length=0 -MMD -MP \
		-MF"$(@:%.o=%.d)" \
		-MT"$(@:%.o=%.d)" \
		-o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '