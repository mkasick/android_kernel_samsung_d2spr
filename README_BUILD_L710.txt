1. How to Build

	You need to get Toolchain and it is in ICS platform source code.
 	- arm-eabi-4.4.3

	$MYPATH is your ICS Android platform code path.

	$ make ARCH=arm CROSS_COMPILE=
	"$MY_PATH/android/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-" 
	m2_spr_defconfig
	
	ex) make ARCH=arm CROSS_COMPILE="~/ICS/android/prebuilt/linux-x86/ \
		toolchain/arm-eabi-4.4.3/bin/arm-eabi- m2_spr_defconfig

	$ make ARCH=arm CROSS_COMPILE=
	"$MY_PATH/android/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-" 
	zImage

2. How to clean

	$ make ARCH=arm CROSS_COMPILE=
	"$MY_PATH/android/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-" 
	clean

