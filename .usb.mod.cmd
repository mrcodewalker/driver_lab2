savedcmd_usb.mod := printf '%s\n'   usb.o | awk '!x[$$0]++ { print("./"$$0) }' > usb.mod
