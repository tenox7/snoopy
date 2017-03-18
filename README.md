# Portable Command Line Packet Sniffer for Windows 

Snoopy is a small and portable packet analyzer for Windows command line. It doesn't install any driver like LibPcap and it's contained to a single exe file for portability. Also it's just 200 lines of code.

![Screenshot](https://raw.githubusercontent.com/tenox7/snoopy/master/screenshot.png "Snoopy Screenshot")

You bind to the NIC you want to listen to by specifying it's IP address on the command line. The -v option enables verbose mode where more detailed protocol information is displayed. Currently Snoopy doesn't allow for any filtering, but this can be done by piping output to findstr command.

Note that due to use of raw sockets instead of a driver, the functionality is severaly limited to only listening to unicast TCP, UDP, ICMP, etc. You cannot see anything below layer 3, broadcasts, unicasts, etc. However if you just need something simple to check for traffic going to a specific IP address or port number, this is a perfect handy dandy utility.

Minimum OS version is Windows Server 2008 R2. So no Alpha, MIPS, PowerPC ports.