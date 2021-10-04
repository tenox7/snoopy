set APP=snoopy

set INCLUDE=
set LIB=
set LIBPATH=
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64
echo on
del %APP%-x64.exe 
cl /Fe%APP%-x64.exe %APP%.c 

set INCLUDE=
set LIB=
set LIBPATH=
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64_x86
echo on
del %APP%-x86.exe 
cl /Fe%APP%-x86.exe %APP%.c 

set INCLUDE=
set LIB=
set LIBPATH=
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64_arm
echo on
del %APP%-arm.exe 
cl /D_ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE /Fe%APP%-arm.exe %APP%.c 

pause
