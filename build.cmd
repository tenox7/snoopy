set APP=snoopy
set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat"

set INCLUDE=
set LIB=
set LIBPATH=
call %VCVARS% amd64
echo on
del %APP%-x64.exe 
cl /Fe%APP%-x64.exe %APP%.c 

set INCLUDE=
set LIB=
set LIBPATH=
call %VCVARS% amd64_x86
echo on
del %APP%-x86.exe 
cl /Fe%APP%-x86.exe %APP%.c 

set INCLUDE=
set LIB=
set LIBPATH=
call %VCVARS% amd64_arm
echo on
del %APP%-arm.exe 
cl /D_ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE /Fe%APP%-arm.exe %APP%.c 

pause
