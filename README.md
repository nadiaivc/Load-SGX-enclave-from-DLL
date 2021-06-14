# Loading SGX enclave from DLL Sample (with remote attestation)

* [Introduction](#intro)
* Building
  * [Windows*](#build-win)
* [Running](#running-quick)
* [Demonstration](#output)

## <a name="intro"></a>Introduction

This code sample demonstrates the procedures that must be followed when running SGX enclave from DLL(untrusted SGX module) that also performing Remote Attestation for an Intel SGX enclave when using EPID attestations. You could use it to load your SGX enclave into any process using DLL injection. In this example, I use it to read the executable modules of target process and calculate their checksums. The code sample includes both a sample client DLL (and its enclave) and remote attestation server. It has been tested on the following platforms:

**Microsoft* Windows**
 * Windows 10 64-bit

For complete information on remote attestation, see the [white paper](https://software.intel.com/en-us/articles/intel-software-guard-extensions-remote-attestation-end-to-end-example) on Intel's Developer Zone.

## <a name="build"></a>Building the Sample

For simplicity, the client and server are packaged and built together. In a real-world environment, these would be separate builds.

The service provider's remote attestation server _does not require Intel SGX hardware or software to run_. The server in this code sample requires the Intel SGX SDK header files in order to simplify the code and build process, but this is not strictly necessary.

### <a name="build-win"></a>Windows

#### Prerequisites

* Ensure you have the following:

  * Windows 10 64-bit
  * Microsoft* Visual Studio 2017 or newer
  * [Intel SGX SDK and Platform Software for Windows](https://software.intel.com/en-us/sgx-sdk/download) v2.7 or later

* Install OpenSSL 1.1.0 for Windows. The [Win64 OpenSSL v1.1.0 package from Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html) is recommended. **Select the option to copy the DLL's to your Windows system directory.**

* Download [applink.c](https://github.com/openssl/openssl/blob/master/ms/applink.c) from GitHub and install it to OpenSSL's `include\openssl` directory.

#### Configure and Compile
I used absolute paths in the Properties so you will have to modify them.
If you want to inject client.dll to some process, you have to change the configuration of project: Properties -> General -> Configuration type = ".dll"

* Open the Solution file `remote-attestation-sample.sln` in the `vs/` subdirectory.

* Set the configuration to "Debug" and the platform to "x64".

* Configure the client build

  * Open the **client** project properties

  * Navigate to "C/C++ -> General" and edit "Additional Include Directories" to include your OpenSSL include path. 
  
  * Navigate to "Linker -> General" and edit "Additional Library Directories" to `C:\OpenSSL-Win64\lib`

* Configure the *server* build

  * Open the **sp** project properties

  * Navigate to "Linker -> Additional Library Directories" and edit "Additional Library Directories" to include your OpenSSL library path.

* Build the Solution. The binaries will be written to `vs\x64\Debug`

## <a name="running-quick"></a>Running the Sample (Quick Start Guide)

By default, the server listens on port 7777 and the client connects to localhost. The server will make use of system proxy settings when contacting IAS.

### Enclave Verification Policy

I wrote all the parameters for remote attestation in the code, so you don't need .cmd files. If you want to set your parameters, use this instruction: https://www.programmersought.com/article/42885534811/

### Server

You just need to run sp.exe

### Client

Injection:
You have to inject your client.dll to the target process (in x64\Debug\ I put an empty program (hello.exe) that prints the line "hello"). It doesn't work with simple LoadLibrary injection!! I used this injector (https://github.com/guided-hacking/GuidedHacking-Injector) and type "ManualMap" and it works good.

## <a name="output"></a>Demonstration

https://user-images.githubusercontent.com/47255730/121778815-60415680-cba1-11eb-88fe-ff6d36afb33a.mp4

