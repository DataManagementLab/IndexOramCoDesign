# Oblivious OLTP - Rust SGX SDK

## Branch overview
- main: Current working approach, contains the latest stable and checked optimizations
- client_request_batches: Work on ORAM access batching
- opt_intf_1: Better enclave-app interface by deserializing raw request
- opt_intf_2: branch opt_intf_1 + nested ecall for returning ORAM path to enclave
- others: Not described or archived old optimizations

## Prerequisites
- Docker 
- Intel SGX OOT 2.11.0 Driver or DCAP 1.36.2 Driver 
- Intel SGX SDK v2.12 
- Intel SGX PSW
- Ubuntu 18.04

Installation guides for Intel SGX software: [Intel SGX Guides](https://download.01.org/intel-sgx/sgx-linux/2.12/docs/) 
<br>
Installation files: [Drivers & SDK](https://download.01.org/intel-sgx/sgx-linux/2.12/distro/ubuntu18.04-server/)

## Inital commands to create environment

- Create a folder, f.e. with name Workspace, and visit it
```
mkdir Workspace
cd Workspace
```
- Clone this repo here
```
git clone git@github.com:philito/oblivious_oltp_rust_sgx.git
```
- Clone Apache Teaclave SDK:
```
git clone https://github.com/apache/incubator-teaclave-sgx-sdk.git
```
- Pull the docker image for our Ubuntu 18.04
```
cd incubator-teaclave-sgx-sdk
docker pull baiduxlab/sgx-rust:1804-1.1.3
cd ..
```
## How to compile & run
- Start docker in ```Workspace``` folder with sgx reachable in ```/dev/sgx``` (could be also ```/dev/isgx``` in your system f.e.):
```
sudo docker run -v $(pwd):/root/sgx -ti --device /dev/sgx baiduxlab/sgx-rust:1804-1.1.3
```
- When in docker, enter the following commands:
```
LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/
/opt/intel/sgx-aesm-service/aesm/aesm_service
CUSTOM_EDL_PATH=~/sgx/incubator-teaclave-sgx-sdk/edl
CUSTOM_COMMON_PATH=~/sgx/incubator-teaclave-sgx-sdk/common 
```
- Visit the folder of this repo/project:
```
cd sgx/oblivious_oltp_rust_sgx
```
- Compile the project
```
make
```
- Execute the binary
```
cd bin
./app
```


## Guidelines

- Enclave source code goes in ```enclave/src```, host/app source code goes in ```app/src```), or modify the ```.rs``` files already included with the project
- Interface between enclave and app is ```Enclave.edl``` file
- Change the ```Cargo.toml (or/and Xargo.toml if you want to use Xargo)``` files depending on of your needs (adding/removing dependencies).
    - Be careful if you want to change the library name on the ```Cargo.toml``` file (enclave part), you will need to reflect this change on the enclave ```Makefile```, more specifically on the ```ENCLAVE_CARGO_LIB``` variable, and on the ```lib.rs``` file.
    - If you need to change the app/host name, please make sure to edit the host ```Makefile```, and change the variable ```APP_U```.

## Additional info for Building 

By default, your project will be compiled in hardware mode. If you wish to compile your project in software/simulation mode, you will need to specify it, either by adding ```SGX_MODE=SW``` before make, or by setting the SGX_MODE variable environment to SW.

Cargo is used by default when compiling, but you can also use Xargo either by adding ```XARGO_SGX=1``` before make, or by setting the XARGO_SGX variable environment to 1. You will also need to specify Xargo library path with XARGO_PATH.

### The makefile has those commands available: 
- make (will compile everything)
- make host (will only compile the host part)
- make enclave (will only compile the enclave part)
- make clean (will clean the objects/C edl files generated)
- make clean_host (will clean the objects/C edl files generated for the host only)
- make clean_enclave (will clean the objects/C edl files generated for the enclave only)
- make fclean (will clean objects/C edl files and the binaries, plus calling cargo clean for everything)
- make fclean_host (will clean objects/C edl files and the binaries, plus calling cargo clean for the host only)
- make fclean_enclave (will clean objects/C edl files and the binaries, plus calling cargo clean for the enclave only)
- make re (re as relink, will clean everything then compile everything again)
- make re_host (re as relink, will clean the host part then compile it again)
- make re_enclave (re as relink, will clean the enclave part then compile it again)

## Debugging
Debugging needs some special debug parameters, adaptions in the makefiles as well a workaround for the needed sgx-ring crate. sgx-ring cannot debug without implementing the assert_fail method on our own, see more in the [corresponding issue](https://github.com/apache/incubator-teaclave-sgx-sdk/issues/44). That is why there is a seperate implementation in the special branch measure_gdb. This branch should only be used for developing and research purposes.
Inside the docker, you need to install these packages:
- libsgx-enclave-common-dbgsym
- libsgx-urts-dbgsym

Moreover, sgx-gdb needs to be installed in the docker:
```
apt-get update && apt-get install -y gdb
```

Afterwards, run sgx-gdb:
```
sgx-gdb
```
For monitoring the enclave resource usage, use sgx_emmt inside the sgx-gdb execution:
```
enable sgx_emmt
```
sgx_emmt statistics are shown when an enclave is destroyed using the corresponding API of Intel.
Now, the project app binary (in /bin) must be made executable in gdb with
```
exec-file app
```
and can be started by a simple command.
```
run
```

For more details how to debug, f.e. with breakpoints, you can have a look into a [HowTo from the SDK developers](https://teaclave.apache.org/sgx-sdk-docs/debugging-a-local-rust-sgx-enclave/).
