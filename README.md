<div align=center><img src="https://github.com/DeaglePC/XTunnel/blob/master/logos.png"/></div>

[中文](https://github.com/DeaglePC/XTunnel/blob/master/README_CN.md) | [English](https://github.com/DeaglePC/XTunnel/blob/master/README.md)

# Introduction  
A tool for penetrating the Intranet, allowing LAN ports to expose to the public network to penetrate the LAN, similar to FRP, ngork and other software, but more lightweight, only for TCP connections, support multi-user and multi-client.  

*The network IO model adopts the event driven model of reactor pattern, and the implementation method refers to redis source code*

**Supporting Linux only for now. WSL is recommended under Windows**

# Feature
1. The size of executable file is very small.（100+kb）
2. Easy to run, without any dependence , can run directly to the background of the daemon process.
3. The configuration file is simple.
4. Encryption transmission, the forwarded data will be encrypted and then transmitted, encryption algorithm defaults to aes-256-cbc.
5. High performance IO, based on IO multiplexing, network event processing refers to redis Reactor event driven model.

# Installation
* Compile  
```bash
git clone https://github.com/DeaglePC/XTunnel.git && cd XTunnel/xtun/ && cmake -DCMAKE_BUILD_TYPE=Release . && make
```
* Download  
[XTunnel_0.2_linux_x86_64.zip](https://github.com/DeaglePC/XTunnel/releases/download/0.2/XTunnel_0.2_linux_x86_64.zip)


# Configuration

## Server
*Example： `ts.ini`*
```ini
[common]
server_port = 10087         # for client connection
password = 666              # keep it private
log_path = /home/xxx/log    # log file path, make sure you have permission to write and read
```

## Client
*Example： `tc.ini`*
```ini
[common]
server_ip = 12.13.14.15     # server public ip address
server_port = 10087         # the server_port in ts.ini
password = 666              # server password in ts.ini
log_path = /home/xxx/log    # log file path, make sure you have permission to write and read

[ssh]
local_ip = 127.0.0.1
local_port = 22             # local application's port, here is ssh
remote_port = 12300         # You want to expose the port on the public network

[vnc]
local_ip = 192.168.1.11
local_port = 5900
remote_port = 12301

[rdp]
local_ip = 192.168.1.12
local_port = 3389
remote_port = 12302
```
The port mapping is as follows:
|LAN network|Public network|
|-|-|
|127.0.0.1:22|12.13.14.15:12300|
|192.168.1.11:5900|12.13.14.15:12301|
|192.168.1.12:3389|12.13.14.15:12302|

According to the above configuration file, by connecting to the IP: port of the public network, you can connect to the application in the LAN. For example, the above configuration files can be connected to SSH, VNC, and Windows RDP remote desktop respectively.


# Startup(Server & Client)
1. Run server（Runs on a host with a public network IP）  
```shell
./tunserver -c ts.ini -d
```
*`-d` Parameter representation runs as a daemon*

2. Run client（Runs on a host in LAN）
```shell
./tunclient -c tc.ini -d
```

3. Connect to LAN applications by connecting to public network IP
```shell
ssh test@12.13.14.15 -p 12300
```


TODO：  
- [x] 1. The configuration file  
- [x] 2. Password encryption  
- [x] 3. Heartbeats  
- [x] 4. Encryption transmission  
- [x] 5. Reconnect after disconnection
- [ ] 6. Keep log files for n days only
- [ ] 7. Add restart and stop parameters
- [ ] 8. Optimize the code

# Thanks：
[Winnerhust](https://github.com/Winnerhust/inifile2)   for inifile2  
[JieweiWei](https://github.com/JieweiWei/md5) for MD5  
[ttfutt](https://github.com/ttfutt/logger)  for logger
