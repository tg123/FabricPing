# FabricPing

Network debugging tools for [Service Fabric](https://azure.microsoft.com/en-us/services/service-fabric/)

## Install


### Windows

 * powershell

    ```
    Invoke-WebRequest -OutFile 'FabricPing_windows_amd64.zip' -Uri 'https://github.com/tg123/FabricPing/releases/latest/download/FabricPing_windows_amd64.zip' -UseBasicParsing

    Expand-Archive ./FabricPing_windows_amd64.zip -DestinationPath .
    ```
 

 * using [built in curl](https://docs.microsoft.com/en-us/virtualization/community/team-blog/2017/20171219-tar-and-curl-come-to-windows) in case of `Invoke-WebRequest` not working on Windows Server Core

    ```
    curl.exe -L https://github.com/tg123/FabricPing/releases/latest/download/FabricPing_windows_amd64.zip -o FabricPing_windows_amd64.zip
    ```
 

### Linux

```
curl -L https://github.com/tg123/FabricPing/releases/latest/download/FabricPing_linux_amd64.tar.gz | tar xz
```

## Usage

### Test Fabric protocol endpoints

This mode works with Fabric Port (typically 1025) and Fabric Gateway Port (typically 19000)

```
FabricPing.exe 127.0.0.1:1025
```

### Test Lease endpoint (`-l`)

The mode pings a Lease Port (typically 1026) and requires `FabricPing` running inside the VNET of the Service Fabric Cluster as remote lease agents will connect back

```
FabricPing.exe -l 127.0.0.1:1026
```

### Discover all known nodes (`-d`)

The mode connects to Fabric Port (typically 1025) and requires `FabricPing` running inside the VNET of the Service Fabric Cluster as remote fabric will connect back,
 
```
FabricPing.exe -d 127.0.0.1:1025
```

#### Node Phases
  * Booting: the node is sending VotePing to seed nodes
  * Joining: the node is establishing lease with its neighbors
  * Inserting: the node is negotiating token range with its neighbors
  * Routing: the node is serving
  * Shutdown: the node is shutting down
