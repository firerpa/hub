<h3><p align="center">Firerpa P2P device hub | FIRERPA P2P 设备管理平台。</p></h3>

<p align="center">
<img src=".github/images/detail.png" alt="demo" width="100%">
</p>

<p align="center">
<img src=".github/images/totalview.png" alt="demo" width="100%">
</p>

## How to develop

The project consists of a frontend and a backend. This repository is the backend, and it already includes the packaged frontend code. If you need to modify the frontend, please go to the hub-vue project, repackage the frontend code, and replace the existing files in server/html and server/static accordingly. 本项目分为前后端，本项目为后端，已包含打包好的前端代码。如需修改前端，请转到 hub-vue 项目，并将重新打包的前端代码平替到 server/html、server/static。

## How to build

Run the below command to build the Docker image. 运行如下命令构建 docker 镜像。

```bash
docker build -t hub .
```


## How to run

We recommend running Docker on a Linux system, as Docker networking on Windows hosts may not properly connect devices with the services inside the Docker container. 我们建议在 Linux 系统上运行 docker，并且使用 host 网络模式，windows 宿主机的 docker 网无法正确的使设备和 docker 内的服务连通。

```bash
docker run -d --name hub --net host --privileged -v ~/hub-data:/user -e DOMAIN=firerpa.local -e WEB_PORT=8000 -e API_PORT=65000 -e TOP_ENDPOINT=.. -e TOP_CLIENT_KEY=.. -e TOP_SECRET=.. --restart always hub:latest
```

WEB_PORT is the port bound to the HTTP service, API_PORT is the port bound to the client API (recommended to be 65000). WEB_PORT 是HTTP服务绑定的端口，API_PORT 是客户端 API 绑定的端口（建议为 65000）。