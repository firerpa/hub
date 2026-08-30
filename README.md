PIGEON is an open-source, locally-deployed Android device management and automation scripting system, supporting P2P/FRP cross-network connectivity, script development, online debugging, realtime task dispatch, execution, and tracking, ideal for remote device ops and RPA/AI scripts.

## BUILDING

```bash
docker build -t firerpa/pigeon:1.0 . # or pull from docker hub
```

## DEPLOYMENT

```bash
cp -pr docker ~/pigeon

cd ~/pigeon
cp .env.example .env

# !! Edit the .env file according to your own environment (see .env.example for more instructions).

docker compose -f docker-compose.yml up --force-recreate -d
```

Visit https://${LOCAL_IP/PUBLIC_IP}:8000 and log in with default credentials: username `admin`, password `pigeon`.