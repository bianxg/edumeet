# ![edumeet logo](/app/public/images/logo.edumeet.svg)
# Documentation / Table Of Contents
### [Overview eduMEET](/README.md)
### [Documentation of configuration for client/app](/app/public/config/README.md)
### [Documentation of configuration for server](/server/config/README.md)
### [Documentation of Development enviroment with Docker](/compose/README.md)
### [Setup HAproxy / load balancing edumeet](HAproxy.md)
### [Scaling and recommended Hardware](SCALING_AND_HARDWARE.md)

cd app
export NODE_OPTIONS=--openssl-legacy-provider
yarn build


# Stop your locally running server. Copy systemd-service file `edumeet.service` to `/etc/systemd/system/` and check location path settings:
cp edumeet.service /etc/systemd/system/

# modify the install paths, if required
sudo edit /etc/systemd/system/edumeet.service

# Reload systemd configuration and start service:
sudo systemctl daemon-reload
sudo systemctl start edumeet

# If you want to start edumeet at boot time:
sudo systemctl enable edumeet

# Viewing Logs with journalctl
journalctl -f -u edumeet
journalctl -u edumeet.service > edumeet_logs.txt
journalctl -u edumeet.service | gzip > edumeet_logs.gz
journalctl -u edumeet.service --since "1 hour ago" > edumeet_logs_last_hour.txt
journalctl -f -u edumeet.service | tee edumeet_real_time_logs.txt
