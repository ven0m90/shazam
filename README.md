# Recon Automation For Bug Bounty & Pentesting
# Installation
```console
sudo apt install -y git ; git clone https://github.com/ven0m90/shazam 
chmod +x shazam/* 
bash install-shazam
```
# Note! 
add your blind xss payload
```console

scripts/xssscan.sh
scripts/xssscan-crawl.sh

```



# Note! 
Add Your Discord Web Hook For Notify to enable notification feature 
```console
~/.config/notify/provider-config.yaml
```
```console
discord:
  - id: "subs"
    discord_channel: "subs"
    discord_username: "test"
    discord_format: "{{data}}"
    discord_webhook_url: "web-hook-url"

```
# Usage
```console
./subenum.sh domains.txt 
```
# More options and tools Coming Soon....
