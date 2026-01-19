#!/bin/bash
set -ex
apt install -y sudo inetutils-ping net-tools locales xfce4 xfce4-terminal dbus-x11 adb vim bash git procps xterm novnc x11vnc xvfb

# set novnc auto connect
sed -i "s,UI.getSetting('resize'),'scale',g" /usr/share/novnc/app/ui.js
sed -i "s,autoconnect === 'true',1,g" /usr/share/novnc/app/ui.js

# install chromium
apt install -y chromium ttf-wqy*

# set chromium default preferences
echo '{"distribution":{"import_bookmarks":false,"make_chrome_default":false,"make_chrome_default_for_user":false,"verbose_logging":false,"skip_first_run_ui":true,"create_all_shortcuts":true,"suppress_first_run_default_browser_prompt":true},"browser":{"show_home_button":true,"has_seen_welcome_page":true,"check_default_browser":false},"bookmark_bar":{"show_on_all_tabs":false},"net":{"network_prediction_options":2},"search":{"suggest_enabled":false},"signin":{"allowed":false,"allowed_on_next_startup":false},"autofill":{"profile_enabled":false,"credit_card_enabled":false},"safebrowsing":{"enabled":false},"dns_prefetching":{"enabled":false},"alternate_error_pages":{"enabled":false},"credentials_enable_service":false,"credentials_enable_autosignin":false,"default_apps":"noinstall","hide_web_store_icon":true,"homepage_is_newtabpage":true,"homepage":"chrome://new-tab-page"}' >/etc/chromium/master_preferences

# allow root to use chromium
echo 'export CHROMIUM_FLAGS="$CHROMIUM_FLAGS -no-sandbox --test-type --disable-dev-shm-usage"' >>/etc/chromium.d/default-flags

# upgrade websockify
pip install --break-system-packages -U --force-reinstall websockify==0.12.0

# vscode
apt install -y software-properties-common apt-transport-https wget gpg
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /usr/share/keyrings/packages.microsoft.gpg
echo "deb [arch=amd64,arm64,armhf signed-by=/usr/share/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list
chmod 644 /usr/share/keyrings/packages.microsoft.gpg

apt update
apt install -y code
# allow root to run vscode
sed -i '2i set -- --no-sandbox --disable-gpu --user-data-dir=/user/.vscode "$@"' /usr/share/code/bin/code
sed -i 's,/usr/share/code/code,/usr/share/code/bin/code,g' /usr/share/applications/code.desktop
# finish

# desktop init script
cat <<EOL >/usr/bin/desktop-init.sh
#!/bin/sh
notify-send "用户警告   WARNING" "
重启镜像后临时系统及 APT/PIP 安装的软件包将被清空，不要在除了用户目录和桌面的地方放置文件！

After restarting the image, the temporary system and the software
packages installed by APT/PIP will be cleared. Do not place files anywhere
except the user directory and desktop!" -u critical
EOL
chmod 755 /usr/bin/desktop-init.sh

cat <<EOL > /etc/xdg/autostart/init.desktop
[Desktop Entry]
Type=Application
Name=Desktop Init
Exec=/usr/bin/desktop-init.sh
X-GNOME-Autostart-enabled=true
EOL
# finish

# only create desktop & downloads
cat <<EOL >/etc/xdg/user-dirs.defaults
DESKTOP=Desktop
DOWNLOAD=Downloads
EOL

cat <<EOL >/etc/supervisor/conf.d/desktop.conf
[program:xvfb]
command                 = Xvfb +extension RANDR "%(ENV_DISPLAY)s" -screen 0 "%(ENV_DISPLAY_WIDTH)s"x"%(ENV_DISPLAY_HEIGH)s"x24 -nolisten tcp -ac
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startretries            = 10000
priority                = 100

[program:novnc]
command                 = websockify --web /usr/share/novnc --unix-listen=/run/novnc.sock --unix-target=/run/x11vnc.sock
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startretries            = 10000
priority                = 100

[program:x11vnc]
command                 = x11vnc -display "%(ENV_DISPLAY)s" -xkb -forever -shared -xrandr newfbsize -capslock -unixsock /run/x11vnc.sock -rfbport 0 -rfbportv6 0
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startretries            = 10000
priority                = 100

[program:xfce4]
command                 = /usr/bin/xfce4-session
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startretries            = 10000
priority                = 100

[group:desktop]
programs=xfce4,x11vnc,novnc,xvfb
EOL