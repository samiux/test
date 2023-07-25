sudo cp auto_config /etc/croissants/conf.d/
sudo chmod +x /etc/croissants/conf.d/auto_config

yes N | sudo dpkg -i *.deb

sudo /etc/croissants/conf.d/auto_config
