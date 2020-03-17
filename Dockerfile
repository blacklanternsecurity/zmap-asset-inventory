#
# Running inside a container allows more reliable scanning of local subnet.
# 
# Build docker image
#   $ docker build -t zmap-assets .
#
# Start container (making sure to remap the script's working directory to the host)
#   $ docker run -it -v /root/inventory/asset_inventory:/root/.asset_inventory zmap-assets
#
# Start scan with desired options
#   $ ./zmap-asset-inventory -t 10.0.0.0/8
#

FROM kalilinux/kali

# INSTALL DUMB-INIT
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install python-dev python-pip
RUN pip install dumb-init

# INSTALL ZMAP
RUN apt-get -y install zmap

# INSTALL NMAP + SCRIPTS, PING, TRACEROUTE, VNCSNAPSHOT, GIT, PATATOR, VIM, ADD-APT-REPOSITORY
RUN apt-get -y install iputils-ping net-tools git nmap vncsnapshot wget vim libcurl4-openssl-dev libssl-dev
WORKDIR /usr/share/nmap/scripts
RUN wget https://svn.nmap.org/nmap/scripts/smb-vuln-ms17-010.nse
WORKDIR /opt
RUN git clone https://github.com/lanjelot/patator.git
WORKDIR /opt/patator

# FIX VNC-INFO SCRIPT
RUN sed -i 's/table.insert( vncsec.types, string.unpack("B", tmp, i) )/table.insert( vncsec.types, (string.unpack("B", tmp, i)) )/g' /usr/share/nmap/nselib/vnc.lua

# RUN python2 -m pip install -r requirements.txt
RUN cat requirements.txt | xargs -n 1 python2 -m pip install || true
RUN ln -s  /opt/patator/patator.py /usr/bin/patator

# INSTALL PYTHON 3.7
RUN apt-get -y install python3.7 python3-pip

# INSTALL IMPACKET
RUN apt-get -y install
RUN python3 -m pip install pipenv
RUN rm -r $(ls /root/.local/share/virtualenvs | grep impacket | head -n 1) &>/dev/null
RUN rm -r /opt/impacket &>/dev/null
WORKDIR /opt
RUN git clone https://github.com/CoreSecurity/impacket.git
WORKDIR /opt/impacket
RUN python3 -m pipenv install
RUN python3 -m pipenv run python setup.py install
RUN ln -s ~/.local/share/virtualenvs/$(ls /root/.local/share/virtualenvs | grep impacket | head -n 1)/bin/*.py /usr/bin/
WORKDIR /
RUN rm -r /opt/impacket

# INSTALL PYTHON 3 PACKAGES
RUN python3 -m pip install openpyxl

# INSTALL ZMAP ASSET INVENTORY
RUN git clone https://github.com/blacklanternsecurity/zmap-asset-inventory
WORKDIR /zmap-asset-inventory

ENTRYPOINT ["dumb-init", "/bin/bash"]