#!/bin/bash

TMP_FOLDER=$(mktemp -d)
CONFIG_FILE="digifel.conf"
DIGIFEL_DAEMON="/usr/local/bin/digifeld"
DIGIFEL_CLI="/usr/local/bin/digifel-cli"
DIGIFEL_REPO="https://github.com/digifel/digifel-core"
DEFAULTDIGIFELPORT=10070
DEFAULTDIGIFELUSER="digifel"
NODEIP=$(curl -s4 api.ipify.org)


RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


function compile_error() {
if [ "$?" -gt "0" ];
 then
  echo -e "${RED}Failed to compile $@. Please investigate.${NC}"
  exit 1
fi
}


function checks() {
if [[ $(lsb_release -d) != *16.04* ]]; then
  echo -e "${RED}You are not running Ubuntu 16.04. Installation is cancelled.${NC}"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}$0 must be run as root.${NC}"
   exit 1
fi

if [ -n "$(pidof $DIGIFEL_DAEMON)" ] || [ -e "$DIGIFEL_DAEMOM" ] ; then
  echo -e "${GREEN}\c"
  read -e -p "Digifel is already installed. Do you want to add another MN? [Y/N]" NEW_DIGIFEL
  echo -e "{NC}"
  clear
else
  NEW_DIGIFEL="new"
fi
}

function prepare_system() {

echo -e "Prepare the system to install Digifel master node."
apt-get update >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get update > /dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y -qq upgrade >/dev/null 2>&1
apt install -y software-properties-common >/dev/null 2>&1
echo -e "${GREEN}Adding bitcoin PPA repository"
apt-add-repository -y ppa:bitcoin/bitcoin >/dev/null 2>&1
echo -e "Installing required packages, it may take some time to finish.${NC}"
apt-get update >/dev/null 2>&1
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" make software-properties-common \
build-essential libtool autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev libboost-program-options-dev \
libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git wget pwgen curl libdb4.8-dev bsdmainutils libdb4.8++-dev \
libminiupnpc-dev libgmp3-dev ufw fail2ban >/dev/null 2>&1
clear
if [ "$?" -gt "0" ];
  then
    echo -e "${RED}Not all required packages were installed properly. Try to install them manually by running the following commands:${NC}\n"
    echo "apt-get update"
    echo "apt -y install software-properties-common"
    echo "apt-add-repository -y ppa:bitcoin/bitcoin"
    echo "apt-get update"
    echo "apt install -y make build-essential libtool software-properties-common autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev \
libboost-program-options-dev libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git pwgen curl libdb4.8-dev \
bsdmainutils libdb4.8++-dev libminiupnpc-dev libgmp3-dev pkg-config libevent-dev"
 exit 1
fi

clear
echo -e "Checking if swap space is needed."
PHYMEM=$(free -g|awk '/^Mem:/{print $2}')
SWAP=$(free -g|awk '/^Swap:/{print $2}')
if [ "$PHYMEM" -lt "2" ] && [ -n "$SWAP" ]
  then
    echo -e "${GREEN}Server is running with less than 2G of RAM without SWAP, creating 2G swap file.${NC}"
    SWAPFILE=$(mktemp)
    dd if=/dev/zero of=$SWAPFILE bs=1024 count=2M
    chmod 600 $SWAPFILE
    mkswap $SWAPFILE
    swapon -a $SWAPFILE
else
  echo -e "${GREEN}Server running with at least 2G of RAM, no swap needed.${NC}"
fi
clear
}

function compile_digifel() {
  echo -e "Clone git repo and compile it. This may take some time. Press a key to continue."
  cd $TMP_FOLDER
  git clone $DIGIFEL_REPO
  cd digifel-core
  chmod +x ./autogen.sh
  ./autogen.sh
  ./configure
  make
  compile_error Digifel
  make install
  compile_error Digifel
  cd ~
  rm -rf $TMP_FOLDER
  clear
}

function enable_firewall() {
  echo -e "Installing fail2ban and setting up firewall to allow ingress on port ${GREEN}$DIGIFELPORT${NC}"
  ufw allow $DIGIFELPORT/tcp comment "Digifel MN port" >/dev/null
  ufw allow $[DIGIFELPORT+1]/tcp comment "Digifel RPC port" >/dev/null
  ufw allow ssh comment "SSH" >/dev/null 2>&1
  ufw limit ssh/tcp >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  echo "y" | ufw enable >/dev/null 2>&1
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl start fail2ban >/dev/null 2>&1
}

function systemd_digifel() {
  cat << EOF > /etc/systemd/system/$DIGIFELUSER.service
[Unit]
Description=Digifel service
After=network.target

[Service]
User=$DIGIFELUSER
Group=$DIGIFELUSER

Type=forking
PIDFile=$DIGIFELFOLDER/$DIGIFELUSER.pid


ExecStart=$DIGIFEL_DAEMON -daemon -pid $DIGIFELFOLDER/$DIGIFELUSER.pid -conf=$DIGIFELFOLDER/$CONFIG_FILE -datadir=$DIGIFELFOLDER
ExecStop=-$DIGIFEL_CLI -conf=$DIGIFELFOLDER/$CONFIG_FILE -datadir=$DIGIFELFOLDER stop

Restart=always
PrivateTmp=true
TimeoutStopSec=60s
TimeoutStartSec=2s
StartLimitInterval=120s
StartLimitBurst=5


[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  sleep 3
  systemctl start $DIGIFELUSER.service
  systemctl enable $DIGIFELUSER.service

  if [[ -z "$(ps axo user:15,cmd:100 | egrep ^$DIGIFELUSER | grep $DIGIFEL_DAEMON)" ]]; then
    echo -e "${RED}Digifeld is not running${NC}, please investigate. You should start by running the following commands as root:"
    echo -e "${GREEN}systemctl start $DIGIFELUSER.service"
    echo -e "systemctl status $DIGIFELUSER.service"
    echo -e "less /var/log/syslog${NC}"
    exit 1
  fi
}

function ask_port() {
read -p "DIGIFEL Port: " -i $DEFAULTDIGIFELPORT -e DIGIFELPORT
: ${DIGIFELPORT:=$DEFAULTDIGIFELPORT}
}

function ask_user() {
  read -p "Digifel user: " -i $DEFAULTDIGIFELUSER -e DIGIFELUSER
  : ${DIGIFELUSER:=$DEFAULTDIGIFELUSER}

  if [ -z "$(getent passwd $DIGIFELUSER)" ]; then
    USERPASS=$(pwgen -s 12 1)
    useradd -m $DIGIFELUSER
    echo "$DIGIFELUSER:$USERPASS" | chpasswd

    DIGIFELHOME=$(sudo -H -u $DIGIFELUSER bash -c 'echo $HOME')
    DEFAULTDIGIFELFOLDER="$DIGIFELHOME/.digifelcore"
    read -p "Configuration folder: " -i $DEFAULTDIGIFELFOLDER -e DIGIFELFOLDER
    : ${DIGIFELFOLDER:=$DEFAULTDIGIFELFOLDER}
    mkdir -p $DIGIFELFOLDER
    chown -R $DIGIFELUSER: $DIGIFELFOLDER >/dev/null
  else
    clear
    echo -e "${RED}User exits. Please enter another username: ${NC}"
    ask_user
  fi
}

function check_port() {
  declare -a PORTS
  PORTS=($(netstat -tnlp | awk '/LISTEN/ {print $4}' | awk -F":" '{print $NF}' | sort | uniq | tr '\r\n'  ' '))
  ask_port

  while [[ ${PORTS[@]} =~ $DIGIFELPORT ]] || [[ ${PORTS[@]} =~ $[DIGIFELPORT+1] ]]; do
    clear
    echo -e "${RED}Port in use, please choose another port:${NF}"
    ask_port
  done
}

function create_config() {
  RPCUSER=$(pwgen -s 8 1)
  RPCPASSWORD=$(pwgen -s 15 1)
  cat << EOF > $DIGIFELFOLDER/$CONFIG_FILE
rpcuser=$RPCUSER
rpcpassword=$RPCPASSWORD
rpcallowip=127.0.0.1
rpcport=$[DIGIFELPORT+1]
listen=1
server=1
daemon=1
port=$DIGIFELPORT
EOF
}

function create_key() {
  echo -e "Enter your ${RED}Masternode Private Key${NC}. Leave it blank to generate a new ${RED}Masternode Private Key${NC} for you:"
  read -e DIGIFELKEY
  if [[ -z "$DIGIFELKEY" ]]; then
  su $DIGIFELUSER -c "$DIGIFEL_DAEMON -conf=$DIGIFELFOLDER/$CONFIG_FILE -datadir=$DIGIFELFOLDER"
  sleep 20
  if [ -z "$(ps axo user:15,cmd:100 | egrep ^$DIGIFELUSER | grep $DIGIFEL_DAEMON)" ]; then
   echo -e "${RED}Digifeld server couldn't start. Check /var/log/syslog for errors.{$NC}"
   exit 1
  fi
  DIGIFELKEY=$(su $DIGIFELUSER -c "$DIGIFEL_CLI -conf=$DIGIFELFOLDER/$CONFIG_FILE -datadir=$DIGIFELFOLDER masternode genkey")
  su $DIGIFELUSER -c "$DIGIFEL_CLI -conf=$DIGIFELFOLDER/$CONFIG_FILE -datadir=$DIGIFELFOLDER stop"
fi
}

function update_config() {
  sed -i 's/daemon=1/daemon=0/' $DIGIFELFOLDER/$CONFIG_FILE
  cat << EOF >> $DIGIFELFOLDER/$CONFIG_FILE
maxconnections=256
masternode=1
externalip=$NODEIP:$DIGIFELPORT
masternodeprivkey=$DIGIFELKEY
EOF
  chown -R $DIGIFELUSER: $DIGIFELFOLDER >/dev/null
}

function important_information() {
 echo
 echo -e "================================================================================================================================"
 echo -e "Digifel Masternode is up and running as user ${GREEN}$DIGIFELUSER${NC} and it is listening on port ${GREEN}$DIGIFELPORT${NC}."
 echo -e "${GREEN}$DIGIFELUSER${NC} password is ${RED}$USERPASS${NC}"
 echo -e "Configuration file is: ${RED}$DIGIFELFOLDER/$CONFIG_FILE${NC}"
 echo -e "Start: ${RED}systemctl start $DIGIFELUSER.service${NC}"
 echo -e "Stop: ${RED}systemctl stop $DIGIFELUSER.service${NC}"
 echo -e "VPS_IP:PORT ${RED}$NODEIP:$DIGIFELPORT${NC}"
 echo -e "MASTERNODE PRIVATEKEY is: ${RED}$DIGIFELKEY${NC}"
 echo -e "Please check Digifel is running with the following command: ${GREEN}systemctl status $DIGIFELUSER.service${NC}"
 echo -e "================================================================================================================================"
}

function setup_node() {
  ask_user
  check_port
  create_config
  create_key
  update_config
  enable_firewall
  systemd_digifel
  important_information
}


##### Main #####
clear

checks
if [[ ("$NEW_DIGIFEL" == "y" || "$NEW_DIGIFEL" == "Y") ]]; then
  setup_node
  exit 0
elif [[ "$NEW_DIGIFEL" == "new" ]]; then
  prepare_system
  compile_digifel
  setup_node
else
  echo -e "${GREEN}Digifel MN already running.${NC}"
  exit 0
fi

