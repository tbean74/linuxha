#!/bin/bash                                                                    #
#                                                                              #
# This script automatically installs and configures a high-availability,       #
# active/active cluster with the following software: Amavisd, Apache HTTPS,    #
# AppArmor, AutofsLDAP, Bucardo, ClamAV, CLVM, Cyrus SASL, Dovecot IMAPS,      #
# DRBD, FAI, FreeRADIUS, FusionDirectory, GFS, dynamic Bind DNS,               #
# dynamic Kea DHCP, Kerberos, LCMC, LTSP, MariadB, Munin, Nagios, NFS,         #
# OpenLDAP, OpenSSL, OpenVPN, Open-Xchange, Pacemaker, phpLDAPadmin,           #
# phpMyAdmin, phpPgAdmin, Postfix SMTPS, PostgreSQL, Privoxy, ProFTPD,         #
# Shorewall, Snort, SpamAssassin, Squid, SquidClamAV, and Webmin.              #
#                                                                              #
################################################################################
#                                                                              #
# Copyfree 2016                                                                #
#                                                                              #
################################################################################
#                                                                              #
# This script supports Ubuntu Server with four Ethernet adapters. The DRBD     #
# interface is for a crossover cable to provide a redundant link for DRBD      #
# replicated storage. The WAN interfaces provide support for two modems. An    #
# extra modem from a secondary ISP provides load balancing and redundancy.     #
#                                                                              #
# During Ubuntu Server installation, it is important to partition your hard    #
# drive correctly to support this script. Allocate your hard drive's free      #
# space to a boot partition, a physical volume (PV), a volume group (VG), and  #
# logical volumes (LVs). For example, create a VG named vg_system, and add to  #
# this VG a swap LV named lv-swap that is at least 1.5 times as big as your    #
# physical memory, a root LV named lv-root, and a DRBD LV named lv-drbd. Do    #
# not format and mount lv-drbd, as this volume will be automatically formatted #
# and mounted by this script.                                                  #
#                                                                              #
# Start this script on both Domain Controllers at the same time. If there is a #
# delay starting the script on one machine or the other, this script is        #
# designed to wait for the other server to connect. If there is any error      #
# condition, view install.log for further details.                             #
#                                                                              #
# Before running this script, set your user account directory to another       #
# location other than /home. This script mounts a DRBD volume onto the /home   #
# directory. Log in with the root account to change your user account          #
# directory path. For example, to change the user account directory path from  #
# /home/ubuntu-admin to /ubuntu-admin, use the root account to issue the       #
# following command: "usermod ubuntu-admin --move-home --home /ubuntu-admin."  #
# After moving the user account directory, add the user account to the sudo    #
# group with "usermod -aG sudo ubuntu-admin." After you move your user account #
# directory, make sure you log out of root and log in with your user account   #
# before you run this script.                                                  #
#                                                                              #
# Enable root account.                                                         #
# sudo passwd root                                                             #
#                                                                              #
# Disable root account (after script is run).                                  #
# sudo passwd -l root                                                          #
#                                                                              #
# Run this script with the following command: sudo bash LinuxHA.sh.            #            
#                                                                              #
################################################################################
#                                                                              
# Manually adjust variables:                                                   
#                                                                              
SERVER_ADMIN="Administrator"                                                   
EMAIL_ADDRESS="admin@example.com"                                              
ORGANIZATION="Example"                                                         
# Set the Primary and Backup Domain Controllers.                                       
PDC="or-dc1-ub"                                                                
BDC="or-dc2-ub"                                                                
# Use only a two-digit country code.                                           
COUNTRY="US"                                                                   
# Spell out the state in full.                                                 
STATE="Oregon"                                                                 
LAN_DOMAIN="example.local"                                                     
WAN_DOMAIN="example.com"                                                       
LAN_NETMASK="255.255.255.0"                                                    
LAN_INTERFACE="enp0s1"                                                         
PDC_LAN_IP_ADDRESS="192.168.0.1"                                               
BDC_LAN_IP_ADDRESS="192.168.0.2"                                               
DRBD_INTERFACE="enp0s2"                                                        
PDC_DRBD_IP_ADDRESS="192.168.1.1"                                              
BDC_DRBD_IP_ADDRESS="192.168.1.2"                                              
WAN_INTERFACE1="enp0s3"                                                        
PDC_WAN_IP_ADDRESS1="1.1.1.1"                                                  
BDC_WAN_IP_ADDRESS1="1.1.1.2"                                                  
WAN_INTERFACE2="enp0s4"                                                        
PDC_WAN_IP_ADDRESS2="1.1.1.3"                                                  
BDC_WAN_IP_ADDRESS2="1.1.1.4"                                                  
# Set the fastest Ubuntu mirror.                                               
UBUNTU_MIRROR="http://archive.ubuntu.com"                                      
# Set the path to a LV used for DRBD replicated storage. This LV must already 
# exist and must be the same size on both PDC and BDC. Give the full path to the 
# device (e.g., /dev/vg_system/lv-drbd). Make sure this LV is not mounted, as 
# this volume will be automatically mounted by this script.                                                      
LV_DRBD_PATH="/dev/vg_system/lv-drbd"                                          
# Set the size for the /var/www LV. This size is a percentage of the DRBD LV 
# size. The /var/www LV is created by this script.
WWW_SIZE="10%"
# Set the size for the /srv LV. This size is a percentage of the DRBD LV size. 
# The /srv LV is created by this script.
SRV_SIZE="10%"
# Set the STONITH plugin for Pacemaker. Run the "stonith -L" command to 
# determine what plugins are available for your hardware. The meatware plugin 
# needs to be replaced, as it is only a temporary placeholder.
STONITH_PLUGIN="meatware"
# Set the path to the LTSP virtual machine (VM). This VM is deployed to all LTSP 
# clients.
LTSP_VM_PATH="$HOME/VirtualBox\ VMs/ubuntu/ubuntu-flat.vmdk"
#                                                                             
################################################################################

# This script must be run as root.
if [ "$(id | awk '{ print $1 }')" != "uid=0(root)" ]; then
  clear
  echo ""
  echo "This script must be run as root."
  echo ""
  exit 1
fi

# Check for an internet connection.
ping -q -w 1 -c 1 8.8.8.8 > /dev/null
if [ $? -ne 0 ]; then
  clear
  echo ""
  echo "Please check your internet connection."
  echo ""
  exit 1
fi

# Set domain controller.
clear
echo ""
read -rp "Is this your primary or backup server? [PDC/BDC]: " SERVER
while [ "$SERVER" != "pdc" ] && [ "$SERVER" != "Pdc" ] && [ "$SERVER" != "PDC" ] && \
[ "$SERVER" != "primary" ] && [ "$SERVER" != "Primary" ] && [ "$SERVER" != "PRIMARY" ] && \
[ "$SERVER" != "bdc" ] && [ "$SERVER" != "Bdc" ] && [ "$SERVER" != "BDC" ] && \
[ "$SERVER" != "backup" ] && [ "$SERVER" != "Backup" ] && [ "$SERVER" != "BACKUP" ]; do
  clear
  echo ""
  echo "Your response is invalid; please try again."
  echo ""
  read -rp "Is this your primary or backup server? [PDC/BDC]: " SERVER
done
if [ "$SERVER" = "pdc" ] || [ "$SERVER" = "Pdc" ] || [ "$SERVER" = "PDC" ] || \
  [ "$SERVER" = "primary" ] || [ "$SERVER" = "Primary" ] || [ "$SERVER" = "PRIMARY" ]; then
  SERVER="pdc"
elif [ "$SERVER" = "bdc" ] || [ "$SERVER" = "Bdc" ] || [  "$SERVER" = "BDC" ] || \
  [ "$SERVER" = "backup" ] || [ "$SERVER" = "Backup" ] || [ "$SERVER" = "BACKUP" ]; then
  SERVER="bdc"
fi

# Set the system root password.
clear
echo ""
read -rsp "Enter your root password \
(use the same password on both servers): " ROOT_PASSWORD1
clear
echo ""
read -rsp "Re-enter root password to verify: " ROOT_PASSWORD2
while [ "$ROOT_PASSWORD1" != "$ROOT_PASSWORD2" ]; do
  clear
  echo ""
  echo "Your passwords do not match; please try again."
  echo ""
  read -rsp "Enter your root password\
 (use the same password on both servers): " ROOT_PASSWORD1
  clear
  echo ""
  read -rsp "Re-enter root password to verify: " ROOT_PASSWORD2
done
ROOT_PASSWORD=$ROOT_PASSWORD1

# Set the administrator password.
clear
echo ""
read -rsp "Enter your administrator password \
(use the same password on both servers): " ADMIN_PASSWORD1
clear
echo ""
read -rsp "Re-enter administrator password to verify: " ADMIN_PASSWORD2
while [ "$ADMIN_PASSWORD1" != "$ADMIN_PASSWORD2" ]; do
  clear
  echo ""
  echo "Your passwords do not match; please try again."
  echo ""
  read -rsp "Enter your administrator password\
 (use the same password on both servers): " ADMIN_PASSWORD1
  clear
  echo ""
  read -rsp "Re-enter administrator password to verify: " ADMIN_PASSWORD2
done
ADMIN_PASSWORD=$ADMIN_PASSWORD1

(# STDOUT and STDERROR logged to terminal and install.log.

echo "Script start time: $(date +%c)"
echo ""

# Temporarily deactivate the Debconf frontend.
export DEBIAN_FRONTEND=noninteractive 

# Apt-pinning is used to prevent conflicting package selection. 
cat > /etc/apt/preferences << EOF.apt.pinning

# This package is deprecated and replaced with Kea DHCP.
Package: isc-dhcp-server
Pin: version *
Pin-Priority: -100

# This package interferes with /opt/open-xchange/sbin/createcontext.
Package: open-xchange-admin-autocontextid
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-authentication-imap.
Package: open-xchange-authentication-application-storage-rdb
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-authentication-imap.
Package: open-xchange-authentication-database
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-authentication-imap.
Package: open-xchange-authentication-kerberos
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-authentication-imap.
Package: open-xchange-authentication-ldap
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-authentication-imap.
Package: open-xchange-authentication-oauth
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-admin-autocontextid.
Package: open-xchange-admin-reseller
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-drive-client-windows-files.
Package: open-xchange-drive-client-windows
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-eas.
Package: open-xchange-eas-provisioning
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-hostname-ldap.
Package: open-xchange-hostname-config-cascade
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-gui-wizard-plugin.
Package: open-xchange-meta-backend-ox6
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-eas.
Package: open-xchange-meta-mobility
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-admin-reseller.
Package: open-xchange-meta-parallels
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-gui-* and open-xchange-online-help-*.
Package: open-xchange-meta-ui-ox6
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-gui-* and open-xchange-online-help-*.
Package: open-xchange-meta-ui-ox6-compat
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-authentication-imap.
Package: open-xchange-parallels
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-passwordchange-script.
Package: open-xchange-passwordchange-database
Pin: version *
Pin-Priority: -100

# This package conflicts with open-xchange-passwordchange-database.
Package: open-xchange-passwordchange-script
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-saml-backend.
Package: open-xchange-saml
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-admin-reseller.
Package: open-xchange-admin-plugin-reseller
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-admin-reseller.
Package: open-xchange-admin-soap-reseller
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-hostname-config-cascade.
Package: open-xchange-config-cascade-hostname
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-parallels.
Package: open-xchange-custom-parallels
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-meta-backend.
Package: open-xchange-meta-cpanel
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-passwordchange-database.
Package: open-xchange-meta-databaseonly
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-meta-backend.
Package: open-xchange-meta-server
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-parallels.
Package: open-xchange-spamhandler-parallels
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-admin-soap-reseller.
Package: open-xchange-admin-plugin-reseller-soap
Pin: version *
Pin-Priority: -100

# This package depends on open-xchange-meta-server.
Package: open-xchange-meta-singleserver
Pin: version *
Pin-Priority: -100
EOF.apt.pinning

# Apt function to fetch binary software packages.
apt_function() {
  APT="apt-get --yes --allow-unauthenticated \
    -o Dpkg::Options::=--force-confdef,overwrite"
  APT_ARRAY=($*)
  $APT ${APT_ARRAY[*]}
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo ""
    sleep 60
    apt clean all
    rm -f /var/cache/apt/{archives,partial}/lock
    dpkg --force-confdef,overwrite --configure -a
    $APT ${APT_ARRAY[*]}
  done
  return 0
}

# SVN function to fetch source software packages.
svn_function() {
  SVN_ARRAY=($*)
  svn --trust-server-cert --non-interactive --force export ${SVN_ARRAY[*]}
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo "" 
    sleep 60
    svn --trust-server-cert --non-interactive --force export ${SVN_ARRAY[*]}
  done
  return 0
}

# GIT function to fetch source software packages.
git_function() {
  GIT_ARRAY=($*)
  git clone --verbose ${GIT_ARRAY[*]}
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo "" 
    sleep 60
    git clone --verbose ${GIT_ARRAY[*]}
  done
  return 0
}

# Wget function to fetch and extract .tar.gz archives.
WGET="wget --progress=bar:force --continue --tries=0 \
  --no-dns-cache --no-check-certificate --retry-connrefused"
wget_tar_function() {
  $WGET $1 -O /usr/local/src/$2.tar.gz
  cd /usr/local/src
  tar xzf $2.tar.gz
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo ""
    sleep 60
    rm -rf /usr/local/src/$2*
    $WGET $1 -O /usr/local/src/$2.tar.gz
    cd /usr/local/src
    tar xzf $2.tar.gz
  done
  return 0
}

# Wget function to fetch .deb packages.
wget_deb_function() {
  $WGET $1 -O /usr/local/src/$2.deb
  dpkg --force-confdef,overwrite -i /usr/local/src/$2.deb
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo "" 
    sleep 60
    rm -f /usr/local/src/$2.deb
    $WGET $1 -O /usr/local/src/$2.deb
    dpkg --force-confdef,overwrite -i /usr/local/src/$2.deb
  done
  rm -f /usr/local/src/$2.deb
  return 0
}

# Function to convert the subnet mask to CIDR format.
mask2cidr() {
  NBITS=0
  IFS=.
  for IP_4TH_OCTET in $1; do
    case $IP_4TH_OCTET in
      255) let NBITS+=8;;
      254) let NBITS+=7;;
      252) let NBITS+=6;;
      248) let NBITS+=5;;
      240) let NBITS+=4;;
      224) let NBITS+=3;;
      192) let NBITS+=2;;
      128) let NBITS+=1;;
      0);;
      *) exit 1
    esac
  done
  echo "$NBITS"
  return 0
}

# Function to get the network address.
get_network_address() {
  SAVE_IFS=$IFS
  IFS=.
  typeset -a IP_ADDRESS_ARRAY=($1)
  typeset -a NETMASK_ARRAY=($2)
  IFS=$SAVE_IFS
  echo $((${IP_ADDRESS_ARRAY[0]} & ${NETMASK_ARRAY[0]})).$((${IP_ADDRESS_ARRAY[1]} & \
    ${NETMASK_ARRAY[1]})).$((${IP_ADDRESS_ARRAY[2]} & \
    ${NETMASK_ARRAY[2]})).$((${IP_ADDRESS_ARRAY[3]} & ${NETMASK_ARRAY[3]}))
  return 0
}

# Function to get the broadcast address.
get_broadcast_address() {
  SAVE_IFS=$IFS
  IFS=.
  typeset -a IP_ADDRESS_ARRAY=($1)
  typeset -a NETMASK_ARRAY=($2)
  IFS=$SAVE_IFS
  echo $((${IP_ADDRESS_ARRAY[0]} | (255 ^ ${NETMASK_ARRAY[0]}))).$((${IP_ADDRESS_ARRAY[1]} | \
    (255 ^ ${NETMASK_ARRAY[1]}))).$((${IP_ADDRESS_ARRAY[2]} | \
    (255 ^ ${NETMASK_ARRAY[2]}))).$((${IP_ADDRESS_ARRAY[3]} | \
    (255 ^ ${NETMASK_ARRAY[3]})))
  return 0
}

# Define system variables.
OS_RELEASE=$(lsb_release -c -s)
USERNAME=$(users | awk '{ print $1 }')
LAN_DOMAIN=$(echo $LAN_DOMAIN | tr '[:upper:]' '[:lower:]')
WAN_DOMAIN=$(echo $WAN_DOMAIN | tr '[:upper:]' '[:lower:]')
KERBEROS_REALM=$(echo "$LAN_DOMAIN" | tr "[:lower:]" "[:upper:]")
PDC=$(echo $PDC | tr '[:upper:]' '[:lower:]')
BDC=$(echo $BDC | tr '[:upper:]' '[:lower:]')
PDC_FQDN=$PDC.$LAN_DOMAIN
BDC_FQDN=$BDC.$LAN_DOMAIN
if [ "$SERVER" = "pdc" ]; then
  LAN_IP_ADDRESS=$PDC_LAN_IP_ADDRESS
  WAN_IP_ADDRESS=$PDC_WAN_IP_ADDRESS1
  DRBD_IP_ADDRESS=$PDC_DRBD_IP_ADDRESS
  HOSTNAME=$PDC
  FQDN=$PDC.$LAN_DOMAIN  
else
  LAN_IP_ADDRESS=$BDC_LAN_IP_ADDRESS
  WAN_IP_ADDRESS=$BDC_WAN_IP_ADDRESS1
  DRBD_IP_ADDRESS=$BDC_DRBD_IP_ADDRESS
  HOSTNAME=$BDC
  FQDN=$BDC.$LAN_DOMAIN  
fi
CIDR=$(mask2cidr $LAN_NETMASK)
LAN_BROADCAST=$(get_broadcast_address $LAN_IP_ADDRESS $LAN_NETMASK)
LAN_NETWORK_ADDRESS=$(get_network_address $LAN_IP_ADDRESS $LAN_NETMASK)
DRBD_NETWORK_ADDRESS=$(get_network_address $DRBD_IP_ADDRESS $LAN_NETMASK)
IFS=. read -ra LAN_IP_ADDRESS_OCTETS <<< "$LAN_IP_ADDRESS"
IFS=. read -ra WAN_IP_ADDRESS_OCTETS <<< "$WAN_IP_ADDRESS"
IFS=. read -ra PDC_LAN_IP_ADDRESS_OCTETS <<< "$PDC_LAN_IP_ADDRESS"
IFS=. read -ra BDC_LAN_IP_ADDRESS_OCTETS <<< "$BDC_LAN_IP_ADDRESS"
IFS=. read -ra LAN_NETWORK_ADDRESS_OCTETS <<< "$LAN_NETWORK_ADDRESS"
IFS=. read -ra PDC_WAN_IP_ADDRESS1_OCTETS <<< "$PDC_WAN_IP_ADDRESS1"
IFS=. read -ra PDC_WAN_IP_ADDRESS2_OCTETS <<< "$PDC_WAN_IP_ADDRESS2"
IFS=. read -ra BDC_WAN_IP_ADDRESS1_OCTETS <<< "$BDC_WAN_IP_ADDRESS1"
IFS=. read -ra BDC_WAN_IP_ADDRESS2_OCTETS <<< "$BDC_WAN_IP_ADDRESS2"
PDC_WAN_IP_ADDRESS1_4TH_OCTET=${PDC_WAN_IP_ADDRESS1_OCTETS[3]}
PDC_WAN_IP_ADDRESS2_4TH_OCTET=${PDC_WAN_IP_ADDRESS2_OCTETS[3]}
BDC_WAN_IP_ADDRESS1_4TH_OCTET=${BDC_WAN_IP_ADDRESS1_OCTETS[3]}
BDC_WAN_IP_ADDRESS2_4TH_OCTET=${BDC_WAN_IP_ADDRESS2_OCTETS[3]}
PDC_LAN_IP_ADDRESS_4TH_OCTET=${PDC_LAN_IP_ADDRESS_OCTETS[3]}
BDC_LAN_IP_ADDRESS_4TH_OCTET=${BDC_LAN_IP_ADDRESS_OCTETS[3]}
LAN_REVERSE_ZONE=${LAN_IP_ADDRESS_OCTETS[2]}.${LAN_IP_ADDRESS_OCTETS[1]}.\
${LAN_IP_ADDRESS_OCTETS[0]}.in-addr.arpa
WAN_REVERSE_ZONE=${WAN_IP_ADDRESS_OCTETS[2]}.${WAN_IP_ADDRESS_OCTETS[1]}.\
${WAN_IP_ADDRESS_OCTETS[0]}.in-addr.arpa
DHCP_HOST_MIN=${LAN_NETWORK_ADDRESS_OCTETS[0]}.${LAN_NETWORK_ADDRESS_OCTETS[1]}.\
${LAN_NETWORK_ADDRESS_OCTETS[2]}.1
DHCP_HOST_MAX=${LAN_IP_ADDRESS_OCTETS[0]}.${LAN_IP_ADDRESS_OCTETS[1]}.\
${LAN_IP_ADDRESS_OCTETS[2]}.$(($(echo "$LAN_BROADCAST" | cut -d\. -f4) - 1))
TOP_LEVEL_LAN_DOMAIN=$(echo "$LAN_DOMAIN" | cut -d\. -f2)
SECOND_LEVEL_LAN_DOMAIN=$(echo "$LAN_DOMAIN" | cut -d\. -f1)
LDAP_BASE_DN=dc=$SECOND_LEVEL_LAN_DOMAIN,dc=$TOP_LEVEL_LAN_DOMAIN

# Add the admin user account.
useradd -md /admin admin
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | passwd admin

# Add administrator account for CUPS.
usermod -aG lpadmin admin

# Configure hosts.
if [ ! -f /etc/hosts.orig ]; then mv /etc/hosts /etc/hosts.orig; fi
cat << EOF.hosts | column -t > /etc/hosts
127.0.0.1	localhost.localdomain	localhost
$PDC_LAN_IP_ADDRESS	$PDC_FQDN	$PDC
$PDC_DRBD_IP_ADDRESS	$PDC_FQDN-alt	$PDC-alt
$BDC_LAN_IP_ADDRESS	$BDC_FQDN	$BDC
$BDC_DRBD_IP_ADDRESS	$BDC_FQDN-alt	$BDC-alt
EOF.hosts

# Set hostname.
hostnamectl set-hostname "$HOSTNAME"

# Configure Sysctl.
if [ ! -f /etc/sysctl.conf.orig ]; then 
  mv /etc/sysctl.conf /etc/sysctl.conf.orig
fi
cat > /etc/sysctl.conf << EOF.sysctl.conf
# Set the domain name.
kernel.domainname = $LAN_DOMAIN
# Enable IP forwarding.
net.ipv4.ip_forward = 1
# Do not accept ICMP redirects (prevent MITM attacks).
net.ipv4.conf.all.accept_redirects = 0
EOF.sysctl.conf
sysctl -p /etc/sysctl.conf

clear
echo ""
echo "Configuring repositories."
echo ""

# Update Apt sources.list.
if [ ! -f /etc/apt/sources.list.orig ]; then 
  cp /etc/apt/sources.list /etc/apt/sources.list.orig
fi
sed -i "s|http://*.*.archive.ubuntu.com|$UBUNTU_MIRROR|g" \
  /etc/apt/sources.list

# Add the Fusiondirectory repository.
echo "deb [signed-by=/etc/apt/keyrings/FD-archive-key.gpg] \
  https://public.fusiondirectory.org/debian/fusiondirectory-integrator/ bullseye main" > \
  /etc/apt/sources.list.d/fusiondirectory-integrator.list
echo "deb [signed-by=/etc/apt/keyrings/FD-archive-key.gpg] \
  https://public.fusiondirectory.org/debian/fusiondirectory-tools/ bullseye main" > \
  /etc/apt/sources.list.d/fusiondirectory-tools.list
echo "deb [signed-by=/etc/apt/keyrings/FD-archive-key.gpg] \
  https://public.fusiondirectory.org/debian/fusiondirectory-external-libraries/ bullseye main" > \
  /etc/apt/sources.list.d/fusiondirectory-external-libraries.list
echo "deb [signed-by=/etc/apt/keyrings/FD-archive-key.gpg] \
  https://public.fusiondirectory.org/debian/bullseye-fusiondirectory-release/ bullseye main" > \
  /etc/apt/sources.list.d/bullseye-fusiondirectory-release.list
$WGET -qO- https://public.fusiondirectory.org/FD-archive-key \
  | gpg --dearmor | sudo tee /etc/apt/keyrings/FD-archive-key.gpg

# Add the Open-Xchange repository.
echo "deb [signed-by=/etc/apt/keyrings/0xDFD4BCF6-oxbuildkey.gpg] \
  http://software.open-xchange.com/products/appsuite/stable/usm/DebianBookworm/ /" > \
  /etc/apt/sources.list.d/open-xchange.list
echo "deb [signed-by=/etc/apt/keyrings/0xDFD4BCF6-oxbuildkey.gpg] \
  http://software.open-xchange.com/products/appsuite/stable/backend/DebianBookworm/ /" >> \
  /etc/apt/sources.list.d/open-xchange.list
echo "deb [signed-by=/etc/apt/keyrings/0xDFD4BCF6-oxbuildkey.gpg] \
  http://software.open-xchange.com/products/appsuite/stable/appsuiteui/DebianBookworm/ /" >> \
  /etc/apt/sources.list.d/open-xchange.list
$WGET -qO- https://software.open-xchange.com/0xDFD4BCF6-oxbuildkey.pub \
  | gpg --dearmor | sudo tee /etc/apt/keyrings/0xDFD4BCF6-oxbuildkey.gpg

# Add the Webmin repository.
echo "deb [signed-by=/etc/apt/keyrings/jcameron-key.gpg] \
  http://download.webmin.com/download/repository sarge contrib" \
  > /etc/apt/sources.list.d/webmin.list
$WGET -qO- http://www.webmin.com/jcameron-key.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/jcameron-key.gpg

# Fetch public GPG keys.
tmp="$(mktemp)"
apt update 2>&1 | sed -En 's/.*NO_PUBKEY ([[:xdigit:]]+).*/\1/p' | sort -u > "${tmp}"
cat "${tmp}" | xargs sudo gpg --keyserver "hkps://keyserver.ubuntu.com:443" --recv-keys  # to /usr/share/keyrings/*
cat "${tmp}" | xargs -L 1 sh -c 'sudo gpg --yes --output "/etc/apt/trusted.gpg.d/$1.gpg" --export "$1"' sh  # to /etc/apt/trusted.gpg.d/*
rm "${tmp}"

# Resynchronize the package index files from their sources.
apt_function update

# Define software package variables.
AMAVISD="amavisd-new-postfix unrar-free"
APACHE="apache2 apache2-doc apache2-utils"
APACHE_MODULES="libapache2-mod-auth-gssapi libapache2-mod-fcgid \
  libapache2-mod-passenger libapache2-mod-php8.3"
APPARMOR="apparmor apparmor-notify apparmor-profiles apparmor-utils \
  dh-apparmor"
BIND="bind9 bind9-doc bind9utils libnet-dns-sec-perl"
CHRONY="chrony"
CLAMAV="clamav clamav-daemon clamav-docs clamav-freshclam"
CLUSTER_SUITE="cluster-glue crmsh dlm-controld drbd-utils fence-agents \
  gfs2-utils lvm2-lockd pacemaker pacemaker-resource-agents resource-agents-extra \
  rng-tools"
CUPS="cups foomatic-db printer-driver-gutenprint"
DOVECOT="dovecot-antispam dovecot-core dovecot-gssapi dovecot-imapd \
  dovecot-ldap dovecot-lmtpd dovecot-pop3d"
FAI="debmirror fai-doc fai-server"
FREERADIUS="freeradius freeradius-krb5 freeradius-ldap libpam-radius-auth"
FUSIONDIRECTORY="fusiondirectory fusiondirectory-tools \
  fusiondirectory-plugin-autofs5 fusiondirectory-plugin-autofs5-schema \
  fusiondirectory-plugin-certificates fusiondirectory-plugin-dovecot \
  fusiondirectory-plugin-dovecot-schema fusiondirectory-plugin-fai \
  fusiondirectory-plugin-fai-schema fusiondirectory-plugin-freeradius \
  fusiondirectory-plugin-gpg fusiondirectory-plugin-gpg-schema \
  fusiondirectory-plugin-kerberos fusiondirectory-plugin-ldapmanager \
  fusiondirectory-plugin-postfix fusiondirectory-plugin-postfix-schema \
  fusiondirectory-plugin-quota fusiondirectory-plugin-quota-schema \
  fusiondirectory-plugin-spamassassin fusiondirectory-plugin-spamassassin-schema \
  fusiondirectory-plugin-ssh fusiondirectory-plugin-ssh-schema \
  fusiondirectory-plugin-sudo fusiondirectory-plugin-sudo-schema"
JDK="default-jdk"
KEA="kea"
KERBEROS="krb5-admin-server krb5-config krb5-doc krb5-kdc krb5-user kstart \
  libpam-krb5 wamerican"
LTSP="ltsp dnsmasq epoptes"
MARIADB="automysqlbackup mariadb-server phpmyadmin"
MUNIN="ethtool libcgi-fast-perl libnet-cidr-perl libnet-ssleay-perl \
  munin munin-node munin-plugins-extra smartmontools"
NAGIOS="nagios4 nagios4-cgi monitoring-plugins"
NFS="libnfsidmap1 nfs4-acl-tools nfs-kernel-server"
OPENXCHANGE="open-xchange*"
OPENLDAP="authselect autofs-ldap krb5-kdc-ldap ldap-utils phpldapadmin \
  schema2ldif slapd sssd-krb5 sssd-ldap"
OPENSSH="openssh-server sshpass"
OPENSSL="openssl"
OPENVPN="openvpn"
PHP="php8.3 php8.3-dev"
POSTFIX="postfix postfix-doc postfix-ldap postfix-policyd-spf-python postgrey \
  procmail"
POSTGRESQL="autopostgresqlbackup bucardo phppgadmin postgresql \
  postgresql-client postgresql-*.*-debversion postgresql-doc"
PROFTPD="proftpd-core proftpd-doc proftpd-mod-clamav proftpd-mod-ldap"
PROXY="c-icap privoxy squid"
SASL="cyrus-sasl2-doc libsasl2-2 libsasl2-modules libsasl2-modules-gssapi-mit \
  sasl2-bin"
SHOREWALL="shorewall shorewall-doc shorewall-init"
SNORT="oinkmaster snort snort-doc"
SOURCE_CODE_DEPENDS="gcc git make subversion"
SPAM_PREVENTION="pyzor razor spamassassin"
SQUIDCLAMAV_DEPENDS="libicapapi-dev libssl-dev libtimedate-perl"
SYSTEM_DEPENDS="apt-utils dkms vim-scripts"
WEBMIN="at cups mdadm quota quotatool sarg stunnel4 usermin webalizer webmin wodim"

SOFTWARE_PACKAGES="$AMAVISD $APACHE $APACHE_MODULES $APPARMOR $BIND $CHRONY \
  $CLAMAV $CLUSTER_SUITE $CUPS $DOVECOT $FAI $FOREMAN $FREERADIUS \
  $FUSIONDIRECTORY $JDK $KERBEROS $LTSP $MARIADB $MUNIN $NAGIOS $NFS \
  $OPENXCHANGE $OPENLDAP $OPENSSH $OPENSSL $OPENVPN $PHP $POSTFIX $POSTGRESQL \
  $PROFTPD $PROXY $SASL $SHOREWALL $SNORT $SOURCE_CODE_DEPENDS $SPAM_PREVENTION \
  $SQUIDCLAMAV_DEPENDS $SYSTEM_DEPENDS $WEBMIN"

# Software package verification.
apt-get -s install $SOFTWARE_PACKAGES > /dev/null
if [ $? -ne 0 ]; then
  clear
  echo ""
  echo "Software package verification problem detected."
  echo "View software.log for further details."
  echo ""
  echo "Analyze the packages in software.log. For example, if the log contains"
  echo "a package named php8.1, this means that php8.1 is not found on your" 
  echo "Ubuntu mirror. Packages may change over time. Use the 'apt-cache search'"
  echo "command to search for just the package name, without the version number."
  echo "For example, the 'apt-cache search php' command will show if there is"
  echo "an updated PHP package available. For your information, php8.1 is" 
  echo "available on Ubuntu 22.04 mirrors, and php8.3 is available on Ubuntu"
  echo "24.04 mirrors."
  echo ""
  echo "If the log contains the name of a package that does not show up when"
  echo "you search for it with 'apt-cache search', this means the package is"
  echo "most likely deprecated and needs to be removed from this script."
  echo ""
  apt-get -s install $SOFTWARE_PACKAGES 2> software.log
  exit 1
fi

### Define automatic software packages. ###
# http://sourceforge.net/projects/lcmc/files
$WGET https://raw.github.com/rasto/lcmc/master/debian/changelog \
  -O /tmp/lcmc_changelog
while [ $? -ne 0 ]; do 
  $WGET https://raw.github.com/rasto/lcmc/master/debian/changelog \
  -O /tmp/lcmc_changelog
done
LCMC_APPLET_REV=$(sed -n 1p /tmp/lcmc_changelog | awk '{ print $2 }' | \
  sed 's/[()]//g' | cut -d\- -f1)
LCMC_APPLET="http://downloads.sourceforge.net/project/lcmc/all-releases\
/LCMC-applet-$LCMC_APPLET_REV.jar"
# squidclamav.darold.net
SQUIDCLAMAV="https://github.com/darold/squidclamav"

clear
echo ""
echo "Installing prerequisite software packages."
echo ""

# Install software prerequisites.
apt_function install $SYSTEM_DEPENDS $SOURCE_CODE_DEPENDS

################################################################################
#                                                                              #
# The following routine installs and configures Chrony, which provides time    #
# synchronization.                                                             #
#                                                                              #
# chrony.tuxfamily.org                                                         #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Chrony."
echo ""

# Install Chrony.
apt_function install $CHRONY

# Configure chrony.conf.
if [ ! -f /etc/chrony/chrony.conf.orig ]; then 
  cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.orig
fi
grep -q "allow $LAN_NETWORK_ADDRESS/$CIDR" /etc/chrony/chrony.conf || \
cat >> /etc/chrony/chrony.conf << EOF.chrony.conf

# Allow a subnet from which NTP clients can access the NTP server.
allow $LAN_NETWORK_ADDRESS/$CIDR
EOF.chrony.conf

# Reload configuration.
systemctl restart chrony

################################################################################
#                                                                              #
# The following routine installs and configures OpenSSH, which provides a      #
# means for encrypted communication. Secure Shell (SSH) uses public/private    # 
# key pairs for its encryption.                                                #
#                                                                              #
# openssh.com                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing OpenSSH."
echo ""

# Install OpenSSH.
apt_function install $OPENSSH

# Allow root login.
sed -i "s|#PermitRootLogin prohibit-password|PermitRootLogin yes|" \
  /etc/ssh/sshd_config
systemctl restart ssh

# Generate Authorized Keys.
echo "exec cat" > /tmp/cat_helper.sh
chmod 700 /tmp/cat_helper.sh
export DISPLAY=1
eval "$(ssh-agent)" > /dev/null
trap 'killall ssh-agent' EXIT > /dev/null
if [ "$SERVER" = "pdc" ]; then
  rm -f /root/.ssh/id_rsa*
  mkdir -p -m 700 /root/.ssh
  ssh-keygen -b 8192 -N "$ROOT_PASSWORD" -v -f /root/.ssh/id_rsa
  echo "$ROOT_PASSWORD" | SSH_ASKPASS=/tmp/cat_helper.sh ssh-add /root/.ssh/id_rsa  
  SSHPASS="$ROOT_PASSWORD" sshpass -e ssh -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 root@$BDC_LAN_IP_ADDRESS mkdir -p -m 700 /root/.ssh
  SSHPASS="$ROOT_PASSWORD" sshpass -e scp -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 /root/.ssh/id_rsa.pub \
    $BDC_LAN_IP_ADDRESS:/root/.ssh/authorized_keys
  SSHPASS="$ROOT_PASSWORD" sshpass -e ssh -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 root@$BDC_LAN_IP_ADDRESS \
    chmod 600 /root/.ssh/authorized_keys
  while [ ! -f /root/.ssh/authorized_keys ]; do
    clear
    echo ""
    echo "Please wait for SSH Authorized Keys synchronization."
    sleep 30    
  done
  rm -f /"$USERNAME"/.ssh/id_rsa*
  mkdir -p -m 700 /"$USERNAME"/.ssh
  chown -R "$USERNAME":"$USERNAME" /"$USERNAME"/.ssh
  sudo -u "$USERNAME" ssh-keygen -b 8192 -N "$ADMIN_PASSWORD" -v \
    -f /"$USERNAME"/.ssh/id_rsa
  echo "$ADMIN_PASSWORD" | SSH_ASKPASS=/tmp/cat_helper.sh ssh-add \
    /"$USERNAME"/.ssh/id_rsa
  SSHPASS="$ADMIN_PASSWORD" sshpass -e ssh -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 "$USERNAME"@$BDC_LAN_IP_ADDRESS \
    mkdir -p -m 700 /"$USERNAME"/.ssh
  SSHPASS="$ADMIN_PASSWORD" sshpass -e scp -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 /"$USERNAME"/.ssh/id_rsa.pub \
    $BDC_LAN_IP_ADDRESS:/"$USERNAME"/.ssh/authorized_keys
  SSHPASS="$ROOT_PASSWORD" sshpass -e ssh -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 "$USERNAME"@$BDC_LAN_IP_ADDRESS \
    chmod 600 /"$USERNAME"/.ssh/authorized_keys
  while [ ! -f /"$USERNAME"/.ssh/authorized_keys ]; do
    clear
    echo ""
    echo "Please wait for SSH Authorized Keys synchronization."
    sleep 30    
  done
else
  rm -f /root/.ssh/id_rsa*
  mkdir -p -m 700 /root/.ssh
  ssh-keygen -b 8192 -N "$ROOT_PASSWORD" -v -f /root/.ssh/id_rsa
  echo "$ROOT_PASSWORD" | SSH_ASKPASS=/tmp/cat_helper.sh ssh-add /root/.ssh/id_rsa
  SSHPASS="$ROOT_PASSWORD" sshpass -e ssh -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 root@$PDC_LAN_IP_ADDRESS mkdir -p -m 700 /root/.ssh
  SSHPASS="$ROOT_PASSWORD" sshpass -e scp -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 /root/.ssh/id_rsa.pub \
    $PDC_LAN_IP_ADDRESS:/root/.ssh/authorized_keys
  SSHPASS="$ROOT_PASSWORD" sshpass -e ssh -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 root@$PDC_LAN_IP_ADDRESS \
    chmod 600 /root/.ssh/authorized_keys
  while [ ! -f /root/.ssh/authorized_keys ]; do
    clear
    echo ""
    echo "Please wait for SSH Authorized Keys synchronization."
    sleep 30    
  done
  rm -f /"$USERNAME"/.ssh/id_rsa*
  mkdir -p -m 700 /"$USERNAME"/.ssh
  chown -R "$USERNAME":"$USERNAME" /"$USERNAME"/.ssh
  sudo -u "$USERNAME" ssh-keygen -b 8192 -N "$ADMIN_PASSWORD" -v \
    -f /"$USERNAME"/.ssh/id_rsa
  echo "$ADMIN_PASSWORD" | SSH_ASKPASS=/tmp/cat_helper.sh ssh-add \
    /"$USERNAME"/.ssh/id_rsa
  SSHPASS="$ADMIN_PASSWORD" sshpass -e ssh -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 "$USERNAME"@$PDC_LAN_IP_ADDRESS \
    mkdir -p -m 700 /"$USERNAME"/.ssh
  SSHPASS="$ADMIN_PASSWORD" sshpass -e scp -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 /"$USERNAME"/.ssh/id_rsa.pub \
    $PDC_LAN_IP_ADDRESS:/"$USERNAME"/.ssh/authorized_keys
  SSHPASS="$ROOT_PASSWORD" sshpass -e ssh -q -o StrictHostKeyChecking=no \
    -o ConnectionAttempts=99 "$USERNAME"@$PDC_LAN_IP_ADDRESS \
    chmod 600 /"$USERNAME"/.ssh/authorized_keys 
  while [ ! -f /"$USERNAME"/.ssh/authorized_keys ]; do
    clear
    echo ""
    echo "Please wait for SSH Authorized Keys synchronization."
    sleep 30    
  done
fi
rm -f /tmp/cat_helper.sh

################################################################################
#                                                                              #
# The following routine installs AppArmor, a Linux Security Module             #
# implementation of name-based mandatory access controls. AppArmor confines    #
# individual programs to a set of listed files and POSIX 1003.1e draft         #
# capabilities.                                                                #
#                                                                              #
# wiki.apparmor.net                                                            #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing AppArmor."
echo ""

# Install AppArmor.
apt_function install $APPARMOR

################################################################################
#                                                                              #
# The following routine installs and configures Shorewall, a high-level tool   #
# for configuring Netfilter. You describe your firewall/gateway requirements   #
# using entries in a set of configuration files. Shorewall reads those         #
# configuration files, and with the help of the iptables utility, Shorewall    #
# configures Netfilter to match your requirements.                             #
#                                                                              #
# shorewall.org                                                                #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Shorewall."
echo ""

# Install Shorewall.
apt_function install $SHOREWALL

# Modify shorewall.conf.
if [ ! -f /etc/shorewall/shorewall.conf.orig ]; then 
  cp /etc/shorewall/shorewall.conf /etc/shorewall/shorewall.conf.orig
fi
sed -i "s|LOG_MARTIANS=Yes|LOG_MARTIANS=No|
  s|STARTUP_ENABLED=No|STARTUP_ENABLED=Yes|" /etc/shorewall/shorewall.conf

# Create rules.
cat > /etc/shorewall/rules << EOF.shorewall
?SECTION NEW
#ACTION               SOURCE  DEST
Corosync(ACCEPT)      lan    \$FW
CUPS(ACCEPT)          lan    \$FW
DHCP(ACCEPT)          lan    \$FW
DLM(ACCEPT)           lan    \$FW
DNS(ACCEPT)           lan    \$FW
DRBD(ACCEPT)          lan    \$FW
FTP(ACCEPT)           lan    \$FW
GALERA(ACCEPT)        lan    \$FW
HTTP(ACCEPT)          lan    \$FW
HTTPS(ACCEPT)         lan    \$FW
IMAP(ACCEPT)          lan    \$FW
IMAPS(ACCEPT)         lan    \$FW
Kerberos5(ACCEPT)     lan    \$FW
LDAP(ACCEPT)          lan    \$FW
LTSP(ACCEPT)          lan    \$FW
Munin(ACCEPT)         lan    \$FW
MySQL(ACCEPT)         lan    \$FW
Nagios(ACCEPT)        lan    \$FW
NFS(ACCEPT)           lan    \$FW
NTP(ACCEPT)           lan    \$FW
Open-Xchange(ACCEPT)  lan    \$FW
OpenVPN(ACCEPT)       lan    \$FW
Ping(ACCEPT)          lan    \$FW
POP3(ACCEPT)          lan    \$FW
POP3S(ACCEPT)         lan    \$FW
PostgreSQL(ACCEPT)    lan    \$FW
RADIUS(ACCEPT)        lan    \$FW
RNDC(ACCEPT)          lan    \$FW
SMTP(ACCEPT)          lan    \$FW
SMTPS(ACCEPT)         lan    \$FW
Submission(ACCEPT)    lan    \$FW
Squid(ACCEPT)         lan    \$FW
Syslog(ACCEPT)        lan    \$FW
SSH(ACCEPT)           lan    \$FW
TFTP(ACCEPT)          lan    \$FW
Usermin(ACCEPT)       lan    \$FW
Webmin(ACCEPT)        lan    \$FW
REDIRECT              lan     3128  tcp  www  -  !$LAN_IP_ADDRESS

Corosync(ACCEPT)      vpn    \$FW
CUPS(ACCEPT)          vpn    \$FW
DHCP(ACCEPT)          vpn    \$FW
DLM(ACCEPT)           vpn    \$FW
DNS(ACCEPT)           vpn    \$FW
DRBD(ACCEPT)          vpn    \$FW
FTP(ACCEPT)           vpn    \$FW
GALERA(ACCEPT)        vpn    \$FW
HTTP(ACCEPT)          vpn    \$FW
HTTPS(ACCEPT)         vpn    \$FW
IMAP(ACCEPT)          vpn    \$FW
IMAPS(ACCEPT)         vpn    \$FW
Kerberos5(ACCEPT)     vpn    \$FW
LDAP(ACCEPT)          vpn    \$FW
LTSP(ACCEPT)          vpn    \$FW
Munin(ACCEPT)         vpn    \$FW
MySQL(ACCEPT)         vpn    \$FW
Nagios(ACCEPT)        vpn    \$FW
NFS(ACCEPT)           vpn    \$FW
NTP(ACCEPT)           vpn    \$FW
Open-Xchange(ACCEPT)  vpn    \$FW
OpenVPN(ACCEPT)       vpn    \$FW
Ping(ACCEPT)          vpn    \$FW
POP3(ACCEPT)          vpn    \$FW
POP3S(ACCEPT)         vpn    \$FW
PostgreSQL(ACCEPT)    vpn    \$FW
RADIUS(ACCEPT)        vpn    \$FW
RNDC(ACCEPT)          vpn    \$FW
SMTP(ACCEPT)          vpn    \$FW
SMTPS(ACCEPT)         vpn    \$FW
Submission(ACCEPT)    vpn    \$FW
Squid(ACCEPT)         vpn    \$FW
SSH(ACCEPT)           vpn    \$FW
Syslog(ACCEPT)        vpn    \$FW
TFTP(ACCEPT)          vpn    \$FW
Usermin(ACCEPT)       vpn    \$FW
Webmin(ACCEPT)        vpn    \$FW
REDIRECT              vpn     3128  tcp  www  -  !$LAN_IP_ADDRESS

Corosync(ACCEPT)      drbd   \$FW
DRBD(ACCEPT)          drbd   \$FW
SCTP(ACCEPT)          drbd   \$FW

Auth(REJECT)          wan    \$FW
FTP(ACCEPT)           wan    \$FW
HTTP(ACCEPT)          wan    \$FW
HTTPS(ACCEPT)         wan    \$FW
IMAP(ACCEPT)          wan    \$FW
IMAPS(ACCEPT)         wan    \$FW
OpenVPN(ACCEPT)       wan    \$FW
Ping(DROP)            wan    \$FW
SMTP(ACCEPT)          wan    \$FW
SMTPS(ACCEPT)         wan    \$FW
Submission(ACCEPT)    wan    \$FW
SSHKnock:info         wan    \$FW  tcp  22,1700,1701,1702

# Port Map
# 8 = ICMP (Internet Control Message Protocol)
# 21 = FTP (File Transfer Protocol is used by ProFTPD)
# 22 = SSH (Secure Shell)
# 25 = SMTP (Simple Mail Transport Protocol is used by Postfix)
# 53 = DNS (Domain Name Service is used by Bind)
# 67, 68, 8000 = DHCP (Dynamic Host Configuration Protocol)
# 69 = TFTP (Trivial File Transfer Protocol is used by LTSP)
# 80 = HTTP (Hypertext Transfer Protocol is used by Apache)
# 88 = Kerberos-SEC (Kerberos KDC)
# 110 = POP3 (Post Office Protocol, version 3)
# 111 = RPCbind is used by NFS.
# 113 = IDENT (Identification Protocol is blocked to enhance security)
# 123 = NTP (Network Time Protocol)
# 132 = SCTP (Stream Control Transmission Protocol is used by Pacemaker)
# 143 = IMAP (Internet Mail Access Protocol is used by Dovecot)
# 389 = LDAP (Lightweight Directory Access Protocol)
# 443 = HTTPS (HTTP, secure)
# 464 = Kpasswd (Kerberos password)
# 465 = SMTPS (SMTP, secure)
# 514 = Syslog
# 587 = SMTP Submission
# 631 = CUPS
# 749, 750 = Kerberos-ADM (Kerberos admin/changepw)
# 953 = RNDC (Remote Name Daemon Controller is used by Bind)
# 993 = IMAPS (IMAP, secure)
# 995 = POP3S (POP3, secure)
# 1099 = Java RMI (Open-Xchange Remote Management Interface)
# 1194 = OpenVPN
# 1812 = RADIUS (Remote Authentication Dial-In Service)
# 2000 = NBD Image Export for LTSP
# 2049 = NFS (Network File System)
# 3128 = Squid
# 3306 = MariaDB
# 4000, 4001 = RPC.statd is used by NFS.
# 4002 = RPC.mountd is used by NFS.
# 4444, 4567, 4568 = Galera
# 4949 = Munin
# 5300 = DDNS (Dynamic DNS)
# 5404, 5405, 5406 = Corosync
# 5432 = PostgrSQL
# 5666 = Nagios
# 5701, 5702, 5703 = Open-Xchange Hazelcast
# 7788 = DRBD (Distributed Block Device)
# 8009 = Proxy_HTTP (Open-Xchange Load Balancer)
# 9571 = Ldminfod (login and locale settings for LTSP)
# 9572 = Nbdswapd (NBD swap for LTSP)
# 10000 = Webmin
# 10809 = NBD-server (Network Block Device)
# 20000 = Usermin
# 21064 = Distributed Lock Manager
EOF.shorewall

### Define macros. ###

# Corosync macro.
cat > /etc/shorewall/macro.Corosync << EOF.corosync.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     udp    5404
PARAM    -       -     udp    5405
PARAM    -       -     udp    5406
EOF.corosync.macro

# CUPS macro.
cat > /etc/shorewall/macro.CUPS << EOF.cups.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    631
EOF.cups.macro

# DHCP macro.
cat > /etc/shorewall/macro.DHCP << EOF.DHCP.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     udp    67
PARAM    -       -     udp    68
PARAM    -       -     tcp    5300
PARAM    -       -     tcp    8000
EOF.DHCP.macro

# DLM macro.
cat > /etc/shorewall/macro.DLM << EOF.dlm.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    21064
EOF.dlm.macro

# DRBD macro.
cat > /etc/shorewall/macro.DRBD << EOF.drbd.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    7788
EOF.drbd.macro

# Galera macro.
cat > /etc/shorewall/macro.Galera << EOF.galera.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    4444
PARAM    -       -     tcp    4567
PARAM    -       -     udp    4567
PARAM    -       -     tcp    4568
EOF.galera.macro

# Kerberos5 macro.
cat > /etc/shorewall/macro.Kerberos5 << EOF.kerberos5.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    88
PARAM    -       -     tcp    464
PARAM    -       -     udp    464
PARAM    -       -     tcp    749
PARAM    -       -     udp    749
PARAM    -       -     tcp    750
PARAM    -       -     udp    750
EOF.kerberos5.macro

# LTSP macro.
cat > /etc/shorewall/macro.LTSP << EOF.ltsp.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    2000
PARAM    -       -     tcp    9571
PARAM    -       -     tcp    9572
PARAM    -       -     tcp    10809
EOF.ltsp.macro

# Nagios macro.
cat > /etc/shorewall/macro.Nagios << EOF.nagios.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    5666
EOF.nagios.macro

# NFS macro.
cat > /etc/shorewall/macro.NFS << EOF.nfs.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    111
PARAM    -       -     tcp    2049
PARAM    -       -     tcp    4000
PARAM    -       -     tcp    4001
PARAM    -       -     tcp    4002
EOF.nfs.macro

# Open-Xchange macro.
cat > /etc/shorewall/macro.Open-Xchange << EOF.openxchange.macro
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    1099
PARAM    -       -     tcp    5701
PARAM    -       -     tcp    5702
PARAM    -       -     tcp    5703
PARAM    -       -     tcp    8009
EOF.openxchange.macro

# RADIUS macro.
cat > /etc/shorewall/macro.RADIUS << EOF.radius.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    1812
EOF.radius.macro

# SCTP macro.
cat > /etc/shorewall/macro.SCTP << EOF.sctp.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO
PARAM    -       -     132
EOF.sctp.macro

# Usermin macro.
cat > /etc/shorewall/macro.Usermin << EOF.usermin.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    20000
EOF.usermin.macro

# Create zones.
cat > /etc/shorewall/zones << EOF.zones
#ZONE  TYPE
fw     firewall
wan    ipv4
lan    ipv4
drbd   ipv4
vpn    ipv4
EOF.zones

# Create interfaces.
cat << EOF.interfaces | column -t > /etc/shorewall/interfaces
#ZONE	INTERFACE	BROADCAST	OPTIONS
lan	$LAN_INTERFACE	detect	tcpflags,nosmurfs,routefilter
drbd	$DRBD_INTERFACE	detect	tcpflags,nosmurfs,routefilter
vpn	tun+	detect	routeback
wan	$WAN_INTERFACE1	detect	dhcp,tcpflags,nosmurfs,routefilter
wan	$WAN_INTERFACE2	detect	dhcp,tcpflags,nosmurfs,routefilter
EOF.interfaces

# Create policy.
cat > /etc/shorewall/policy << EOF.policy
#SOURCE  DEST  POLICY  LOG
fw       all   ACCEPT
lan      wan   ACCEPT
vpn      lan   ACCEPT   
drbd     fw    REJECT  info
lan      fw    REJECT  info
wan      all   DROP    info
all      all   REJECT  info
EOF.policy

# Create snat.
cat << EOF.snat | column -t > /etc/shorewall/snat
#ACTION SOURCE  DEST
SNAT	$LAN_NETWORK_ADDRESS/$CIDR	$WAN_INTERFACE1
SNAT	$LAN_NETWORK_ADDRESS/$CIDR	$WAN_INTERFACE2
EOF.snat

# Create providers.
cat << EOF.providers | column -t > /etc/shorewall/providers
#NAME	NUMBER	MARK	DUPLICATE	INTERFACE	GATEWAY	OPTIONS	COPY
ISP1	1	1	main	$WAN_INTERFACE1	detect	track,balance\	$LAN_INTERFACE,$DRBD_INTERFACE
ISP2	2	2	main	$WAN_INTERFACE2	detect	track,balance\	$LAN_INTERFACE,$DRBD_INTERFACE
EOF.providers

# Create tunnels.
cat << EOF.tunnels | column -t > /etc/shorewall/tunnels
#TYPE	ZONE	GATEWAY
openvpnserver:1194	wan	0.0.0.0/0
EOF.tunnels

# Create action.SSHKnock.
touch /etc/shorewall/action.SSHKnock

# Create actions.
cat > /etc/shorewall/actions << EOF.actions
#ACTION
SSHKnock
EOF.actions

# Create SSHKnock.
cat > /etc/shorewall/SSHKnock << EOF.sshknock
use Shorewall::Chains;

if ( \$level ) {
  log_rule_limit( \$level,
  \$chainref,
  'SSHKnock',
  'ACCEPT',
  '',
  \$tag,
  'add',
  '-p tcp --dport 22   -m recent --rcheck --name SSH ' );

  log_rule_limit( \$level,
  \$chainref,
  'SSHKnock',
  'DROP',
  '',
  \$tag,
  'add',
  '-p tcp ! --dport 22 ' );
}

add_rule( \$chainref, '-p tcp --dport 22 -m recent --rcheck --seconds 60 \
  --name SSH -j ACCEPT' );
# For security purposes, use a unique set of ports for port knocking.
# Reference shorewall.net/PortKnocking.html and soloport.com/iptables.html.
add_rule( \$chainref, '-p tcp --dport 1700 -m recent --name SSH \
  --remove -j DROP' );
add_rule( \$chainref, '-p tcp --dport 1701 -m recent --name SSH \
  --set    -j DROP' );
add_rule( \$chainref, '-p tcp --dport 1702 -m recent --name SSH \
  --remove -j DROP' );

1;
EOF.sshknock

# Shorewall startup.
sed -i "s|startup=0|startup=1|" /etc/default/shorewall
pgrep shorewall > /dev/null
if [ $? -eq 1 ]; then
  shorewall start
else
  shorewall restart
fi

################################################################################
#                                                                              #
# The following routine installs and configures CLVM, Corosync, DRBD, GFS,     #
# LCMC, and Pacemaker to create a high-availability, active/active cluster.    #
#                                                                              #
# drbd.org                                                                     #
# clusterlabs.org                                                              #
# lcmc.sourceforge.net                                                         #
# sourceware.org/cluster/gfs                                                   #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing cluster suite."
echo ""

# Install the HA cluster suite.
apt_function install $CLUSTER_SUITE

# Disable "hung task" messages.
echo "0" > /proc/sys/kernel/hung_task_timeout_secs

# CLVM startup is handled by Pacemaker.
systemctl disable clvm

# Create DRBD's global_common.conf.
if [ ! -f /etc/drbd.d/global_common.conf.orig ]; then 
  mv /etc/drbd.d/global_common.conf /etc/drbd.d/global_common.conf.orig
fi
cat > /etc/drbd.d/global_common.conf << EOF.global_common.conf
global {
   usage-count yes;
}
common {
  handlers {
    fence-peer "/usr/lib/drbd/crm-fence-peer.sh";
    unfence-peer "/usr/lib/drbd/crm-unfence-peer.sh";
    split-brain "/usr/lib/drbd/notify-split-brain.sh root";
    before-resync-target "/usr/lib/drbd/snapshot-resync-target-lvm.sh";
    after-resync-target "/usr/lib/drbd/unsnapshot-resync-target-lvm.sh";
  }
  disk {
    # When disk-barrier is turned off, you must protect your hard disk with an 
    # Uninterruptible Power Supply.
    disk-barrier no; 
    fencing resource-and-stonith;
  }
  net {
    protocol C;
    allow-two-primaries yes;
    max-buffers 8000;
    max-epoch-size 8000;
    verify-alg md5;
    csums-alg md5;
    after-sb-0pri discard-zero-changes;
    after-sb-1pri consensus;
    after-sb-2pri disconnect;
  }
}
EOF.global_common.conf

# Create DRBD's r0.res.
cat > /etc/drbd.d/r0.res << EOF.r0.res
resource r0 {
  meta-disk internal;
  disk $LV_DRBD_PATH;
  device /dev/drbd0;
  on $PDC {
    address $PDC_DRBD_IP_ADDRESS:7788;
  }
  on $BDC {
    address $BDC_DRBD_IP_ADDRESS:7788;
  }
}
EOF.r0.res

# Create DRBD's online device verification cron job.
echo "@daily root /sbin/drbdadm verify r0" > /etc/cron.d/drbd_verify

# Initialize DRBD's backing device.
dd if=/dev/zero bs=1M count=1 of=$LV_DRBD_PATH; sync

# Initialize DRBD's metadata.
yes yes | drbdadm create-md r0

# Load DRBD's kernel module.
modprobe drbd

# Attach DRBD's backing device and connect to the peer.
if [ "$SERVER" = "pdc" ]; then # Begin the DRBD conditional IF statement. 
  drbdadm up r0
  while [ $? -ne 0 ]; do
    drbdadm secondary r0
    drbdadm down r0
    drbdadm up r0
  done

  # This cstate-wait state is necessary to establish node connectivity.
  # (It takes four minutes to establish a connection between nodes.)
  CSTATE=$(drbdadm cstate r0)
  while [ "$CSTATE" != "Connected" ]; do
    clear
    echo ""
    echo "Please wait until DRBD replicated storage is online."
    sleep 60
    CSTATE=$(drbdadm cstate r0)
  done 

  # Generate a new UUID and clear the dirty bitmap.
  drbdadm new-current-uuid --clear-bitmap r0/0
  while [ $? -ne 0 ]; do
    drbdadm disconnect r0
    drbdadm new-current-uuid --clear-bitmap r0/0
    drbdadm connect r0
  done
else
  # Activate DRBD's resource.
  drbdadm up r0
  while [ $? -ne 0 ]; do
    drbdadm secondary r0
    drbdadm down r0
    drbdadm up r0
  done

  CSTATE=$(drbdadm cstate r0)
  while [ "$CSTATE" != "Connected" ]; do
    clear
    echo ""
    echo "Please wait until DRBD replicated storage is online."
    sleep 60
    CSTATE=$(drbdadm cstate r0)
  done
  # This wait state is necessary to prevent BDC promotion 
  # prior to PDC promotion.
  sleep 90 
fi # End the DRBD conditional IF statement

# Promote DRBD's resource to primary.
drbdadm primary --force r0

# Create Corosync's authkey.
if [ "$SERVER" = "pdc" ]; then
  cd /etc/corosync
  rngd -r /dev/urandom # RNGD generates artificial entropy.
  corosync-keygen
  # Synchronize Corosync's authkey.
  scp -q -o StrictHostKeyChecking=no -o ConnectionAttempts=99 \
    /etc/corosync/authkey "$BDC_FQDN":/etc/corosync/
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Please wait for Corosync authkey sync."
    echo ""
    sleep 15
    scp -q -o StrictHostKeyChecking=no -o ConnectionAttempts=99 \
      /etc/corosync/authkey "$BDC_FQDN":/etc/corosync/
  done
  killall rngd
else
  while [ ! -f /etc/corosync/authkey ]; do
    clear
    echo ""
    echo "Please wait for Corosync authkey sync."
    echo ""
    sleep 15
  done
fi

# Create corosync.conf.
if [ ! -f /etc/corosync/corosync.conf.orig ]; then 
  mv /etc/corosync/corosync.conf /etc/corosync/corosync.conf.orig
fi
cat > /etc/corosync/corosync.conf << EOF.corosync.conf
totem {
  version: 2
  cluster_name: LinuxHA
  secauth: on
  link_mode: active
  interface {
    linknumber: 0
    bindnetaddr: $LAN_NETWORK_ADDRESS
  }
  # Redundant communications channel.
  interface {
    linknumber: 1
    bindnetaddr: $DRBD_NETWORK_ADDRESS
  }
}

nodelist {
  node {
    name: $PDC
    nodeid: 1
    ring0_addr: $PDC_LAN_IP_ADDRESS
    ring1_addr: $PDC_DRBD_IP_ADDRESS
    quorum_votes: 1
  }
  node {
    name: $BDC
    nodeid: 2
    ring0_addr: $BDC_LAN_IP_ADDRESS
    ring1_addr: $BDC_DRBD_IP_ADDRESS
    quorum_votes: 1
  }
}

logging {
  logger_subsys {
    subsys: QUORUM
  }
}

quorum {
  provider: corosync_votequorum
  expected_votes: 1
  two_node: 1
}
EOF.corosync.conf

# Create Corosync's log directory.
mkdir -p /var/log/corosync
chown hacluster:haclient /var/log/corosync

# Corosync startup.
sed -i "s|START=no|START=yes|" /etc/default/corosync
pgrep corosync > /dev/null
if [ $? -eq 0 ]; then
  systemctl restart corosync
else
  systemctl start corosync
fi

# Pacemaker startup.
pgrep pacemakerd > /dev/null
if [ $? -eq 0 ]; then
  systemctl restart pacemaker
else
  systemctl start pacemaker
fi

# Configure lvm.conf.
if [ ! -f /etc/lvm/lvm.conf.orig ]; then 
  cp /etc/lvm/lvm.conf /etc/lvm/lvm.conf.orig
fi
sed -i "s|# use_lvmlockd = 0|use_lvmlockd = 1|
  s|write_cache_state = 1|write_cache_state = 0|
  s|# volume_list = .*$|volume_list = \[ \"vg_drbd\", \"@linux_ha\" \]|" \
    /etc/lvm/lvm.conf

# Remove stale cache entries.
rm -f /etc/lvm/cache/.cache

# Wait until both nodes are online.
clear
echo ""
echo "Please wait until the cluster is online."
echo ""
sleep 120
crm_mon -s
while [ $? -ne 0 ]; do
  sleep 60
  crm_mon -s
done

# Create /var/www mount point.
mkdir –p /var/www

# Activate Pacemaker's Stonith Fencing.
  if [ "$SERVER" = "pdc" ]; then # Begin the cluster conditional IF statement.
crm<<EOF.stonith
  configure
    erase
    property stonith-enabled="true"
    primitive stonith stonith:$STONITH_PLUGIN \
      params hostlist="$PDC $BDC" \      
      op monitor interval="60s" timeout="60s" \
      op start interval="0" timeout="60s" \
      op stop interval="0" timeout="15s"
    clone cl_stonith stonith \
      meta interleave="true"
    commit
EOF.stonith

# Activate Pacemaker's Distributed Lock Manager (DLM) and LVM locking daemon (LVMLOCKD). 
# DLM and LVMLOCKD must be activated together.
crm<<EOF.base
  configure
    property no-quorum-policy="ignore"
    rsc_defaults resource-stickiness="100"
    primitive controld ocf:pacemaker:controld \
      op monitor interval="60s" timeout="90s" \
      op start interval="0" timeout="90s" \
      op stop interval="0" timeout="100s"
    primitive lvmlockd lvmlockd \
      op monitor interval="60s" timeout="30s" \
      op start interval="0" timeout="90s" \
      op stop interval="0" timeout="100s"
    primitive LVM LVM-activate \
      params vgname=$(echo $LV_DRBD_PATH | cut -d "/" -f3) vg_access_mode=lvmlockd activation_mode=shared \
      op monitor interval="60s" timeout="90s" \
      op start interval="0" timeout="90s" \
      op stop interval="0" timeout="100s"
    group gr_base controld lvmlockd LVM 
    clone cl_base gr_base \
      meta interleave="true"
    commit
EOF.base

# This wait state is necessary to ensure Base Group resources are fully started.
BASE_START_STATUS=$(crm_resource -L | grep "Stopped")
BASE_RUN_STATUS=$(crm_resource -L | grep "cl_base")
while [ ! -z "$BASE_START_STATUS" ] || [ -z "$BASE_RUN_STATUS" ]; do
clear
  echo ""
  echo "Please wait until Base Group resources are started."
  echo ""
  sleep 30 
  BASE_START_STATUS=$(crm_resource -L | grep "Stopped")
  BASE_RUN_STATUS=$(crm_resource -L | grep "cl_base")
done

# Create DRBD's LVM structure.
pvcreate --force --yes /dev/drbd0
vgcreate --addtag @linux_ha --force vg_drbd /dev/drbd0
lvcreate --addtag @linux_ha --name lv_www --extents +${WWW_SIZE}FREE vg_drbd
lvcreate --addtag @linux_ha --name lv_srv --extents +${SRV_SIZE}FREE vg_drbd
lvcreate --addtag @linux_ha --name lv_home --extents +100%FREE vg_drbd
vgchange --available y

# Create GFS filesystems.
clear
echo ""
echo "Please wait until GFS filesystems are formatted."
echo ""
mkfs.gfs2 -O -j 2 -t linux_ha:gfs_lv_www /dev/vg_drbd/lv_www
mkfs.gfs2 -O -j 2 -t linux_ha:gfs_lv_srv /dev/vg_drbd/lv_srv
mkfs.gfs2 -O -j 2 -t linux_ha:gfs_lv_home /dev/vg_drbd/lv_home

# Configure Pacemaker's filesystems. 
# (You must protect filesystems with an Uninterruptible Power Supply 
# if using the data=writeback or nobarrier options.)
crm<<EOF.filesystems
  configure 
    primitive drbd ocf:linbit:drbd \
      params drbd_resource="r0" \
      op monitor interval="59s" role="Master" timeout="30s" \
      op monitor interval="60s" role="Slave" timeout="30s"  \
      op start interval="0" timeout="240s" start-delay="15s" \
      op stop interval="0" timeout="100s"
    primitive fs_www ocf:heartbeat:Filesystem \      
      params device="/dev/vg_drbd/lv_www" directory="/var/www" fstype="gfs2" \
      options="acl,noatime,data=writeback,commit=30,quota=on,nobarrier" \
      op monitor interval="60s" timeout="40s" \
      op start interval="0" timeout="120s" start-delay="15s" \
      op stop interval="0" timeout="60s"
    primitive fs_srv ocf:heartbeat:Filesystem \      
      params device="/dev/vg_drbd/lv_srv" directory="/srv" fstype="gfs2" \
      options="acl,noatime,data=writeback,commit=30,quota=on,nobarrier" \
      op monitor interval="60s" timeout="40s" \
      op start interval="0" timeout="120s" start-delay="15s" \
      op stop interval="0" timeout="60s"
    primitive fs_home ocf:heartbeat:Filesystem \      
      params device="/dev/vg_drbd/lv_home" directory="/home" fstype="gfs2" \
      options="acl,noatime,data=writeback,commit=30,quota=on,nobarrier" \
      op monitor interval="60s" timeout="40s" \
      op start interval="0" timeout="120s" start-delay="15s" \
      op stop interval="0" timeout="60s"
    group gr_filesystems fs_srv fs_www fs_home
    clone cl_filesystems gr_filesystems \
      meta interleave="true"    
    clone cl_drbd drbd \
      clone-max="2" clone-node-max="1" notify="true"
    colocation lvm-and-gfs-with-drbd inf: cl_filesystems cl_drbd:Master
    order drbd-before-lvm-and-gfs mandatory: cl_drbd:promote cl_base:start \
      cl_filesystems:start
    commit
EOF.filesystems
  fi # End the cluster conditional IF statement.

# This wait state is necessary to ensure GFS filesystems are fully mounted.
GFS_START_STATUS=$(crm_resource -L | grep "Stopped")
GFS_MOUNT_STATUS=$(crm_resource -L | grep "cl_filesystem")
while [ ! -z "$GFS_START_STATUS" ] || [ -z "$GFS_MOUNT_STATUS" ]; do
clear
  echo ""
  echo "Please wait until GFS filesystems are mounted."
  echo ""
  sleep 30 
  GFS_START_STATUS=$(crm_resource -L | grep "Stopped")
  GFS_MOUNT_STATUS=$(crm_resource -L | grep "cl_filesystem")
done

clear
echo ""
echo "Installing Linux Cluster Management Console."
echo ""

# Install Linux Cluster Management Console (LCMC).
apt_function $JDK
  if [ "$SERVER" = "pdc" ]; then
mkdir -p /var/www/html
$WGET "$LCMC_APPLET" -O /var/www/html/LCMC-applet.jar
while [ $? -ne 0 ]; do $WGET "$LCMC_APPLET" -O /var/www/html/LCMC-applet.jar; done

# Create lcmc.html.
cat > /var/www/html/lcmc.html << EOF.lcmc.html
<html>
  <body>
    <applet archive="LCMC-applet.jar"
      code="lcmc.LCMCApplet"
      name=LCMCApplet
      height="100%"
      width="100%"
      vspace=0
      hspace=0>
    </applet>
  </body>
</html>
EOF.lcmc.html
  fi

# Create LCMC's lcmc-conf.lcmc.
cat > /admin/lcmc-conf.lcmc << EOF.lcmc-conf.lcmc
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<drbdgui dwpasswd="" dwuser="">
  <hosts>
    <host name="$PDC" ssh="22" sudo="true">
      <ip>$PDC_LAN_IP_ADDRESS</ip>
      <user>admin</user>
    </host>
    <host name="$BDC" ssh="22" sudo="true">
      <ip>$BDC_LAN_IP_ADDRESS</ip>
      <user>admin</user>
    </host>
  </hosts>
  <clusters>
    <cluster name="LinuxHA">
      <host>$PDC</host>
      <host>$BDC</host>
    </cluster>
  </clusters>
</drbdgui>
EOF.lcmc-conf.lcmc
chown admin:admin /admin/lcmc-conf.lcmc

################################################################################
#                                                                              #
# The following routine installs and configures malware and spam scanners      #
# (ClamAV, SpamAssassin, and Amavis).                                          #
#                                                                              #
# clamav.net                                                                   #
# spamassassin.apache.org                                                      #
# ijs.si/software/amavisd                                                      #
# wbmclamav.labs.libre-entreprise.org                                          #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing malware and spam scanners."
echo ""

# Install malware and spam scanners.
apt_function install $AMAVISD $SPAM_PREVENTION $CLAMAV

# Configure clamd.conf.
if [ ! -f /etc/clamav/clamd.conf.orig ]; then 
  cp /etc/clamav/clamd.conf /etc/clamav/clamd.conf.orig
fi
sed -i "s|DetectPUA false|DetectPUA true|
  s|HeuristicScanPrecedence false|HeuristicScanPrecedence true|
  s|StructuredDataDetection false|StructuredDataDetection true|
  /LocalSocketGroup/ c\LocalSocketGroup amavis" \
    /etc/clamav/clamd.conf

# Update ClamAV's malware signatures.
clear
echo ""
echo "Please wait for FreshClam to update ClamAV malware signatures."
echo ""
freshclam

# Set Amavis's myhostname.
if [ ! -f /etc/amavis/conf.d/05-node_id.orig ]; then 
  cp /etc/amavis/conf.d/05-node_id /etc/amavis/conf.d/05-node_id.orig
fi
sed -i "s|#\$myhostname = .*$|\$myhostname = \"mail.$WAN_DOMAIN\";|" \
  /etc/amavis/conf.d/05-node_id

# Enable Amavis's virus/spam scanning.
if [ ! -f /etc/amavis/conf.d/15-content_filter_mode.orig ]; then 
  cp /etc/amavis/conf.d/15-content_filter_mode \
    /etc/amavis/conf.d/15-content_filter_mode.orig
fi
sed -i "/bypass/ s|^#||" /etc/amavis/conf.d/15-content_filter_mode

# Update and compile SpamAssassin rule updates.
$WGET "http://spamassassin.apache.org/updates/GPG.KEY" -O /tmp/GPG.key
sa-update --import /tmp/GPG.key
sa-update -D
sa-compile

# Create SpamAssassin's cron job.
cat > /usr/local/bin/sa-update.sh << EOF.sa-update
sa-update --allowplugins --channel updates.spamassassin.org
sa-compile
EOF.sa-update
echo "@daily root /usr/local/bin/sa-update.sh" > /etc/cron.d/sa-update
chmod 700 /usr/local/bin/sa-update.sh

# Configure Razor.
mkdir -p /etc/spamassassin/.razor
razor-admin -home=/etc/spamassassin/.razor -register
razor-admin -home=/etc/spamassassin/.razor -create
razor-admin -home=/etc/spamassassin/.razor -discover
grep -q "razor_config" /etc/spamassassin/local.cf || \
cat >> /etc/spamassassin/local.cf << EOF.local.cf

# Razor configuration.
razor_config /etc/spamassassin/.razor/razor-agent.conf
EOF.local.cf

# Configure Pyzor.
mkdir -p /etc/spamassassin/.pyzor
chown debian-spamd:debian-spamd /etc/spamassassin/.pyzor
grep -q "pyzor_options" /etc/spamassassin/local.cf || \
cat >> /etc/spamassassin/local.cf << EOF.local.cf

# Pyzor configuration.
pyzor_options --homedir /etc/spamassassin/.pyzor
pyzor_timeout 20
EOF.local.cf

# Reload configuration.
systemctl restart clamav-daemon
systemctl restart clamav-freshclam
systemctl restart amavis

################################################################################
#                                                                              #
# The following routine installs and configures OpenSSL, which implements      #
# cryptographic functions and provides a Certificate Authority.                #
#                                                                              #
# openssl.org                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing OpenSSL."
echo ""

# Install OpenSSL.
apt_function install $OPENSSL

# Create CA directory structure.
mkdir -p /etc/ssl/crl
mkdir -p /etc/ssl/certs
mkdir -p /etc/ssl/private

# Configure openssl.cnf.
if [ ! -f /etc/ssl/openssl.cnf.orig ]; then
  cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.orig
fi
grep -q "/etc/ssl" /etc/ssl/openssl.cnf || \
sed -ri "s|(default_bits\s+).+$|\1= 8192|
  s|365|7300|
  s|./demoCA|/etc/ssl|
  s|$dir/crlnumber|$dir/crl/crlnumber|
  s|$dir/crl.pem|$dir/crl/crl.pem|
  s|$dir/cacert.pem|$dir/certs/ca-bundle.pem|
  s|$dir/private/cakey.pem#|$dir/private/ca-key.pem #|" /etc/ssl/openssl.cnf

# Create CA key and certificate.
# Note: the CA expiration must be longer than the server certificate expiration
# (e.g., 7301 days for CA expiration and 7300 days for server certificate 
# expiration).
openssl genrsa -out /etc/ssl/private/ca-key.pem -aes256 \
  -passout pass:$ADMIN_PASSWORD 8192
openssl req -new -x509 -key /etc/ssl/private/ca-key.pem \
  -passin pass:$ADMIN_PASSWORD -subj "/C=$COUNTRY/ST=$STATE/O=$ORGANIZATION/\
OU=PKI/CN=$HOSTNAME/emailAddress=$EMAIL_ADDRESS" -days 7301 \
  -out /etc/ssl/certs/ca-cert.pem
ln -fs /etc/ssl/certs/ca-cert.pem /etc/ssl/certs/"$(openssl x509 -noout -hash \
  -in /etc/ssl/certs/ca-cert.pem)".0
chmod 400 /etc/ssl/private/ca-key.pem

# Concatenate PDC and BDC CA certs into ca-bundle.pem.
if [ "$SERVER" = "pdc" ]; then  
  scp -q -o StrictHostKeyChecking=no -o ConnectionAttempts=99 \
    /etc/ssl/certs/ca-cert.pem "$BDC_LAN_IP_ADDRESS":/tmp/ca-cert."$PDC_FQDN".pem
  while [ ! -f /tmp/ca-cert."$BDC_FQDN".pem ]; do
    clear
    echo ""
    echo "Please wait for CA TLS certificate sync."
    echo ""
    sleep 15  
  done
  cat /etc/ssl/certs/ca-cert.pem /tmp/ca-cert."$BDC_FQDN".pem > /etc/ssl/certs/ca-bundle.pem
  openssl x509 -in /etc/ssl/certs/ca-cert.pem -out /tmp/ca-cert.crt
  openssl x509 -in /tmp/ca-cert."$BDC_FQDN".pem \
    -out /tmp/ca-cert."$BDC_FQDN".crt
  cat /tmp/ca-cert.crt /tmp/ca-cert."$BDC_FQDN".crt > \
    /var/www/html/ca-bundle.crt
  rm -f /tmp/ca-cert.crt /tmp/ca-cert."$BDC_FQDN".crt /tmp/ca-cert."$BDC_FQDN".pem
else
  scp -q -o StrictHostKeyChecking=no -o ConnectionAttempts=99 \
    /etc/ssl/certs/ca-cert.pem "$PDC_LAN_IP_ADDRESS":/tmp/ca-cert."$BDC_FQDN".pem
  while [ ! -f /tmp/ca-cert."$PDC_FQDN".pem ]; do
    clear
    echo ""
    echo "Please wait for CA TLS certificate sync."
    echo ""
    sleep 15    
  done
  cat /etc/ssl/certs/ca-cert.pem /tmp/ca-cert."$PDC_FQDN".pem > /etc/ssl/certs/ca-bundle.pem
  openssl x509 -in /etc/ssl/certs/ca-cert.pem -out /tmp/ca-cert.crt
  openssl x509 -in /tmp/ca-cert."$PDC_FQDN".pem \
    -out /tmp/ca-cert."$PDC_FQDN".crt
  cat /tmp/ca-cert.crt /tmp/ca-cert."$PDC_FQDN".crt > \
    /var/www/html/ca-bundle.crt
  rm -f /tmp/ca-cert.crt /tmp/ca-cert."$PDC_FQDN".crt /tmp/ca-cert."$PDC_FQDN".pem
fi
sleep 30

# Create the ca-bundle.pem hash value.
ln -fs /etc/ssl/certs/ca-bundle.pem /etc/ssl/certs/"$(openssl x509 -noout -hash \
  -in /etc/ssl/certs/ca-bundle.pem)".0

# Configure ca-key.pem permissions.
chmod 400 /etc/ssl/private/ca-key.pem

# Create the Certificate Revocation List (CRL).
touch /etc/ssl/index.txt
echo "01" > /etc/ssl/crl/crlnumber
openssl ca -gencrl -passin pass:"$ADMIN_PASSWORD" -out /etc/ssl/crl/crl.pem
ln -fs /etc/ssl/crl/crl.pem /etc/ssl/"$(openssl crl -noout -hash \
  -in /etc/ssl/crl/crl.pem)".r0
ln -fs /etc/ssl/crl/crl.pem /var/www/html/crl.pem
sed -i "s|nsCaRevocationUrl.*$\
|nsCaRevocationUrl\t\t http://$WAN_DOMAIN/crl.pem|" /etc/ssl/openssl.cnf

# Create server key and certificate.
openssl req -newkey rsa:8192 -nodes -days 7300 -keyout /etc/ssl/private/tls-key.pem \
  -out newreq.pem -subj "/C=$COUNTRY/ST=$STATE/O=$ORGANIZATION/\
OU=TLS/CN=$FQDN/emailAddress=$EMAIL_ADDRESS" --addext "extendedKeyUsage = serverAuth" \
  --addext "subjectAltName = email:copy, DNS:*.$WAN_DOMAIN, DNS:*.$LAN_DOMAIN"
openssl x509 -req -days 7300 -in newreq.pem -CA /etc/ssl/certs/ca-cert.pem \
  -CAkey /etc/ssl/private/ca-key.pem -passin pass:"$ADMIN_PASSWORD" -CAcreateserial \
  -out /etc/ssl/certs/tls-cert.pem
ln -fs /etc/ssl/certs/tls-cert.pem /etc/ssl/certs/"$(openssl x509 -noout \
  -hash -in /etc/ssl/certs/tls-cert.pem)".0  
rm -f newcert.pem newreq.pem
chmod 440 /etc/ssl/private/tls-key.pem

# Create LCMC's Java Key Store (JKS).
openssl pkcs12 -export -passin pass:"$ADMIN_PASSWORD" -passout pass:"$ADMIN_PASSWORD" \
  -out /tmp/keystore.p12 -inkey /etc/ssl/private/tls-key.pem \
  -in /etc/ssl/certs/tls-cert.pem
keytool -importkeystore -destkeystore /etc/ssl/certs/java/keystore.jks \
  -srcstoretype PKCS12 -srckeystore /tmp/keystore.p12 \
  -deststorepass "$ADMIN_PASSWORD" -srcstorepass "$ADMIN_PASSWORD"
keytool -importcert -noprompt -trustcacerts -file /etc/ssl/certs/ca-bundle.pem \
  -keystore /etc/ssl/certs/java/keystore.jks -storepass "$ADMIN_PASSWORD"

# Digitally sign LCMC's Java applet.
jarsigner -storepass "$ADMIN_PASSWORD" -keystore /etc/ssl/certs/java/keystore.jks \
  -tsa http://timestamp.digicert.com /var/www/html/LCMC-applet.jar 1

# Update AppArmor's profile for <abstractions/ssl_certs>.
if [ ! -f /etc/apparmor.d/abstractions/ssl_certs.orig ]; then 
  cp /etc/apparmor.d/abstractions/ssl_certs \
    /etc/apparmor.d/abstractions/ssl_certs.orig
fi
grep -q "/etc/ssl/certs/ca-bundle.pem" /etc/apparmor.d/abstractions/ssl_certs || \
cat >> /etc/apparmor.d/abstractions/ssl_certs << EOF.apparmor.ssl
  /etc/ssl/certs/ca-bundle.pem r,
  /etc/ssl/crl/crl.pem r,
  /etc/pkcs11/modules/* r,
EOF.apparmor.ssl
systemctl restart apparmor

# Create Diffie-Hellman parameters.
openssl dhparam -dsaparam -out /etc/ssl/dh 8192

################################################################################
#                                                                              #
# The following routine installs and configures Apache, a robust,              #
# commercial-grade, featureful, and freely available source code               #
# implementation of an HTTP (Web) server.                                      #
#                                                                              #
# apache.org                                                                   #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Apache."
echo ""

# Install Apache.
apt_function install $APACHE $APACHE_MODULES $PHP

### Enable necessary Apache modules. ###
# CGI module.
a2enmod cgi
# SSL module.
a2enmod ssl
# GSSAPI authentication module.
a2enmod auth_gssapi
# WebDav modules.
a2enmod dav dav_fs
# Passenger module for Foreman.
a2enmod passenger
# FastCGI Munin module.
a2enmod fcgid
# Open-Xchange modules.
a2enmod proxy proxy_http proxy_balancer expires deflate headers rewrite mime \
  setenvif lbmethod_byrequests

# Add ServerName to default sites.
if [ ! -f /etc/apache2/sites-available/000-default.conf.orig ]; then 
  cp /etc/apache2/sites-available/000-default.conf \
   /etc/apache2/sites-available/000-default.conf.orig
fi
sed -i "s|#ServerName www.example.com|ServerName $FQDN|" \
  /etc/apache2/sites-available/000-default.conf
if [ ! -f /etc/apache2/sites-available/default-ssl.conf.orig ]; then 
  cp /etc/apache2/sites-available/default-ssl.conf \
   /etc/apache2/sites-available/default-ssl.conf.orig
fi
grep -q "ServerName" /etc/apache2/sites-available/default-ssl.conf || \
  sed -i "/ServerAdmin/ a\ \n\tServerName $FQDN" \
    /etc/apache2/sites-available/default-ssl.conf

# Add OpenSSL RewriteEngine.
grep -q "RewriteEngine On" /etc/apache2/sites-available/000-default.conf || \
  sed -i "/ServerName $FQDN/ a\ \n\tRewriteEngine On\n\tRewriteCond %{HTTPS} \
!=on\n\tRewriteRule ^/?(.*) https://%{SERVER_NAME}/\$1 [R,L]" \
  /etc/apache2/sites-available/000-default.conf

# Configure default-ssl.conf.
sed -i "s|ssl-cert-snakeoil.pem|tls-cert.pem|
  s|ssl-cert-snakeoil.key|tls-key.pem|
  s|#SSLCACertificateFile .*$|SSLCACertificateFile /etc/ssl/certs/ca-bundle.pem|
  s|#SSLCARevocationFile .*$|SSLCARevocationFile /etc/ssl/crl/crl.pem|" \
    /etc/apache2/sites-available/default-ssl.conf
grep -q "SSLCARevocationCheck" \
  /etc/apache2/sites-available/default-ssl.conf || \
  sed -i "/SSLCARevocationFile/ a\ \n\tSSLCARevocationCheck chain" \
    /etc/apache2/sites-available/default-ssl.conf

# Enable the default-ssl VirtualHost.
a2ensite default-ssl

# Add www.$WAN_DOMAIN VirtualHost.
cp /etc/apache2/sites-available/000-default.conf \
  /etc/apache2/sites-available/www."$WAN_DOMAIN".conf
sed -i "s|<VirtualHost \*:80>|<VirtualHost www.$WAN_DOMAIN:80>|
  s|ServerName $FQDN|ServerName www.$WAN_DOMAIN|" \
    /etc/apache2/sites-available/www."$WAN_DOMAIN".conf
a2ensite www."$WAN_DOMAIN"

# Add www.$WAN_DOMAIN-ssl VirtualHost.
cp /etc/apache2/sites-available/default-ssl.conf \
  /etc/apache2/sites-available/www."$WAN_DOMAIN"-ssl.conf
sed -i "s|<VirtualHost _default_:443>|<VirtualHost www.$WAN_DOMAIN:443>|
  s|ServerName $FQDN|ServerName www.$WAN_DOMAIN|" \
    /etc/apache2/sites-available/www."$WAN_DOMAIN"-ssl.conf
a2ensite www."$WAN_DOMAIN"-ssl

# Configure ports.conf.
if [ ! -f /etc/apache2/ports.conf.orig ]; then 
  mv /etc/apache2/ports.conf /etc/apache2/ports.conf.orig
fi
cat > /etc/apache2/ports.conf << EOF.ports.conf
Listen 80
<IfModule ssl_module>
  Listen 443
  Listen 3000
</IfModule>
EOF.ports.conf

# Set the Kerberos keytab path.
if [ ! -f /etc/default/apache2.orig ]; then 
  cp /etc/default/apache2 /etc/default/apache2.orig
fi
grep -q "KRB5_KTNAME" /etc/default/apache2 || \
cat >> /etc/default/apache2 << EOF.apache2.default

# Kerberos keytab path.
export KRB5_KTNAME=/etc/apache2/http.keytab
EOF.apache2.default

# Add the www-data user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert www-data

# Reload configuration.
systemctl restart apache2

################################################################################
#                                                                              #
# The following routine installs and configures MariaDB and phpMyAdmin.        #
#                                                                              #
# MariaDB provides a relational database management system (RDBMS) that runs   #
# as a server providing multi-user access to a number of databases.            #
#                                                                              #
# phpMyAdmin provides a graphical user interface to manage MariaDB.            #
#                                                                              #
# mariadb.com                                                                  #
# phpmyadmin.net                                                               #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing MariaDB."
echo ""

# Install MariaDB.
apt_function install $MARIADB

# Configure Galera.
sed -i "/wsrep_on/ s|^# ||
  /wsrep_cluster_name/ s|^# ||
  /binlog_format/ s|^# ||
  /default_storage_engine/ s|^# ||
  /innodb_autoinc_lock_mode/ s|^# ||
  /bind_address/ s|^# ||
  s|0.0.0.0|$LAN_IP_ADDRESS|
  /wsrep_cluster_address/ c\wsrep_cluster_address    = gcomm://$PDC_LAN_IP_ADDRESS,$BDC_LAN_IP_ADDRESS
  /wsrep_slave_threads/ c\wsrep_slave_threads = $(nproc --all)" /etc/mysql/mariadb.conf.d/60-galera.cnf

if [ "$SERVER" = "pdc" ]; then
  systemctl stop mariadb
  galera_new_cluster
  systemctl start mariadb
else
  systemctl restart mariadb
fi

# Enable PHP extensions (needed for phpMyAdmin).
phpenmod mbstring mcrypt 

# Set MariaDB's root password.
mysqladmin --user=root password "$ADMIN_PASSWORD"

# Add MariaDB's administrator account.
mysql --user=root --password="$ADMIN_PASSWORD" << EOF.mysql_admin
CREATE USER 'admin'@'$LAN_IP_ADDRESS' IDENTIFIED VIA mysql_native_password USING '$ADMIN_PASSWORD';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'$LAN_IP_ADDRESS';
FLUSH PRIVILEGES; 
EOF.mysql_admin

# Change database backup compression.
sed -i "s|COMP=gzip|COMP=bzip2|" /etc/default/automysqlbackup

# Create a controluser for phpMyAdmin.
mysql --user=root --password="$ADMIN_PASSWORD" << EOF.controluser
CREATE USER 'pma'@'localhost' IDENTIFIED VIA mysql_native_password USING '$ADMIN_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON `phpmyadmin`.* TO 'pma'@'localhost';
EOF.controluser

# Create the PMA database and tables.
mysql < /usr/share/phpmyadmin/sql/create_tables.sql

# Disable phpMyAdmin's Suhosin warning.
if [ ! -f /etc/phpmyadmin/config.inc.php.orig ]; then 
  cp /etc/phpmyadmin/config.inc.php /etc/phpmyadmin/config.inc.php.orig
fi
grep -q "SuhosinDisableWarning" /etc/phpmyadmin/config.inc.php || \
cat >> /etc/phpmyadmin/config.inc.php << EOF.config.inc.php

/* Disable displayed warning on the main page when Suhosin is detected. */
\$cfg['SuhosinDisableWarning'] = TRUE;
EOF.config.inc.php

# Configure phpMyAdmin's Debconf.
if [ ! -f /etc/dbconfig-common/phpmyadmin.conf.orig ]; then 
  cp /etc/dbconfig-common/phpmyadmin.conf /etc/dbconfig-common/phpmyadmin.conf.orig
fi
sed -i "/dbc_install=/ c\dbc_install='false'
  /dbc_dbuser=/ c\dbc_dbuser='pma'
  /dbc_dbpass=/ c\dbc_dbpass='$ADMIN_PASSWORD'
  /dbc_dballow=/ c\dbc_dballow='localhost'
  /dbc_dbname=/ c\dbc_dbname='phpmyadmin'
  /dbc_dbadmin=/ c\dbc_dbadmin='admin'" /etc/dbconfig-common/phpmyadmin.conf

# Create config-db.php.
/usr/sbin/dbconfig-generate-include /etc/dbconfig-common/phpmyadmin.conf -f php \
  > /etc/phpmyadmin/config-db.php

# Configure phpMyAdmin's apache.conf.
if [ ! -f /etc/phpmyadmin/apache.conf.orig ]; then 
  cp /etc/phpmyadmin/apache.conf /etc/phpmyadmin/apache.conf.orig
fi
grep -q "DirectoryIndex" /etc/phpmyadmin/apache.conf || \
sed -i "/DirectoryIndex/ a\    Require ip 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR" \
  /etc/phpmyadmin/apache.conf  
ln -fs /etc/phpmyadmin/apache.conf /etc/apache2/conf-available/phpmyadmin.conf
a2enconf phpmyadmin

# Add the mysql user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert mysql

# Reload configuration.
systemctl restart mysql 
systemctl restart apache2

################################################################################
#                                                                              #
# The following routine installs and configures Bucardo, phpPgAdmin, and       #
# PostgreSQL.                                                                  #
#                                                                              #
# Bucardo provides multi-master replication.                                   #
#                                                                              #
# phpPgAdmin provides a graphical user interface to manage PostgreSQL.         #
#                                                                              #
# PostgreSQL provides a powerful, open-source, object-relational database      #
# system.                                                                      #
#                                                                              #
# postgresql.org                                                               #
# bucardo.org/wiki/Bucardo                                                     #
# phppgadmin.sourceforge.net                                                   #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing PostgreSQL."
echo ""

# Install PostgreSQL.
apt_function install $POSTGRESQL

# Install Bucardo's schema.
sed -i "/CREATE DATABASE/ c\CREATE DATABASE bucardodb OWNER bucardo;
  s|\\\c bucardo bucardo|\\\c bucardodb|" /usr/share/bucardo/bucardo.schema
sudo -u postgres psql -f /usr/share/bucardo/bucardo.schema
sudo -u postgres psql -c "ALTER USER bucardo WITH PASSWORD '$ADMIN_PASSWORD';"

# Create bucardorc.
cat > /etc/bucardorc << EOF.bucardorc
dbport = 5432
dbhost = $LAN_IP_ADDRESS
dbname = bucardodb
dbuser = bucardo
dbpass = $ADMIN_PASSWORD
EOF.bucardorc
chmod 640 /etc/bucardorc
chown bucardo:bucardo /etc/bucardorc

# Create the administrator account.
sudo -u postgres psql \
  -c "CREATE USER admin WITH SUPERUSER LOGIN ENCRYPTED PASSWORD \
    '$ADMIN_PASSWORD';"

# Create the Nagios account (required for the check_pgsql plugin).
sudo -u postgres psql -c "CREATE USER nagios WITH LOGIN;"

# Set path.
POSTGRES_PATH=$(echo /etc/postgresql/*)

# Configure postgresql.conf.
if [ ! -f "$POSTGRES_PATH"/main/postgresql.conf.orig ]; then 
  cp "$POSTGRES_PATH"/main/postgresql.conf \
    "$POSTGRES_PATH"/main/postgresql.conf.orig
fi
sed -i "s|ssl-cert-snakeoil.pem|tls-cert.pem|
  s|ssl-cert-snakeoil.key|tls-key.pem|
  s|#ssl_ca_file = ''|ssl_ca_file = '/etc/ssl/certs/ca-bundle.pem'|
  s|#ssl_crl_file = ''|ssl_crl_file = '/etc/ssl/crl/crl.pem'|
  s|#krb_server_keyfile = ''\
|krb_server_keyfile = '$POSTGRES_PATH/main/postgres.keytab'|
  /#krb_srvname/ s|^#||" "$POSTGRES_PATH"/main/postgresql.conf

# Configure pg_hba.conf.
if [ ! -f "$POSTGRES_PATH"/main/pg_hba.conf.orig ]; then 
  cp "$POSTGRES_PATH"/main/pg_hba.conf "$POSTGRES_PATH"/main/pg_hba.conf.orig
fi
grep -q "local template1 nagios trust" "$POSTGRES_PATH"/main/pg_hba.conf || \
cat >> "$POSTGRES_PATH"/main/pg_hba.conf << EOF.pg_hba.conf
local template1 nagios trust
local bucardodb bucardo scram-sha-256
EOF.pg_hba.conf

# Change database backup compression.
sed -i "s|COMP=gzip|COMP=bzip2|" /etc/default/autopostgresqlbackup

# Configure phppgadmin.conf.
if [ ! -f /etc/apache2/conf-available/phppgadmin.conf.orig ]; then 
  cp /etc/apache2/conf.d/phppgadmin \
    /etc/apache2/conf-available/phppgadmin.conf.orig
fi
sed -i "/Require local/ c\Require ip 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR" \
  /etc/apache2/conf-available/phppgadmin.conf
a2enconf phppgadmin

# Configure phpPgAdmin's config.inc.php.
if [ ! -f /etc/phppgadmin/config.inc.php.orig ]; then 
  cp /etc/phppgadmin/config.inc.php /etc/phppgadmin/config.inc.php.orig
fi
sed -i "/\$conf\['servers'\]\[0\]\['host'\]/ c\        \$conf\['servers'\]\[0\]\['host'\] = '';" \
  /etc/phppgadmin/config.inc.php

# Reload configuration.
systemctl restart apache2
systemctl restart bucardo
systemctl restart postgresql 

################################################################################
#                                                                              #
# The following routine installs FusionDirectory, which provides a graphical   #
# user interface that helps you manage an OpenLDAP backend to securely set up  #
# identity management for managing users, groups, passwords, access control,   #
# and email; efficiently manage system services such as DNS, DHCP, Samba,      #
# FreeRADIUS, and AutoFS; and automatically deploy Linux and Windows systems   #
# with FAI and Opsi.                                                           #
#                                                                              #
# fusiondirectory.org                                                          #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing FusionDirectory."
echo ""

# Install FusionDirectory.
apt_function install $FUSIONDIRECTORY

# Move schema files.
mv -u /etc/ldap/schema/fusiondirectory/*.schema /etc/ldap/schema
rm -rf /etc/ldap/schema/fusiondirectory

################################################################################
#                                                                              #
# The following routine installs and configures OpenLDAP and phpLDAPadmin.     #
#                                                                              #
# OpenLDAP provides an object-oriented database used to store uid/gid,         #
# passwords, etc., in a single repository on a network.                        #
#                                                                              #
# phpLDAPadmin provides a graphical user interface to manage OpenLDAP.         #
#                                                                              #
# openldap.org                                                                 #
# phpldapadmin.sourceforge.net                                                 #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing OpenLDAP."
echo ""

# Install OpenLDAP.
apt_function install $OPENLDAP

# Configure phpLDAPadmin's config.php.
if [ ! -f /etc/phpldapadmin/config.php.orig ]; then 
  cp /etc/phpldapadmin/config.php /etc/phpldapadmin/config.php.orig
fi
sed -i "s|\$servers->setValue('server','name'.*$\
|\$servers->setValue('server','name','$FQDN');|
  s|\$servers->setValue('server','host'.*$\
|\$servers->setValue('server','host','ldapi:///');|
  s|\$servers->setValue('server','base'.*$\
|\$servers->setValue('server','base',array('$LDAP_BASE_DN'));|
  s|\$servers->setValue('login','auth_type'.*$\
|\$servers->setValue('login','auth_type','sasl');|
  s|\$servers->setValue('server','tls'.*$\
|\$servers->setValue('server','tls',true);|
  /ca.crt/ c\$servers->setValue('server','tls_cacert','/etc/ssl/certs/ca-bundle.pem');
  /ldap_user.crt/ c\$servers->setValue('server','tls_cert','/etc/ssl/certs/tls-cert.pem');
  /ldap_user.key/ c\$servers->setValue('server','tls_key','/etc/ssl/private/tls-key.pem');
  /\$servers->setValue('sasl','mech','GSSAPI');/ s|^\/\/ ||
  /'sasl','realm','EXAMPLE.COM'/ c\$servers->setValue('sasl','realm','$KERBEROS_REALM');
  /'auto_number','search_base'/ c\$servers->setValue('auto_number','search_base','ou=people,$LDAP_BASE_DN');"\
  /etc/phpldapadmin/config.php

# Configure phpLDAPadmin's apache.conf.
if [ ! -f /etc/phpldapadmin/apache.conf.orig ]; then 
  cp /etc/phpldapadmin/apache.conf /etc/phpldapadmin/apache.conf.orig
fi
grep -q "AllowOverride" /etc/phpldapadmin/apache.conf || \
sed -i "/AllowOverride/ a\    Require ip 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR" \
  /etc/phpldapadmin/apache.conf

# Use authselect to configure authentication and identity sources.
authselect select sssd --force

# Create sssd.conf.
# (Used for System Security Services Daemon.)
if [ ! -f /etc/sssd/sssd.conf.orig ]; then
  mv /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig
fi
cat > /etc/sssd/sssd.conf << EOF.sssd.conf
[sssd]
domains = LDAP
services = nss, pam, sudo, autofs, ssh
config_file_version = 2

[nss]
filter_groups = root
filter_users = root

[domain/LDAP]
id_provider = ldap
ldap_uri = ldapi:///
ldap_search_base = $LDAP_BASE_DN

auth_provider = krb5
krb5_server = 127.0.0.1
krb5_realm = $KERBEROS_REALM
EOF.sssd.conf
chmod 0600 /etc/sssd/sssd.conf

# Create directories.
systemctl stop slapd
if [ -d /var/lib/ldap ]; then 
  mv /var/lib/ldap /var/lib/ldap."$(date +%m%d%y-%T)"
fi
if [ -d /etc/ldap/slapd.d ]; then 
  mv /etc/ldap/slapd.d /etc/ldap/slapd.d."$(date +%m%d%y-%T)"
fi
mkdir -p /etc/ldap/slapd.d /var/lib/ldap

# Extract kerberos.schema for LDIF conversion. 
# (The packaged kerberos.ldif is non-functional.)
if [ -f /usr/share/doc/krb5-kdc-ldap/kerberos.schema.gz ]; then
  zcat -qf /usr/share/doc/krb5-kdc-ldap/kerberos.schema.gz > \
    /etc/ldap/schema/kerberos.schema
fi

# Convert schema files to LDIF format.
for FILE in /etc/ldap/schema/*.schema
do
  echo "Running schema2ldif on $FILE"
  schema2ldif "$FILE"  > "$(echo "$FILE" | cut -d. -f1)".ldif
done

# Create config.ldif.
cat > /tmp/config.ldif << EOF.config.ldif
# Global configuration.
dn: cn=config
objectClass: olcGlobal
cn: config
olcLogLevel: stats
olcPidFile: /run/slapd/slapd.pid
olcArgsFile: /run/slapd/slapd.args
olcServerID: 1 ldap://$PDC_FQDN
olcServerID: 2 ldap://$BDC_FQDN

# Schema configuration.
dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file:///etc/ldap/schema/core.ldif
include: file:///etc/ldap/schema/cosine.ldif
include: file:///etc/ldap/schema/nis.ldif
include: file:///etc/ldap/schema/inetorgperson.ldif
include: file:///etc/ldap/schema/argonaut-fd.ldif
include: file:///etc/ldap/schema/autofs.ldif
include: file:///etc/ldap/schema/autofs5-fd-conf.ldif
include: file:///etc/ldap/schema/core-fd-conf.ldif
include: file:///etc/ldap/schema/core-fd.ldif
include: file:///etc/ldap/schema/dovecot-fd.ldif
include: file:///etc/ldap/schema/fai-fd-conf.ldif
include: file:///etc/ldap/schema/fai.ldif
include: file:///etc/ldap/schema/gpg-fd.ldif
include: file:///etc/ldap/schema/kerberos.ldif
include: file:///etc/ldap/schema/ldapns.ldif
include: file:///etc/ldap/schema/openssh-lpk.ldif
include: file:///etc/ldap/schema/pgp-keyserver.ldif
include: file:///etc/ldap/schema/pgp-recon.ldif
include: file:///etc/ldap/schema/pgp-remte-prefs.ldif
include: file:///etc/ldap/schema/postfix-fd.ldif
include: file:///etc/ldap/schema/quota-fd.ldif
include: file:///etc/ldap/schema/quota.ldif
include: file:///etc/ldap/schema/service-fd.ldif
include: file:///etc/ldap/schema/spamassassin-fd.ldif
include: file:///etc/ldap/schema/sudo-fd-conf.ldif
include: file:///etc/ldap/schema/sudo.ldif
include: file:///etc/ldap/schema/systems-fd-conf.ldif
include: file:///etc/ldap/schema/systems-fd.ldif
include: file:///etc/ldap/schema/template-fd.ldif

# Module configuration.
dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModulePath: /usr/lib/ldap
olcModuleLoad: back_mdb
olcModuleLoad: back_monitor
olcModuleLoad: syncprov

# Config database configuration.
dn: olcDatabase=config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: config
olcRootDN: uid=admin,cn=gssapi,cn=auth
olcMirrorMode: TRUE
olcSyncRepl: 
  rid=1 
  provider=ldap://$PDC_FQDN 
  bindmethod=sasl 
  saslmech=GSSAPI
  searchbase="cn=config" 
  type=refreshAndPersist 
  retry="5 +" 
olcSyncRepl: 
  rid=2 
  provider=ldap://$BDC_FQDN 
  bindmethod=sasl 
  saslmech=GSSAPI
  searchbase="cn=config" 
  type=refreshAndPersist 
  retry="5 +" 

# Syncprov Overlay configuration for the config database.    
dn: olcOverlay=syncprov,olcDatabase={0}config,cn=config
objectclass: olcOverlayConfig
objectclass: olcSyncProvConfig
olcOverlay: syncprov
olcSpCheckpoint: 100 10

# Backend database configuration.
dn: olcDatabase=mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: mdb
olcDbMaxSize: 10000000
olcDbDirectory: /var/lib/ldap
olcDbIndex: objectClass eq
olcDbIndex: cn,uid eq
olcDbIndex: uidNumber,gidNumber eq
olcDbIndex: member,memberUid eq
olcDbIndex: mail eq,sub
olcSuffix: $LDAP_BASE_DN
olcRootDN: uid=admin,ou=people,$LDAP_BASE_DN
olcRootPW: $(slappasswd -s "$ADMIN_PASSWORD")
olcAccess: to dn.subtree="cn=krbContainer,$LDAP_BASE_DN"
  by dn.base="cn=adm-srv,cn=krbContainer,$LDAP_BASE_DN" write
  by dn.base="cn=kdc-srv,cn=krbContainer,$LDAP_BASE_DN" read
olcAccess: to attrs=userPassword
  by self write
  by anonymous auth
  by * none
olcAccess: to attrs=shadowLastChange
  by self write
  by * read
olcAccess: to *
  by self write
  by * read
olcMirrorMode: TRUE
olcSyncRepl: 
  rid=3 
  provider=ldap://$PDC_FQDN 
  bindmethod=sasl 
  saslmech=GSSAPI
  searchbase=$LDAP_BASE_DN 
  type=refreshAndPersist 
  retry="5 +" 
olcSyncRepl: 
  rid=4 
  provider=ldap://$BDC_FQDN 
  bindmethod=sasl 
  saslmech=GSSAPI
  searchbase=$LDAP_BASE_DN 
  type=refreshAndPersist 
  retry="5 +" 

# Syncprov Overlay configuration for the backend database.
dn: olcOverlay=syncprov,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcSyncProvConfig
olcOverlay: syncprov
olcSpCheckpoint: 100 10
EOF.config.ldif

# Populate the config database.
slapadd -F /etc/ldap/slapd.d -n 0 -l /tmp/config.ldif

# Create backend.ldif.
cat > /tmp/backend.ldif << EOF.backend.ldif
dn: $LDAP_BASE_DN
dc: $SECOND_LEVEL_LAN_DOMAIN
o: $ORGANIZATION
objectClass: top
objectClass: dcObject
objectClass: organization
description: LDAP Base

dn: ou=people,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: people

dn: ou=groups,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: groups

dn: ou=computers,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: computers

dn: ou=idmap,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: idmap

dn: cn=krbContainer,$LDAP_BASE_DN
objectClass: krbContainer
cn: krbContainer

dn: ou=automount,$LDAP_BASE_DN
ou: automount
objectClass: top
objectClass: organizationalUnit

dn: ou=auto.master,ou=automount,$LDAP_BASE_DN
ou: auto.master
objectClass: top
objectClass: automountMap

dn: cn=/home/people,ou=auto.master,ou=automount,$LDAP_BASE_DN
cn: /home/people
objectClass: top
objectClass: automount
automountInformation: ldap:ou=auto.home,ou=automount,$LDAP_BASE_DN \
--timeout=60 --ghost

dn: ou=auto.home,ou=automount,$LDAP_BASE_DN
ou: auto.home
objectClass: top
objectClass: automountMap

dn: cn=/,ou=auto.home,ou=automount,$LDAP_BASE_DN
cn: /
objectClass: top
objectClass: automount
automountInformation: -fstype=nfs4,rw,sec=krb5p $FQDN:/home/people/&

dn: cn=sharedDocs,ou=auto.home,ou=automount,$LDAP_BASE_DN
cn: sharedDocs
objectClass: top
objectClass: automount
automountInformation: -fstype=nfs4,rw,sec=krb5p $FQDN:/home/sharedDocs

dn: cn=kdc-srv,cn=krbContainer,$LDAP_BASE_DN
cn: kdc-srv
sn: kdc-srv
uid: kdc-srv
objectClass: top
objectClass: inetOrgPerson
description: Default bind DN for the Kerberos KDC server.

dn: cn=adm-srv,cn=krbContainer,$LDAP_BASE_DN
cn: adm-srv
sn: adm-srv
uid: adm-srv
objectClass: top
objectClass: inetOrgPerson
description: Default bind DN for the Kerberos Administration server.

dn: cn=$KERBEROS_REALM,cn=krbContainer,$LDAP_BASE_DN
cn: $KERBEROS_REALM
objectClass: top
objectClass: krbRealmContainer
objectClass: krbTicketPolicyAux
EOF.backend.ldif
 
# Populate the backend database.
if [ "$SERVER" = "pdc" ]; then 
  slapadd -F /etc/ldap/slapd.d -n 1 -l /tmp/backend.ldif
fi
rm -f /tmp/{config.ldif,backend.ldif}

# Set directory permissions.
chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap

# Add the OpenLDAP user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert openldap

# OpenLDAP startup.
systemctl start slapd
sleep 15 # This sleep state is necessary to avoid the dreaded 
         # "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)."
systemctl restart apache2

# Enable SSSD services and reload the configuration.
systemctl enable sssd-{nss,pam,sudo,autofs,ssh}
systemctl restart sssd

# Set passwords.
if [ "$SERVER" = "pdc" ]; then
  ldappasswd -H ldapi:/// -D uid=admin,ou=people,$LDAP_BASE_DN \
    -w "$ADMIN_PASSWORD" -s "$ADMIN_PASSWORD" cn=adm-srv,cn=krbContainer,$LDAP_BASE_DN
  ldappasswd -H ldapi:/// -D uid=admin,ou=people,$LDAP_BASE_DN \
    -w "$ADMIN_PASSWORD" -s "$ADMIN_PASSWORD" cn=kdc-srv,cn=krbContainer,$LDAP_BASE_DN
fi

# Create the database backup cron job.
mkdir -p -m 700 /home/ldap_backup
cat > /usr/local/bin/ldap_backup.sh << EOF.ldap_backup
mkdir -p /tmp/ldap_backup/$(date +%m%d%y)
mdb_copy /var/lib/ldap /tmp/ldap_backup/$(date +%m%d%y)
tar -cJf /home/ldap_backup/ldap.$(date +%m%d%y).tar.xz \
  /tmp/ldap_backup/$(date +%m%d%y)
rm -rf /tmp/ldap_backup/$(date +%m%d%y)

function number_of_backups() {
  echo $(ls -1 /home/ldap_backup | wc -l)
}
 
function oldest_backup() {
  echo -n $(ls -1 /home/ldap_backup | head -1)
}
 
if [ \$(number_of_backups) -gt 30 ]; then
  rm -f "/home/ldap_backup/\$(oldest_backup)"
fi
EOF.ldap_backup
echo "@daily root /usr/local/bin/ldap_backup.sh" > /etc/cron.d/ldap_backup
chmod 700 /usr/local/bin/ldap_backup.sh

################################################################################
#                                                                              #
# The following routine installs and configures Kerberos, a network            #
# authentication protocol designed to provide strong authentication for        #
# client/server applications by using secret-key cryptography.                 #
#                                                                              #
# web.mit.edu/kerberos                                                         #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Kerberos."
echo ""

# Install Kerberos.
apt_function install $KERBEROS

# Configure krb5.conf.
if [ ! -f /etc/krb5.conf.orig ]; then mv /etc/krb5.conf /etc/krb5.conf.orig; fi
cat > /etc/krb5.conf << EOF.krb5.conf
[libdefaults]
  default_realm = $KERBEROS_REALM

[realms]
  $KERBEROS_REALM = {
    kdc = 127.0.0.1
    master_kdc = 127.0.0.1
    admin_server = 127.0.0.1
    database_module = openldap_ldapconf
  }

[domain_realm]
  .$LAN_DOMAIN = $KERBEROS_REALM
  $LAN_DOMAIN = $KERBEROS_REALM

[dbdefaults]
  ldap_kerberos_container_dn = cn=krbContainer,$LDAP_BASE_DN

[dbmodules]
  openldap_ldapconf = {
    db_library = kldap
    ldap_conns_per_server = 5
    ldap_kdc_dn = cn=kdc-srv,cn=krbContainer,$LDAP_BASE_DN
    ldap_kadmind_dn = cn=adm-srv,cn=krbContainer,$LDAP_BASE_DN
    ldap_service_password_file = /etc/krb5kdc/service.keyfile
    ldap_servers = ldapi:///
  }

[logging]
  kdc = FILE:/var/log/krb5/kdc.log
  admin_server = FILE:/var/log/krb5/kadmin.log
  default = FILE:/var/log/krb5/klib.log
EOF.krb5.conf

# Create the log directory.
mkdir -p /var/log/krb5

# Rotate log files.
cat > /etc/logrotate.d/krb5 << EOF.logrotate
/var/log/krb5/kadmin.log /var/log/krb5/kdc.log /var/log/krb5/klib.log {
  daily
  missingok
  rotate 7
  compress
  delaycompress
  notifempty
}
EOF.logrotate

# Set the LDAP keytab path.
sed -i "s|#export KRB5_KTNAME=.*$|export KRB5_KTNAME=/etc/ldap/ldap.keytab|" \
  /etc/default/slapd

# Configure kdc.conf.
if [ ! -f /etc/krb5kdc/kdc.conf.orig ]; then 
  cp /etc/krb5kdc/kdc.conf /etc/krb5kdc/kdc.conf.orig
fi
sed -i "s|EXAMPLE.COM|$KERBEROS_REALM|" /etc/krb5kdc/kdc.conf
grep -q "dict_file" /etc/krb5kdc/kdc.conf || \
  sed -i "/acl_file/ a\        dict_file = /etc/dictionaries-common/words" \
    /etc/krb5kdc/kdc.conf

# Create the KADMIND ACL for authorization.
cat > /etc/krb5kdc/kadm5.acl << EOF.kadm5.acl
admin@$KERBEROS_REALM *
*/*@$KERBEROS_REALM *
EOF.kadm5.acl

# Create a new realm ("dn: cn=$KERBEROS_REALM,cn=krbContainer,$LDAP_BASE_DN" 
# is necessary to add backend.ldif, but has to be removed and re-added by 
# kdb5_ldap_util to properly initialize the Kerberos LDAP objects).
if [ "$SERVER" = "pdc" ]; then
  kdb5_ldap_util -f -D uid=admin,ou=people,$LDAP_BASE_DN -w "$ADMIN_PASSWORD" \
    -P "$ADMIN_PASSWORD" -H ldapi:/// destroy -r "$KERBEROS_REALM"
  kdb5_ldap_util -D uid=admin,ou=people,$LDAP_BASE_DN -w "$ADMIN_PASSWORD" \
    -P "$ADMIN_PASSWORD" -H ldapi:/// create -r "$KERBEROS_REALM" -s
fi

# Create stash file.
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | kdb5_ldap_util \
  -D uid=admin,ou=people,$LDAP_BASE_DN -w "$ADMIN_PASSWORD" stashsrvpw \
  -f /etc/krb5kdc/service.keyfile cn=kdc-srv,cn=krbContainer,$LDAP_BASE_DN
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | kdb5_ldap_util \
  -D uid=admin,ou=people,$LDAP_BASE_DN -w "$ADMIN_PASSWORD" stashsrvpw \
  -f /etc/krb5kdc/service.keyfile cn=adm-srv,cn=krbContainer,$LDAP_BASE_DN

# Sync the password stash between PDC and BDC.
if [ "$SERVER" = "pdc" ]; then
  ssh -q -o StrictHostKeyChecking=no -o ConnectionAttempts=99 $BDC_LAN_IP_ADDRESS \
    mkdir -p /etc/krb5kdc
  scp -q -o StrictHostKeyChecking=no -o ConnectionAttempts=99 \
    /etc/krb5kdc/stash $BDC_LAN_IP_ADDRESS:/etc/krb5kdc
fi

# krb5-admin-server startup.
if [ "$SERVER" = "bdc" ]; then
  while [ ! -f /etc/krb5kdc/stash ]; do
    clear
    echo ""
    echo "Please wait for password stash sync."
    echo ""
    sleep 30
  done
fi
pgrep kadmind > /dev/null
if [ $? -eq 1 ]; then
  systemctl start krb5-admin-server
  clear
  echo ""
  echo "Please wait for Kerberos admin server startup."
  echo ""
  sleep 60
else
  systemctl restart krb5-admin-server
fi

# krb5-kdc startup.
pgrep krb5kdc > /dev/null
if [ $? -eq 1 ]; then
  systemctl start krb5-kdc
else
  systemctl restart krb5-kdc
fi

if [ "$SERVER" = "pdc" ]; then
  # Create policies.
  kadmin.local -p admin -q "add_policy -minlength 8 -minclasses 2 user"
  kadmin.local -p admin -q "add_policy -minlength 8 -minclasses 3 admin"
  kadmin.local -p admin -q "add_policy -minlength 8 -minclasses 4 host"
  kadmin.local -p admin -q "add_policy -minlength 8 -minclasses 4 service"

  # Create a principle for the root user.
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
    kadmin.local -q "addprinc -policy user root"

  # Create a principle for the admin user.
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
    kadmin.local -q "addprinc -policy user admin"
fi

# Create a principal and keytab for the HOST service.
if [ -f /etc/krb5.keytab ]; then rm -f /etc/krb5.keytab; fi
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy host -randkey host/$FQDN"
while [ $? -ne 0 ]; do
  clear
  echo ""
  echo "Please wait for Kerberos admin server initialization."
  echo ""
  sleep 30
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy host -randkey host/$FQDN"
done
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/krb5.keytab host/$FQDN"

# Create a principal and keytab for the NFS service.
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy service -randkey nfs/$FQDN"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/krb5.keytab nfs/$FQDN"
while [ $? -ne 0 ]; do 
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/krb5.keytab nfs/$FQDN"
done

# Create a principal and keytab for the LDAP service.
if [ -f /etc/ldap/ldap.keytab ]; then rm -f /etc/ldap/ldap.keytab; fi
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy service -randkey ldap/$FQDN"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/ldap/ldap.keytab ldap/$FQDN"
while [ $? -ne 0 ]; do 
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/ldap/ldap.keytab ldap/$FQDN"
done
 
# Create a principal and keytab for the RADIUS service.
if [ -f /etc/freeradius/3.0/radius.keytab ]; then \
  rm -f /etc/freeradius/*.*/radius.keytab
fi
mkdir -p /etc/freeradius/3.0
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy service -randkey radius/$FQDN"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/freeradius/*.*/radius.keytab radius/$FQDN"
while [ $? -ne 0 ]; do 
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/freeradius/*.*/radius.keytab radius/$FQDN"
done

# Create a principal and keytab for the HTTP service.
if [ -f /etc/apache2/http.keytab ]; then rm -f /etc/apache2/http.keytab; fi
mkdir -p /etc/apache2
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy service -randkey http/$FQDN"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/apache2/http.keytab http/$FQDN"
while [ $? -ne 0 ]; do 
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/apache2/http.keytab http/$FQDN"
done

# Create a principal and keytab for the SMTP service.
if [ -f /etc/postfix/smtp.keytab ]; then rm -f /etc/postfix/smtp.keytab; fi
mkdir -p /etc/postfix
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy service -randkey smtp/$FQDN"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/postfix/smtp.keytab smtp/$FQDN"
while [ $? -ne 0 ]; do 
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/postfix/smtp.keytab smtp/$FQDN"
done

# Create a principal and keytab for the IMAP service.
if [ -f /etc/dovecot/imap.keytab ]; then rm -f /etc/dovecot/imap.keytab; fi
mkdir -p /etc/dovecot
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy service -randkey imap/$FQDN"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/dovecot/imap.keytab imap/$FQDN"
while [ $? -ne 0 ]; do 
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/dovecot/imap.keytab imap/$FQDN"
done

# Create a principal and keytab for the PostgreSQL service.
if [ -f "$POSTGRES_PATH"/main/postgres.keytab ]; then 
  rm -f "$POSTGRES_PATH"/main/postgres.keytab
fi
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy service -randkey postgres/$FQDN"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd \
    -k $POSTGRES_PATH/main/postgres.keytab postgres/$FQDN"
while [ $? -ne 0 ]; do 
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd \
    -k $POSTGRES_PATH/main/postgres.keytab postgres/$FQDN"
done

# Create a principal and keytab for the DHCP service.
if [ -f /etc/kea/dhcp.keytab ]; then rm -f /etc/kea/dhcp.keytab; fi
mkdir -p /etc/kea
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy service -randkey dhcp/$FQDN"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/kea/dhcp.keytab dhcp/$FQDN"
while [ $? -ne 0 ]; do
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/kea/dhcp.keytab dhcp/$FQDN"
done

# Create a principal and keytab for the DNS service.
if [ -f /etc/bind/dns.keytab ]; then rm -f /etc/bind/dns.keytab; fi
mkdir -p /etc/kea
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "addprinc -policy service -randkey dns/$FQDN"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/bind/dns.keytab dns/$FQDN"
while [ $? -ne 0 ]; do
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/bind/dns.keytab dns/$FQDN"
done

# Create the kadmind keytab.
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/krb5kdc/kadm5.keytab kadmin/admin"
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/krb5kdc/kadm5.keytab kadmin/changepw"
while [ $? -ne 0 ]; do 
  echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | \
  kadmin -p admin -q "ktadd -k /etc/krb5kdc/kadm5.keytab kadmin/changepw"
done

# Set permissions on krb5.keytab.
chmod 640 /etc/krb5.keytab
chown root:root /etc/krb5.keytab

# Set permissions on ldap.keytab.
chmod 640 /etc/ldap/ldap.keytab
chown root:openldap /etc/ldap/ldap.keytab

# Set permissions on http.keytab.
chmod 640 /etc/apache2/http.keytab
chown root:www-data /etc/apache2/http.keytab

# Set permissions on postgres.keytab.
chmod 640 "$POSTGRES_PATH"/main/postgres.keytab
chown root:postgres "$POSTGRES_PATH"/main/postgres.keytab

# Create smtpd.conf.
mkdir -p /etc/postfix/sasl
cat > /etc/postfix/sasl/smtpd.conf << EOF.smtpd.conf
pwcheck_method: saslauthd
mech_list: gssapi scram-sha-256-plus
keytab: /etc/postfix/smtp.keytab
EOF.smtpd.conf

# Create slapd.conf.
cat > /etc/ldap/sasl2/slapd.conf << EOF.slapd.conf
pwcheck_method: saslauthd
mech_list: gssapi
keytab: /etc/ldap/ldap.keytab
EOF.slapd.conf

# Update AppArmor's profiles.
if [ ! -f /etc/apparmor.d/abstractions/kerberosclient.orig ]; then 
  cp /etc/apparmor.d/abstractions/kerberosclient \
    /etc/apparmor.d/abstractions/kerberosclient.orig
fi
sed -i "s|/tmp/krb5cc\* r,|/tmp/krb5cc\* rk,|" \
  /etc/apparmor.d/abstractions/kerberosclient
grep -q "/etc/ldap/ldap.keytab" /etc/apparmor.d/abstractions/kerberosclient || \
  sed -i "/krb5.keytab/ a\  /etc/ldap/ldap.keytab\t\tr," \
    /etc/apparmor.d/abstractions/kerberosclient
if [ ! -f /etc/apparmor.d/usr.sbin.slapd.orig ]; then 
  cp /etc/apparmor.d/usr.sbin.slapd /etc/apparmor.d/usr.sbin.slapd.orig
fi
grep -q "#include <abstractions/kerberosclient>" \
  /etc/apparmor.d/usr.sbin.slapd || \
  sed -i "/# kerberos\/gssapi/ a\  #include <abstractions/kerberosclient>" \
    /etc/apparmor.d/usr.sbin.slapd
systemctl restart apparmor

# Kstart automatically renews Kerberos tickets.
k5start -b -u host/"$FQDN"@"$KERBEROS_REALM" -f /etc/krb5.keytab -K 10 -l 24h \
  -k /tmp/krb5cc_"$(grep root /etc/passwd | cut -d\: -f3)" -o root
k5start -b -u ldap/"$FQDN"@"$KERBEROS_REALM" -f /etc/ldap/ldap.keytab -K 10 \
  -l 24h -k /tmp/krb5cc_"$(grep openldap /etc/passwd | cut -d\: -f3)" -o openldap
cat > /etc/rc.local << EOF.rc.local
#!/bin/sh -e
k5start -b -U -f /etc/krb5.keytab -K 10 -l 24h\
 -k /tmp/krb5cc_$(grep root /etc/passwd | cut -d\: -f3) -o root
k5start -b -U -f /etc/ldap/ldap.keytab -K 10 -l 24h\
 -k /tmp/krb5cc_$(grep openldap /etc/passwd | cut -d\: -f3) -o openldap
exit 0
EOF.rc.local
cat > /etc/systemd/system/rc-local.service << EOF.rc-local.service
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF.rc-local.service
chmod +x /etc/rc.local
systemctl enable rc-local

################################################################################
#                                                                              #
# The following routine installs and configures SASL, the Simple               #
# Authentication and Security Layer, a framework for adding authentication and #
# data security to connection-based protocols.                                 #
#                                                                              #
# asg.web.cmu.edu/sasl                                                         #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing SASL."
echo ""

# Install SASL.
apt_function install $SASL

# Make the OpenLDAP user a member of the SASL group so that slapd can 
# communicate with saslauthd.
usermod -aG sasl openldap

# Create saslauthd.
if [ ! -f /etc/default/saslauthd.orig ]; then 
  cp /etc/default/saslauthd /etc/default/saslauthd.orig
fi
sed -i "s|START=no|START=yes|
  s|MECHANISMS=\"pam\"|MECHANISMS=\"kerberos5\"|" /etc/default/saslauthd

# SASL startup.
pgrep saslauthd > /dev/null
if [ $? -eq 1 ]; then
  systemctl start saslauthd
else
  systemctl restart saslauthd
fi

# Create sasl.ldif.
cat > /tmp/sasl.ldif << EOF.sasl.ldif
dn: olcDatabase=mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: uid=admin,cn=gssapi,cn=auth
-
delete: olcRootPW
EOF.sasl.ldif

# Modify OpenLDAP.
ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/sasl.ldif
rm -f /tmp/sasl.ldif

################################################################################
#                                                                              #
# The following routine installs and configures Bind DNS for your LAN and WAN. #
# BIND (Berkeley Internet Name Domain) is an implementation of the Domain Name #
# System (DNS) protocols and provides an openly redistributable reference      #
# implementation of the major components of the Domain Name System.            #
#                                                                              #
# isc.org/bind                                                                 #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Bind DNS."
echo ""

# Install Bind DNS.
apt_function install $BIND

# Configure named.conf.
if [ ! -f /etc/bind/named.conf.orig ]; then 
  mv /etc/bind/named.conf /etc/bind/named.conf.orig
fi
cat > /etc/bind/named.conf << EOF.named.conf
include "/etc/bind/zones.rfc1918";
include "/etc/bind/named.conf.log";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.default-zones";
EOF.named.conf

# Create named.conf.log.
cat > /etc/bind/named.conf.log << EOF.named.conf.log
logging {
  channel update_debug {
    file "/var/log/named/update_debug.log" versions 3 size 100k;
      severity debug;
      print-severity  yes;
      print-time      yes;
    };
    channel security_info {
      file "/var/log/named/security_info.log" versions 1 size 100k;
      severity info;
      print-severity  yes;
      print-time      yes;
    };
    channel bind_log {
    file "/var/log/named/bind.log" versions 3 size 1m;
      severity info;
      print-category  yes;
      print-severity  yes;
      print-time      yes;
    };

    category default { bind_log; };
    category lame-servers { null; };
    category update { update_debug; };
    category update-security { update_debug; };
    category security { security_info; };
};
EOF.named.conf.log
mkdir -p /var/log/named
chown bind /var/log/named

# Configure Logrotate.
cat > /etc/logrotate.d/bind << EOF.logrotate.d
/var/log/named/*.log {
  compress
  create 0644 named named
  daily
  dateext
  missingok
  notifempty
  rotate 30
  sharedscripts
  postrotate
    /usr/sbin/rndc reconfig > /dev/null 2>/dev/null || true
  endscript
}
EOF.logrotate.d

# Configure DNS forwarders.
NAMESERVERS=$(awk '/^nameserver/{ print $2 }' /etc/resolv.conf)
NS1=$(echo "$NAMESERVERS" | awk '{ print $1 }')
NS2=$(echo "$NAMESERVERS" | awk '{ print $2 }')
if [ -z "$NS2" ]; then
  NAMESERVERS="$NS1"
else
  NAMESERVERS="$NS1; $NS2"
fi

# Configure named.conf.options.
if [ ! -f /etc/bind/named.conf.options.orig ]; then 
  mv /etc/bind/named.conf.options /etc/bind/named.conf.options.orig
fi
cat > /etc/bind/named.conf.options << EOF.named.conf.options
options {
  directory "/var/cache/bind";
  forwarders { $NAMESERVERS; 208.67.222.222; 208.67.220.220; 208.67.222.220; \
208.67.220.222; 8.8.8.8; 8.8.4.4; };
  auth-nxdomain no;    # Conform to RFC1035.
  transfer-format many-answers;
  max-transfer-time-in 60;
  notify no;
  version "Not currently available.";
  dnssec-enable yes;
  dnssec-validation auto;
  dnssec-lookaside auto;
  tkey-gssapi-keytab "/etc/bind/dns.keytab";
};
EOF.named.conf.options

# Configure named.conf.local.
if [ ! -f /etc/bind/named.conf.local.orig ]; then 
  mv /etc/bind/named.conf.local /etc/bind/named.conf.local.orig
fi
if [ "$SERVER" = "pdc" ]; then
  DNS_TYPE="master"
  DNS_TRANSFER="grant "DNS/$FQDN@$KERBEROS_REALM" zonesub any"
  DNS_NOTIFY="$BDC_LAN_IP_ADDRESS"
else
  DNS_TYPE="slave"
  DNS_TRANSFER="grant "DNS/$FQDN@$KERBEROS_REALM" zonesub any"
  DNS_NOTIFY="$PDC_LAN_IP_ADDRESS"  
fi
cat > /etc/bind/named.conf.local << EOF.named.conf.local

zone "$LAN_DOMAIN" {
  type $DNS_TYPE;
  also-notify { $DNS_NOTIFY; };
  allow-transfer { $DNS_TRANSFER; };  
  update-policy {
    grant "DHCP/$FQDN@$KERBEROS_REALM" zonesub any;
  };
  file "/var/cache/bind/db.$LAN_DOMAIN.";
};

zone "$LAN_REVERSE_ZONE" {
  type $DNS_TYPE;
  also-notify { $DNS_NOTIFY; };
  allow-transfer { $DNS_TRANSFER; };
  update-policy {
    grant "DHCP/$FQDN@$KERBEROS_REALM" zonesub any;
  };
  file "/var/cache/bind/db.$LAN_REVERSE_ZONE.";
};

zone "$WAN_DOMAIN" {
  type $DNS_TYPE;
  also-notify { $DNS_NOTIFY; };
  allow-transfer { $DNS_TRANSFER; };
  file "/var/cache/bind/db.$WAN_DOMAIN.signed";
};

zone "$WAN_REVERSE_ZONE" {
  type $DNS_TYPE;
  also-notify { $DNS_NOTIFY; };
  allow-transfer { $DNS_TRANSFER; };
  file "/var/cache/bind/db.$WAN_REVERSE_ZONE.";
};
EOF.named.conf.local

# Add the masters notify option to the secondary DNS server.
grep -q "masters { $PDC_LAN_IP_ADDRESS; };" /etc/bind/named.conf.local || \
  sed -i "/type slave;/ a\    masters { $PDC_LAN_IP_ADDRESS; };" \
    /etc/bind/named.conf.local

# Create the forward LAN DNS zone.
cat << EOF.db.LAN_DOMAIN | column -t > /var/cache/bind/db."$LAN_DOMAIN".
\$TTL 3600
\$ORIGIN $LAN_DOMAIN.
@	IN	SOA	ns.$LAN_DOMAIN. hostmaster.$LAN_DOMAIN. (
			$(date +%Y%m%d00) ; Serialnumber
			900        ; refresh (15 minutes)
			900        ; retry (15 minutes)
			604800     ; expire (1 week)
			3600       ; minimum (1 hour)
			)
	IN	NS		ns.$LAN_DOMAIN.
$PDC	IN	A        $PDC_LAN_IP_ADDRESS
$BDC	IN	A        $BDC_LAN_IP_ADDRESS
ns	IN	A        $PDC_LAN_IP_ADDRESS
	IN	A        $BDC_LAN_IP_ADDRESS
ldap	IN	A        $PDC_LAN_IP_ADDRESS
	IN	A        $BDC_LAN_IP_ADDRESS
_ldap._tcp	IN	SRV		0 0 389 ldap
_kerberos._udp	IN	SRV		10 0 88 $PDC
	IN	SRV		20 0 88 $BDC
_kerberos-master._udp	IN	SRV		0 0 88 $PDC
_kerberos-adm._tcp	IN	SRV		0 0 749 $PDC
_kpasswd._udp	IN	SRV		0 0 464 $PDC
EOF.db.LAN_DOMAIN

# Create the reverse LAN DNS zone.
cat << EOF.db.LAN_REVERSE_ZONE | column -t > /var/cache/bind/db."$LAN_REVERSE_ZONE". 
\$TTL 3600
\$ORIGIN $LAN_REVERSE_ZONE.
@	IN	SOA	ns.$LAN_DOMAIN. hostmaster.$LAN_DOMAIN. (
			$(date +%Y%m%d00) ; Serialnumber
			900        ; refresh (15 minutes)
			900        ; retry (15 minutes)
			604800     ; expire (1 week)
			3600       ; minimum (1 hour)
			)
	IN	NS		ns.$LAN_DOMAIN.
$PDC_LAN_IP_ADDRESS_4TH_OCTET	IN	PTR		$PDC_FQDN.
	IN	PTR		ns.$LAN_DOMAIN.
	IN	PTR		ldap.$LAN_DOMAIN.
$BDC_LAN_IP_ADDRESS_4TH_OCTET	IN	PTR		$BDC_FQDN.
	IN	PTR		ns.$LAN_DOMAIN.
	IN	PTR		ldap.$LAN_DOMAIN.
EOF.db.LAN_REVERSE_ZONE

# Create the forward WAN DNS zone.
cat << EOF.db.WAN_DOMAIN | column -t > /var/cache/bind/db."$WAN_DOMAIN". 
\$TTL 30
\$ORIGIN $WAN_DOMAIN. 
@	IN	SOA	ns1.$WAN_DOMAIN. hostmaster.$WAN_DOMAIN. (
			$(date +%Y%m%d00) ; Serialnumber
			900        ; refresh (15 minutes)
			900        ; retry (15 minutes)
			604800     ; expire (1 week)
			30         ; minimum (30 sec)
			)
	IN	NS		ns1.$WAN_DOMAIN.
	IN	NS		ns2.$WAN_DOMAIN.
	IN	MX		10 mail.$WAN_DOMAIN.
ns1	IN	A		$PDC_WAN_IP_ADDRESS1
	IN	A		$PDC_WAN_IP_ADDRESS2
ns2	IN	A		$BDC_WAN_IP_ADDRESS1
	IN	A		$BDC_WAN_IP_ADDRESS2
ftp	IN	A		$PDC_WAN_IP_ADDRESS1
	IN	A		$PDC_WAN_IP_ADDRESS2
	IN	A		$BDC_WAN_IP_ADDRESS1
	IN	A		$BDC_WAN_IP_ADDRESS2
www	IN	A		$PDC_WAN_IP_ADDRESS1
	IN	A		$PDC_WAN_IP_ADDRESS2
	IN	A		$BDC_WAN_IP_ADDRESS1
	IN	A		$BDC_WAN_IP_ADDRESS2
mail	IN	A		$PDC_WAN_IP_ADDRESS1
	IN	A		$PDC_WAN_IP_ADDRESS2
	IN	A		$BDC_WAN_IP_ADDRESS1
	IN	A		$BDC_WAN_IP_ADDRESS2
EOF.db.WAN_DOMAIN

# Create the reverse WAN DNS zone.
cat << EOF.db.WAN_REVERSE_ZONE | column -t > /var/cache/bind/db."$WAN_REVERSE_ZONE". 
\$TTL 30
\$ORIGIN $WAN_REVERSE_ZONE.
@	IN	SOA	ns1.$WAN_DOMAIN. hostmaster.$WAN_DOMAIN. (
			$(date +%Y%m%d00) ; Serialnumber
			900        ; refresh (15 minutes)
			900        ; retry (15 minutes)
			604800     ; expire (1 week)
			30         ; minimum (30 sec)
			)
	IN	NS		ns1.$WAN_DOMAIN.
	IN	NS		ns2.$WAN_DOMAIN.
	IN	MX		10 mail.$WAN_DOMAIN.
$PDC_WAN_IP_ADDRESS1_4TH_OCTET	IN	PTR		ns1.$WAN_DOMAIN.
	IN	PTR		ftp.$WAN_DOMAIN.
	IN	PTR		www.$WAN_DOMAIN.
	IN	PTR		mail.$WAN_DOMAIN.
$PDC_WAN_IP_ADDRESS2_4TH_OCTET	IN	PTR		ns1.$WAN_DOMAIN.
	IN	PTR		ftp.$WAN_DOMAIN.
	IN	PTR		www.$WAN_DOMAIN.
	IN	PTR		mail.$WAN_DOMAIN.
$BDC_WAN_IP_ADDRESS1_4TH_OCTET	IN	PTR		ns2.$WAN_DOMAIN.
	IN	PTR		ftp.$WAN_DOMAIN.
	IN	PTR		www.$WAN_DOMAIN.
	IN	PTR		mail.$WAN_DOMAIN.
$BDC_WAN_IP_ADDRESS2_4TH_OCTET	IN	PTR		ns2.$WAN_DOMAIN.
	IN	PTR		ftp.$WAN_DOMAIN.
	IN	PTR		www.$WAN_DOMAIN.
	IN	PTR		mail.$WAN_DOMAIN.
EOF.db.WAN_REVERSE_ZONE

# Reload configuration.
systemctl restart bind9 

# Create DDNSSEC keys to protect the WAN zone.
zonesigner -genkeys -usensec3 -zone "$WAN_DOMAIN" \
  /var/cache/bind/db."$WAN_DOMAIN".
donuts --level 8 -v /var/cache/bind/db."$WAN_DOMAIN".signed "$WAN_DOMAIN"

# Bind's configuration has to be reloaded again for the signed zone.
systemctl restart bind9

################################################################################
#                                                                              #
# The following routine installs and configures Kea DHCP, a collection of      #
# software that implements all aspects of the DHCP (Dynamic Host Configuration #
# Protocol) suite.                                                             #
#                                                                              #
# isc.org/kea                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Kea DHCP Server."
echo ""

# Install the Kea DHCP Server.
apt_function install $KEA

# Configure the kea-api-password.
echo "$ADMIN_PASSWORD" > /etc/kea/kea-api-password

# Configure Kea's MariaDB database.
mysql --user=root --password="$ADMIN_PASSWORD" << EOF.kea
CREATE DATABASE kea;
CREATE USER 'kea'@'localhost' IDENTIFIED VIA mysql_native_password USING '$ADMIN_PASSWORD';
GRANT ALL ON `kea`.* TO 'kea'@'localhost';
FLUSH PRIVILEGES;
EOF.kea

# Use kea-admin to create the Kea database.
kea-admin db-init mysql -u kea -p "$ADMIN_PASSWORD" -n kea

# Configure kea-dhcp4.conf.
if [ ! -f /etc/kea/kea-dhcp4.conf.orig ]; then 
  mv /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf.orig
fi
cat > /etc/kea/kea-dhcp4.conf << EOF.kea-dhcp4.conf
{
  "Dhcp4": {
    "interfaces-config": {
      "interfaces": [ "$LAN_INTERFACE" ]
    },

    "control-socket": {
      "socket-type": "unix",
      "socket-name": "/run/kea/kea4-ctrl-socket"
    },

    "hooks-libraries": [{
      "library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so",
      "parameters": { }
    }, {
      "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
        "parameters": {
          "high-availability": [{
            "this-server-name": "$HOSTNAME",
            "mode": "load-balancing",
            "heartbeat-delay": 10000,
            "max-response-delay": 60000,
            "max-ack-delay": 5000,
            "max-unacked-clients": 5,
            "max-rejected-lease-updates": 10,
            "delayed-updates-limit": 100,
            "peers": [{
              "name": "$PDC",
              "url": "http://$PDC_LAN_IP_ADDRESS:8000/",
              "role": "primary",
              "auto-failover": true
            }, {
              "name": "$BDC",
              "url": "http://$BDC_LAN_IP_ADDRESS:8000/",
              "role": "secondary",
              "auto-failover": true
            }]
          }]
       }
    }],

    "subnet4": [{
      "id": 1,
      "subnet": "$LAN_NETWORK_ADDRESS/$CIDR",
      "pools": [{
        "pool": "$DHCP_HOST_MIN - $(( $DHCP_HOST_MAX / 2 ))",
        "client-class": "HA_server1"
      }, {
        "pool": "$(( $DHCP_HOST_MAX / 2 + 1 )) - $DHCP_HOST_MAX",
        "client-class": "HA_server2"
      }],

      "option-data": [{
        "name": "routers",
        "data": "$PDC_LAN_IP_ADDRESS,$BDC_LAN_IP_ADDRESS"
      }, {
        "name": "domain-name-servers",
        "data": "$PDC_LAN_IP_ADDRESS,$BDC_LAN_IP_ADDRESS"
      }],

      "reservations": [{
	"hw-address": "$(ssh $PDC_LAN_IP_ADDRESS "\$(ip addr show \$(ip link \
          | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}') | grep link/ether | awk '{ print $2 }')")",
	"ip-address": "$PDC_LAN_IP_ADDRESS"
      }, {
	"hw-address": "$(ssh $BDC_LAN_IP_ADDRESS "\$(ip addr show \$(ip link \
          | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}') | grep link/ether | awk '{ print $2 }')")",
        "ip-address": "$BDC_LAN_IP_ADDRESS"
      }],

      "relay": { "ip-address": "10.1.2.3" }
    }]
  }
}
EOF.kea-dhcp4.conf

# Configure kea-dhcp-ddns.conf.
if [ ! -f /etc/kea/kea-dhcp-ddns.conf.orig ]; then
  mv /etc/kea/kea-dhcp-ddns.conf /etc/kea/kea-dhcp-ddns.conf.orig
fi
cat > /etc/kea/kea-dhcp-ddns.conf << EOF.kea-dhcp-ddns.conf
{
  "DhcpDdns": {
    // The following parameters are used to receive NCRs (NameChangeRequests)
    // from the local Kea DHCP server. Make sure your kea-dhcp4 and kea-dhcp6
    // matches this.
    "ip-address": "127.0.0.1",
    "port": 53001,
    
    "control-socket": {
      "socket-type": "unix",
      "socket-name": "/run/kea/kea-ddns-ctrl-socket"
    },

    "dns-server-timeout" : 1000,

    // Logging configuration starts here. Kea uses different loggers to log various
    // activities. For details (e.g., names of loggers), see Chapter 18.
    "loggers": [{
      // This specifies the logging for the D2 (DHCP-DDNS) daemon.
      "name": "kea-dhcp-ddns",
      "output_options": [{
        // Specifies the output file. There are several special values
        // supported:
        // - stdout (prints on standard output)
        // - stderr (prints on standard error)
        // - syslog (logs to syslog)
        // - syslog:name (logs to syslog using specified name)
        // Any other value is considered the name of the file
        "output": "stdout",

        // Shorter log pattern suitable for use with systemd,
        // avoids redundant information
        "pattern": "%-5p %m\n"

        // This governs whether the log output is flushed to disk after
        // every write.
        // "flush": false,

        // This specifies the maximum size of the file before it is
        // rotated.
        // "maxsize": 1048576,

        // This specifies the maximum number of rotated files to keep.
        // "maxver": 8
      }],
        // This specifies the severity of log messages to keep. Supported values
        // are: FATAL, ERROR, WARN, INFO, DEBUG
        "severity": "INFO",

        // If DEBUG level is specified, this value is used. 0 is least verbose,
        // 99 is most verbose. Be cautious; Kea can generate lots and lots
        // of logs if told to do so.
        "debuglevel": 0
    }]
  
    // Forward zone: secure.example.org. It uses GSS-TSIG. It is served
    // by two DNS servers, which listen for DDNS requests at $PDC_LAN_IP_ADDRESS
    // and $BDC_LAN_IP_ADDRESS.
    "forward-ddns": {
      "ddns-domains": [{
        // DdnsDomain for zone "$LAN_DOMAIN."
        "name": "$LAN_DOMAIN.",
        "comment": "DdnsDomain",
        
        "dns-servers": [{ // This server has an entry in gss/servers and
                          // thus will use GSS-TSIG.
          "ip-address": "$PDC_LAN_IP_ADDRESS"
        }, { // This server also has an entry there, so will
             // use GSS-TSIG, too.
          "ip-address": "$BDC_LAN_IP_ADDRESS",
          "port": 5300
        }]
      }]
    },

    // Reverse zone: we want to update the reverse zone "$LAN_REVERSE_ZONE".
    "reverse-ddns": {
      "ddns-domains": [{
        "name": "$LAN_REVERSE_ZONE.",
        "dns-servers": [{
          // There is a GSS-TSIG definition for this server (see
          // DhcpDdns/gss-tsig/servers), so it will use
          // Krb/GSS-TSIG.
          "ip-address": "$PDC_LAN_IP_ADDRESS"
        }, {   // This server also has an entry there, so will
               // use GSS-TSIG, too.
          "ip-address": "$BDC_LAN_IP_ADDRESS",
          "port": 5300
        }]
      }]
    },

    // The GSS-TSIG hook is loaded, and its configuration is specified here.
    "hooks-libraries": [{
      "library": "/opt/lib/libddns_gss_tsig.so",
      "parameters": {
        // This section governs the GSS-TSIG integration. Each server
        // mentioned in forward-ddns and/or reverse-ddns needs to have
        // an entry here to be able to use GSS-TSIG defaults (optional,
        // if specified, they apply to all the GSS-TSIG servers, unless
        // overwritten on specific server level).

        "server-principal": "DNS/$FQDN@$KERBEROS_REALM",
        "client-principal": "DHCP/$FQDN@$KERBEROS_REALM",

        // client-keytab and credentials-cache can both be used to
        // store client keys. As the credentials cache is more flexible,
        // it is recommended to use it. Typically, using both at the
        // same time may cause problems.
        // "client-keytab": "FILE:/etc/kea/dhcp.keytab", // toplevel only
        "credentials-cache": "FILE:/etc/ccache", // toplevel only
        "gss-replay-flag": true, // GSS anti-replay service
        "gss-sequence-flag": false, // no GSS sequence service
        "tkey-lifetime": 3600, // 1 hour
        "rekey-interval": 2700, // 45 minutes
        "retry-interval": 120, // 2 minutes
        "tkey-protocol": "TCP",
        "fallback": false,

        // The list of GSS-TSIG capable servers
        "servers": [{
          // First server (identification is required)
          "id": "server1",
          "domain-names": [ ], // if not specified or empty, will
                               // match all domains that want to
                               // use this IP+port pair
          "ip-address": "$PDC_LAN_IP_ADDRESS",
          "port": 53,
          "server-principal": "DNS/$PDC_FQDN@$KERBEROS_REALM",
          "client-principal": "DHCP/$PDC_FQDN@$KERBEROS_REALM",
          "gss-replay-flag": false, // no GSS anti-replay service
          "gss-sequence-flag": false, // no GSS sequence service
          "tkey-lifetime": 7200, // 2 hours
          "rekey-interval": 5400, // 90 minutes
          "retry-interval": 240, // 4 minutes
          "tkey-protocol": "TCP",
          "fallback": true // if no key is available, fallback to the
                           // standard behavior (vs skip this server)
        }, {
          // The second server.
          "id": "server2",
          "ip-address": "$BDC_LAN_IP_ADDRESS",
          "port": 5300
          "server-principal": "DNS/$BDC_FQDN@$KERBEROS_REALM",
          "client-principal": "DHCP/$BDC_FQDN@$KERBEROS_REALM",
          "gss-replay-flag": false, // no GSS anti-replay service
          "gss-sequence-flag": false, // no GSS sequence service
          "tkey-lifetime": 7200, // 2 hours
          "rekey-interval": 5400, // 90 minutes
          "retry-interval": 240, // 4 minutes
          "tkey-protocol": "TCP",
          "fallback": true // if no key is available, fallback to the
                           // standard behavior (vs skip this server)
        }]
      }
    }]
  }
}
EOF.kea-dhcp-ddns.conf

# Reload configuration.
systemctl restart kea-dhcp4-server

################################################################################
#                                                                              #
# The following routine installs and configures FreeRADIUS, which allows one   #
# to set up a RADIUS protocol server, which can be used for authentication and #
# accounting for various types of network access.                              #
#                                                                              #
# freeradius.org                                                               #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing FreeRADIUS."
echo ""

# Install FreeRADIUS.
apt_function install $FREERADIUS

# Create radiusd.conf.
if [ ! -f /etc/freeradius/3.0/radiusd.conf.orig ]; then 
  cp /etc/freeradius/*.*/radiusd.conf /etc/freeradius/*.*/radiusd.conf.orig
fi
sed -i "s|ipaddr = \*|ipaddr = $LAN_IP_ADDRESS|" /etc/freeradius/*.*/radiusd.conf

# Create proxy.conf.
if [ ! -f /etc/freeradius/3.0/proxy.conf.orig ]; then 
  mv /etc/freeradius/*.*/proxy.conf /etc/freeradius/*.*/proxy.conf.orig
fi
cat > /etc/freeradius/*.*/proxy.conf << EOF.proxy
proxy server {
  default_fallback = no
}

home_server $PDC_FQDN {
  type = auth
  ipaddr = $PDC_LAN_IP_ADDRESS
  port = 1812
  secret = $ADMIN_PASSWORD
  require_message_authenticator = yes
  response_window = 20
  zombie_period = 40
  revive_interval = 120
  status_check = status-server
  check_interval = 30
  num_answers_to_alive = 3
  coa {
  irt = 2
  mrt = 16
  mrc = 5
  mrd = 30
  }
}

home_server $BDC_FQDN {
  type = auth
  ipaddr = $BDC_LAN_IP_ADDRESS
  port = 1812
  secret = $ADMIN_PASSWORD
  require_message_authenticator = yes
  response_window = 20
  zombie_period = 40
  revive_interval = 120
  status_check = status-server
  check_interval = 30
  num_answers_to_alive = 3
  coa {
  irt = 2
  mrt = 16
  mrc = 5
  mrd = 30
  }
}

home_server_pool my_auth_failover {
  type = fail-over
  home_server = $PDC_FQDN
  home_server = $BDC_FQDN
}

realm $LAN_DOMAIN {
  auth_pool = my_auth_failover
}
EOF.proxy
chmod 640 /etc/freeradius/*.*/proxy.conf
chown root:freerad /etc/freeradius/*.*/proxy.conf

# Create eap.conf.
if [ ! -f /etc/freeradius/3.0/mods-available/eap.org ]; then 
  cp /etc/freeradius/*.*/mods-available/eap /etc/freeradius/*.*/mods-available/eap.orig
fi
sed -i "0,/default_eap_type = md5/s||default_eap_type = ttls|" \
  /etc/freeradius/*.*/mods-available/eap
sed -i "s|private_key_password = .*$|private_key_password = $ADMIN_PASSWORD|
  s|private_key_file = .*$|private_key_file = /etc/ssl/private/tls-key.pem|
  s|certificate_file = .*$|certificate_file = /etc/ssl/certs/tls-cert.pem|
  s|CA_file = .*$|CA_file = /etc/ssl/certs/ca-bundle.pem|
  s|dh_file = .*$|dh_file = /etc/ssl/dh|
  s|CA_path = .*$|CA_path = /etc/ssl|
  s|default_eap_type = md5|default_eap_type = mschapv2|" \
    /etc/freeradius/*.*/mods-available/eap
chmod 640 /etc/freeradius/*.*/mods-available/eap
chown root:freerad /etc/freeradius/*.*/mods-available/eap

# Create clients.conf.
if [ ! -f /etc/freeradius/3.0/clients.conf.orig ]; then 
  mv /etc/freeradius/*.*/clients.conf /etc/freeradius/*.*/clients.conf.orig
fi
cat > /etc/freeradius/*.*/clients.conf << EOF.clients.conf
client localhost {
  ipaddr = 127.0.0.1
  secret = $ADMIN_PASSWORD
  shortname = localhost
}

client $LAN_NETWORK_ADDRESS/$CIDR {
  secret  = $ADMIN_PASSWORD
  shortname = private-network
}
EOF.clients.conf
chmod 640 /etc/freeradius/*.*/clients.conf
chown root:freerad /etc/freeradius/*.*/clients.conf

# Update users configuration.
grep -q "Kerberos" /etc/freeradius/*.*/mods-config/files/authorize || \
  echo "DEFAULT Auth-Type = Kerberos" >> /etc/freeradius/*.*/mods-config/files/authorize

# Configure the LDAP module.
if [ ! -f /etc/freeradius/3.0/mods-available/ldap.orig ]; then 
  cp /etc/freeradius/*.*/mods-available/ldap /etc/freeradius/*.*/mods-available/ldap.orig
fi
sed -i "s|server = .*$|server = \"ldapi:///\"|
  s|basedn = .*$|basedn = \"$LDAP_BASE_DN\"|
  s|filter = .*$|filter = \"(krbPrincipalName=%{User-Name})\"|
  s|start_tls = no|start_tls = yes|
  s|cacertfile.*$|cacertfile = /etc/ssl/certs/ca-bundle.pem|
  s|cacertdir.*$|cacertdir = /etc/ssl|
  s|certfile.*$|certfile = /etc/ssl/certs/tls-cert.pem|
  s|keyfile.*$|keyfile = /etc/ssl/private/tls-key.pem|
  s|randfile.*$|randfile = /dev/urandom|
  /# cacertfile/ s|^# ||
  /# cacertdir/ s|^# ||
  /# certfile/ s|^# ||
  /# keyfile/ s|^# ||
  /# randfile/ s|^# ||
  /# base_filter/ s|^# ||" /etc/freeradius/*.*/mods-available/ldap

# Create the MSCHAP module.
if [ ! -f /etc/freeradius/3.0/mods-available/mschap.orig ]; then 
  mv /etc/freeradius/*.*/mods-available/mschap /etc/freeradius/*.*/mods-available/mschap.orig
fi
cat > /etc/freeradius/*.*/mods-available/mschap << EOF.mschap
mschap {
  use_mppe = yes
  require_encryption = yes
  require_strong = yes
}
EOF.mschap

# Configure the Kerberos module.
if [ ! -f /etc/freeradius/3.0/mods-available/krb5.orig ]; then 
  cp /etc/freeradius/*.*/mods-available/krb5 /etc/freeradius/*.*/mods-available/krb5.orig
fi
sed -i "s|keytab = .*$|keytab = /etc/freeradius/*.*/radius.keytab|
  s|service_principal = .*$|service_principal = radius/$FQDN|" \
    /etc/freeradius/*.*/mods-available/krb5

# Set permissions on radius.keytab.
chmod 640 /etc/freeradius/*.*/radius.keytab
chown root:freerad /etc/freeradius/*.*/radius.keytab

# Set the Kerberos keytab path.
if [ ! -f /etc/default/freeradius.orig ]; then 
  cp /etc/default/freeradius /etc/default/freeradius.orig
fi
grep -q "KRB5_KTNAME" /etc/default/freeradius || \
cat >> /etc/default/freeradius << EOF.freeradius.default

# Kerberos keytab path.
export KRB5_KTNAME=/etc/freeradius/*.*/radius.keytab
EOF.freeradius.default

# Add the freerad user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert freerad

# Reload configuration.
systemctl restart freeradius

################################################################################
#                                                                              #
# The following routine installs and configures ProFTPD, a                     # 
# highly configurable, secure FTP server.                                      #
#                                                                              #
# proftpd.org                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing ProFTPD."
echo ""

# Install ProFTPD.
apt_function install $PROFTPD

# Configure proftpd.conf.
if [ ! -f /etc/proftpd/proftpd.conf.orig ]; then 
  cp /etc/proftpd/proftpd.conf /etc/proftpd/proftpd.conf.orig
fi
sed -ri "s|(ServerName\s+).+$|\1\"$FQDN\"|
  /ldap.conf/ s|^#||
  /tls.conf/ s|^#||
  s|(PersistenPasswd\s+).+$|\1on|" /etc/proftpd/proftpd.conf

# Configure tls.conf.
if [ ! -f /etc/proftpd/tls.conf.orig ]; then 
  cp /etc/proftpd/tls.conf /etc/proftpd/tls.conf.orig
fi
sed -ri "s|(TLSRSACerfificateFile\s+).+$|\1/etc/ssl/certs/tls-cert.pem|
  s|(TLSRSACerfificateKeyFile\s+).+$|\1/etc/ssl/certs/tls-key.pem|" \
    /etc/proftpd/tls.conf

# Configure ldap.conf.
if [ ! -f /etc/proftpd/ldap.conf.orig ]; then 
  cp /etc/proftpd/ldap.conf /etc/proftpd/ldap.conf.orig
fi
sed -i "/mod_ldap.c/ s|^#||" /etc/proftpd/modules.conf
sed -i "/LDAPServer/ c\LDAPServer ldapi:///
  /LDAPBindDN/ c\LDAPBindDN \"\" \"\"
  /LDAPUseTLS/ c\LDAPUseTLS on" /etc/proftpd/ldap.conf

# Reload configuration.
systemctl restart proftpd

################################################################################
#                                                                              #
# The following routine installs and configures Dovecot, an open-source IMAP   #
# and POP3 email server, written with security primarily in mind.              #
#                                                                              #
# dovecot.org                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Dovecot."
echo ""

# Install Dovecot.
apt_function install $DOVECOT

# Configure Vmail.
useradd -m -k "" -s /bin/false vmail
chmod 2770 /home/vmail

# Configure 10-auth.conf.
if [ ! -f /etc/dovecot/conf.d/10-auth.conf.orig ]; then 
  cp /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/conf.d/10-auth.conf.orig
fi
sed -i "/disable_plaintext_auth/ s|^#||
  /auth_default_realm/ c\auth_default_realm = $KERBEROS_REALM
  /auth_username_format/ c\auth_username_format = %u
  /auth_gssapi_hostname/ c\auth_gssapi_hostname = $FQDN
  /auth_krb5_keytab/ c\auth_krb5_keytab = /etc/dovecot/dovecot.keytab
  /auth_failure_delay/ s|^#||
  /auth_mechanisms/ c\auth_mechanisms = gssapi scram-sha-256-plus
  /!include auth-ldap.conf.ext/ s|^#||" /etc/dovecot/conf.d/10-auth.conf

# Configure 10-logging.conf.
if [ ! -f /etc/dovecot/conf.d/10-logging.conf.orig ]; then 
  cp /etc/dovecot/conf.d/10-logging.conf \
    /etc/dovecot/conf.d/10-logging.conf.orig
fi
sed -i "/log_path =/ c\log_path = /var/log/dovecot.log
  /info_log_path =/ c\info_log_path = /var/log/dovecot-info.log" \
    /etc/dovecot/conf.d/10-logging.conf
touch /var/log/{dovecot.log,dovecot-info.log}
chown /var/log/{dovecot.log,dovecot-info.log}

# Configure 10-mail.conf.
if [ ! -f /etc/dovecot/conf.d/10-mail.conf.orig ]; then 
  cp /etc/dovecot/conf.d/10-mail.conf /etc/dovecot/conf.d/10-mail.conf.orig
fi
sed -i "s|mail_location = mbox:~.*$|mail_location = maildir:/home/vmail/%h|
  /mail_uid =/ c\mail_uid = vmail
  /mail_gid =/ c\mail_gid = vmail
  /mail_plugins =/ c\mail_plugins = antispam fts quota
  /mailbox_list_index/ s|^#||
  /mailbox_idle_check_interval/ s|^#||
  /maildir_copy_with_hardlinks/ s|^#||" /etc/dovecot/conf.d/10-mail.conf

# Configure 10-master.conf.
if [ ! -f /etc/dovecot/conf.d/10-master.conf.orig ]; then 
  cp /etc/dovecot/conf.d/10-master.conf /etc/dovecot/conf.d/10-master.conf.orig
fi
cat > /etc/dovecot/conf.d/10-master.conf << EOF.10-master.conf
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service submission-login {
  inet_listener submission {
    port = 587
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service imap {
  process_limit = 1024
}

service pop3 {
  process_limit = 1024
}

service submission {
  process_limit = 1024
}

service auth {
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
    group = vmail
  }

  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

service auth-worker {
  user = vmail
}

service dict {
  unix_listener dict {
    mode = 0660
    user = vmail
    group = vmail
  }
}
EOF.10-master.conf

# Configure 10-ssl.conf.
if [ ! -f /etc/dovecot/conf.d/10-ssl.conf.orig ]; then 
  cp /etc/dovecot/conf.d/10-ssl.conf /etc/dovecot/conf.d/10-ssl.conf.orig
fi
sed -i "/ssl = yes/ s|#||
  /ssl_cert =/ c\ssl_cert = </etc/ssl/certs/tls-cert.pem
  /ssl_key =/ c\ssl_key = </etc/ssl/private/tls-key.pem
  /ssl_ca =/ c\ssl_ca = </etc/ssl/certs/ca-bundle.pem
  /ssl_require_crl =/ c\ssl_require_crl = yes" /etc/dovecot/conf.d/10-ssl.conf

# Configure 20-lmtp.conf.
if [ ! -f /etc/dovecot/conf.d/20-lmtp.conf.orig ]; then
  cp /etc/dovecot/conf.d/20-lmtp.conf.conf /etc/dovecot/conf.d/20-lmtp.conf.orig
fi
grep -q "postmaster_address" /etc/dovecot/conf.d/20-lmtp.conf || \
sed -i "/#mail_plugins = .*/ c\  mail_plugins = \$mail_plugins quota
  /mail_plugins/ a\  postmaster_address = postmaster@localhost" \
  /etc/dovecot/conf.d/20-lmtp.conf

# Configure 20-imap.conf.
if [ ! -f /etc/dovecot/conf.d/20-imap.conf.orig ]; then 
  cp /etc/dovecot/conf.d/20-imap.conf.conf /etc/dovecot/conf.d/20-imap.conf.orig
fi
sed -i "/mail_plugins/ s|^#||" /etc/dovecot/conf.d/20-imap.conf

# Configure 20-pop3.conf.
if [ ! -f /etc/dovecot/conf.d/20-pop3.conf.orig ]; then 
  cp /etc/dovecot/conf.d/20-pop3.conf /etc/dovecot/conf.d/20-pop3.conf.orig
fi
sed -i "/pop3-uidl_format =/ c\pop3-uidl_format = %g" \
  /etc/dovecot/conf.d/20-pop3.conf

# Configure 90-quota.conf.
if [ ! -f /etc/dovecot/conf.d/90-quota.conf.orig ]; then 
  cp /etc/dovecot/conf.d/90-quota.conf /etc/dovecot/conf.d/90-quota.conf.orig
fi
sed -i "/\*:storage=1G/ s|#||
  /storage=95%%/ s|#||
  /service quota-warning/ s|^#||
  /executable/ s|#||
  s|/usr/local/bin/quota-warning.sh|/usr/local/bin/quota-warning.sh|
  /user = dovecot/ s|#||
  /unix_listener/ s|#||
  /user = vmail/ s|#||
  /#  }/ s|#||
  /#}/ s|^#||" /etc/dovecot/conf.d/90-quota.conf

# Configure the quota warning.
cat > /usr/local/bin/quota-warning.sh << EOF.quota-warning.sh
#!/bin/sh
PERCENT=\$1
USER=\$2
cat << EOF | /usr/lib/dovecot/dovecot-lda -d \$USER \
-o \"plugin/quota=maildir:User quota:noenforcing\"
From: postmaster@localhost
Subject: Quota Warning

Your mailbox is now \$PERCENT% full.
EOF
EOF.quota-warning.sh
chmod 700 /usr/local/bin/quota-warning.sh

# Configure dovecot-ldap.conf.ext.
if [ ! -f /etc/dovecot/dovecot-ldap.conf.ext.orig ]; then 
  cp /etc/dovecot/dovecot-ldap.conf.ext /etc/dovecot/dovecot-ldap.conf.ext.orig
fi
sed -i "/uris =/ c\uris = ldapi:///
  /tls =/ c\tls = yes
  /tls_ca_cert_file =/ c\tls_ca_cert_file = /etc/ssl/certs/ca-bundle.pem
  /tls_require_cert =/ c\tls_require_cert = allow
  /auth_bind =/ c\auth_bind = yes
  /auth_bind_userdn =/ c\auth_bind_userdn = uid=%n,ou=people,$LDAP_BASE_DN
  /base =/ c\base = ou=people,$LDAP_BASE_DN
  /uid=user,userPassword=password,\\\/ s|#||
  /homeDirectory=userdb_home/ s|#||
  /iterate_attrs =/ s|#||" /etc/dovecot/dovecot-ldap.conf.ext

# Set permissions on imap.keytab.
chmod 640 /etc/dovecot/imap.keytab
chown root:dovecot /etc/dovecot/imap.keytab

# Add the Dovecot user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert dovecot

# Reload configuration.
systemctl restart dovecot

################################################################################
#                                                                              #
# The following routine installs and configures Postfix, a scalable, secure    #
# implementation of an SMTP Mail Transfer Agent.                               #
#                                                                              #
# postfix.org                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Postfix."
echo ""

# Install Postfix.
apt_function install $POSTFIX

# Change the mail server name.
echo "mail.$WAN_DOMAIN" > /etc/mailname

# Create main.cf.
if [ ! -f /etc/postfix/main.cf.orig ]; then 
  mv /etc/postfix/main.cf /etc/postfix/main.cf.orig
fi
cat > /etc/postfix/main.cf << EOF.main.cf
recipient_delimiter = +
strict_rfc821_envelopes = yes
myorigin = $mydomain
myhostname = mail.$WAN_DOMAIN
alias_maps = hash:/etc/aliases
canonical_maps = hash:/etc/postfix/canonical
relocated_maps = hash:/etc/postfix/relocated
transport_maps = hash:/etc/postfix/transport
mynetworks = 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR
mydestination = \$myhostname, $FQDN, localhost, localhost.$LAN_DOMAIN,\
 www.\$mydomain, ftp.\$mydomain

virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_gid_maps = static:vmail
virtual_uid_maps = static:vmail
virtual_mailbox_base = /home/vmail
dovecot_destination_recipient_limit = 1

smtpd_use_tls = yes
smtpd_tls_loglevel = 1
smtpd_tls_auth_only = yes
smtpd_tls_CAfile = /etc/ssl/certs/ca-bundle.pem
smtpd_tls_cert_file = /etc/ssl/certs/tls-cert.pem
smtpd_tls_key_file = /etc/ssl/private/tls-key.pem
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

smtpd_sender_login_maps=hash:/etc/postfix/virtual

smtpd_sasl_type = dovecot
smtpd_sasl_auth_enable = yes
smtpd_sasl_path = private/auth
smtpd_sasl_local_domain = \$myhostname
smtpd_sasl_security_options = noanonymous

smtpd_delay_reject = yes
smtpd_helo_required = yes
smtpd_helo_restrictions =
  permit_mynetworks,
  reject_non_fqdn_helo_hostname,
  reject_invalid_helo_hostname,
  permit
smtpd_sender_restrictions =
  permit_mynetworks,
  reject_non_fqdn_sender,
  reject_unknown_sender_domain,
  reject_sender_login_mismatch,
  permit
smtpd_recipient_restrictions =
  permit_mynetworks,
  permit_sasl_authenticated,
  reject_unauth_pipelining,
  reject_unauth_destination,
  reject_non_fqdn_recipient,
  reject_unverified_recipient,
  reject_unknown_sender_domain,
  reject_unknown_recipient_domain,
  check_client_access hash:/etc/postfix/access,
  check_policy_service unix:private/policyd-spf,
  check_policy_service inet:127.0.0.1:10023,
  permit
smtpd_data_restrictions =
  reject_unauth_pipelining,
  reject_multi_recipient_bounce
  permit
EOF.main.cf

# Update master.cf for Submission and SMTPS ports.
if [ ! -f /etc/postfix/master.cf.orig ]; then 
  cp /etc/postfix/master.cf /etc/postfix/master.cf.orig
fi
cat > /etc/postfix/master.cf << EOF.master.cf
smtp      inet  n       -       y       -       -       smtpd
  -o content_filter=amavis:[127.0.0.1]:10024
  -o receive_override_options=no_address_mappings
smtps     inet  n       -       n       -       2       smtpd
  -o smtpd_tls_wrappermode=yes
  -o content_filter=amavis:[127.0.0.1]:10024
  -o receive_override_options=no_address_mappings
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
  -o syslog_name=postfix/$service_name
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
maildrop  unix  -       n       n       -       -       pipe
  flags=DRXhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix -       n       n       -       2       pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FRX user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py ${nexthop} ${user
localhost:10025 inet n  -       n       -       2       smtpd
  -o smtp_dns_support_level=enabled
  -o content_filter=
  -o myhostname=mail.$WAN_DOMAIN
  -o local_recipient_maps=
  -o relay_recipient_maps=
  -o smtpd_restriction_classes=
  -o smtpd_client_restrictions=
  -o smtpd_helo_restrictions=
  -o smtpd_sender_restrictions=
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
  -o mynetworks=127.0.0.0/8
  -o strict_rfc821_envelopes=yes
  -o smtpd_error_sleep_time=0
  -o smtpd_soft_error_limit=1001
  -o smtpd_hard_error_limit=1000
  -o smtpd_client_connection_count_limit=0
  -o smtpd_client_connection_rate_limit=0
  -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
  -o smtpd_authorized_xforward_hosts=127.0.0.0/8
amavis    unix  -       -       n       -       2       lmtp
  -o disable_dns_lookups=yes
  -o lmtp_send_xforward_command=yes
  -o lmtp_data_done_timeout=1200
EOF.master.cf

# Create the root alias and update the local alias database.
if [ ! -f /etc/aliases.orig ]; then 
  cp /etc/aliases /etc/aliases.orig
fi
grep -q "root: $EMAIL_ADDRESS" /etc/aliases || \
  echo "root: $EMAIL_ADDRESS" >> /etc/aliases
newaliases

# Create relocated, transport, canonical, access, and address mapping 
# lookup tables.
touch /etc/postfix/{relocated,transport,canonical,access}
postmap /etc/postfix/{relocated,transport,canonical,access}

# Set permissions on smtp.keytab.
chmod 640 /etc/postfix/smtp.keytab
chown dovecot:postdrop /etc/postfix/smtp.keytab

# Set the Kerberos keytab path.
if [ ! -f /etc/default/postfix.orig ]; then 
  cp /etc/default/postfix /etc/default/postfix.orig
fi
echo "# Kerberos keytab path." > /etc/default/postfix
echo "export KRB5_KTNAME=/etc/postfix/smtp.keytab" >> /etc/default/postfix

# Add the Postfix user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert postfix

# Reload configuration.
systemctl restart postfix

################################################################################
#                                                                              #
# The following routine installs and configures OpenVPN, which implements      #
# virtual private network (VPN) techniques for creating secure point-to-point  #
# or site-to-site connections in routed or bridged configurations and remote   #
# access facilities.                                                           #
#                                                                              #
# openvpn.net                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing OpenVPN."
echo ""

# Install OpenVPN.
apt_function install $OPENVPN

# Create server.conf.
if [ "$SERVER" = "pdc" ]; then
  echo "server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
else
  echo "server 10.8.1.0 255.255.255.0" > /etc/openvpn/server/server.conf
fi
cat >> /etc/openvpn/server/server.conf << EOF.server.conf
topology subnet
port 1194
proto udp
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS $PDC_LAN_IP_ADDRESS"
push "dhcp-option DNS $BDC_LAN_IP_ADDRESS"
push "route $LAN_NETWORK_ADDRESS $LAN_NETMASK"
dev tun
persist-tun
crl-verify /etc/ssl/crl/crl.pem
dh /etc/ssl/dh
ca /etc/ssl/certs/ca-bundle.pem
cert /etc/ssl/certs/tls-cert.pem
key /etc/ssl/private/tls-key.pem
tls-auth /etc/ssl/private/ta.key 0
keepalive 10 120
user nobody
group nogroup
status openvpn-status.log
verb 3
explicit-exit-notify 1
EOF.server.conf

# Create the clientvpn script. 
# (Run this script to generate client configuration and TLS certificates 
# necessary to connect to your OpenVPN server.)
cat > /etc/openvpn/clientvpn << EOF.clientvpn
#!/bin/bash

# Create client.conf.
cat > /etc/openvpn/client/client.conf << EOF.client.conf
client
proto udp
dev tun
persist-tun
remote $PDC_WAN_IP_ADDRESS1 1194
remote $BDC_WAN_IP_ADDRESS1 1194
remote-random
resolv-retry infinite
nobind
ca ca-bundle.pem
cert client-cert.pem
key client-key.pem
tls-auth ta.key 1
remote-cert-tls server
user nobody
group nogroup
verb 3
mute-replay-warnings
EOF.client.conf

clear
echo ""
read -p "Type the FQDN of your client (e.g., or-ws1-ub.example.corp), \
followed by [ENTER]: " HOSTNAME

# Create the TLS certificate and key.
openssl req -new -nodes -keyout client-key.pem -out newreq.pem \
  -subj "/C=$COUNTRY/ST=$STATE/O=$ORGANIZATION/OU=TLS/CN=\$HOSTNAME/\
emailAddress=$EMAIL_ADDRESS"
openssl ca -batch -out newcert.pem -passin pass:$ADMIN_PASSWORD -infiles newreq.pem
mv newcert.pem client-cert.pem
rm -f newcert.pem newreq.pem

# Archive files to copy over to your client's OpenVPN directory.
cp -f /etc/ssl/certs/ca-bundle.pem /etc/ssl/private/ta.key ./
tar -czvf \$HOSTNAME.tar.gz ta.key ca-bundle.pem client-cert.pem \
  client-key.pem client.conf
rm -f client.conf ca-bundle.pem client-cert.pem client-key.pem ta.key
EOF.clientvpn
chmod 700 /etc/openvpn/clientvpn
chown root:root /etc/openvpn/clientvpn

# Add the nobody user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert nobody

# Create the shared-secret key.
openvpn --genkey secret /etc/ssl/private/ta.key
chmod 440 /etc/ssl/private/ta.key
chown nobody /etc/ssl/private/ta.key
chgrp ssl-cert /etc/ssl/private/ta.key

# OpenVPN startup.
pgrep openvpn > /dev/null
if [ $? -eq 1 ]; then
  systemctl start openvpn
else
  systemctl restart openvpn
fi

################################################################################
#                                                                              #
# The following routine installs and configures NFS (Network File System),     #
# which allows for fast, seamless sharing of files across a network.           #
#                                                                              #
# ietf.org/rfc/rfc3530.txt                                                     #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing NFS."
echo ""

# Install NFS.
apt_function install $NFS

# Add NFS exports.
if [ ! -f /etc/fstab.orig ]; then 
  cp /etc/fstab /etc/fstab.orig
fi
mkdir -p -m 770 /home/people
mkdir -p -m 777 /home/sharedDocs
mkdir -p /nfs/{people,sharedDocs}
cat > /etc/exports << EOF.exports
/nfs $LAN_NETWORK_ADDRESS/$CIDR(rw)
/nfs gss/krb5(rw,sec=krb5p)
/nfs/people $LAN_NETWORK_ADDRESS/$CIDR(rw)
/nfs/people gss/krb5(rw,sec=krb5p)
/nfs/sharedDocs $LAN_NETWORK_ADDRESS/$CIDR(rw)
/nfs/sharedDocs gss/krb5(rw,sec=krb5p)
EOF.exports
mount --bind /home/people /nfs/people
mount --bind /home/sharedDocs /nfs/sharedDocs
grep -q "/home/people" /etc/fstab || \
  echo "/home/people /nfs/people none bind 0 0" >> /etc/fstab
grep -q "/home/sharedDocs" /etc/fstab || \
  echo "/home/sharedDocs /nfs/sharedDocs none bind 0 0" >> /etc/fstab
exportfs -a

# Configure idmapd.conf.
if [ ! -f /etc/idmapd.conf.orig ]; then 
  cp /etc/idmapd.conf /etc/idmapd.conf.orig
fi
sed -i "s|Domain = .*$|Domain = $LAN_DOMAIN|" /etc/idmapd.conf

# Configure nfs-kernel-server.
if [ ! -f /etc/default/nfs-kernel-server.orig ]; then 
  cp /etc/default/nfs-kernel-server /etc/default/nfs-kernel-server.orig
fi
sed -i "s|RPCMOUNTDOPTS=.*$|RPCMOUNTDOPTS=\"--manage-gids --port 4002\"|
  s|NEED_SVCGSSD=.*$|NEED_SVCGSSD=yes|" /etc/default/nfs-kernel-server

# nfs-kernel-server startup.
pgrep nfsd > /dev/null
if [ $? -eq 1 ]; then
  systemctl start nfs-kernel-server
else
  systemctl restart nfs-kernel-server
fi

################################################################################
#                                                                              #
# The following routine installs and configures FAI, a non-interactive system  #
# to install, customize, and manage Linux systems and software configurations  #
# on computers, as well as virtual machines and chroot environments, from      #
# small networks to large-scale infrastructures and clusters.                  #
#                                                                              #
# fai-project.org                                                              #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing FAI."
echo ""

# Install FAI.
apt_function install $FAI

# Configure fai.conf.
if [ ! -f /etc/fai/fai.conf.orig ]; then 
  cp /etc/fai/fai.conf /etc/fai/fai.conf.orig
fi
sed -i "s|LOGUSER=|LOGUSER=fai|" /etc/fai/fai.conf

# Configure make-fai-nfsroot.conf.
if [ ! -f /etc/fai/make-fai-nfsroot.conf.orig ]; then 
  cp /etc/fai/make-fai-nfsroot.conf /etc/fai/make-fai-nfsroot.conf.orig
fi
sed -i "s|FAI_ROOTPW=.*$|FAI_ROOTPW='$(openssl passwd -1 "$ADMIN_PASSWORD")'|
  s|FAI_DEBOOTSTRAP=.*$|FAI_DEBOOTSTRAP=\"$OS_RELEASE $LAN_IP_ADDRESS/ubuntu\"|" \
    /etc/fai/make-fai-nfsroot.conf

# Create sources.list.
cat > /etc/fai/apt/sources.list << EOF.fai.sources.list
deb $LAN_IP_ADDRESS/ubuntu $OS_RELEASE main restricted universe multiverse
deb $LAN_IP_ADDRESS/ubuntu $OS_RELEASE-updates main restricted universe multiverse
deb $LAN_IP_ADDRESS/ubuntu $OS_RELEASE-security main restricted universe multiverse
deb https://download.jitsi.org/deb stable
deb http://download.videolan.org/pub/debian/stable /
EOF.fai.sources.list

# Run the fai-setup script.
fai-setup -v
while [ $? -ne 0 ]; do fai-setup -v; done

# Make the sample configuration space.
fai-mk-configspace

# Create the local Ubuntu mirror.
cat > /usr/local/bin/debmirror.sh << EOF.debmirror.sh
debmirror --host=$UBUNTU_MIRROR --root-ubuntu --method=http \
  --dist=$OS_RELEASE,$OS_RELEASE-updates,$OS_RELEASE-security \
  --section=main,restricted,universe,multiverse \
  --keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg \
  --state-cache-days=7 /var/www/html/ubuntu
EOF.debmirror.sh
chmod 700 /usr/local/bin/debmirror.sh
echo "@daily root /usr/local/bin/debmirror.sh" > /etc/cron.d/debmirror

################################################################################
#                                                                              #
# The following routine installs and configures the Linux Terminal Server      #
# Project (LTSP), which adds thin-client support to Linux servers. LTSP is a   #
# flexible, cost-effective solution that is empowering schools, businesses,    #
# and organizations all over the world to easily install and deploy desktop    #
# workstations.                                                                #
#                                                                              #
# ltsp.org                                                                     #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing LTSP."
echo ""

# Install LTSP.
apt_function install $LTSP

# Install ltsp.conf.
install -m 660 -g sudo /usr/share/ltsp/common/ltsp/ltsp.conf /etc/ltsp/ltsp.conf

# Install ltsp-dnsmasq.conf.
ltsp dnsmasq --real-dhcp=0 --dns-server="0.0.0.0"

# Install iPXE binaries and configuration.
ltsp ipxe

# Configure NFS exports.
ltsp nfs

# Create the ltsp.img initrd add-on.
mkdir -p /etc/ltsp/bin
cp /usr/bin/sshfs /etc/ltsp/bin/sshfs-"$(uname -m)"
ltsp initrd

# Add admin user to epoptes group.
gpasswd -a admin epoptes

# Create a SquashFS image from a virtual machine.
ln -fs "$LTSP_VM_PATH" /srv/ltsp/ubuntu.img
ltsp image ubuntu

################################################################################
#                                                                              #
# The following routine installs and configures Privoxy, Squid, and            #
# SquidClamAV.                                                                 #
#                                                                              #
# Privoxy filters unwanted advertisements and internet junk that suck up       #
# precious bandwidth.                                                          #
#                                                                              #
# Squid creates a cache of frequently accessed web pages, which improves       #
# performance and helps conserve bandwidth.                                    #
#                                                                              #
# SquidClamAV stops malware before it reaches your workstations.               #
#                                                                              #
# privoxy.org                                                                  #
# squid-cache.org                                                              #
# squidclamav.darold.net/index.html                                            #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Proxy."
echo ""

# Install Proxy.
apt_function install $PROXY

# Configure squid.conf.
if [ ! -f /etc/squid/squid.conf.orig ]; then 
  cp /etc/squid/squid.conf /etc/squid/squid.conf.orig
fi
sed -i "s|#acl localnet src 192.168.0.0/16\
|acl localnet src $LAN_NETWORK_ADDRESS/$CIDR|
  /http_access allow localnet/ s|^#||" /etc/squid/squid.conf

# Configure add-on.conf.
cat > /etc/squid/conf.d/add-on.conf << EOF.add-on.conf
# SquidClamAV configuration.
url_rewrite_children $(nproc --all)
url_rewrite_access allow all
icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_encode off
icap_client_username_header X-Authenticated-User
icap_preview_enable on
icap_preview_size 1024
icap_service service_req reqmod_precache bypass=1 icap://127.0.0.1:1344\
/squidclamav
adaptation_access service_req allow all
icap_service service_resp respmod_precache bypass=1 icap://127.0.0.1:1344\
/squidclamav
adaptation_access service_resp allow all

# Define Privoxy as the parent proxy (without ICP).
cache_peer 127.0.0.1 parent 8118 7 no-query

# Define ACL for protocol FTP.
acl ftp proto FTP

# Do not forward FTP requests to Privoxy.
always_direct allow ftp

# Forward all the rest to Privoxy.
never_direct allow all
EOF.add-on.conf

# Create Squid's cache directories.
systemctl stop squid
squid -z
systemctl start squid

# Install SquidClamAV.
apt_function install $SQUIDCLAMAV_DEPENDS
cd /usr/local/src
if [ -d squidclamav ]; then rm -rf squidclamav; fi
git_function $SQUIDCLAMAV
cd squidclamav
sh configure --prefix=/usr --sysconfdir=/etc --datadir=/usr/share --with-c-icap
make && make install
cd ..
rm -rf squidclamav

# Configure squidclamav.conf.
if [ ! -f /etc/c-icap/squidclamav.conf.orig ]; then 
  cp /etc/c-icap/squidclamav.conf /etc/c-icap/squidclamav.conf.orig
fi
sed -i "s|redirect http://.*$|redirect http://$LAN_IP_ADDRESS/cgi-bin/clwarn.cgi|
  s|safebrowsing 0|safebrowsing 1|" /etc/c-icap/squidclamav.conf

# Configure c-icap.conf.
if [ ! -f /etc/c-icap/c-icap.conf.orig ]; then 
  cp /etc/c-icap/c-icap.conf /etc/c-icap/c-icap.conf.orig
fi
sed -i "s|ServerAdmin .*$|ServerAdmin $EMAIL_ADDRESS|
  s|ServerName YourServerName|ServerName $FQDN|" /etc/c-icap/c-icap.conf
grep -q "# Enable SquidClamAV" /etc/c-icap/c-icap.conf || \
cat >> /etc/c-icap/c-icap.conf << EOF.c-icap.conf

# Enable SquidClamAV.
Service squidclamav squidclamav.so
EOF.c-icap.conf

# Set up clwarn.cgi.
chgrp www-data /usr/lib/cgi-bin
cp -f /usr/libexec/squidclamav/clwarn.cgi.en_EN /usr/lib/cgi-bin/clwarn.cgi

# Configure Privoxy's configuration.
if [ ! -f /etc/privoxy/config.orig ]; then 
  cp /etc/privoxy/config /etc/privoxy/config.orig
fi
sed -i "s|#admin-address .*$|admin-address $EMAIL_ADDRESS|
  s|enable-proxy-authentication-forwarding 0\
|enable-proxy-authentication-forwarding 1|" /etc/privoxy/config
chown privoxy /etc/privoxy/*.action

# Configure Privoxy's match-all.action.
if [ ! -f /etc/privoxy/match-all.action.orig ]; then 
  cp /etc/privoxy/match-all.action /etc/privoxy/match-all.action.orig
fi
sed -i "s|+set-image-blocker{pattern}|+set-image-blocker{blank}|" \
  /etc/privoxy/match-all.action

# Add the proxy user to the www-data group so the daemon can read the http.keytab.
usermod -aG proxy www-data

# Reload configuration.
systemctl restart apache2
systemctl restart privoxy

# c-icap startup.
sed -i "s|START=no|START=yes|" /etc/default/c-icap
pgrep c-icap > /dev/null
if [ $? -eq 1 ]; then
  systemctl start c-icap
else
  systemctl restart c-icap
fi

################################################################################
#                                                                              #
# The following routine installs and configures Nagios, a powerful monitoring  #
# system that enables organizations to identify and resolve IT infrastructure  #
# problems before they affect critical business processes.                     #
#                                                                              #
# nagios.org                                                                   #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Nagios."
echo ""

# Install Nagios.
apt_function install $NAGIOS

# Backup the original configuration to prepare for the new custom configuration.
mv -u /etc/nagios4/conf.d /etc/nagios4/conf.d.orig
mkdir -p /etc/nagios4/conf.d

# Configure authentication.
if [ ! -f /etc/nagios4/cgi.cfg.orig ]; then 
  cp /etc/nagios4/cgi.cfg /etc/nagios4/cgi.cfg.orig
fi
sed -i "s|use_ssl_authentication=0|use_ssl_authentication=1|
  s|authorized_for_system_information.*$\
|authorized_for_system_information=admin|
  s|use_authentication=1|use_authentication=0|" /etc/nagios4/cgi.cfg

# Configure hosts.cfg.
cat > /etc/nagios4/conf.d/hosts.cfg << EOF.hosts.cfg
define host {
  host_name              $PDC
  alias                  Primary Domain Controller
  address                $PDC_LAN_IP_ADDRESS
  max_check_attempts	  5
  check_period           24x7
  check_command          check_host_status
  contacts               root
  contact_groups         admins
  notification_interval  30
  notification_period    24x7
}

define host {
  host_name              $BDC
  alias                  Backup Domain Controller
  address                $BDC_LAN_IP_ADDRESS
  max_check_attempts	  5
  check_period           24x7
  check_command          check_host_status 
  contacts               root
  contact_groups         admins
  notification_interval  30
  notification_period    24x7
}
EOF.hosts.cfg

# Configure hostgroups.cfg.
cat > /etc/nagios4/conf.d/hostgroups.cfg << EOF.hostgroups.cfg
# A list of your Ubuntu Linux servers.
define hostgroup {
  hostgroup_name  ubuntu-servers
  alias           Ubuntu Linux Servers
  members         $PDC,$BDC
}
EOF.hostgroups.cfg

# Configure extinfo.cfg.
cat > /etc/nagios4/conf.d/extinfo.cfg << EOF.extinfo.cfg
define hostextinfo {
# Extended Host and Service Information.
  notes            Ubuntu Linux servers
  icon_image       base/Ubuntu.png
  icon_image_alt   Ubuntu Linux
  vrml_image       ubuntu.png
  statusmap_image  base/ubuntu.gd2
}
EOF.extinfo.cfg

# Configure check_commands.cfg.
chmod u+s  /usr/lib/nagios/plugins/check_dhcp # Must be run as setuid root.
chmod u+s  /usr/lib/nagios/plugins/check_host 
cat > /etc/nagios4/conf.d/check_commands.cfg << EOF.check_commands.cfg
define command {
  command_name check_cluster_host
  command_line /usr/lib/nagios/plugins/check_cluster \
--host -l \$ARG1\$ -w \$ARG2\$ -c \$ARG3\$ -d \$ARG4\$
}

define command {
  command_name check_cluster_service
  command_line /usr/lib/nagios/plugins/check_cluster \
--service -l \$ARG1\$ -w \$ARG2\$ -c \$ARG3\$ -d \$ARG4\$
}

define command {
  command_name check_host_status
  command_line /usr/lib/nagios/plugins/check_host -H 127.0.0.1
}

define command {
  command_name check_ldap_status
  command_line /usr/lib/nagios/plugins/check_ldap \
-T -H 127.0.0.1 -b \$ARG1\$
}

define command {
  command_name check_dhcp_status
  command_line /usr/lib/nagios/plugins/check_dhcp -i $LAN_INTERFACE
}

define command {
  command_name check_dns_status
  command_line /usr/lib/nagios/plugins/check_dns -H 127.0.0.1
}

define command {
  command_name check_imap_status
  command_line /usr/lib/nagios/plugins/check_imap -H 127.0.0.1
}

define command {
  command_name check_mysql_status
  command_line /usr/lib/nagios/plugins/check_mysql -H localhost -u \$ARG1\$ \
-p \$ARG2\$
}

define command {
  command_name check_pgsql_status
  command_line /usr/lib/nagios/plugins/check_pgsql -l \$ARG1\$
}

define command {
  command_name check_smtp_status
  command_line /usr/lib/nagios/plugins/check_smtp -H 127.0.0.1
}

define command {
  command_name check_nagios_status
  command_line /usr/lib/nagios/plugins/check_nagios \
-e \$ARG1\$ -F \$ARG2\$ -C \$ARG3\$
}
EOF.check_commands.cfg

# Configure services.cfg.
cat > /etc/nagios4/conf.d/services.cfg << EOF.services.cfg
# Check that the Host service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    Host Service
  check_command          check_host_status
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the DNS service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    DNS Service
  check_command          check_dns_status
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the DHCP service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    DHCP Service
  check_command          check_dhcp_status
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the FTP service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    FTP Service
  check_command          check_ftp
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the Apache service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    HTTP Service
  check_command          check_http
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the IMAP service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    IMAP Service
  check_command          check_imap_status
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the LDAP service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    LDAP Service
  check_command          check_ldap_status!$LDAP_BASE_DN
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the MariaDB service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    MariaDB Service
  check_command          check_mysql_status!root!$ADMIN_PASSWORD
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the PostgreSQL service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    PostgreSQL Service
  check_command          check_pgsql_status!nagios
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the SMTP service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    SMTP Service
  check_command          check_smtp_status
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the Nagios service is running.
define service {
  hostgroup_name         ubuntu-servers
  service_description    Nagios Service
  check_command          check_nagios_status!5!/var/log/nagios4/nagios.log\
!/usr/sbin/nagios4
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}
EOF.services.cfg
chmod 600 /etc/nagios4/conf.d/services.cfg
chown nagios /etc/nagios4/conf.d/services.cfg

# Configure cluster_hosts.cfg.
cat > /etc/nagios4/conf.d/cluster_hosts.cfg << EOF.cluster_hosts.cfg
define service {
  service_description    Cluster Hosts
  check_command          check_cluster_host!1:2!2:3\
!\$HOSTSTATEID:$PDC\$,\$HOSTSTATEID:$BDC\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}
EOF.cluster_hosts.cfg

# Configure cluster_services.cfg.
cat > /etc/nagios4/conf.d/cluster_services.cfg << EOF.cluster_services.cfg
define service {
  service_description    DNS Service
  check_command	        check_cluster_service!1:2!2:3\
!\$SERVICESTATEID:$PDC:DNS Service Check\$,\$SERVICESTATEID:$BDC\
:DNS Service Check\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}

define service {
  service_description    FTP Service
  check_command	        check_cluster_service!1:2!2:3\
!\$SERVICESTATEID:$PDC:FTP Service Check\$,\$SERVICESTATEID:$BDC\
:FTP Service Check\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}

define service {
  service_description    HTTP Service
  check_command	        check_cluster_service!1:2!2:3\
!\$SERVICESTATEID:$PDC:HTTP Service Check\$,\$SERVICESTATEID:$BDC\
:HTTP Service Check\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}

define service {
  service_description    IMAP Service
  check_command	        check_cluster_service!1:2!2:3\
!\$SERVICESTATEID:$PDC:IMAP Service Check\$,\$SERVICESTATEID:$BDC\
:IMAP Service Check\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}

define service {
  service_description    LDAP Service
  check_command	        check_cluster_service!1:2!2:3\
!\$SERVICESTATEID:$PDC:LDAP Service Check\$,\$SERVICESTATEID:$BDC\
:LDAP Service Check\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}

define service {
  service_description    MariaDB Service
  check_command	        check_cluster_service!1:2!2:3\
!\$SERVICESTATEID:$PDC:MYSQL Service Check\$,\$SERVICESTATEID:$BDC\
:MYSQL Service Check\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}

define service {
  service_description    PostgreSQL Service
  check_command	        check_cluster_service!1:2!2:3\
!\$SERVICESTATEID:$PDC:POSTGRESQL Service Check\$,\$SERVICESTATEID:$BDC\
:POSTGRESQL Service Check\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}

define service {
  service_description    SMTP Service
  check_command	        check_cluster_service!1:2!2:3\
!\$SERVICESTATEID:$PDC:SMTP Service Check\$,\$SERVICESTATEID:$BDC\
:SMTP Service Check\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}

define service {
  service_description    Nagios Service
  check_command	        check_cluster_service!1:2!2:3\
!\$SERVICESTATEID:$PDC:Nagios Service Check\$,\$SERVICESTATEID:$BDC\
:Nagios Service Check\$
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins
}
EOF.cluster_services.cfg

# Configure contacts.cfg.
cat > /etc/nagios4/objects/contacts.cfg << EOF.contacts.cfg
define contact {
  host_notifications_enabled     1
  service_notifications_enabled  1
  contact_name                   root
  service_notification_period    24x7
  host_notification_period       24x7
  service_notification_options   w,u,c,r
  host_notification_options      d,r
  service_notification_commands  notify-service-by-email
  host_notification_commands     notify-host-by-email
  email                          root@localhost
}

define contactgroup {
  contactgroup_name  admins
  alias              Nagios Administrators
  members            root
}
EOF.contacts.cfg

# Update apache2.conf.
if [ ! -f /etc/nagios4/apache2.conf.orig ]; then
  cp /etc/nagios4/apache2.conf /etc/nagios4/apache2.conf.orig
fi
grep -q "AuthType GSSAPI" /etc/nagios4/apache2.conf || \
sed -i "/AuthDigestDomain/d
  /AuthDigestProvider/d
  /AuthUserFile/d
  /AuthGroupFile/d
  /AuthName/d
  /AuthType/d
  /Require all/d
  /#Require/d
  /Require ip/ c\    Require ip 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR
  /AllowOverride/ a\    <RequireAll>\n\
    SSLRequireSSL\n\
    AuthName \"Nagios Login\"\n\
    AuthType GSSAPI\n\
    GssapiBasicAuth On\n\
    GssapiLocalName On\n\
    GssapiCredStore /etc/apache2/http.keytab\n\
    Require valid-user
  </RequireAll>" /etc/nagios4/apache2.conf
ln -fs /etc/nagios4/apache2.conf /etc/apache2/conf-available/nagios4-cgi.conf

# Reload configuration.
systemctl restart nagios4
systemctl restart apache2

################################################################################
#                                                                              #
# The following routine installs and configures Munin, a networked resource    #
# monitoring tool that can help analyze resource trends and performance        #
# problems.                                                                    #
#                                                                              #
# munin-monitoring.org                                                         #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Munin."
echo ""

# Install Munin.
apt_function install $MUNIN

# Install plugins.
rm -f /etc/munin/plugins/*
ln -fs /usr/share/munin/plugins/load /etc/munin/plugins
ln -fs /usr/share/munin/plugins/memory /etc/munin/plugins
ln -fs /usr/share/munin/plugins/cpu* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/diskstat* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/smart* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/fw* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/tcp /etc/munin/plugins
ln -fs /usr/share/munin/plugins/apache* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/amavis /etc/munin/plugins
ln -fs /usr/share/munin/plugins/bind* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/freeradius* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/postgres* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/mysql* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/nfsd* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/openvpn /etc/munin/plugins
ln -fs /usr/share/munin/plugins/postfix* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/snort* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/slapd* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/squid* /etc/munin/plugins

# Configure munin.conf.
if [ ! -f /etc/munin/munin.conf.orig ]; then 
  cp /etc/munin/munin.conf /etc/munin/munin.conf.orig
fi
sed -i "s|\[localhost.localdomain\]|\[$FQDN\]|
  s|address 127.0.0.1|address $LAN_IP_ADDRESS|" /etc/munin/munin.conf

# Configure munin-node.conf.
if [ ! -f /etc/munin/munin-node.conf.orig ]; then 
  cp /etc/munin/munin-node.conf /etc/munin/munin-node.conf.orig
fi
sed -i "s|# cidr_allow 192.*$|cidr_allow $LAN_NETWORK_ADDRESS/$CIDR|
  s|#host_name localhost.localdomain|host_name $FQDN|
  s|host \*|host $LAN_IP_ADDRESS|" /etc/munin/munin-node.conf

# Update apache24.conf.
if [ ! -f /etc/munin/apache24.conf.orig ]; then
  cp /etc/munin/apache24.conf /etc/munin/apache24.conf.orig
fi
grep -q "AuthType GSSAPI" /etc/munin/apache24.conf || \
sed -i "0,/Require local/{//d}
    /<Directory \/var\/cache\/munin\/www>/ a\<RequireAll>\n\
    SSLRequireSSL\n\
    Require ip 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR
    AuthName \"Munin Login\"\n\
    AuthType GSSAPI\n\
    GssapiBasicAuth On\n\
    GssapiLocalName On\n\
    GssapiCredStore /etc/apache2/http.keytab\n\
    Require valid-user\n\
</RequireAll>" /etc/munin/apache24.conf

# Reload configuration.
systemctl restart apache2
systemctl restart munin-node

################################################################################
#                                                                              #
# The following routine installs and configures Snort, which provides an       #
# open-source network intrusion detection and prevention system capable of     #
# performing real-time traffic analysis and packet logging on IP networks.     #
#                                                                              #
# snort.org                                                                    #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Snort."
echo ""

# Install Snort.
apt_function install $SNORT

# Configure Snort's MariaDB database.
mysql --user=root --password="$ADMIN_PASSWORD" << EOF.snortdb
DROP DATABASE IF EXISTS snortdb;
CREATE DATABASE snortdb;
CREATE USER 'snort'@'localhost' IDENTIFIED VIA mysql_native_password USING '$ADMIN_PASSWORD';
GRANT CREATE,INSERT,SELECT,DELETE,UPDATE ON `snortdb`.* TO 'snort'@'localhost';
FLUSH PRIVILEGES;
EOF.snortdb

# Configure snort.debian.conf.
if [ ! -f /etc/snort/snort.debian.conf.orig ]; then 
  cp /etc/snort/snort.debian.conf /etc/snort/snort.debian.conf.orig
fi
sed -i "s|DEBIAN_SNORT_HOME_NET=.*$\
|DEBIAN_SNORT_HOME_NET=\"$LAN_NETWORK_ADDRESS/$CIDR\"|
  s|DEBIAN_SNORT_INTERFACE=.*$\
|DEBIAN_SNORT_INTERFACE=\"$LAN_INTERFACE $WAN_INTERFACE1 $WAN_INTERFACE2\"|" \
    /etc/snort/snort.debian.conf

# Remove the pending Snort database configuration file.
rm -rf /etc/snort/db-pending-config

# Configure oinkmaster.conf.
if [ ! -f /etc/oinkmaster.conf.orig ]; then 
  cp /etc/oinkmaster.conf /etc/oinkmaster.conf.orig
fi
sed -i "/Community-Rules-CURRENT.tar.gz/ s|^# ||" /etc/oinkmaster.conf

# Create the Oinkmaster cron job.
echo "@daily root oinkmaster -o /etc/snort/rules \
-b /etc/snort/backup 2>&1 | logger -t oinkmaster" > \
  /etc/cron.d/oinkmaster_updater

# Reload configuration.
systemctl restart snort

################################################################################
#                                                                              #
# The following routine installs and configures Webmin, a web-based interface  #
# for system administration. Using any browser that supports tables and forms  #
# (and Java for the File Manager module), you can set up user accounts,        #
# Apache, DNS, file sharing, and so on.                                        #
#                                                                              #
# webmin.com                                                                   #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Webmin."
echo ""

# Install Webmin.
apt_function install $WEBMIN

# Configure miniserv.conf.
if [ ! -f /etc/webmin/miniserv.conf.orig ]; then 
  cp /etc/webmin/miniserv.conf /etc/webmin/miniserv.conf.orig
fi
sed -i "s|keyfile=/etc/webmin/miniserv.pem\
|keyfile=/etc/ssl/private/tls-key.pem|" /etc/webmin/miniserv.conf
grep -q "certfile" /etc/webmin/miniserv.conf || \
  sed -i "/keyfile=/ \
a\certfile=/etc/ssl/certs/tls-cert.pem\nssl_redirect=1" \
    /etc/webmin/miniserv.conf
grep -q "allow=127.0.0.1 LOCAL" /etc/webmin/miniserv.conf || \
  echo "allow=127.0.0.1 LOCAL" >> /etc/webmin/miniserv.conf

# Configure miniserv.users.
echo "admin:x:0::::::::" > /etc/webmin/miniserv.users

# Configure Stunnel.
if [ ! -f /etc/webmin/config.orig ]; then 
  cp /etc/webmin/config /etc/webmin/config.orig
fi
sed -i "/stunnel_path=/ c\stunnel_path=/usr/bin/stunnel4
  /pem_path=/ c\pem_path=/etc/ssl/certs/tls-cert.pem" /etc/webmin/config
sed -i "s|ENABLED=0|ENABLED=1|" /etc/default/stunnel4
cp /usr/share/doc/stunnel4/examples/stunnel.conf-sample \
  /etc/stunnel/stunnel.conf
if [ ! -f /etc/stunnel/stunnel.conf.orig ]; then 
  cp /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.conf.orig
fi
sed -i "/cert =/ c\cert = /etc/ssl/certs/tls-cert.pem
  /key =/ c\key = /etc/ssl/private/tls-key.pem
  /CAfile =/ c\CAfile = /etc/ssl/certs/ca-bundle.pem
  /CRLfile =/ c\CRLfile = /etc/ssl/crl/crl.pem" /etc/stunnel/stunnel.conf

# Set administrator password for Webmin.
webmin passwd --user admin --password $ADMIN_PASSWORD

# Set the administrator password for MariaDB.
if [ ! -f /etc/webmin/mysql/config.orig ]; then 
  cp /etc/webmin/mysql/config /etc/webmin/mysql/config.orig
fi
grep -q "pass=$ADMIN_PASSWORD" /etc/webmin/mysql/config || \
  echo "pass=$ADMIN_PASSWORD" >> /etc/webmin/mysql/config
chmod 600 /etc/webmin/mysql/config

# Configure admin.acl.
cat > /etc/webmin/admin.acl << EOF.admin.acl
rpc=2
nodot=0
webminsearch=1
uedit_mode=0
gedit_mode=0
feedback=2
otherdirs=
readonly=0
fileunix=root
uedit=
negative=0
root=/
uedit2=
gedit=
gedit2=
EOF.admin.acl

# Configure webmin.acl.
echo "admin: backup-config change-user webmincron usermin webminlog webmin \
servers acl init passwd quota mount fsdump ldap-client \
ldap-useradmin logrotate mailcap pam proc at cron package-updates software man \
syslog system-status useradmin security-updates apache bind8 dovecot \
ldap-server mysql postfix postgresql procmail mailboxes sshd spam squid \
sarg virtual-server webalizer bandwidth krb5 exports net inetd pap stunnel \
shorewall tcpwrappers idmapd filter burner grub raid lvm fdisk lpadmin \
smart-status time cluster-passwd cluster-copy cluster-cron cluster-shell \
cluster-software cluster-usermin cluster-useradmin cluster-webmin shell custom \
file tunnel phpini cpan htaccess-htpasswd telnet status ajaxterm updown proftpd" \
> /etc/webmin/webmin.acl

# Configure installed.cache.
cat > /etc/webmin/installed.cache << EOF.installed.cache
custom=1
procmail=1
cpan=1
qmailadmin=0
cluster-software=1
cluster-webmin=1
cluster-shell=1
majordomo=0
ipsec=0
sshd=1
ldap-server=1
lvm=1
useradmin=1
ldap-client=1
status=1
inetd=1
cluster-usermin=1
system-status=1
heartbeat=0
acl=1
htaccess-htpasswd=1
bind8=1
lpadmin=1
file=1
vgetty=0
proc=1
exports=1
webmincron=1
mysql=1
cluster-cron=1
apache=1
telnet=1
cluster-passwd=1
postgresql=1
ppp-client=0
webminlog=1
shell=1
sarg=1
syslog-ng=0
backup-config=1
pptp-server=0
exim=0
stunnel=1
iscsi-target=0
xinetd=0
adsl-client=0
change-user=1
raid=1
pap=1
syslog=1
usermin=1
webmin=1
bandwidth=1
cluster-useradmin=1
servers=1
fetchmail=0
postfix=1
pptp-client=0
samba=0
net=1
at=1
grub=1
firewall=1
pserver=0
tcpwrappers=1
time=1
mon=1
wuftpd=0
package-updates=1
filter=1
krb5=1
tunnel=1
openslp=0
sendmail=0
fsdump=1
fail2ban=0
mailcap=1
ldap-useradmin=1
man=1
init=1
ajaxterm=1
burner=1
webalizer=1
logrotate=1
fdisk=1
idmapd=1
shorewall6=0
software=1
lilo=0
mailboxes=1
cfengine=0
passwd=1
iscsi-tgtd=0
quota=1
phpini=1
frox=0
mount=1
sentry=0
nis=1
jabber=0
iscsi-server=0
proftpd=1
dovecot=1
shorewall=1
spam=1
updown=1
pam=1
dhcpd=0
smart-status=1
cron=1
iscsi-client=1
squid=1
cluster-copy=1
virtualmin-awstats=0
security-updates=1
virtual-server=1
EOF.installed.cache

# Add the Stunnel4 user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert stunnel4

# Reload configuration.
systemctl restart webmin
systemctl restart stunnel4
systemctl restart apache2

################################################################################
#                                                                              #
# The following routine installs and configures Open-Xchange, an easy-to-use   #
# email, communication, and collaboration platform.                            #
#                                                                              #
# open-xchange.com                                                             #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Open-Xchange."
echo ""

# This "wait state" is necessary to prevent installation conflict between 
# PDC and BDC. This conflict is only a problem when using a GFS or OCFS 
# active/active mirror.
if [ -d /var/www/appsuite ]; then
  RESULTS=$(find /var/www/appsuite -name '*.dpkg-new')
  while [ ! -z "$RESULTS" ]; do
    clear
    echo ""
    echo "Please wait for Open-Xchange installation initialization."
    echo ""
    sleep 30
    RESULTS=$(find /var/www/appsuite -name '*.dpkg-new')
  done
fi

# Bug workaround for open-xchange-munin-scripts.
systemctl stop munin-node

# Install Open-Xchange.
apt_function install $OPENXCHANGE

# Create the Open-Xchange user on each cluster node.
mysql --user=root --password="$ADMIN_PASSWORD" << EOF.openxchange_user
CREATE USER 'openexchange'@'$PDC_LAN_IP_ADDRESS' IDENTIFIED VIA mysql_native_password USING '$ADMIN_PASSWORD';
CREATE USER 'openexchange'@'$BDC_LAN_IP_ADDRESS' IDENTIFIED VIA mysql_native_password USING '$ADMIN_PASSWORD';
GRANT ALL PRIVILEGES ON *.* TO 'openexchange'@'$PDC_LAN_IP_ADDRESS';
GRANT ALL PRIVILEGES ON *.* TO 'openexchange'@'$BDC_LAN_IP_ADDRESS';
FLUSH PRIVILEGES;
EOF.openxchange_user

# Create the configdb database at the MariaDB Master.
if [ "$SERVER" = "pdc" ]; then
  /opt/open-xchange/sbin/initconfigdb -i --configdb-pass="$ADMIN_PASSWORD" \
    --configdb-host=$PDC_LAN_IP_ADDRESS 
fi

# Run oxinstaller.
if [ "$SERVER" = "pdc" ]; then
  /opt/open-xchange/sbin/oxinstaller --servername=oxserver \
    --configdb-readhost=$LAN_IP_ADDRESS --configdb-writehost=$LAN_IP_ADDRESS \
    --master-pass="$ADMIN_PASSWORD" --configdb-pass="$ADMIN_PASSWORD" --jkroute=OX1 \
    --no-license --network-listener-host=* \
    --servermemory "$(echo "$(grep MemTotal /proc/meminfo | \
      awk '{ print $2 }')" / 1000 / 2 | bc)"
else
  sleep 30 # PDC has to register the database first.
  /opt/open-xchange/sbin/oxinstaller --servername=oxserver \
    --configdb-readhost=$LAN_IP_ADDRESS --configdb-writehost=$LAN_IP_ADDRESS \
    --master-pass="$ADMIN_PASSWORD" --configdb-pass="$ADMIN_PASSWORD" --jkroute=OX2 \
    --no-license --network-listener-host=* \
    --servermemory "$(echo "$(grep MemTotal /proc/meminfo | \
      awk '{ print $2 }')" / 1000 / 2 | bc)"
  while [ $? -ne 0 ]; do
    clear
    echo ""    
    echo "Please wait for database registration."
    echo ""
    sleep 30
    /opt/open-xchange/sbin/oxinstaller --servername=oxserver \
      --configdb-readhost=$LAN_IP_ADDRESS --configdb-writehost=$LAN_IP_ADDRESS \
      --master-pass="$ADMIN_PASSWORD" --configdb-pass="$ADMIN_PASSWORD" --jkroute=OX2 \
      --no-license --network-listener-host=* \
      --servermemory "$(echo "$(grep MemTotal /proc/meminfo | \
        awk '{ print $2 }')" / 1000 / 2 | bc)"
  done
fi

# Start the daemon.
systemctl start open-xchange
# Sleep state is necessary to avoid "Error: Connection refused to host."
sleep 15 

if [ "$SERVER" = "pdc" ]; then # Start the register database conditional IF statement.
  # Register the Open-Xchange server at the database.
  /opt/open-xchange/sbin/registerserver -n oxserver -A oxadminmaster \
    -P "$ADMIN_PASSWORD"
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Please wait until the Open-Xchange administration daemon is online."
    echo ""
    sleep 30
    /opt/open-xchange/sbin/registerserver -n oxserver -A oxadminmaster \
      -P "$ADMIN_PASSWORD"
  done  

  # Register the filestore.
  mkdir -p /home/open-xchange/filestore
  chown -R open-xchange:open-xchange /home/open-xchange/filestore
  /opt/open-xchange/sbin/registerfilestore -A oxadminmaster -P "$ADMIN_PASSWORD" \
    -t file:///home/open-xchange/filestore

  # Register the MariaDB master database in configdb.
  DATABASE_ID=$(/opt/open-xchange/sbin/registerdatabase -A oxadminmaster \
    -P "$ADMIN_PASSWORD" --name oxdatabase --hostname $PDC_LAN_IP_ADDRESS \
    --dbuser openexchange --dbpasswd "$ADMIN_PASSWORD" \
    --master true | awk '{ print $2 }')
  if [ -z "$DATABASE_ID" ]; then
    /opt/open-xchange/sbin/unregisterdatabase -A oxadminmaster \
      -P "$ADMIN_PASSWORD" --name oxdatabase
    DATABASE_ID=$(/opt/open-xchange/sbin/registerdatabase -A oxadminmaster \
      -P "$ADMIN_PASSWORD" --name oxdatabase --hostname $PDC_LAN_IP_ADDRESS \
      --dbuser openexchange --dbpasswd "$ADMIN_PASSWORD" \
      --master true | awk '{ print $2 }')
  fi

  # Register the MariaDB slave database in configdb.
  /opt/open-xchange/sbin/registerdatabase -A oxadminmaster -P "$ADMIN_PASSWORD" \
    --name oxdatabase_slave --hostname $BDC_LAN_IP_ADDRESS --dbuser openexchange \
    --dbpasswd "$ADMIN_PASSWORD" --master false --masterid="$DATABASE_ID"
  if [ $? -ne 0 ]; then
    /opt/open-xchange/sbin/unregisterdatabase -A oxadminmaster \
      -P "$ADMIN_PASSWORD" --name oxdatabase_slave
    /opt/open-xchange/sbin/registerdatabase -A oxadminmaster -P "$ADMIN_PASSWORD" \
      --name oxdatabase_slave --hostname $BDC_LAN_IP_ADDRESS --dbuser openexchange \
      --dbpasswd "$ADMIN_PASSWORD" --master false --masterid="$DATABASE_ID"
  fi
fi # End the register database conditional IF statement.

# Configure configdb.properties.
if [ ! -f /opt/open-xchange/etc/configdb.properties.orig ]; then 
  cp /opt/open-xchange/etc/configdb.properties \
    /opt/open-xchange/etc/configdb.properties.orig
fi
sed -i "s|readUrl=.*$|readUrl=jdbc:mysql://$PDC_LAN_IP_ADDRESS/configdb|
  s|writeUrl=.*$|writeUrl=jdbc:mysql://$PDC_LAN_IP_ADDRESS/configdb|
  s|readProperty.2=password=secret|readProperty.2=password=$ADMIN_PASSWORD|
  s|writeProperty.2=password=secret|writeProperty.2=password=$ADMIN_PASSWORD|" \
    /opt/open-xchange/etc/configdb.properties
chmod 640 /opt/open-xchange/etc/configdb.properties
chown root:open-xchange /opt/open-xchange/etc/configdb.properties

# Configure filestorage.properties.
if [ ! -f /opt/open-xchange/etc/filestorage.properties.orig ]; then 
  cp /opt/open-xchange/etc/filestorage.properties \
    /opt/open-xchange/etc/filestorage.properties.orig
fi
sed -i "/com.openexchange.file.storage/ s|^# ||
  s|http://your-webdav-server|http://$FQDN|" \
    /opt/open-xchange/etc/filestorage.properties

# Configure hazelcast.properties.
if [ ! -f /opt/open-xchange/etc/hazelcast.properties.orig ]; then 
  cp /opt/open-xchange/etc/hazelcast.properties \
    /opt/open-xchange/etc/hazelcast.properties.orig
fi
sed -i "/group.name=/ c\com.openexchange.hazelcast.group.name=LinuxHA
  /group.password=/ c\com.openexchange.hazelcast.group.password\
=$(openssl passwd -1 "$ADMIN_PASSWORD")
  /network.join=/ c\com.openexchange.hazelcast.network.join=static
  /join.static.nodes=/ c\com.openexchange.hazelcast.network.join.static.nodes=\
$PDC_LAN_IP_ADDRESS, $BDC_LAN_IP_ADDRESS
  /network.interfaces/ c\com.openexchange.hazelcast.network.interfaces\
=$LAN_IP_ADDRESS" /opt/open-xchange/etc/hazelcast.properties
chmod 640 /opt/open-xchange/etc/hazelcast.properties

# Configure imapauth.properties.
if [ -f /opt/open-xchange/etc/imapauth.properties ]; then
  if [ ! -f /opt/open-xchange/etc/imapauth.properties.orig ]; then 
    cp /opt/open-xchange/etc/imapauth.properties \
      /opt/open-xchange/etc/imapauth.properties.orig
  fi
  sed -i "/IMAP_PORT/ c\IMAP_PORT=993
    /USE_SECURE/ c\IMAP_USE_SECURE=true|
    /USE_FULL_LOGIN_INFO/ c\USE_FULL_LOGIN_INFO=false" \
      /opt/open-xchange/etc/imapauth.properties
  chown root:open-xchange /opt/open-xchange/etc/imapauth.properties
fi

# Configure ldapauth.properties.
if [ -f /opt/open-xchange/etc/ldapauth.properties ]; then 
  if [ ! -f /opt/open-xchange/etc/ldapauth.properties.orig ]; then 
    cp /opt/open-xchange/etc/ldapauth.properties \
      /opt/open-xchange/etc/ldapauth.properties.orig
  fi
  sed -i "s|dc=com|dc=corp|
    /provider.url=/ c\java.naming.provider.url=ldapi:///
    /baseDN=ou=Users/ c\baseDN=ou=people,$LDAP_BASE_DN" \
      /opt/open-xchange/etc/ldapauth.properties
fi

# Configure mail.properties.
if [ ! -f /opt/open-xchange/etc/mail.properties.orig ]; then 
  cp /opt/open-xchange/etc/mail.properties \
    /opt/open-xchange/etc/mail.properties.orig
fi
sed -i "/mail.loginSource/ c\com.openxchange.mail.loginSource=mail" \
  /opt/open-xchange/etc/mail.properties

# Configure rmi.properties.
if [ ! -f /opt/open-xchange/etc/rmi.properties.orig ]; then 
  cp /opt/open-xchange/etc/rmi.properties \
    /opt/open-xchange/etc/rmi.properties.orig
fi
sed -i "/rmi.host =/ c\com.openexchange.rmi.host = 0" \
  /opt/open-xchange/etc/rmi.properties

# Configure server.properties.
if [ ! -f /opt/open-xchange/etc/server.properties.orig ]; then 
  cp /opt/open-xchange/etc/server.properties \
    /opt/open-xchange/etc/server.properties.orig
fi
sed -i "/forceHTTPS=/ c\com.openexchange.forceHTTPS=true" \
  /opt/open-xchange/etc/server.properties

# Configure kerberosLogin.conf.
if [ -f /opt/open-xchange/etc/kerberosLogin.conf ]; then 
  if [ ! -f /opt/open-xchange/etc/kerberosLogin.conf.orig ]; then 
    cp /opt/open-xchange/etc/kerberosLogin.conf \
      /opt/open-xchange/etc/kerberosLogin.conf.orig
  fi
  sed -i "/principal=/ c\principal=\"http/$FQDN@$KERBEROS_REALM\"
    /debug=/ c\debug=true
    /keyTab=/ c\keyTab=\"/etc/apache2/http.keytab\"" \
      /opt/open-xchange/etc/kerberosLogin.conf
fi   

# Configure kerberos.properties.
sed -i "/kr5.debug=/ c\sun.security.kr5.debug=true" \
  /opt/open-xchange/etc/kerberos.properties

# Symlink to krb5.conf.
ln -fs /etc/krb5.conf /opt/open-xchange/etc/krb5.conf

# Set permissions on http.keytab.
chown open-xchange:www-data /etc/apache2/http.keytab

# Configure proxy_http.conf.
zcat -qf /usr/share/doc/open-xchange-core/examples/proxy_http.conf.gz > \
  /etc/apache2/conf-available/proxy_http.conf
sed -i "s|http://localhost|http://$PDC_FQDN|
  s|http://localhost|http://$BDC_FQDN|
  s|http://localhost|http://$PDC_FQDN|
  s|http://localhost|http://$BDC_FQDN|" /etc/apache2/conf-available/proxy_http.conf
a2enconf proxy_http.conf

# Add Open-Xchange Appsuite alias to 000-default.conf.
cat > /tmp/000-default.conf << EOF.000-default.conf

	Alias /appsuite /var/www/html/appsuite
	<Directory /var/www/html/appsuite>
	  Options None +SymLinksIfOwnerMatch
	  AllowOverride Indexes FileInfo
	</Directory>
EOF.000-default.conf
grep -q "appsuite" /etc/apache2/sites-available/000-default.conf || \
  sed -i "/Include conf-available/r /tmp/000-default.conf" \
    /etc/apache2/sites-available/000-default.conf

# Add Open-Xchange Appsuite alias to default-ssl.conf.
cat > /tmp/default-ssl.conf << EOF.default-ssl.conf

		Alias /appsuite /var/www/html/appsuite
		<Directory /var/www/html/appsuite>
		  Options None +SymLinksIfOwnerMatch
		  AllowOverride Indexes FileInfo
		</Directory>

		RequestHeader set X-Forwarded-Proto "https"
EOF.default-ssl.conf
grep -q "appsuite" /etc/apache2/sites-available/default-ssl.conf || \
  sed -i "/<\/Directory>/r /tmp/default-ssl.conf" \
    /etc/apache2/sites-available/default-ssl.conf

# Add ox.$WAN_DOMAIN VirtualHost.
cp /etc/apache2/sites-available/000-default.conf \
  /etc/apache2/sites-available/ox."$WAN_DOMAIN".conf
sed -i "s|<VirtualHost \*:80>|<VirtualHost ox.$WAN_DOMAIN:80>|
  s|ServerName $FQDN|ServerName ox.$WAN_DOMAIN|
  s|DocumentRoot /var/www/html|DocumentRoot /var/www|" \
    /etc/apache2/sites-available/ox."$WAN_DOMAIN".conf
cat > /tmp/ox."$WAN_DOMAIN".conf << EOF.ox.$WAN_DOMAIN.conf

	<Directory /var/www/>
	  Options Indexes FollowSymLinks MultiViews
	  AllowOverride None
	  Require all granted
	  RedirectMatch ^/$ /appsuite/
	</Directory>

	<Directory /var/www/appsuite>
	  Options None +SymLinksIfOwnerMatch
	  AllowOverride Indexes FileInfo
	</Directory>
EOF.ox.$WAN_DOMAIN.conf
grep -q "appsuite" /etc/apache2/sites-available/ox."$WAN_DOMAIN".conf || \
  sed -i "/<\/Directory>/r /tmp/ox.$WAN_DOMAIN.conf" \
    /etc/apache2/sites-available/ox."$WAN_DOMAIN".conf
a2ensite ox."$WAN_DOMAIN"

# Add ox.$WAN_DOMAIN-ssl VirtualHost.
cp /etc/apache2/sites-available/default-ssl.conf \
  /etc/apache2/sites-available/ox."$WAN_DOMAIN"-ssl.conf
sed -i "s|<VirtualHost _default_:443>|<VirtualHost ox.$WAN_DOMAIN:443>|
  s|DocumentRoot /var/www/html|DocumentRoot /var/www|
  s|ServerName $FQDN|ServerName ox.$WAN_DOMAIN|" \
    /etc/apache2/sites-available/ox."$WAN_DOMAIN"-ssl.conf
cat > /tmp/ox."$WAN_DOMAIN"-ssl.conf << EOF.ox.$WAN_DOMAIN-ssl.conf

		<Directory /var/www/>
		  Options Indexes FollowSymLinks MultiViews
		  AllowOverride None
		  Require all granted
		  RedirectMatch ^/$ /appsuite/
		</Directory>

		<Directory /var/www/appsuite>
		  Options None +SymLinksIfOwnerMatch
		  AllowOverride Indexes FileInfo
		</Directory>

		RequestHeader set X-Forwarded-Proto "https"
EOF.ox.$WAN_DOMAIN-ssl.conf
grep -q "appsuite" /etc/apache2/sites-available/ox."$WAN_DOMAIN"-ssl.conf || \
  sed -i "/<\/Directory>/r /tmp/ox.$WAN_DOMAIN-ssl.conf" \
    /etc/apache2/sites-available/ox."$WAN_DOMAIN"-ssl.conf
a2ensite ox."$WAN_DOMAIN"-ssl

# Bug workaround for open-xchange-munin-scripts.
systemctl start munin-node

# Reload configuration.
systemctl restart apache2
systemctl restart open-xchange

# Create a new context.
if [ "$SERVER" = "pdc" ]; then
  /opt/open-xchange/sbin/createcontext -c 1 -A oxadminmaster -P "$ADMIN_PASSWORD" \
    -u admin -d "Context Admin" -g Admin -s User -p "$ADMIN_PASSWORD" \
    -L defaultcontext -e $EMAIL_ADDRESS -q 1024 --access-combination-name=all
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Please wait until Open-Xchange is fully started."
    echo ""
    sleep 60
    /opt/open-xchange/sbin/createcontext -c 1 -A oxadminmaster \
      -P "$ADMIN_PASSWORD" -u admin -d "Context Admin" -g Admin -s User \
      -p "$ADMIN_PASSWORD" -L defaultcontext -e $EMAIL_ADDRESS -q 1024 \
      --access-combination-name=all
  done
fi

# Create the web-access menu.
cat > /var/www/html/index.html << EOF.index.html
<html>
  <body>
    <div align="center">
      <a href="https://$LAN_IP_ADDRESS:631/admin" target="_blank">CUPS</a> |
      <a href="https://$LAN_IP_ADDRESS/fusiondirectory" \
target="_blank">FusionDirectory</a> |
      <a href="https://$LAN_IP_ADDRESS/lcmc.html" target="_blank">LCMC</a> |
      <a href="https://$LAN_IP_ADDRESS/munin" target="_blank">Munin</a> |
      <a href="https://$LAN_IP_ADDRESS/nagios4" target="_blank">Nagios</a> |
      <a href="https://$LAN_IP_ADDRESS/appsuite" target="_blank">Open-Xchange</a> |
      <a href="https://$LAN_IP_ADDRESS/phpldapadmin" \
target="_blank">phpLDAPadmin</a> |
      <a href="https://$LAN_IP_ADDRESS/phpmyadmin" target="_blank">phpMyAdmin</a> |
      <a href="https://$LAN_IP_ADDRESS/phppgadmin" target="_blank">phpPgAdmin</a> |
      <a href="https://$LAN_IP_ADDRESS:10000" target="_blank">Webmin</a>
    </div>
  </body>
</html>
EOF.index.html

echo "Script end time: $(date +%c)"

# Activate the Debconf frontend.
unset DEBIAN_FRONTEND

# Log in to the GUI.
clear
echo ""
echo "Access your Ubuntu Linux server at https://$LAN_IP_ADDRESS"
echo ""
echo "Log in to the GUI with the following:"
echo ""
echo "username = admin"
echo "password = enter your administrator password"
echo ""
echo "phpLDAPadmin username = uid=admin,cn=gssapi,cn=auth"
echo ""

# End of redirect (STDOUT and STDERROR logged to terminal and install.log).
) 2>&1 | tee install.log 

exit 0
