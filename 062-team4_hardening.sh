#!/bin/bash
# Hardening Script
# Create log file
touch /var/log/hardening.log

function temp() {
  cd /var && dd if=/dev/zero of=tmpMnt bs=1024 count=1048576 && mkfs.ext3 -j /var/tmpMnt && cp -Rp /tmp /tmp_backup && mount -o loop,noexec,nosuid,rw /var/tmpMnt /tmp && chmod 0777 /tmp && cp -Rp /tmp_backup/* /tmp/
  echo "/var/tmpMnt /tmp ext3 loop,rw,noexec,nosuid,nodev 0 0" >> /etc/fstab
  
  if [[ $? -eq 0 ]] ; then
    echo "[*] /tmp succesfully mounted" >> /var/log/hardening.log
  fi
}

# 1.1.2 ensure /tmp is configured in the fstab
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab   #Check if /tmp is in fstab
if [[ $? == 1 ]] ; then
  echo "[*] /tmp is not mounted in fstab" >> /var/log/hardening.log
  echo "[*] mounting /tmp" >> /var/log/hardening.log
  temp
else
  echo "[*] /tmp is succesfully mounted in fstab" >> /var/log/hardening.log
fi

# 1.1.3 ensure noexec option set on /tmp partition
grep "noexec" /etc/fstab
if [[ $? == 0 ]] ; then
  echo "[*] noexec option succesfully set on /tmp" >> /var/log/hardening.log
else
  echo "[*] noexec option NOT configured" >> /var/log/hardening.log
  temp
  [[ $? == = ]] && echo "[*] noexec option succesfully configured" >> /var/log/hardening.log
fi

# 1.1.4 ensure nodev options set on /tmp partition
grep "nodev" /etc/fstab
if [[ $? == 0 ]] ; then
  echo "[*] nodev option succesfully set on /tmp" >> /var/log/hardening.log
else
  echo "[*] nodev option NOT configured" >> /var/log/hardening.log
  temp
  [[ $? == = ]] && echo "[*] noexec option succesfully configured" >> /var/log/hardening.log
fi

# 1.1.5 ensure nosuid option set on /tmp partition
grep "nosuid" /etc/fstab
if [[ $? == 0 ]] ; then
  echo "[*] nodev option succesfully set on /tmp" >> /var/log/hardening.log
else
  echo "[*] nodev option NOT configured" >> /var/log/hardening.log
  temp
  [[ $? == = ]] && echo "[*] noexec option succesfully configured" >> /var/log/hardening.log
fi


# 1.5.1 ensure core dumps are restricted
# 3.1.1 disable IPv6
sysctl -w net.ipv6.conf.default.disable_ipv6=1
echo "[*] disabled IPv6" >> /var/log/hardening.log

# 3.2.1 ensure IP forwarding is disabled
sysctl net.ipv4.ip_forward | grep -E "net.ipv4.ip_forward = 0"
if [[ $? == 0 ]]; then
  exit 0
fi

if [[ $(ls -A /etc/sysctl.d/) ]] ; then
  grep "net.ipv4.ip_forward" /etc/sysctl.conf /etc/sysctl.d/* | grep -E "net.ipv4.ip_forward = 0" || exit $?
else
  grep "net.ipv4.ip_forward" /etc/sysctl.conf | grep -E "net.ipv4.ip_forward = 0" || exit $?
fi


# 3.3.2 ensure ICMP redirects are not accepted
sysctl net.ipv4.conf.all.accept_redirects | grep -E "net.ipv4.conf.all.accept_redirects = 0"
if [[ $? == 0 ]]; then
  echo "[*] ICMP redirects not accepted" >> /var/log/hardening.log
  exit 0
fi

if [[ $(ls -A /etc/sysctl.d/) ]] ; then
  grep "net.ipv4.conf.all.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* | grep -E "net.ipv4.conf.all.accept_redirects = 0" || exit $?
else
  grep "net.ipv4.conf.all.accept_redirects" /etc/sysctl.conf | grep -E "net.ipv4.conf.all.accept_redirects = 0" || exit $?
fi

sysctl net.ipv4.conf.default.accept_redirects | grep -E "net.ipv4.conf.default.accept_redirects = 0"                    
if [[ $? == 0 ]]; then
  exit 0
fi

if [[ $(ls -A /etc/sysctl.d/) ]] ; then
  grep "net.ipv4.conf.default.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* | grep -E "net.ipv4.conf.default.accept_redirects = 0" || exit $?
else                                                                                                                            
  grep "net.ipv4.conf.default.accept_redirects" /etc/sysctl.conf | grep -E "net.ipv4.conf.default.accept_redirects = 0" || exit $? 
fi

# 3.3.5 ensure broadcast ICMP requests are ignored                                                                      
sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep -E "net.ipv4.icmp_echo_ignore_broadcasts = 1"                        
if [[ $? == 0 ]]; then                                                                                                          
  exit 0                                                                                                          
fi                                                                                                                      

if [[ $(ls -A /etc/sysctl.d/) ]] ; then                                                                                         
  grep "net.ipv4.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/* | grep -E "net.ipv4.icmp_echo_ignore_broadcasts = 1" || exit $?
else                                                                                                                            
  grep "net.ipv4.icmp_echo_ignore_broadcasts" /etc/sysctl.conf | grep -E "net.ipv4.icmp_echo_ignore_broadcasts = 1" || exit $?    
fi


# 3.3.6 ensure bogus ICMP responses are ignored                                                                         
sysctl net.ipv4.icmp_ignore_bogus_error_responses                                                                       

# 3.3.8 ensure TCP SYN cookies is enabled                                                                               
sysctl net.ipv4.tcp_syncookies | grep -E "net.ipv4.tcp_syncookies = 1"                                                  
if [[ $? == 0 ]]; then                                                                                                          
exit 0                                                                                                          
fi

if [[ $(ls -A /etc/sysctl.d/) ]] ; then                                                                                         
  grep "net.ipv4.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/* | grep -E "net.ipv4.tcp_syncookies = 1" || exit $?
else                                                                                                                            
  grep "net.ipv4.tcp_syncookies" /etc/sysctl.conf | grep -E "net.ipv4.tcp_syncookies = 1" || exit $? 
fi
