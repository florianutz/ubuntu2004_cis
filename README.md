Ubuntu 20.04 CIS STIG
================

[![Build Status](https://travis-ci.com/florianutz/ubuntu2004_cis.svg?branch=main)](https://travis-ci.com/florianutz/ubuntu2004_cis)
[![Ansible Role](https://img.shields.io/badge/role-florianutz.ubuntu2004--cis-blue.svg)](https://galaxy.ansible.com/florianutz/ubuntu2004_cis/)

**This role is based on 18.04 migration. The tasks are correct in content, but have to be re-sorted to fit the 20.04 Benchmark. Contribution welcome.**

Configure Ubuntu 20.04 machine to be CIS compliant. Level 1 and 2 findings will be corrected by default.

This role **will make changes to the system** that could break things. This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted.

## IMPORTANT INSTALL STEP

If you want to install this via the `ansible-galaxy` command you'll need to run it like this:

`ansible-galaxy install -p roles -r requirements.yml`

With this in the file requirements.yml:

```
- src: https://github.com/florianutz/Ubuntu2004-CIS.git
```

[](# Example Playbook)

Based on [CIS Ubuntu Benchmark ](https://www.cisecurity.org/cis-benchmarks/).

This repo originated from work done by [MindPointGroup](https://github.com/MindPointGroup/RHEL7-CIS)

## Requirements

You should carefully read through the tasks to make sure these changes will not break your systems before running this playbook.

## Role Variables

There are many role variables defined in defaults/main.yml. This list shows the most important.

**ubuntu2004cis_notauto**: Run CIS checks that we typically do NOT want to automate due to the high probability of breaking the system (Default: false)

**ubuntu2004cis_section1**: CIS - General Settings (Section 1) (Default: true)

**ubuntu2004cis_section2**: CIS - Services settings (Section 2) (Default: true)

**ubuntu2004cis_section3**: CIS - Network settings (Section 3) (Default: true)

**ubuntu2004cis_section4**: CIS - Logging and Auditing settings (Section 4) (Default: true)

**ubuntu2004cis_section5**: CIS - Access, Authentication and Authorization settings (Section 5) (Default: true)

**ubuntu2004cis_section6**: CIS - System Maintenance settings (Section 6) (Default: true)  

### Disable all selinux functions
`ubuntu2004cis_selinux_disable: false`

### Service variables
####These control whether a server should or should not be allowed to continue to run these services

```
ubuntu2004cis_avahi_server: false  
ubuntu2004cis_cups_server: false  
ubuntu2004cis_dhcp_server: false  
ubuntu2004cis_ldap_server: false  
ubuntu2004cis_telnet_server: false  
ubuntu2004cis_nfs_server: false  
ubuntu2004cis_rpc_server: false  
ubuntu2004cis_ntalk_server: false  
ubuntu2004cis_rsyncd_server: false  
ubuntu2004cis_tftp_server: false  
ubuntu2004cis_rsh_server: false  
ubuntu2004cis_nis_server: false  
ubuntu2004cis_snmp_server: false  
ubuntu2004cis_squid_server: false  
ubuntu2004cis_smb_server: false  
ubuntu2004cis_dovecot_server: false  
ubuntu2004cis_httpd_server: false  
ubuntu2004cis_vsftpd_server: false  
ubuntu2004cis_named_server: false  
ubuntu2004cis_bind: false  
ubuntu2004cis_vsftpd: false  
ubuntu2004cis_httpd: false  
ubuntu2004cis_dovecot: false  
ubuntu2004cis_samba: false  
ubuntu2004cis_squid: false  
ubuntu2004cis_net_snmp: false  
```  

### Designate server as a Mail server
`ubuntu2004cis_is_mail_server: false`


####System network parameters (host only OR host and router)
`ubuntu2004cis_is_router: false`  


####IPv6 required
`ubuntu2004cis_ipv6_required: true`  


### AIDE
`ubuntu2004cis_config_aide: true`

#### AIDE cron settings
```
ubuntu2004cis_aide_cron:
  cron_user: root
  cron_file: /etc/crontab
  aide_job: '/usr/sbin/aide --check'
  aide_minute: 0
  aide_hour: 5
  aide_day: '*'
  aide_month: '*'
  aide_weekday: '*'  
```


### Set to 'true' if X Windows is needed in your environment
`ubuntu2004cis_xwindows_required: no`


### Client application requirements
```
ubuntu2004cis_openldap_clients_required: false
ubuntu2004cis_telnet_required: false
ubuntu2004cis_talk_required: false  
ubuntu2004cis_rsh_required: false
ubuntu2004cis_ypbind_required: false
```

### Time Synchronization
```
ubuntu2004cis_time_synchronization: chrony
ubuntu2004cis_time_Synchronization: ntp

ubuntu2004cis_time_synchronization_servers:
  - uri: "0.pool.ntp.org"
    config: "minpoll 8"
  - uri: "1.pool.ntp.org"
    config: "minpoll 8"
  - uri: "2.pool.ntp.org"
    config: "minpoll 8"
  - uri: "3.pool.ntp.org"
    config: "minpoll 8"

```
### - name: "SCORED | 1.1.5 | PATCH | Ensure noexec option set on /tmp partition"
It is not implemented, noexec for /tmp will disrupt apt. /tmp contains executable scripts during package installation
```

```  
### 1.5.3 | PATCH | Ensure authentication required for single user mode
It is disabled by default as it is setting random password for root. To enable it set:
```yaml
ubuntu2004cis_rule_1_5_3: true
```
To use other than random password:
```yaml
ubuntu2004cis_root_password: 'new password'
```

### 3.4.2 | PATCH | Ensure /etc/hosts.allow is configured
```
ubuntu2004cis_host_allow:
  - "10.0.0.0/255.0.0.0"  
  - "172.16.0.0/255.240.0.0"  
  - "192.168.0.0/255.255.0.0"    
```  

```
ubuntu2004cis_firewall: firewalld
ubuntu2004cis_firewall: iptables
```

### 5.3.1 | PATCH | Ensure password creation requirements are configured
```
ubuntu2004cis_pwquality:
  - key: 'minlen'
    value: '14'
  - key: 'dcredit'
    value: '-1'
  - key: 'ucredit'
    value: '-1'
  - key: 'ocredit'
    value: '-1'
  - key: 'lcredit'
    value: '-1'
```


## Dependencies

Developed and testes with Ansible 2.10

## Example Playbook

```
- name: Harden Server
  hosts: servers
  become: yes

  roles:
    - Ubuntu2004-CIS
```

To run the tasks in this repository, first create this file one level above the repository
(i.e. the playbook .yml and the directory `Ubuntu2004-CIS` should be next to each other),
then review the file `defaults/main.yml` and disable any rule/section you do not wish to execute.

Assuming you named the file `site.yml`, run it with:
```bash
ansible-playbook site.yml
```

## Tags

Many tags are available for precise control of what is and is not changed.

Some examples of using tags:

```
    # Audit and patch the site
    ansible-playbook site.yml --tags="patch"
```

## License


MIT
