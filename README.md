
# IPv6-first Enterprise Lab 
**Dual-stack + OSPFv3 + DHCPv6 (SLAAC/Stateless + Stateful) + DNS + IPv6 ACL + Rogue RA Simulation**

This lab demonstrates IPv6-first operations in an enterprise-style topology using **Cisco Packet Tracer 8.2.2.0400** with:
- **IPv6-first** routing and reachability
- **Dual-stack** (IPv4 + IPv6) across core and access
- **OSPFv3** for IPv6 routing
- **OSPFv2** for IPv4 routing
- **SLAAC + Stateless DHCPv6** for Users LAN
- **Stateful DHCPv6** for Server LAN
- **DNS (A + AAAA)** records for name-based access over IPv6
- **IPv6 ACL** segmentation (least privilege) on Users LAN
- **Rogue Router Advertisement** attack simulation (default gateway hijack) and remediation

---

![Base Project SS](./Screenshots/Screenshot%202026-03-05%20173755.png)

## Table of Contents
1. [Requirements](#requirements)
2. [Topology](#topology)
3. [Address Plan](#address-plan)
4. [Step 1: Build the Enterprise Skeleton (Dual-stack + OSPF)](#step-1-build-the-enterprise-skeleton-dual-stack--ospf)
5. [Step 2: Users LAN = SLAAC + Stateless DHCPv6](#step-2-users-lan--slaac--stateless-dhcpv6)
6. [Step 3: Server LAN = Stateful DHCPv6](#step-3-server-lan--stateful-dhcpv6)
7. [Step 4: DNS + Hostnames (A/AAAA) + Name-based IPv6 Reachability](#step-4-dns--hostnames-aaaaa--name-based-ipv6-reachability)
8. [Step 5: Basic IPv6 ACL Segmentation (Then Harden)](#step-5-basic-ipv6-acl-segmentation-then-harden)
9.  [Step 6: Production-Style Improvements (Passive OSPF + Least-Privilege IPv6 ACL)](#step-6-production-style-improvements-passive-ospf--least-privilege-ipv6-acl)
10. [Step 7: Rogue RA Simulation + Detection + Remediation](#step-7-rogue-ra-simulation--detection--remediation)
11. [Validation Matrix](#validation-matrix)
12. [Troubleshooting Notes](#troubleshooting-notes)

---

## Requirements
- **Cisco Packet Tracer 8.2.2.0400**
- Devices:
  - Routers: 4 (R1 HQ-EDGE, R2 CORE, R3 BRANCH, R-ROGUE)
  - Switches: 2 (USER-SW, SERVER-SW)
  - End devices: 1 PC (PC1), 2 Servers (INFRA1, Server1)
  
  I have used 2911 Router and 2960 Switch
---

## Topology


Refer the diagram 

Router links:
- R1 G0/0 ↔ R2 G0/0  (transit)
- R2 G0/1 ↔ R3 G0/0  (transit)

LAN links:
- R1 G0/1 ↔ USER-SW ↔ PC1
- R3 G0/1 ↔ SERVER-SW ↔ INFRA1, Server1
- R-ROGUE G0/0 ↔ USER-SW (for Step 7 only)

---

## Address Plan

### IPv6 Site Prefix
- `2001:db8:1000::/48`

### IPv6 /64s
- R1–R2 transit: `2001:db8:1000:12::/64`
- R2–R3 transit: `2001:db8:1000:23::/64`
- Users LAN: `2001:db8:1000:101::/64`
- Server LAN: `2001:db8:1000:201::/64`

### IPv4
- R1–R2 transit: `10.10.12.0/30`
- R2–R3 transit: `10.10.23.0/30`
- Users LAN: `10.10.101.0/24`
- Server LAN: `10.10.201.0/24`

---


## Step 1: Build the Enterprise Skeleton (Dual-stack + OSPF)

### 1.1 Place devices and cable

* R1 G0/0 ↔ R2 G0/0
* R2 G0/1 ↔ R3 G0/0
* R1 G0/1 ↔ USER-SW ↔ PC1
* R3 G0/1 ↔ SERVER-SW ↔ INFRA1 + Server1

### 1.2 Configure routers (Dual-stack + OSPFv2 + OSPFv3 IPv6)

#### R1 (HQ-EDGE)

```cisco
enable
conf t
hostname R1
ipv6 unicast-routing

ipv6 router ospf 1
 router-id 1.1.1.1
 passive-interface g0/1
exit

router ospf 10
 router-id 1.1.1.1
 network 10.10.12.0 0.0.0.3 area 0
 network 10.10.101.0 0.0.0.255 area 0
 passive-interface g0/1
exit

interface g0/0
 description R1-to-R2
 ipv6 address 2001:db8:1000:12::1/64
 ip address 10.10.12.1 255.255.255.252
 no shut
 ipv6 ospf 1 area 0
exit

interface g0/1
 description R1-to-USER-LAN
 ipv6 address 2001:db8:1000:101::1/64
 ip address 10.10.101.1 255.255.255.0
 no shut
 ipv6 ospf 1 area 0
exit

end
wr
```

#### R2 (CORE)

```cisco
enable
conf t
hostname R2
ipv6 unicast-routing

ipv6 router ospf 1
 router-id 2.2.2.2
exit

router ospf 10
 router-id 2.2.2.2
 network 10.10.12.0 0.0.0.3 area 0
 network 10.10.23.0 0.0.0.3 area 0
exit


interface g0/0
 description R2-to-R1
 ipv6 address 2001:db8:1000:12::2/64
 ip address 10.10.12.2 255.255.255.252
 no shut
 ipv6 ospf 1 area 0
exit

interface g0/1
 description R2-to-R3
 ipv6 address 2001:db8:1000:23::2/64
 ip address 10.10.23.1 255.255.255.252
 no shut
 ipv6 ospf 1 area 0
exit

end
wr
```

#### R3 (BRANCH)

```cisco
enable
conf t
hostname R3
ipv6 unicast-routing

ipv6 router ospf 1
 router-id 3.3.3.3
 passive-interface g0/1
exit

router ospf 10
 router-id 3.3.3.3
 network 10.10.23.0 0.0.0.3 area 0
 network 10.10.201.0 0.0.0.255 area 0
 passive-interface g0/1
exit

interface g0/0
 description R3-to-R2
 ipv6 address 2001:db8:1000:23::3/64
 ip address 10.10.23.2 255.255.255.252
 no shut
 ipv6 ospf 1 area 0
exit

interface g0/1
 description R3-to-SERVER-LAN
 ipv6 address 2001:db8:1000:201::1/64
 ip address 10.10.201.1 255.255.255.0
 no shut
 ipv6 ospf 1 area 0
exit

end
wr
```

#### USER-SW (portfast)
```cisco
en
conf t
interface FastEthernet0/1
 switchport mode access
 spanning-tree portfast
 end
wr
```


#### SERVER-SW (portfast)
```cisco
en
conf t
interface FastEthernet0/1
 switchport mode access
 spanning-tree portfast
!
interface FastEthernet0/2
 switchport mode access
 spanning-tree portfast
 end
wr
```

### 1.3 End hosts (temporary static to validate baseline)

#### PC1 (Users LAN)

* IPv4: `10.10.101.10/24`, GW `10.10.101.1`
* IPv6: `2001:db8:1000:101::10/64`, GW `2001:db8:1000:101::1`

#### Server1 (Server LAN) initial

* IPv4: `10.10.201.10/24`, GW `10.10.201.1`
* IPv6: `2001:db8:1000:201::10/64`, GW `2001:db8:1000:201::1`

### 1.4 Verify

On R2:

```cisco
show ipv6 ospf neighbor
show ip ospf neighbor
show ipv6 route ospf
show ip route ospf
```

From PC1:

```text
ping 2001:db8:1000:201::10
ping 10.10.201.10
```

---

## Step 2: Users LAN = SLAAC + Stateless DHCPv6

Goal: Users get IPv6 via SLAAC, and DNS/domain via DHCPv6 “other config”.

### 2.1 Configure R1 DHCPv6 stateless pool + RA flag

```cisco
enable
conf t
ipv6 dhcp pool USER-LAN-STATELESS
 dns-server 2001:db8:1000:201::10
 domain-name lab.local
exit

interface g0/1
 ipv6 nd other-config-flag
 ipv6 dhcp server USER-LAN-STATELESS
exit

end
wr
```

### 2.2 Set PC1 IPv6 to Auto Config

PC1 → Desktop → IP Configuration → IPv6 → **Auto Config**

### 2.3 Verify

PC1:

```text
ping 2001:db8:1000:101::1
ping 2001:db8:1000:201::10
ipconfig
```

R1:

```cisco
show ipv6 interface g0/1
show ipv6 dhcp binding
```

Note: bindings may be empty for **stateless** DHCPv6 (normal).

---

## Step 3: Server LAN = Stateful DHCPv6

Goal: Servers get routable IPv6 addresses from DHCPv6, and DNS/domain.

### 3.1 Configure R3 DHCPv6 stateful pool + managed flag

```cisco
enable
conf t

ipv6 dhcp pool SERVER-LAN-STATEFUL
 address prefix 2001:db8:1000:201::/64
 dns-server 2001:db8:1000:201::10
 domain-name lab.local
exit

interface g0/1
 ipv6 nd managed-config-flag
 ipv6 dhcp server SERVER-LAN-STATEFUL
exit

end
wr
```

### 3.2 Set Server1 IPv6 to Auto Config

Server1 → Desktop → IP Configuration → IPv6 → **Auto Config**

### 3.3 Verify DHCPv6 lease

R3:

```cisco
show ipv6 interface g0/1
show ipv6 dhcp binding
```

You should see a leased IPv6 address for Server1 (example):
`2001:db8:1000:201:8F3F:719D:630B:5578`

### 3.4 Update your expectations

After stateful DHCPv6, `2001:db8:1000:201::10` may no longer be Server1.
Ping the leased address instead:

```text
ping 2001:db8:1000:201:<leased-address>
```

---

## Step 4: DNS + Hostnames (AAAA/A) + Name-based IPv6 Reachability

Goal: Stop depending on static IPv6 for hosts; use DNS and AAAA records.

### 4.1 Add INFRA1 with stable IP

Add a second server on SERVER-SW named **INFRA1**.

INFRA1 IP config:

* IPv4: `10.10.201.10/24`, GW `10.10.201.1`
* IPv6: `2001:db8:1000:201::10/64`, GW `2001:db8:1000:201::1`

Change Server1 IPv4 to avoid conflict:

* Server1 IPv4: `10.10.201.20/24`, GW `10.10.201.1`
* Server1 IPv6 stays DHCPv6 auto.

### 4.2 Enable DNS service on INFRA1 and add records

INFRA1 → Services → DNS → **On**

Add records:

**A records**

* `infra.lab.local` → `10.10.201.10`
* `server1.lab.local` → `10.10.201.20`

**AAAA records**

* `infra.lab.local` → `2001:db8:1000:201::10`
* `server1.lab.local` → Server1 leased IPv6 (from `ipconfig` or `show ipv6 dhcp binding`)

### 4.3 Ensure DHCPv6 pools point to INFRA1 as DNS server

R1:

```cisco
conf t
ipv6 dhcp pool USER-LAN-STATELESS
 dns-server 2001:db8:1000:201::10
 domain-name lab.local
end
wr
```

R3:

```cisco
conf t
ipv6 dhcp pool SERVER-LAN-STATEFUL
 dns-server 2001:db8:1000:201::10
 domain-name lab.local
end
wr
```

### 4.4 Refresh clients (PT method)

* Toggle IPv6 Auto Config OFF/ON on PC1 and Server1.

### 4.5 Verify name-based IPv6

PC1:

```text
ping infra.lab.local
ping server1.lab.local
```

---

## Step 5: Production-Style Improvements (Passive OSPF + Least-Privilege IPv6 ACL)

### 6.1 Apply least-privilege IPv6 ACL on Users LAN (R1 inbound on g0/1)

Policy:

* Allow NDP/RA/RS essentials + ICMP errors
* Allow DHCPv6 client traffic (UDP 546→547)
* Allow DNS/HTTP to INFRA1 only
* Allow ping only to gateway + INFRA1
* Deny Users → Server LAN
* Permit Users → anywhere else (future zones)

> NOTE: We explicitly removed `permit icmp any any echo-*` because it allows ping to everything and bypasses the deny.

#### Build ACL (R1)

```cisco
enable
conf t
interface g0/1
 no ipv6 traffic-filter USERS-IN in
exit

no ipv6 access-list USERS-IN
ipv6 access-list USERS-IN
 !
 ! ===== Keep IPv6 working (NDP/RA + ICMPv6 essentials) =====
 permit icmp any any nd-ns
 permit icmp any any nd-na
 permit icmp any any router-solicitation
 permit icmp any any router-advertisement
 permit icmp any any packet-too-big
 permit icmp any any time-exceeded
 permit icmp any any destination-unreachable
 permit icmp any any parameter-problem
 !
 ! ===== DHCPv6 (Users are SLAAC + stateless DHCPv6) =====
 permit udp 2001:db8:1000:101::/64 eq 546 any eq 547
 !
 ! ===== Allow DNS to INFRA1 only =====
 permit udp 2001:db8:1000:101::/64 host 2001:db8:1000:201::10 eq 53
 permit tcp 2001:db8:1000:101::/64 host 2001:db8:1000:201::10 eq 53
 !
 ! ===== Allow HTTP to INFRA1 only (optional) =====
 permit tcp 2001:db8:1000:101::/64 host 2001:db8:1000:201::10 eq 80
 !
 ! ===== Allow ping only to Users gateway + INFRA1 =====
 permit icmp 2001:db8:1000:101::/64 host 2001:db8:1000:101::1 echo-request
 permit icmp host 2001:db8:1000:101::1 2001:db8:1000:101::/64 echo-reply
 permit icmp 2001:db8:1000:101::/64 host 2001:db8:1000:201::10 echo-request
 permit icmp host 2001:db8:1000:201::10 2001:db8:1000:101::/64 echo-reply
 !
 ! ===== Block Users from Server LAN (everything else) =====
 deny ipv6 2001:db8:1000:101::/64 2001:db8:1000:201::/64
 !
 ! ===== Permit Users to other destinations (future zones) =====
 permit ipv6 2001:db8:1000:101::/64 any
exit

interface g0/1
 ipv6 traffic-filter USERS-IN in
exit

end
wr
```

#### Verify ACL is working

PC1:

```text
ping 2001:db8:1000:101::1
ping infra.lab.local
ping server1.lab.local   (EXPECTED: FAIL - blocked by deny)
```

R1:

```cisco
show ipv6 access-list USERS-IN
show ipv6 interface g0/1
```

---

## Step 7: Rogue RA Simulation + Detection + Remediation

Packet Tracer may not enforce switch RA Guard, but it can demonstrate:

* Default gateway hijack via rogue RAs (link-local default router changes)
* Operational detection (gateway change + DNS disruption)
* Remediation (remove rogue)

### 7.1 Add R-ROGUE connected to USER-SW

Connect **R-ROGUE g0/0** to USER-SW.

### 7.2 Configure R-ROGUE to advertise on Users LAN

```cisco
enable
conf t
hostname R-ROGUE
ipv6 unicast-routing

interface g0/0
 description Rogue-on-USER-LAN
 ipv6 address 2001:db8:1000:101::666/64
 no shut
exit

end
wr
```

### 7.3 Detect rogue RA impact

On PC1:

```text
ipconfig
```

Example (rogue active):

* Default Gateway becomes R-ROGUE link-local:

  * `FE80::202:17FF:FE5C:C101`

Confirm link-local ownership:
R-ROGUE:

```cisco
show ipv6 interface brief
```

R1:

```cisco
show ipv6 interface brief
```

Expected evidence:

* R-ROGUE g0/0 link-local matches PC1 Default Gateway.

### 7.4 Remediate: shut down rogue interface

R-ROGUE:

```cisco
conf t
interface g0/0
 shutdown
end
wr
```

On PC1, refresh:

* Toggle IPv6 Auto Config OFF/ON, then `ipconfig` again.

Expected (rogue removed):

* Default Gateway returns to R1 link-local (example):

  * `FE80::2D0:97FF:FE49:6602`

### 7.5 Production mitigation design (write-up)

Packet Tracer limitation: switch RA Guard enforcement may not be fully emulated.
In production you would:

* Enable **RA Guard** on access ports (untrusted ports to endpoints)
* Mark only router uplinks as **trusted**
* Use **DHCPv6 Guard** to block rogue DHCPv6 servers
* Optionally use ND inspection / IPv6 snooping features depending on platform
* Monitor for unexpected RA sources / default gateway changes

---

## Validation Matrix

### Routing

* `show ipv6 ospf neighbor` on R2 shows FULL adjacencies on transit links.
* `show ip ospf neighbor` on R2 shows FULL adjacencies on transit links.
* `show ipv6 route ospf` includes remote LAN prefixes.
* `show ip route ospf` includes remote LAN prefixes.

### IPv6 Host Provisioning

* PC1: SLAAC address in `2001:db8:1000:101::/64` + default gateway via RA.
* R1 Users LAN shows:

  * “Hosts use stateless autoconfig”
  * “Hosts use DHCP to obtain other configuration.”
* Server1: Stateful DHCPv6 lease present in `show ipv6 dhcp binding` on R3.

### DNS

* PC1 can resolve and ping over IPv6:

  * `ping infra.lab.local`
  * `ping server1.lab.local`

### Security (IPv6 ACL)

* PC1 can ping gateway + INFRA1.
* PC1 cannot reach Server LAN hostnames (expected fail):

  * `ping server1.lab.local` fails (blocked by `deny ipv6 ... 201::/64`).
* R1 ACL match counters increment accordingly:

  * `show ipv6 access-list USERS-IN`

### Rogue RA

* PC1 default gateway changes to rogue link-local when R-ROGUE is connected.
* After shutting down R-ROGUE, gateway reverts to R1.

---

## Troubleshooting Notes

### 1. After stateful DHCPv6, old static IPv6 stops responding

Expected. The host got a new leased IPv6. Use:

* `show ipv6 dhcp binding` on R3
* DNS AAAA records to avoid hardcoding addresses

### 2. ACL allows ping unexpectedly

Cause: `permit icmp any any echo-request/echo-reply` bypasses denies.
Fix: remove those lines and permit only specific echo destinations.

### 3. Packet Tracer DHCPv6 “other config” refresh

If DNS suffix does not refresh after rogue RA removal, toggle IPv6 Auto Config OFF/ON on the endpoint.
If PT still refuses to apply DNS via stateless DHCPv6, set DNS server manually on PC1:

* IPv6 DNS: `2001:db8:1000:201::10`

---

## (Optional) Useful “clear” commands during testing

* Reset OSPFv3:

  ```cisco
  clear ipv6 ospf process
  ```
* Reset OSPFv2:

  ```cisco
  clear ip ospf process
  ```
* Clear ARP:

  ```cisco
  clear arp
  ```
* Clear IPv6 neighbors (if supported by PT):

  ```cisco
  clear ipv6 neighbors
  ```

---

## Summary 
Through this project I demonstrate the ability to:

- Design and implement an **IPv6-first addressing plan** within an enterprise-style network topology.
- Deploy and operate a **dual-stack environment** using **OSPFv3 (IPv6)** and **OSPFv2 (IPv4)** for dynamic routing.
- Configure **IPv6 host provisioning** using **SLAAC with stateless DHCPv6** for user networks and **stateful DHCPv6** for server networks.
- Integrate basic network services including **DNS with AAAA and A records** to enable name-based connectivity over IPv6 and IPv4.
- Apply **IPv6 ACL-based segmentation** while maintaining required control-plane traffic such as NDP and ICMPv6.
- Identify and analyze the impact of **rogue Router Advertisements (RA)** and document appropriate mitigations such as **RA Guard and DHCPv6 Guard**.

