# Host Security Audit Report

| Field | Value |
|-------|-------|
| **Host** | kenneth-VirtualBox |
| **Date** | 2026-05-31 13:30:09 |
| **OS** | Ubuntu 24.04.1 LTS |
| **Auditor** | Kenneth |

> This report was generated automatically by a custom audit script.
> Mapped to ISO 27001 controls: A.5.18 (Information security roles), A.8.1 (User endpoint devices), A.8.5 (Secure authentication).

---

## 1. System Information

- **Kernel:** 6.17.0-35-generic
- **Uptime:** up 31 minutes
- **Active Sessions:** 2

## 2. Privileged User Audit

### Users with UID 0 (root access)
```
root
```

### Sudo Group Members
```
kenneth
```


## 3. Network Exposure

### Listening Ports (TCP/UDP)
```
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0         127.0.0.54:53         0.0.0.0:*          
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*          
udp   UNCONN 0      0            0.0.0.0:631        0.0.0.0:*          
udp   UNCONN 0      0            0.0.0.0:35932      0.0.0.0:*          
udp   UNCONN 0      0            0.0.0.0:5353       0.0.0.0:*          
udp   UNCONN 0      0               [::]:51602         [::]:*          
udp   UNCONN 0      0               [::]:5353          [::]:*          
tcp   LISTEN 0      4096      127.0.0.54:53         0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:631        0.0.0.0:*          
tcp   LISTEN 0      4096           [::1]:631           [::]:*          
```


## 4. Failed Authentication (SSH, last 24h)

```
No failures logged or insufficient permissions.
```


## 5. File Permission Risks

### World-Writable Files in /etc, /tmp, /var/tmp
```
```

> **Risk Note:** World-writable files in /etc indicate configuration tampering risk (ISO 27001 A.8.1).
