# Docker Security

**Author :** HUGUET Rémi

[[TOC]]

## Tools 

### [Docker bench Security](https://github.com/docker/docker-bench-security)
- [Docker bench](https://github.com/docker/docker-bench-security) : Docker's open-source script for auditing containers against common security best practices. (bases its tests on the industry-standard[ CIS benchmarks](https://www.cisecurity.org/benchmark/docker/))   
  **Tool based on Docker bench :**
  - [Docker Bench Test](https://github.com/alexei-led/docker-bench-test): Bats test set that contains tests for dozens of common best-practices around deploying Docker containers in production
  - [Drydlock](https://github.com/zuBux/drydock): A flexible way of assessing the security of your Docker daemon configuration and containers using editable audit templates
  - [Actuary](https://github.com/diogomonica/actuary): Checks for dozens of common best-practices around deploying Docker containers in production

!!! <> Run docker bench
    **Methode 1**
    ```bash
    docker build --no-cache -t docker-bench-security .
    
    docker run -it --net host --pid host --userns host -cap-add audit_control \
        -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
        -v /etc:/etc \
        -v /usr/bin/docker-containerd:/usr/bin/ocker-containerd \
        -v /usr/bin/docker-runc:/usr/bin/docker-runc \
        -v /usr/lib/systemd:/usr/lib/systemd \
        -v /var/lib:/var/lib \
        -v /var/run/docker.sock:/var/run/docker.sock \
        --label docker_bench_security \
        docker/docker-bench-security
    ```
    **Methode 2**
    ```bash 
    docker-compose run --rm docker-bench-security
    ```
    **Methode 3**
    ```bash
    sudo sh docker-bench-security.sh
    ```

### [AppArmor](https://gitlab.com/apparmor/apparmor/wikis/home/)

- [AppArmor](https://gitlab.com/apparmor/apparmor/wikis/home/): Docker can automatically generate and load a default AppArmor profile for containers named docker-default. You can create specific security profiles for your containers or the applications inside them.



### [Calico](https://github.com/projectcalico/calico) 

- [Calico](https://github.com/projectcalico/calico) : Calico is often deployed during installation with the rest of your Kubernetes cluster components to provide the inter container network layer. Calico implements the default Kubernetes Network Policy interface to define firewalling capabilities and extends it providing features like namespace isolation, advanced endpoint ACLs, annotation-based network security and outgoing (egress) container rules


### [Clair](https://github.com/coreos/clair) by CoreOS

- [Clair](https://github.com/coreos/clair) : Vulnerability Static Analysis for Containers.   
    **Tool based on Clair :**
    - [Klar](https://github.com/optiopay/klar): Integration of Clair and Docker Registry
    - [Clair-scanner ](https://github.com/arminc/clair-scanner): Docker containers vulnerability scan
    - [clairctl](https://github.com/jgsqware/clairctl): Tracking container vulnerabilities with Clair Control for CoreOS Clair.

### [Cilium](https://github.com/cilium/cilium) bu CoreOS

- [Cilium](https://github.com/cilium/cilium) : API Aware Networking and Security using BPF and XDP. Work with kubernetes technogies/env such as : 
  - Kubectl
  - minikube
  - microk8s
  - kubeadm
  - Cloud (AWS EKS, Google GKE)

!!! <> Cilium Deploy
    ```bash 
    kubectl create -f ./cilium.yaml \ 
        clusterrole "cilium" \
        created serviceaccount "cilium" \
        created clusterrolebinding "cilium" \ 
        created configmap "cilium-config" \
        created secret "cilium-etcd-secrets" \
        created daemonset "cilium" \
        created $ kubectl get ds --namespace kube-system NAME DESIRED CURRENT READY NODE-SELECTOR AGE cilium 1 1 1 <none> 2m
    ```

### [Anchore](https://github.com/anchore/anchore-engine)

- [Anchore](https://github.com/anchore/anchore-engine): Tool for analyzing container images. In addition to CVE-based security vulnerability reporting, Anchore Engine can evaluate Docker images using custom policies. - [Anchore cli](https://github.com/anchore/anchore-cli)

!!! <> Installation/Setup
    ```bash
    mkdir ~/aevolume
    cd ~/aevolume

    docker pull docker.io/anchore/anchore-engine:latest
    docker create --name ae docker.io/anchore/anchore-engine:latest
    docker cp ae:/docker-compose.yaml ~/aevolume/docker-compose.yaml
    docker rm ae

    docker-compose pull
    docker-compose up -d
    ```
    And then you can use the cli  to communicate with your anchore engine :   
    ```bash 
    apt-get update
    apt-get install python-pip
    pip install anchorecli
    # Note make sure ~/.local/bin is part of your PATH or just  export it directly: export PATH="$HOME/.local/bin/:$PATH"
    ```

### [OpenSCAP Workbench](https://github.com/OpenSCAP/scap-workbench/releases)

- [OpenScap](https://github.com/OpenSCAP/scap-workbench/releases) : Ecosystem for IT admins and security auditors that includes many open security benchmark guides, configuration baselines, and open-source tools. - [OpenScap](https://github.com/OpenSCAP/openscap)
  - openscap-scanner :   
  ```bash
  yum install openscap-scanner
  yum install openscap-utils
  # https://github.com/ComplianceAsCode/content
  yum install scap-security-guide 
  ```

### [Dagda](https://github.com/eliasgranderubio/dagda)

- [Dagda](https://github.com/eliasgranderubio/dagda): A tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities. (Use [ClamAV](https://www.clamav.net/))   

    **Build on top of :**
    -  [OWASP dependency check](https://github.com/jeremylong/DependencyCheck)
    -  [Retire.js](https://github.com/retirejs/retire.js/)  
    -  [ExploitDB](https://github.com/offensive-security/exploitdb)
    -  [Redhat OVAL](https://www.redhat.com/security/data/oval/)

    **And Integrated in :**
    - [Sysdig Falco](https://sysdig.com/opensource/falco/) : Open Source Container Native Runtime Security. A [CNCF](https://www.cncf.io/certification/software-conformance/) Sandbox project.

### [Notary](http://github.com/theupdateframework/notary)

- [Notary](http://github.com/theupdateframework/notary): Docker image signing framework  for boosting container security with a server for cryptographically delegating responsibility (CNCF project)


### [Grafeas](https://github.com/grafeas/grafeas)

- [Grafaes](https://github.com/grafeas/grafeas) : A metadata API to help govern internal security policies. Grafaes can greatly help you create your own container security scanning projects. (Developed by IBM and Google).    
   **Contain :**   
    - [IBM Vulnerability Advisor](https://console.bluemix.net/docs/services/va/va_index.html)   
    
    **Good to be used with :** 
    - [Kritis](https://github.com/grafeas/kritis) : Open-source solution for securingsoftware supply chain for Kubernetes applications. Kritis enforces deploy-time security policies using the Google Cloud Container Analysis API, and in a subsequent release, Grafeas.


### [Sysdif Falco](https://sysdig.com/opensource/falco/)

- [Sysdig Falco](https://sysdig.com/opensource/falco/) : Open Source Container Native Runtime Security. A [CNCF](https://www.cncf.io/certification/software-conformance/) Sandbox project.

### [Banyan Collector](https://github.com/banyanops/collector)

- [Banyan Collector](https://github.com/banyanops/collector) :
Open-source utility that can be used to "peek" inside Docker container image files. Using Collector, developers can collect container data, enforce security policies, and more.


### [DockScan](https://github.com/kost/dockscan)

- [DockScan](https://github.com/kost/dockscan) : A simple ruby script that analyzes the Docker installation and running containers, both for local and remote hosts.
It’s easy to install and run with just one command and can generate HTML report files. 

### [Open Policy Agent](https://www.openpolicyagent.org/)

- [Open Policy Agent](https://www.openpolicyagent.org/) : Pluggable and platform-agnostic policy definitions, easily extendable and customizable rule engine and language. Open Policy Agent can decouple security policies and security best practices from your runtime platform (Kubernetes, Docker) and services (Kafka, etc…). Security policies are written using OPA’s purpose-built, declarative language: Rego. 




## Guideline/Good Practice

### **Docker Bench Security** 

After running your benchmark security test you will have by default a file called ```docker-bench-security.sh.log``` containing the result of the benchmarking. We will see how to remove all the warning.

_Prerequirement_ : ```sudo apt install auditd```


!!! warning Ensure a separate partition for containers has been created.
    Keep Docker containers and all of ```/var/lib/docker``` on their own filesystem partition.

!!! Warning Ensure the container host has been Hardened
    look here for now https://www.digitalocean.com/community/tutorials/7-security-measures-to-protect-your-servers

!!! Warning Ensure Docker is up to date
    Just update/upgrade your docker packages
    ```bash 
    sudo apt-get update 
    sudo apt-get upgrade 
    ```

!!! warning Ensure only trusted users are allowed to control Docker daemon
    The test output the content of ```/etc/group```.   
    Make sure that only appropriate user are authorized to control the Docker daemon.   
    To remove users from this group, you can use ```gpasswd``` : 
    ```bash 
    gpasswd -d username docker
    ```


!!! warning Ensure auditing is configured for the Docker daemon
    We need auditd packages to audit some of Docker's files, directories, and sockets.
    ```bash 
    sudo apt-get install auditd
    sudo service 
    ```
    We’ll now configure auditd to monitor Docker files and directories : 
    ```bash 
    sudo nano /etc/audit/rules.d/audit.rules
    ```
    ```bash
    # Add these lines add the end of the files 

    -w /usr/bin/docker -p wa
    -w /var/lib/docker -p wa
    -w /etc/docker -p wa
    -w /lib/systemd/system/docker.service -p wa
    -w /lib/systemd/system/docker.socket -p wa
    -w /etc/default/docker -p wa
    -w /etc/docker/daemon.json -p wa
    -w /usr/bin/docker-containerd -p wa
    -w /usr/bin/docker-runc -p wa
    ```
    **-w** stand for **watch** the specified file or directory and log any writes or attribute changes **(-p wa)** to those files.
    
    Finaly restart the service : 
    ```bash 
    sudo systemctl restart auditd
    ```

!!! warning Daemon warning 
    Add these line in ```/etc/docker/daemon.json``` : 
    ```json 
    {
    "icc": false,
    "userns-remap": "default",
    "log-driver": "syslog",
    "disable-legacy-registry": true,
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true
    }
    ```
    Then restart docker daemon : 
    ```bash 
    sudo systemctl restart docker
    ```
!!! warning Ensure network traffic is restricted between containers on the default bridge : ```"icc": false```
    This configuration creates containers that can only communicate with  each other when explicitly linked using ```--link=container_name``` on the  Docker command line or the ```links:``` parameter in Docker Compose configuration files.  
     
     One benefit of this is that if an  attacker compromises one container, they’ll have a harder time  finding and attacking other containers on the same host.

!!! warning Enable user namespace support : ``` "userns-remap": "default"```
    User namespace remapping allows processes to run as ```root``` in a container while being remapped to a ```less privileged user``` on the host.

    Docker will create a dockremap user to which container users will be remapped. You can verify that the dockremap user was created using the id command:
    ```bash 
    root@secops:~ sudo id dockremap
    > uid=114(dockremap) gid=121(dockremap) groups=121(dockremap)
    ```

!!!  Ensure that authorization for Docker client commands is enabled
    [Protect the Docker daemon socket](https://docs.docker.com/engine/security/https/)     

    !!! TODO 

!!! warning Ensure centralized and remote logging is configured ```"log-driver": "syslog"```
    !!! TODO I need syslog server or a kibana (+filebeat) install

!!! warning Ensure live restore is Enabled : ```"live-restore": true```
    Allow containers to continue running when the Docker daemon is not.    
    This improves container uptime during updates of the host system and other stability issues.

!!! Warning Ensure Userland Proxy is Disabled : ```"userland-proxy": false```
    Disables the docker-proxy userland process that by default handles forwarding host ports to containers, and replaces it with iptables rules

!!! warning Ensure containers are restricted from acquiring new privileges : ```"no-new-privileges": true```
    Prevents privilege escalation from inside containers. This ensures that containers cannot gain new privileges using setuid or setgid binaries.

!!! warning  Ensure that containers use trusted base images
    Make sure to pull trusted/Official image : 
    ```bash 
    docker search <image> 
    ```
    check if ```[OFFICIAL] [OK]```

!!! warning Ensure Content trust for Docker is Enabled
    Content trust is a system for signing Docker images and verifying their signatures before running them.   
    We can enable content trust with the ```DOCKER_CONTENT_TRUST``` environment variable.
    We enable it for all session and user by putting hit in ```/etc/environment``` : 
    ```bash 
    echo "DOCKER_CONTENT_TRUST=1" | sudo tee -a /etc/environment
    ```

!!!  warning Ensure HEALTHCHECK instructions have been added to the container image
    Adding ```HEALTHCHECK``` instruction to
    container image ensures that the docker engine periodically checks the running container
    instances against that instruction to ensure that the instances are still working.

    In your ```Dockerfile``` use the ```HEALTHCHECK``` Instruction ( ```HEALTHCHECK [OPTIONS] CMD command``` ): 
    ```bash 
    # If you want to check if your application is up on localhost:5000
    HEALTHCHECK CMD curl --fail http://localhost:5000/ || exit 1
    ```

    To see the health status : 
    ```bash 
    docker inspect --format='{{ .Config.Healthcheck }}' <your_image>
    ```



### **Clair **
#### Installation as a docker

```bash 
mkdir $PWD/clair_config
curl -L https://raw.githubusercontent.com/coreos/clair/master/config.yaml.sample -o $PWD/clair_config/config.yaml
docker run -d -e POSTGRES_PASSWORD="" -p 5432:5432 postgres:9.6
docker run --net=host -d -p 6060-6061:6060-6061 -v $PWD/clair_config:/config quay.io/coreos/clair-git:latest -config=/config/config.yaml
```

### **Anchore**
#### Installation 
- Docker-compose 
```bash 
# On crée un dossier anchore pour le projet...
mkdir anchore/ && cd anchore/
mkdir config 
# ... et on y crée un dossier config dans lequel on DL le config.yaml
cd config && curl -O https://raw.githubusercontent.com/anchore/anchore-engine/master/scripts/docker-compose/config.yaml
# Puis dans le dossier anchore, on crée un dossier db pour notre base de donnée.
cd .. && mkdir db && cd .. 
# On télécharge ensuite le docker-compose.yaml dans le dossier anchore/
curl -O https://raw.githubusercontent.com/anchore/anchore-engine/master/scripts/docker-compose/docker-compose.yaml

# On pull anchore-db et anchore-engine
docker-compose pull
# On run anchore engine en silent-mode 
docker-compose up -d

# On installe ensuite anchore cli via pip 
sudo apt-get update
sudo pip install anchorecli
source ~/.profile
anchore-cli --version

# On export ensuite quelques variable 
ANCHORE_CLI_URL=http://localhost:8228/v1
ANCHORE_CLI_USER=admin
ANCHORE_CLI_PASS=foobar
export ANCHORE_CLI_URL
export ANCHORE_CLI_USER
export ANCHORE_CLI_PASS
```

Now that the installation of Anchore Engine and Anchore CLI is all set and done, we are ready to analyze a Docker image. We will make use of the ```openjdk:10-jdk```

```bash
root@secops: anchore-cli image add openjdk:10-jdk

Image Digest: sha256:923d074ef1f4f0dceef68d9bad8be19c918d9ca8180a26b037e00576f24c2cb4
Parent Digest: sha256:9f17c917630d5e95667840029487b6561b752f1be6a3c4a90c4716907c1aad65
Analysis Status: not_analyzed
Image Type: docker
Image ID: b11e88dd885d8b2621d448f3d2099068d181c5c778c2ab0cf0f61b573fa429b7
Dockerfile Mode: None
Distro: None
Distro Version: None
Size: None
Architecture: None
Layer Count: None
Full Tag: docker.io/openjdk:10-jdk
```

We are able to monitor the progress with the list command, which shows us the Docker images added to Anchore Engine and their respective status : 
```bash 
root@secops:anchore-cli image list
Full Tag                        Image Digest                      Analysis Status        
docker.io/openjdk:10-jdk        sha256:923d074ef1f4f0dceef68d9    Analyzed
```

The first time Anchore Engine is run, it needs to download the vulnerabilities. So wait until there is no ```0``` in ```recordCount```
```bash 
root@secops: anchore-cli system feeds list
Feed                   Group                  LastSync                          RecordCount        
vulnerabilities        alpine:3.10            2019-07-24T08:00:04.178445        1370               
vulnerabilities        alpine:3.3             2019-07-24T08:00:12.157212        457                
vulnerabilities        alpine:3.4             2019-07-24T08:00:24.355669        681                
vulnerabilities        alpine:3.5             2019-07-24T08:00:39.849756        875                
vulnerabilities        alpine:3.6             2019-07-24T08:00:59.189845        1051               
vulnerabilities        alpine:3.7             2019-07-24T08:01:21.060162        1194               
vulnerabilities        alpine:3.8             2019-07-24T08:01:43.319267        1274               
vulnerabilities        alpine:3.9             2019-07-24T08:02:11.959717        1305               
vulnerabilities        amzn:2                 2019-07-24T08:02:33.631668        194                
vulnerabilities        centos:5               2019-07-24T08:03:47.686158        1323               
vulnerabilities        centos:6               2019-07-24T08:05:03.087283        1347               
vulnerabilities        centos:7               2019-07-24T08:05:52.553390        805                
vulnerabilities        centos:8               2019-07-24T08:05:57.335101        44                 
vulnerabilities        debian:10              2019-07-24T08:10:57.911519        20618              
vulnerabilities        debian:7               2019-07-24T08:16:10.612292        20455              
vulnerabilities        debian:8               2019-07-24T08:21:50.921032        22041 
```

Then retrieve the result when the analyze is down : 
```bash 
root@secops: anchore-cli image vuln openjdk:10-jdk all 
Vulnerability ID        Package                               Severity          Fix                   Vulnerability URL                                                   
CVE-2018-1000802        libpython2.7-minimal-2.7.15-4         High              2.7.15-5              https://security-tracker.debian.org/tracker/CVE-2018-1000802        
CVE-2018-1000802        libpython2.7-stdlib-2.7.15-4          High              2.7.15-5              https://security-tracker.debian.org/tracker/CVE-2018-1000802        
CVE-2018-1000802        python2.7-2.7.15-4                    High              2.7.15-5              https://security-tracker.debian.org/tracker/CVE-2018-1000802        
CVE-2018-1000802        python2.7-minimal-2.7.15-4            High              2.7.15-5              https://security-tracker.debian.org/tracker/CVE-2018-1000802        
CVE-2018-15686          libpam-systemd-239-11                 High              239-12                https://security-tracker.debian.org/tracker/CVE-2018-15686          
CVE-2018-15686          libsystemd0-239-11                    High              239-12                https://security-tracker.debian.org/tracker/CVE-2018-15686          
CVE-2018-15686          libudev1-239-11                       High              239-12                https://security-tracker.debian.org/tracker/CVE-2018-15686          
CVE-2018-15686          systemd-239-11                        High              239-12                https://security-tracker.debian.org/tracker/CVE-2018-15686          
CVE-2018-15686          systemd-sysv-239-11                   High              239-12                https://security-tracker.debian.org/tracker/CVE-2018-15686          
CVE-2018-18311          libperl5.28-5.28.0-3                  High              5.28.1-1              https://security-tracker.debian.org/tracker/CVE-2018-18311          
CVE-2018-18311          perl-5.28.0-3                         High              5.28.1-1              https://security-tracker.debian.org/tracker/CVE-2018-18311          
CVE-2018-18311          perl-base-5.28.0-3                    High              5.28.1-1              https://security-tracker.debian.org/tracker/CVE-2018-18311   
```

Next we want to do the samething but for custom image:
When analyzing our custom Docker image, we also need to provide the Dockerfile of the Docker image.
```bash 
anchore-cli image add myimage/myimage:latest --dockerfile=/home/secops/myimage/Dockerfile
```

!!! info  
    - Anchore have a jenkins plugin : [here](https://plugins.jenkins.io/anchore-container-scanner) 
    - Anchore is compatible with Kubernetes Image Policy WebHook interface


### **Dagda**

#### Installation 

```bash 
git clone https://github.com/eliasgranderubio/dagda
pip install -r requirements.txt

# We need a mongoDB 
docker pull mongo
docker run -d -p 27017:27017 mongo

sudo apt-get -y install linux-headers-$(uname -r)
/usr/lib/dkms/dkms_autoinstaller start

python3 dagda.py
export DAGDA_HOST='127.0.0.1'
export DAGDA_PORT=5000

# populating database 
python3 dagda.py vuln --init
```

OR 

```bash 
docker-compose build
docker-compose up -d
```

### [Falco install](https://falco.org/docs/installation/)

You can install falco with a script: 
```bash
curl -o install-falco.sh -s https://s3.amazonaws.com/download.draios.com/stable/install-falco
sudo bash install-falco.sh
```

or with os packages : 
```bash 
curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add -
curl -s -o /etc/apt/sources.list.d/draios.list https://s3.amazonaws.com/download.draios.com/stable/deb/draios.list
apt-get update

sudo apt-get -y install linux-headers-$(uname -r)

sudo apt-get install -y falco
sudo service falco start 
```


## error encountered 

### Request repeated too quickly

```bash
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?


secops systemd[1]: Unit docker.service entered failed state.
secops systemd[1]: docker.service failed.
secops systemd[1]: start request repeated too quickly for docker.service
```

For fixing it : 
```bash 
mv /var/lib/docker  /tmp/
rm -f /var/lib/docker/
mkdir /var/lib/docker/
chmod go-r /var/lib/docker/
cd /var/lib/docker; mv /tmp/docker/*  .
systemctl restart docker
```