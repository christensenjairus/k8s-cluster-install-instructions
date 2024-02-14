# K8S Cluster Install Instructions
My kubernetes cluster creation instructions using kubeadm with external etcd, containerd(cri), and cilium (cni).

### Using Version 1.28.6
(1.29 is out, but is new enough that it has an [unresolved issue](https://github.com/kube-vip/kube-vip/issues/684) with kube-vip)
https://kubernetes.io/releases/#release-v1-28
https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.28.md

### Pre-k8s docemuntation node preparation (copied from k3s install script)

```bash
sudo timedatectl set-timezone America/Denver
sudo apt-get install bash curl grep nfs-common open-iscsi lsscsi sg3-utils multipath-tools scsitools jq apparmor apparmor-utils iperf qemu-guest-agent -y
sudo systemctl enable open-iscsi
sudo systemctl enable iscsid
sudo systemctl enable multipathd
sudo systemctl enable qemu-guest-agent
sudo bash -c 'echo -e \"defaults {\\n    user_friendly_names yes\\n    find_multipaths yes\\n}\\nblacklist {\\n    devnode \\\"^sd[a-z0-9]+\\\"\\n}\" > /etc/multipath.conf'
sudo reboot
```

***
# ***TAKE SNAPSHOT***
```bash
./create_cluster_snapshot.sh beta initial_packages_installed "Installed qemu agent, iscsi and nfs packages"
```
***

### Start Installation
https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/

#### Install a Container Runtime (containerd)
https://kubernetes.io/docs/setup/production-environment/container-runtimes/

```bash
# forwarding ipv4 and letting iptables see bridged traffic
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

# sysctl params required by setup, params persist across reboots
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

# Apply sysctl params without reboot
sudo sysctl --system
```

### Install the Runtime with runc, systemd daemon, and a cri
```bash
# Install Containerd
CONTAINERD_VERSION=1.7.13
wget https://github.com/containerd/containerd/releases/download/v$CONTAINERD_VERSION/containerd-$CONTAINERD_VERSION-linux-amd64.tar.gz
sudo tar Cxzvf /usr/local containerd-$CONTAINERD_VERSION-linux-amd64.tar.gz

# Install systemd service for containerd
sudo wget https://raw.githubusercontent.com/containerd/containerd/main/containerd.service -O /usr/lib/systemd/system/containerd.service

# Install runc
RUNC_VERSION=1.1.12
wget https://github.com/opencontainers/runc/releases/download/v$RUNC_VERSION/runc.amd64
sudo install -m 755 runc.amd64 /usr/local/sbin/runc

# Install CRI Plugins
CNI_VERSION=v1.4.0
wget https://github.com/containernetworking/plugins/releases/download/$CNI_VERSION/cni-plugins-linux-amd64-$CNI_VERSION.tgz
sudo mkdir -p /opt/cni/bin
sudo tar Cxzvf /opt/cni/bin ~/cni-plugins-linux-amd64-$CNI_VERSION.tgz

# Create default containerd config
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml

# Setup cgroup drivers (will use systemd, not cgroupfs, because its native to Ubuntu)
sudo sed -i '/SystemdCgroup = false/s/false/true/' /etc/containerd/config.toml
sudo systemctl daemon-reload
sudo systemctl enable containerd
sudo systemctl restart containerd

# Clean up
sudo rm ~/cni-plugins-linux-amd64-$CNI_VERSION.tgz containerd-$CONTAINERD_VERSION-linux-amd64.tar.gz runc.amd64

# Ensure kubelet is always using correct interface
local_ip="$(ip --json addr show eth0 | jq -r '.[0].addr_info[] | select(.family == "inet") | .local')"
sudo tee /etc/default/kubelet << EOF
KUBELET_EXTRA_ARGS=--node-ip=$local_ip
EOF
```

### Install kubelet, kubectl and kubeadm
```bash
VERSION="1.28"
KUBERNETES_VERSION="1.28.6-1.1" # found this by running `sudo apt-cache madison kubeadm`

sudo apt-get update -y
sudo apt-get install -y apt-transport-https ca-certificates curl gpg
sudo mkdir -m 755 /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v$VERSION/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v$VERSION/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update -y
sudo apt-get install -y kubelet="$KUBERNETES_VERSION" kubectl="$KUBERNETES_VERSION" kubeadm="$KUBERNETES_VERSION"
sudo apt-mark hold kubelet kubeadm kubectl

# Create /etc/hosts record for ease of use by the cluster
VIP=10.0.0.110
VIP_HOSTNAME=kube-api-server
echo "${VIP} ${VIP_HOSTNAME}" | sudo tee -a /etc/cloud/templates/hosts.debian.tmpl | sudo tee -a /etc/hosts
```

### Prepare kube-vip (run on just the control plane nodes)
```bash
# Kube-VIP Manifest for master nodes
export KVVERSION=v0.7.0 # latest at the time of writing, but I wanted it to be static
export VIP="10.0.0.110"
export VIP_HOSTNAME=kube-api-server
export INTERFACE=eth0

sudo ctr image pull ghcr.io/kube-vip/kube-vip:$KVVERSION
sudo ctr run --rm --net-host ghcr.io/kube-vip/kube-vip:$KVVERSION vip /kube-vip manifest pod \
    --interface $INTERFACE \
    --address $VIP \
    --controlplane \
    --services \
    --arp \
    --leaderElection | sudo tee /etc/kubernetes/manifests/kube-vip.yaml
```

***
# ***TAKE SNAPSHOT***
```bash
./create_cluster_snapshot.sh beta kubeadm_packages_installed "Installed kubeadm, kubelet, and kubectl. Kube-Vip manifest created. Ready for etcd cluster creation."
```
***

# Create ETCD Cluster
Copy working ssh key onto first etcd node
```bash
# Create and share SSH key (from your personal pc) to first etcd node's root account
scp ~/.ssh/id_rsa line6@10.0.0.114:~/
ssh line6@10.0.0.114 "sudo mv ~/id_rsa /root/.ssh/id_rsa && sudo chown root:root /root/.ssh/id_rsa && sudo chmod 600 /root/.ssh/id_rsa"
```

Ensure ssh works from first etcd node
```bash
# SSH into first etcd node now and ensure that you can get in
sudo ssh line6@10.0.0.115 echo SSH Works!
sudo ssh line6@10.0.0.116 echo SSH Works!
```

 ### Configure kubelet to be service manager for etcd
 Run on every etc node
```bash
sudo mkdir -p /etc/systemd/system/kubelet.service.d/
cat << EOF | sudo tee /etc/systemd/system/kubelet.service.d/kubelet.conf
# Replace "systemd" with the cgroup driver of your container runtime. The default value in the kubelet is "cgroupfs".
# Replace the value of "containerRuntimeEndpoint" for a different container runtime if needed.
#
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: false
authorization:
  mode: AlwaysAllow
cgroupDriver: systemd
address: 127.0.0.1
containerRuntimeEndpoint: unix:///var/run/containerd/containerd.sock
staticPodPath: /etc/kubernetes/manifests
EOF

cat << EOF | sudo tee /etc/systemd/system/kubelet.service.d/20-etcd-service-manager.conf
[Service]
ExecStart=
ExecStart=/usr/bin/kubelet --config=/etc/systemd/system/kubelet.service.d/kubelet.conf
Restart=always
EOF

sudo systemctl daemon-reload
sudo systemctl restart kubelet
````

### Create the configuration files for kubeadm 
Run on just the first etcd node
```bash
# Update HOST0, HOST1 and HOST2 with the IPs of your hosts
export HOST0=10.0.0.114
export HOST1=10.0.0.115
export HOST2=10.0.0.116

# Update NAME0, NAME1 and NAME2 with the hostnames of your hosts
export NAME0="beta-k8s-etcd-1"
export NAME1="beta-k8s-etcd-2"
export NAME2="beta-k8s-etcd-3"

# Create temp directories to store files that will end up on other hosts
mkdir -p /tmp/${HOST0}/ /tmp/${HOST1}/ /tmp/${HOST2}/

HOSTS=(${HOST0} ${HOST1} ${HOST2})
NAMES=(${NAME0} ${NAME1} ${NAME2})

for i in "${!HOSTS[@]}"; do
HOST=${HOSTS[$i]}
NAME=${NAMES[$i]}
cat << EOF > /tmp/${HOST}/kubeadmcfg.yaml
---
apiVersion: "kubeadm.k8s.io/v1beta3"
kind: InitConfiguration
nodeRegistration:
    name: ${NAME}
localAPIEndpoint:
    advertiseAddress: ${HOST}
---
apiVersion: "kubeadm.k8s.io/v1beta3"
kind: ClusterConfiguration
etcd:
    local:
        serverCertSANs:
        - "${HOST}"
        peerCertSANs:
        - "${HOST}"
        extraArgs:
            initial-cluster: ${NAMES[0]}=https://${HOSTS[0]}:2380,${NAMES[1]}=https://${HOSTS[1]}:2380,${NAMES[2]}=https://${HOSTS[2]}:2380
            initial-cluster-state: new
            name: ${NAME}
            listen-peer-urls: https://${HOST}:2380
            listen-client-urls: https://${HOST}:2379
            advertise-client-urls: https://${HOST}:2379
            initial-advertise-peer-urls: https://${HOST}:2380
EOF
done
```

### Generate certificate authority, certificates, and copy them
Run on first etcd node
```bash
export HOST0=10.0.0.114
export HOST1=10.0.0.115
export HOST2=10.0.0.116

# Generate certificate authority
sudo kubeadm init phase certs etcd-ca

# Generate certificates for each member
sudo kubeadm init phase certs etcd-server --config=/tmp/${HOST2}/kubeadmcfg.yaml
sudo kubeadm init phase certs etcd-peer --config=/tmp/${HOST2}/kubeadmcfg.yaml
sudo kubeadm init phase certs etcd-healthcheck-client --config=/tmp/${HOST2}/kubeadmcfg.yaml
sudo kubeadm init phase certs apiserver-etcd-client --config=/tmp/${HOST2}/kubeadmcfg.yaml
sudo cp -R /etc/kubernetes/pki /tmp/${HOST2}/
# cleanup non-reusable certificates
sudo find /etc/kubernetes/pki -not -name ca.crt -not -name ca.key -type f -delete

sudo kubeadm init phase certs etcd-server --config=/tmp/${HOST1}/kubeadmcfg.yaml
sudo kubeadm init phase certs etcd-peer --config=/tmp/${HOST1}/kubeadmcfg.yaml
sudo kubeadm init phase certs etcd-healthcheck-client --config=/tmp/${HOST1}/kubeadmcfg.yaml
sudo kubeadm init phase certs apiserver-etcd-client --config=/tmp/${HOST1}/kubeadmcfg.yaml
sudo cp -R /etc/kubernetes/pki /tmp/${HOST1}/
sudo find /etc/kubernetes/pki -not -name ca.crt -not -name ca.key -type f -delete

sudo kubeadm init phase certs etcd-server --config=/tmp/${HOST0}/kubeadmcfg.yaml
sudo kubeadm init phase certs etcd-peer --config=/tmp/${HOST0}/kubeadmcfg.yaml
sudo kubeadm init phase certs etcd-healthcheck-client --config=/tmp/${HOST0}/kubeadmcfg.yaml
sudo kubeadm init phase certs apiserver-etcd-client --config=/tmp/${HOST0}/kubeadmcfg.yaml
# No need to move the certs because they are for HOST0

# clean up certs that should not be copied off this host
sudo find /tmp/${HOST2} -name ca.key -type f -delete
sudo find /tmp/${HOST1} -name ca.key -type f -delete

# Copy files to second and third etcd nodes
export USER=line6
export HOST=${HOST1}
sudo scp -r /tmp/${HOST}/* ${USER}@${HOST}:~/
sudo ssh ${USER}@${HOST} sudo chown -R root:root ~/pki
sudo ssh ${USER}@${HOST} sudo mv -f ~/pki /etc/kubernetes/

export HOST=${HOST2}
sudo scp -r /tmp/${HOST}/* ${USER}@${HOST}:~/
sudo ssh ${USER}@${HOST} sudo chown -R root:root ~/pki
sudo ssh ${USER}@${HOST} sudo mv -f ~/pki /etc/kubernetes/
```

### Create static pod manifests
On first node
```bash
sudo kubeadm init phase etcd local --config=/tmp/${HOST0}/kubeadmcfg.yaml
```

On second and third nodes
```bash
sudo kubeadm init phase etcd local --config=$HOME/kubeadmcfg.yaml
```

### See ETCD cluster health
Run on only first etcd node
```bash
# Install ETCDCTL to interact with the etcd cluster
ETCDCTL_VERSION=3.5.12
wget https://github.com/etcd-io/etcd/releases/download/v${ETCDCTL_VERSION}/etcd-v${ETCDCTL_VERSION}-linux-amd64.tar.gz
tar xzvf ./etcd-v$ETCDCTL_VERSION-linux-amd64.tar.gz
sudo install -o root -g root -m 0755 ./etcd-v$ETCDCTL_VERSION-linux-amd64/etcdctl /usr/local/bin/etcdctl
rm -r ./etcd-v$ETCDCTL_VERSION-linux-amd64*

# check health
export HOST0=10.0.0.114
export HOST1=10.0.0.115
export HOST2=10.0.0.116
alias cmd="sudo ETCDCTL_API=3 etcdctl \
--cert /etc/kubernetes/pki/etcd/peer.crt \
--key /etc/kubernetes/pki/etcd/peer.key \
--cacert /etc/kubernetes/pki/etcd/ca.crt"
cmd --endpoints https://${HOST0}:2379 endpoint health
cmd --endpoints https://${HOST1}:2379 endpoint health
cmd --endpoints https://${HOST2}:2379 endpoint health
```

Copy necessary files to the first control plane node
```bash
export USER=line6
export CONTROL_PLANE="$USER@10.0.0.111"
sudo scp /etc/kubernetes/pki/etcd/ca.crt "${CONTROL_PLANE}":~/
sudo scp /etc/kubernetes/pki/apiserver-etcd-client.crt "${CONTROL_PLANE}":~/
sudo scp /etc/kubernetes/pki/apiserver-etcd-client.key "${CONTROL_PLANE}":~/
sudo ssh "${CONTROL_PLANE}" "sudo mkdir -p /etc/kubernetes/pki/etcd && sudo mv ~/apiserver-etcd-client.crt ~/apiserver-etcd-client.key /etc/kubernetes/pki && sudo mv ~/ca.crt /etc/kubernetes/pki/etcd"

# remove ssh keys that we don't need anymore
sudo rm /root/.ssh/id_rsa
```

***
# ***TAKE SNAPSHOT***
```bash
./create_cluster_snapshot.sh beta etcd_cluster_running "Installed etcd cluster on etc nodes. All are healthy. Ready for k8s cluster creation."
```
***

# Create K8S Cluster
Create kubeadm config file on first control plane node
```bash
export VIP="10.0.0.110"
export VIP_HOSTNAME=kube-api-server
export CLUSTER_NAME="beta-k8s"
POD_CIDR="10.42.0.0/16" # default in k3s, may as well be consistent
SVC_CIDR="10.43.0.0/16" # default in k3s, may as well be consistent

cat << EOF > ~/kubeadm-config.yaml
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: v1.28.6
clusterName: $CLUSTER_NAME
controlPlaneEndpoint: "$VIP_HOSTNAME:6443"
apiServer:
  certSANs:
  - "$VIP"
  - "$CLUSTER_NAME"
  - "$CLUSTER_NAME.lan"
  - "$VIP_HOSTNAME"
  - "$VIP_HOSTNAME.lan"
networking:
  dnsDomain: cluster.local
  serviceSubnet: $SVC_CIDR
  podSubnet: $POD_CIDR
etcd:
  external:
    endpoints:
      - https://10.0.0.114:2379
      - https://10.0.0.115:2379
      - https://10.0.0.116:2379
    caFile: /etc/kubernetes/pki/etcd/ca.crt
    certFile: /etc/kubernetes/pki/apiserver-etcd-client.crt
    keyFile: /etc/kubernetes/pki/apiserver-etcd-client.key
EOF
```

Run kubeadm init to create cluster
```bash
# Initialize Cluster
sudo kubeadm init --config ~/kubeadm-config.yaml --upload-certs --skip-phases=addon/kube-proxy
```

### Add other control-plane and worker nodes (not etcd nodes)
Masters should join one at a time, in case the kube-vip master changes when a new one is added

Run output instructions
```bash
# Run instructions output from cluster creation
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

Nodes won't show up as 'Ready' until a CNI is installed, like Cilium

# Install Cilium
Run on only first control plane node
```bash
# get cilium cli
CILIUM_CLI_VERSION=v0.15.21
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}*

POD_CIDR="10.42.0.0/16" # default in k3s, may as well be consistent
cat << EOF > cilium.yaml
cluster:
  id: 0
  name: beta-k8s
envoy:
  enabled: true
encryption:
  nodeEncryption: true
ipv4:
  enabled: true
ipv6:
  enabled: false
ipam:
 mode: cluster-pool
 operator:
   clusterPoolIPv4MaskSize: 20
   clusterPoolIPv4PodCIDRList: 
     - "$POD_CIDR"
k8sServiceHost: 10.0.0.110
k8sServicePort: 6443
kubeProxyReplacement: strict
EOF

# install cilium
CILIUM_VERSION=v1.14.6
cilium install --version=$CILIUM_VERSION --helm-values cilium.yaml

# check cilium status until OK (takes close to a minute before its ready)
cilium status

# enable hubble
cilium enable hubble

# test hubble
cilium hubble port-forward&
hubble status

# optionally observe traffic
hubble observe
```

The nodes should one by one become 'Ready'

### Copy your kubeconfig to your personal PC
```bash
CLUSTER_NAME=beta-k8s
scp line6@10.0.0.111:~/.kube/config ~/.kube/$CLUSTER_NAME.kubeconfig
source ~/.zshrc

# Rename context (don't do until on personal computer)
kubectl config rename-context kubernetes-admin@$CLUSTER_NAME $CLUSTER_NAME
sed -i '' 's/kube-api-server/10.0.0.110/g' $HOME/.kube/$CLUSTER_NAME.kubeconfig
kubectl config use-context $CLUSTER_NAME
kubectl get nodes
```

***
# ***TAKE SNAPSHOT***
```bash
./create_cluster_snapshot.sh beta k8s_cluster_running "Installed k8s cluster on all nodes. Cilium installed with hubble & encryption."
```
***
