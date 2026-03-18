FROM kalilinux/kali-rolling:latest

COPY sources.list /etc/apt

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y vim iproute2 openssh-server nuclei kali-linux-headless

RUN sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/^#Port 22/Port 23/' /etc/ssh/sshd_config 
RUN ssh-keygen -t rsa -f /root/.ssh/id_rsa -N "" -q 
RUN echo 'root:root' | chpasswd
