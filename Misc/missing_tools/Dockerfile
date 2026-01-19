# Use an official Ubuntu base image.
FROM ubuntu:latest

# Avoid interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server and other utilities.
RUN apt-get update && apt-get install -y \
    openssh-server \
    curl \
    vim \
    nano \
    less \
    python3 \
    && apt-get clean

# Create the SSH run directory.
RUN mkdir /var/run/sshd

# Create the CTF user and set the password.
RUN useradd -m ctf && echo "ctf:ctf" | chpasswd

# Add the flag file to the ctf user's home directory.
RUN echo "DSCCTF{M1SS1NG_T00LS_N0_PR0BL3M_2026}" > /home/ctf/flag.txt

# Remove common file reading commands to create the challenge
RUN rm /usr/bin/cat
RUN rm /bin/cat 2>/dev/null || true

# Configure SSH settings
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# Expose the SSH port.
EXPOSE 22

WORKDIR /home/ctf

# Start the SSH daemon and drop into a bash shell
CMD ["/usr/sbin/sshd", "-D"]