# Use an official Ubuntu base image with pinned version
FROM ubuntu:22.04

# Avoid interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server and other utilities.
RUN apt-get update && apt-get install -y \
    openssh-server \
    curl \
    python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create the SSH run directory.
RUN mkdir /var/run/sshd

# Create the CTF user and set the password.
RUN useradd -m ctf && echo "ctf:ctf" | chpasswd

# Copy the flag file to the ctf user's home directory (SECURITY: no longer hardcoded in Dockerfile)
COPY flag.txt /home/ctf/flag.txt

# Remove common file reading commands to create the challenge
RUN rm /usr/bin/cat
RUN rm /bin/cat 2>/dev/null || true

# Configure SSH settings for password authentication
# Remove the Ubuntu 22.04 default config that disables password auth
RUN rm -f /etc/ssh/sshd_config.d/*.conf && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config && \
    sed -i 's/KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#KbdInteractiveAuthentication yes/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM yes/' /etc/ssh/sshd_config

# Generate SSH host keys
RUN ssh-keygen -A

# Expose the SSH port.
EXPOSE 22

WORKDIR /home/ctf

# Start the SSH daemon and drop into a bash shell
CMD ["/usr/sbin/sshd", "-D"]