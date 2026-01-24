FROM ubuntu:latest

# Install some libs
RUN apt-get update && apt-get install -y python3 socat && rm -rf /var/lib/apt/lists/*

# create ctf-user
RUN groupadd -r ctf && useradd -r -g ctf ctf

# add chall items
COPY flag.txt /home/ctf/flag.txt
COPY chall.py /home/ctf/chall.py

#set some proper permissions
RUN chown -R root:ctf /home/ctf
RUN chmod 750 /home/ctf/chall.py
RUN chmod 440 /home/ctf/flag.txt

# Switch to ctf user
USER ctf

# Set working directory
WORKDIR /home/ctf

# Expose the service on port 54321
EXPOSE 54321

# Run the challenge with socat
CMD ["socat", "TCP-LISTEN:54321,reuseaddr,fork", "EXEC:python3 /home/ctf/chall.py"]

