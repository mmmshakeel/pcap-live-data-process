FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    tshark \
    python3 \
    python3-pip

# Copy scripts to the container
COPY scripts/run_tshark.sh /usr/local/bin/run_tshark.sh
COPY scripts/process_traffic.py /usr/local/bin/process_traffic.py

# Give execution permission
RUN chmod +x /usr/local/bin/run_tshark.sh

# Install Python dependencies
RUN pip3 install pandas

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/run_tshark.sh"]
