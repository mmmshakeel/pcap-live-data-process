import dpkt
import socket
import pandas as pd
import time

def extract_features(pcap):
    features = []

    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            protocol = ip.p
            header_length = ip.hl * 4
            size = ip.len

            # TCP/UDP specific features
            if protocol == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                flags = tcp.flags
            elif protocol == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                flags = 0

            features.append({
                'Timestamp': ts,
                'Source IP': src,
                'Destination IP': dst,
                'Protocol': protocol,
                'Header Length': header_length,
                'Size': size,
                'Flags': flags,
            })
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    return features

def calculate_derived_features(df):
    df['flow_duration'] = df['Timestamp'].diff().fillna(0)
    df['Rate'] = df['Size'] / df['flow_duration']
    df['Srate'] = df.groupby('Source IP')['Size'].transform(lambda x: x / df['flow_duration'])
    df['Drate'] = df.groupby('Destination IP')['Size'].transform(lambda x: x / df['flow_duration'])
    df['Flags'] = df['Flags'].astype(str)
    df['IAT'] = df['Timestamp'].diff().fillna(0)
    df['Number'] = df.groupby(['Source IP', 'Destination IP']).cumcount() + 1
    df['Magnitude'] = df['Size'] * df['Rate']
    df['Radius'] = (df['Size'] ** 2 + df['Rate'] ** 2) ** 0.5
    df['Covariance'] = df['Size'].rolling(window=2).cov()
    df['Variance'] = df['Size'].rolling(window=2).var()
    df['Weight'] = df['Size'] * df['Number']

    return df

def main():
    pcap_file = os.getenv('PCAP_FILE')
    csv_file = os.getenv('CSV_FILE')

    with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            features = extract_features(pcap)

        df = pd.DataFrame(features)
        df = calculate_derived_features(df)

        df.to_csv(csv_file, index=False)

if __name__ == '__main__':
    main()
