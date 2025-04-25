import dpkt
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import tarfile
import io
import socket

# Function to read packets from a tar.gz file containing pcap files
def read_pcap_from_tar(file_path):
    packets = []
    with tarfile.open(file_path, 'r:gz') as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith('.pcap'):
                f = tar.extractfile(member)
                if f is not None:
                    pcap_content = f.read()
                    pcap_file = io.BytesIO(pcap_content)
                    pcap = dpkt.pcap.Reader(pcap_file)
                    for ts, buf in pcap:
                        packets.append((ts, buf))
    return packets

# Function to extract relevant packet information
def extract_packet_info(packets):
    packet_info_list = []
    for ts, buf in packets:
        eth = dpkt.ethernet.Ethernet(buf)
        packet_info = {
            'Source IP': None,
            'Destination IP': None,
            'Source Port': None,
            'Destination Port': None,
            'Protocol': 'Unknown',
            'Packet Size': len(buf)
        }
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            packet_info['Source IP'] = socket.inet_ntoa(ip.src)
            packet_info['Destination IP'] = socket.inet_ntoa(ip.dst)

            if isinstance(ip.data, dpkt.tcp.TCP):
                packet_info['Protocol'] = 'TCP'
                packet_info['Source Port'] = ip.data.sport
                packet_info['Destination Port'] = ip.data.dport
            elif isinstance(ip.data, dpkt.udp.UDP):
                packet_info['Protocol'] = 'UDP'
                packet_info['Source Port'] = ip.data.sport
                packet_info['Destination Port'] = ip.data.dport
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                packet_info['Protocol'] = 'ICMP'
        elif isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            packet_info['Protocol'] = 'ARP'
            packet_info['Source IP'] = socket.inet_ntoa(arp.spa)
            packet_info['Destination IP'] = socket.inet_ntoa(arp.tpa)

        packet_info_list.append(packet_info)

    return pd.DataFrame(packet_info_list)


def plot_distributions(df, data):

  plt.figure(figsize=(12, 8))

  plt.subplot(231)
  df[data].plot(kind='hist', title='Overall', color='#b24775');
  overall_mean = df[data].mean()
  overall_median = df[data].median()
  plt.axvline(overall_mean, color='blue', linestyle='dashed', linewidth=2, label=f'Mean: {overall_mean:.2f}')
  plt.axvline(overall_median, color='red', linestyle='dashed', linewidth=2, label=f'Median: {overall_median:.2f}')
  plt.legend()

  protocols = df['Protocol'].unique()
  positions = [232, 233, 234, 235, 236]

  for protocol, pos in zip(protocols, positions):
    df[df['Protocol'] == protocol][data].plot(kind='hist', title=protocol, color='#b24775', ax=plt.subplot(pos))
    protocol_mean = df[df['Protocol'] == protocol][data].mean()
    protocol_median = df[df['Protocol'] == protocol][data].median()
    plt.axvline(protocol_mean, color='blue', linestyle='dashed', linewidth=2, label=f'Mean: {protocol_mean:.2f}')
    plt.axvline(protocol_median, color='red', linestyle='dashed', linewidth=2, label=f'Median: {protocol_median:.2f}')
    plt.legend()

  # Adding an overall x-label
  plt.figtext(0.5, 0.04, data, ha='center', fontsize=14)

  plt.tight_layout(rect=[0.06, 0.06, 1, 0.95])
  plt.suptitle(data+' Distribution')
  plt.show()


# Function to categorize traffic by protocols and calculate aggregate metrics
def categorize_traffic_by_protocols(df):

    protocol_agg = df.groupby('Protocol').agg(
    Count =('Packet Size', 'count'),
    Traffic_Volume =('Packet Size', 'sum')).reset_index()

    protocol_agg['Percent'] = (protocol_agg['Traffic_Volume'] / protocol_agg['Traffic_Volume'].sum()) * 100


    return protocol_agg

# Function to plot Cumulative Distribution Functions (CDFs)
def plot_cdfs(df, data):
  grouped = df.groupby('Protocol')[data]


  plt.figure(figsize=(12, 8))

  all_packet_sizes = []

  i=231
  for protocol, group_data in grouped:
      sorted_data = np.sort(group_data)
      yvals = np.arange(len(sorted_data))/float(len(sorted_data)-1)
      plt.subplot(i)
      i+=1
      plt.plot(sorted_data, yvals, label=protocol)
      plt.title('CDF - '+protocol)


      all_packet_sizes.extend(sorted_data)


  # Calculating overall CDF
  all_packet_sizes = np.sort(all_packet_sizes)
  overall_yvals = np.arange(len(all_packet_sizes))/float(len(all_packet_sizes)-1)
  plt.subplot(236)
  plt.plot(all_packet_sizes, overall_yvals, label='Overall')

  plt.title('CDF - Overall')

  # Adding an overall x-label and y-label
  plt.figtext(0.5, 0.04, data, ha='center', fontsize=14)
  plt.figtext(0.04, 0.5, 'Cumulative Probability', va='center', rotation='vertical', fontsize=14)

  plt.tight_layout(rect=[0.06, 0.06, 1, 0.95])

  plt.show()


file_path = 'trace.tar.gz'
packets = read_pcap_from_tar(file_path)
print("Number of packets:", len(packets))

# Extract packet information and create a DataFrame
packet_info = extract_packet_info(packets)
print("Packets:")
print(packet_info)
print("\n")
print("Packets Summary:")
print(packet_info.describe())
print("\n")

# Plot distributions of packet sizes
plot_distributions(packet_info, 'Packet Size')

# Aggregate flow information and plot distributions of flow sizes
flow_info = packet_info.groupby(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol'],dropna=False).agg(
        {'Packet Size': 'sum'}).reset_index().rename(columns={'Packet Size': 'Flow Size'})
print("Flows:")
print(flow_info)
print("\n")
print("Flows Summary:")
print(flow_info.describe())
print("\n")


plot_distributions(flow_info, 'Flow Size')

# Plot flow counts per protocol
flow_counts = flow_info.groupby('Protocol').agg(
    Count =('Flow Size', 'count')).reset_index().sort_values(by='Count', ascending=False)
print("Flow Counts:")
print(flow_counts)
print("\n")

colors = ['cyan', '#ffdf9a', '#ff8d73', '#fe5377', '#b24775']

flow_counts.sort_values(by='Count').plot.barh(x='Protocol',
                                                    y='Count',
                                                    legend=False,
                                                    title = 'How many flows per protocol?',
                                                    xlabel='Count',
                                                    color = colors,
                                                    edgecolor='black');

flow_info = flow_info[flow_info['Flow Size']<1500]
plot_distributions(flow_info, 'Flow Size')
print("\n")


# Summarize traffic by protocol and plot
protocol_summary = categorize_traffic_by_protocols(packet_info)
print("Protocol Summary:")
print(protocol_summary)
print("\n")

colors = ['cyan', '#ffdf9a', '#ff8d73', '#fe5377', '#b24775']

protocol_summary.sort_values(by='Count').plot.barh(x='Protocol',
                                                    y='Count',
                                                    legend=False,
                                                    title = 'How many packets per protocol?',
                                                    xlabel='Count',
                                                    color = colors,
                                                    edgecolor='black');

protocol_summary.sort_values(by='Traffic_Volume').plot.barh(x='Protocol',
                                                    y='Traffic_Volume',
                                                    legend=False,
                                                    title = 'Traffic Volume per protocol',
                                                    xlabel='Traffic Volume',
                                                    color=colors,
                                                    edgecolor='black');

colors = ['#ff8d73', 'cyan', '#b24775', '#fe5377', '#ffdf9a']

protocol_summary.plot.pie(y='Traffic_Volume',
                           labels=protocol_summary['Protocol'],
                           autopct='%1.1f%%',
                           legend=False,
                           title='Traffic Volume %',
                           ylabel='',
                           colors = colors);

# Plot CDFs for packet sizes and flow sizes
plot_cdfs(packet_info, 'Packet Size')
plot_cdfs(flow_info, 'Flow Size')

