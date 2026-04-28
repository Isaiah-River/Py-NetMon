# 🐍 What is Py-NetMon?

This Python-NetMon is designed to monitor network traffic and detect intrusions based on
user-defined criteria. It provides the flexibility to specify filtering criteria such as target IP, target port, source 
IP, source port, and protocol to customize the detection process.

## 📦 Features

- Sniffs network packets using Scapy library.
- Allows users to set filtering criteria for intrusion detection.
- Detects intrusions based on specified criteria.
- Supports saving detected packets to either CSV or JSON format.
- Provides notifications for detected intrusions using Plyer library.

## ⬇️ Installation

### 1. 🔍 Requirements

Before installing the Py IDS system, ensure you have the following components installed:

- Python 3.x
- Scapy library
- Plyer library

You can install Python 3.x from the [official Python website](https://www.python.org/downloads/).

### 2. 📥 Installing Dependencies

You can install the required Python libraries using pip, the Python package manager. Open a terminal or command prompt 
and run the following commands:

```
pip install scapy
pip install plyer
```

## 🖱️ Using Py-NetMon

Py-NetMon is relatively simple to use. First select the output file you would like detected packets to be saved in (csv or 
json). After this, select the filter you would like to scan packets for (`options 1-5`). After providing the filter, 
select `option 6` to start a scan. This will detect packets in the background and alert your Windows system when a packet
matching the selected filter is found. `Option 7` can be selected in order to stop the scan. Finally, `option 8` will exit
the program, and export the detected packets into detected_packets.json/csv. Additionally, the ids_log.txt file will
contain logs detailing information about the detected packets, as well as Py IDS activity.

If you want to save detected_packets.csv or detected_packets.json, rename the captures, and drag and drop them into the 
detected_packets folder. Enjoy packet detecting! 
