# PcapTree
Simple Multiple Pcap analyzer implemented in Python 2. 

It was developed to analyze a large amount of pcap files that were captured from a network for an extended period of time.
The goal is that of providing quantitative analytics regarding the protocols used within the network spread among the different days.

# PcapTree Output
Pcap Tree outputs a .json file with the following structure:

```json
TODO
```

# Dependencies
to run PcapTree you need to install "scapy" library. (pip install scapy)

The implementation of PcapTree depends on the python implementation of capinfos available at the following repo https://gist.github.com/7h3rAm/225e36ad59729000e00e7814e9644622 Its code was incorporated inside this repo

# Note
The tool was used within a specific project therefore I am aware that the code is not clean (some parts should be fixed)

# TODO
Review code quality (several global variables that I don't like)
Refine analyzer of pcap output
Detect the change of day at packet level and not at pcap level
