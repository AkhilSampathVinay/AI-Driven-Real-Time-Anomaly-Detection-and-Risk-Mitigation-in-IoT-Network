# Sample captures

PCAP files are not committed (they are large and real captures can contain
private data). Generate the synthetic attack scenario with:

```bash
iot-guard generate samples/demo_attack.pcap          # benign traffic + 5 attacks
iot-guard generate samples/benign.pcap --benign-only # benign only
iot-guard analyze  samples/demo_attack.pcap
```

You can also open the file in Wireshark to inspect the attacks.
