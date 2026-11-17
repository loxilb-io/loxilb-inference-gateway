# L4 frontend port replacement

Run on a dedicated Docker test pair with BFD and the frontend on different
networks. Register a FullNAT VIP on a single MASTER and use a customer-side
probe that exits successfully only after receiving a valid response.

```sh
python3 validate.py --node test-l4-a --network test-front \
  --address 192.0.2.11 --vip 192.0.2.253 -- \
  curl --noproxy '*' -fsS --max-time 1 http://192.0.2.253:8080/
```

The case detaches and reattaches the active test node's frontend Docker
network. It requires the same name and a new kernel ifindex. The port API
and transmit map must reference the replacement, BFD and VIP ownership
must remain stable, and the client must recover. The case reports the
transmit-map recovery time. The MASTER re-advertises the affected IPv4
VIPs once after processing the new datapath binding. The normal periodic
advertisement remains available. The unit test separately
delivers the old ifindex's delete after reattachment.
