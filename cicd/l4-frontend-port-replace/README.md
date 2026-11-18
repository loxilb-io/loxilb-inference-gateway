# L4 frontend port replacement

Run on a dedicated Docker test pair with BFD and the frontend on different
networks. Register a FullNAT VIP on a single MASTER and use a customer-side
probe that exits successfully only after receiving a valid response. Use a
fixture that can hold a streaming response open for at least 12 seconds.
Run on the Docker host with permission to capture on the frontend bridge.

```sh
sudo python3 validate.py --node test-l4-a --network test-front \
  --address 192.0.2.11 --vip 192.0.2.253 --tcp-port 8080 \
  --stream-client-port 42201 --capture /tmp/frontend-replace.log \
  --stream-probe 'curl --noproxy "*" -fsS --local-port 42201 --max-time 20 http://192.0.2.253:8080/stream' \
  -- curl --noproxy '*' -fsS --max-time 1 http://192.0.2.253:8080/health
```

The case detaches and reattaches the active test node's frontend Docker
network. It requires the same name and a new kernel ifindex. The port API
and transmit map must reference the replacement within 5 seconds. BFD and
VIP ownership must remain stable. Within 8 seconds of disconnect, a new
connection must succeed with a SYN-ACK from the new MAC and the same TCP
flow opened before disconnect must send payload from the new MAC. The
stream must finish successfully, and subsequent responses in the capture
must continue to use the new MAC.

The MASTER uses the existing IPv4 VIP advertisement after the replacement
datapath work. The unit test also checks that the next hop is refreshed
before the cached source MAC is invalidated and that a late delete from
the old ifindex leaves the new port intact.
