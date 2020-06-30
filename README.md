# chexit
Using a FortiGate configuration, checks a policy, and exits it in CSV.

## Either by VDOM and policy ID, spaced by columns
```
chexit -c CONFIGURATION -vp VDOM,POLID_1[:VDOM,POLID_2]

id|uuid|srcintf|dstintf|srcaddr|dstaddr|service
```

## Or by policy UUID, spaced by columns
```
chexit -c CONFIGURATION -u UUID_1[:UUID_2]
```
