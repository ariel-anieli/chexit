# chexit
Using a FortiGate configuration, checks a policy, and exits it in JSON or CSV.

## Either by VDOM and policy ID, spaced by columns
```
chexit -c CONFIGURATION -vp VDOM_1,POLID_1[:VDOM_2,POLID_2] -f json | jq --slurp '.[0] | map_values(type)'
{
  "id": "number",
  "uuid": "string",
  "srcintf": "array",
  "dstintf": "array",
  "srcaddr": "array",
  "dstaddr": "array",
  "action": "array",
  "schedule": "array",
  "service": "array",
  "logtraffic": "string",
  "comments": "string"
}
```

## Or by policy UUID, spaced by columns
```
chexit -c CONFIGURATION -u UUID_1[:UUID_2] | jq --slurp '.[0] | map_values(type)'
{
  "id": "number",
  "uuid": "string",
  "srcintf": "array",
  "dstintf": "array",
  "srcaddr": "array",
  "dstaddr": "array",
  "action": "array",
  "schedule": "array",
  "service": "array",
  "logtraffic": "string",
  "comments": "string"
}
```
