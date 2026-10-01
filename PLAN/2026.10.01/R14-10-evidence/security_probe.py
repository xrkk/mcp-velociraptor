import sys,json
from pathlib import Path
sys.path.insert(0,str(Path.cwd()))
from mcp.server import MCPServer
from starlette.testclient import TestClient
from velociraptor_transport import build_formal_http_app,resolve_transport_config
from velo_transfer.mcp_tools import TransferToolService
s=MCPServer('audit');s._guest_transfer_tools=TransferToolService()
c=resolve_transport_config({'VELOCIRAPTOR_MCP_TRANSPORT':'http','VELOCIRAPTOR_MCP_HOST':'127.0.0.1','VELOCIRAPTOR_MCP_BEARER_TOKEN':'audit-test'})
print(c)
app=build_formal_http_app(s,c);rows=[]
with TestClient(app) as client:
 for path in ['/mcp','/chunkbin']:
  for label,extra in [('bad_host',{'Host':'untrusted.invalid'}),('bad_origin',{'Host':'127.0.0.1:28790','Origin':'https://untrusted.invalid'})]:
   r=client.post(path,headers={'Authorization':'Bearer audit-test','Content-Type':'application/json','Accept':'application/json, text/event-stream',**extra},content=b'{}');rows.append({'path':path,'case':label,'status':r.status_code})
Path('.tmp/r14-independent-20261001/security-local.json').write_text(json.dumps(rows,indent=2));print(rows)
