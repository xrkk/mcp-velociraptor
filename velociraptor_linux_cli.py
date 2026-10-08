"""One bounded request through the production Linux registry; no listener."""
import argparse
import json
import sys
from velociraptor_linux_backend import LinuxTriageBackend
from velociraptor_linux_domain import register_linux_domain_tools, LinuxDomainError


class RegisteredLinuxClient:
    def __init__(self, deployment_root):
        self.handlers = {}
        self.backend = LinuxTriageBackend(deployment_root)
        register_linux_domain_tools(self, clients_provider=self.backend.clients, backend=self.backend)

    @classmethod
    def for_scope(cls, deployment_root, binding):
        from velociraptor_linux_scope import CurrentBootScopeProfessional
        client = cls.__new__(cls)
        client.handlers = {}
        client.scope_binding = dict(binding)
        client.backend = CurrentBootScopeProfessional(deployment_root, binding)
        register_linux_domain_tools(client, clients_provider=client.backend.clients, backend=client.backend)
        return client

    def add_tool(self, handler, *, name, description):
        if name in self.handlers:
            raise ValueError('duplicate tool')
        self.handlers[name] = handler

    def call(self, name, arguments):
        if hasattr(self, 'scope_binding') and (not name.startswith('linux_scope_')
                or any(arguments.get('request', {}).get(k) != v for k, v in self.scope_binding.items())):
            raise LinuxDomainError('FOREIGN_SCOPE', 'scope client is bound to one owner and session')
        if name not in self.handlers:
            raise LinuxDomainError('UNKNOWN_TOOL', 'unknown registered Linux tool')
        return self.handlers[name](**arguments)

    def collect(self, session_id, *, run_id, client_id, plan):
        return self.call('linux_triage_collect', dict(session_id=session_id, run_id=run_id, client_id=client_id, plan=plan))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment-root', required=True)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(1024*1024+1)
        if len(raw)>1024*1024:raise ValueError('request bound')
        request = json.loads(raw)
        if set(request)!={'tool','arguments'}:raise ValueError('request fields')
        result = RegisteredLinuxClient(args.deployment_root).call(request['tool'],request['arguments'])
        print(json.dumps({'ok':True,'result':result},ensure_ascii=False));return 0
    except Exception as error:
        print(json.dumps({'ok':False,'code':error.code if isinstance(error,LinuxDomainError) else type(error).__name__}));return 1


if __name__=='__main__':sys.exit(main())
