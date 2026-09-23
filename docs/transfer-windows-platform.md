# Windows transfer identity and read-only ACL adapter

`velo_transfer.windows_platform` supplies Windows observations and conservative ACL callbacks to the existing policy, store, and content APIs. It does not change ACLs, launch transfer workers, contact a VM, or report global transfer completion. Native APIs run only on Windows; Linux calls to production entry points raise `windows_platform_unsupported`.

## Identity

`observe_windows(timeout_seconds=10.0) -> WindowsObservation(os_name, vm_uuid, boot_identity)` runs one fixed PowerShell command from `GetSystemDirectoryW()/WindowsPowerShell/v1.0/powershell.exe` with `-NoLogo -NoProfile -NonInteractive`, `shell=False`, no stdin or caller script. It reads only local `Win32_ComputerSystemProduct.UUID` and `Win32_OperatingSystem.LastBootUpTime`, with a single instance required for each. The script converts boot time to fixed UTC text. The UUID is parsed and emitted as canonical lowercase hyphenated text without converting VMware VMX byte order. Missing, all-zero/all-one, malformed or multiple UUIDs, unknown boot time, bad JSON, duplicate keys, nonzero exit, timeout and output overflow fail closed. Two bounded pipe readers cap stdout and stderr independently at 4 KiB; the child is terminated/reaped on timeout or overflow. No raw command output or broad machine environment is logged. `boot_identity` is a SHA-256 identifier derived from the fixed UTC boot value and remains stable across service restarts on the same OS boot.

`observation.for_policy()` returns exactly `{"os_name":"Windows","vm_uuid":"..."}` for `load_policy(..., observation=...)`. The caller separately binds `observation.boot_identity` into its task and terminal protocol key, and supplies its already reviewed expected UUID to policy. The observation is local OS evidence, not a backend `client_id` or remote identity attestation.

## ACL verifier

`WindowsAclVerifier(extra_trusted_sids=())` reads the current process SID with `OpenProcessToken`/`GetTokenInformation(TokenUser)`, closing the token handle. Its default trusted SIDs are the current process user, LocalSystem `S-1-5-18`, and Builtin Administrators `S-1-5-32-544`. Additional service/account SIDs require an explicit deployment-controlled canonical SID list; no path or ordinary transfer request can extend it. The constructor rejects malformed or duplicate SID entries. Tests inject a private `_reader` and `_current_sid`; these are simulation hooks and must not be wired into deployed code.

`verifier(path, kind)` matches `load_policy(..., verify_windows_acl=verifier)` and the stored policy callback. Supported kinds are `policy`, `read_root`, `write_root`, `work`, `tasks`, `task`, `lock`, `state`, `stage`, `parent`. Unknown kinds reject. The one-argument `verifier.content_callback(stage, parent, destination=None)` maps stage to `stage`, parent to `parent`, and the optional post-rename final destination to `stage`; give `destination` when publishing. The same callback can be passed to `prepare_staging`, `unpack_bundle`, and `publish_directory` for one batch.

```python
from pathlib import Path
from velo_transfer.policy import load_policy
from velo_transfer.windows_platform import WindowsAclVerifier, observe_windows

observation = observe_windows()                 # real Windows only
acl = WindowsAclVerifier()                      # real process token and ACL reader
status = load_policy(Path(r"E:\protected\transfer-policy.json"),
                     observation=observation.for_policy(),
                     verify_windows_acl=acl)
if status.enabled:
    policy = status.policy
    # After durable stage intent, use exact batch paths:
    final = Path(r"E:\evidence\batch-1")
    stage = final.parent / ".velo-stage-batch-1"
    content_acl = acl.content_callback(stage, final.parent, final)
    # Pass content_acl to content-layer prepare/unpack/publish calls.
```

This snippet is an integration shape, not a runnable Linux example or an instruction to create the named paths. The test suite runs callback signature smoke checks with explicit simulated snapshots. Real Windows API smoke tests are platform-gated and remain unrun until the controller uses the target VM.

The verifier calls `GetNamedSecurityInfoW` with `OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION` for each existing component from volume root to target, and releases the returned security descriptor with `LocalFree`. It uses `GetAclInformation(AclSizeInformation)` and `GetAce` with bounded ACE count, ACL bytes and pointer checks. Only basic allow and deny ACEs with complete SID bodies are understood; callback/object/compound/unknown ACEs, unknown rights bits, absent or NULL DACL, unreadable owner and malformed structures reject. It checks actual `lstat` device/inode/mode/reparse identity and the owner/DACL snapshots before and after evaluation. A reparse point or change rejects.

Every path component must have a trusted owner and no untrusted *allow* ACE for evidence-changing rights: write/append/create, write EA/attributes, delete child or object, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE`, or `GENERIC_ALL`. An untrusted deny ACE does not cancel an untrusted allow. Inheritable and `INHERIT_ONLY` grants are conservatively considered because they can affect new children. For `work`, `tasks`, `task`, `lock`, `state`, `stage`, and `parent`, untrusted read grants also reject. Ordinary untrusted read/traverse grants on ancestors and on the nonsecret policy file do not by themselves reject. The root-chain rule may reject a deployment whose service account or protected system directory owner is outside the trusted SID set; an authorized deployment operator must inspect and explicitly allowlist that owner SID where justified. The adapter never fixes permissions or broadens a service account.

This is a conservative DACL test, not a proof against administrator, owner, same-account hostile mutation, privileges that override DACLs, or ACL races. The content and store still recheck identities at their own action boundaries. Real Windows ACL behavior and power-loss durability require target-side validation.

## Primary API references

- Microsoft: [Win32_ComputerSystemProduct.UUID](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystemproduct) is the SMBIOS Type 1 UUID; unavailable UUID can be all zeros. [Win32_OperatingSystem.LastBootUpTime](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem) is the last restart time.
- Microsoft: [GetSystemDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw) locates the system directory; [GetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow) returns owner/DACL pointers and a descriptor freed with `LocalFree`.
- Microsoft: [GetAclInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getaclinformation), [GetAce](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getace), [ACE_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header), and [ACCESS_ALLOWED_ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace) define ACE sizes, flags and mask/SID layout.
- Microsoft: [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation) defines `TokenUser` buffer retrieval; [File Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights) describes file and directory rights and inheritance.
