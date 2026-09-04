"""Atomic dynamic MCP tools for the approved Windows artifact set.

The allowlist binds both the artifact name and the exact root-org definition
reviewed in P01.  Runtime metadata may describe the public schema, but it may
not expand or silently replace that approved set.
"""

from __future__ import annotations

import hashlib
import inspect
import re
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Mapping

from jsonschema import Draft202012Validator
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult
from pydantic import Field, StrictBool, StrictFloat, StrictInt, StrictStr

from velociraptor_mcp_core import (
    FlowReferenceResult,
    InvalidArgumentError,
    TargetContext,
    VelociraptorBackend,
    error_result,
    success_result,
)


APPROVED_WINDOWS_ARTIFACTS: dict[str, str] = {
    "Windows.Analysis.EvidenceOfDownload": "4a94b436a7e70714480b3b07741f0baf98972d3b46853ed3afdf5c39386a55e6",
    "Windows.Applications.Chrome.Cookies": "bca618aee4e7114ab7b0ca6c1f7775dbda19dabcbca5332efa95b07f4bc25e76",
    "Windows.Applications.Chrome.Extensions": "f02fdf080be4f9f2f510c7730d0dc8d3fa401e3c228798d28d9399cf098a4ab5",
    "Windows.Applications.Chrome.History": "a8d2a1a73c1533a4faaebb88aa022bb2ce8b8b87ddfcaa3bfe6a7f5b5189540e",
    "Windows.Applications.Edge.History": "5d197d4f0cbe4a592a6b70713b1d0700d5575d6ae84ea77c49e74018f3776737",
    "Windows.Applications.OfficeMacros": "f5b8e5edc8e3c4712d1606bcbfa03d161e4f60bf5f4379336ffcf0e776a749dc",
    "Windows.Attack.Prefetch": "936e355b74cdde62e446a99441b4070bba4ced0c08ae87bea353bf323f7257c5",
    "Windows.Attack.UnexpectedImagePath": "1e18c1046cab0eea6605e6f7edf4d33b14df767484579c5917801a62dc5db04b",
    "Windows.Carving.CobaltStrike": "f6a2e5d3ed8ef5716e28d271850ca3251a4a93c3d2ff6190d633b351831e1ee0",
    "Windows.Detection.Amcache": "8e219980486e049924f99b2d665c06633911c2e8a276bce0b78add84b172e8e9",
    "Windows.Detection.BinaryHunter": "8fd86ce3a7c988d330581641f02d853f89cdf7eb98480505a05c19c5c00b01fe",
    "Windows.Detection.BinaryRename": "630e1188152e348f6ea881bcfcb362a83c4fc67a5b1aeb95ccf482009ab06eb5",
    "Windows.Detection.EnvironmentVariables": "7ee9c5a76e41941242df3f8e51aad0c1812962deff8f1dd5dcee7fcd0d5d09ba",
    "Windows.Detection.ForwardedImports": "db7a918cf67cb83a552cc27e177096de73102c1a5491096b010417187e945517",
    "Windows.Detection.Impersonation": "dffe1142df9eab202f336f80db6ca45db1f67be12d6e1434e809d09fdcd0b1a7",
    "Windows.Detection.Mutants": "b3ba8da81a234b896c5a4e9d42dda2b4b3a94d58be259e3e155c1cd43390abc7",
    "Windows.Detection.TemplateInjection": "646d761eb974fba37b27beed7723da7d53847c7f35907d1f62337218cfefd8dc",
    "Windows.Detection.Yara.NTFS": "c6fd9b24dc56bd72144f4d71d3df75a45971f35fdc64b68e039050f19fe788de",
    "Windows.Detection.Yara.PhysicalMemory": "26382863cea9de1093385b3e22170e76fdd1c79c86df4d288021cf9c9c693c39",
    "Windows.Detection.Yara.Process": "6fb17846fc04e08d28a520e8bff792474eeb82e92c07f23b2b5328cebf429ec0",
    "Windows.ETW.DotNetRundown": "44408a32c5e6eae78df73669c583e3162fe9f677aa2a66abdd5e9c2140dd4603",
    "Windows.EventLogs.AlternateLogon": "6f1b5951ddcced71b7fbeff80cd4daf05581d5fe6b309da41a1f13e6bc8c6063",
    "Windows.EventLogs.Cleared": "1d1fb515c1351d96f0b875bc7942c60df300406e956c88cb058ade8f88b06a39",
    "Windows.EventLogs.Evtx": "85ede504e2817eda3cbfa1320922b4d7251004175c0d68fcb58f3dd4116c71b7",
    "Windows.EventLogs.EvtxHunter": "f7d3f45386a20f5fc2c4b8e48e3f212f8b1db46586838abe91f659679e257574",
    "Windows.EventLogs.ExplicitLogon": "c43f7940ca5156defbcf2331ddbb6f1ec13037151c157258d96b4914be4ae6bb",
    "Windows.EventLogs.Modifications": "d411d71dbc4ae3ad6a892d864405f5dfe1e8882305c43d56dbddf6ab8cdc19ba",
    "Windows.EventLogs.PowershellModule": "ec716203f4d4eb2d731882d9daa1c1f6f5819dbb7ab5f38ae999e81330199f91",
    "Windows.EventLogs.PowershellScriptblock": "948c1e0e944906d429f8c7fbae18a60bff491b9aed64eeed5c6f325cad1b3c96",
    "Windows.EventLogs.RDPAuth": "b2b94196dd7cba027345ed80ad11cda041abed9c3c8f3bf885c7f223c68ca4e2",
    "Windows.EventLogs.ScheduledTasks": "50e85a76f629096c51b07ba9311918f0623d25daf7255fa8a541b9895ad3f532",
    "Windows.EventLogs.ServiceCreationComspec": "1c4521e27eb3c01686a5bdbd025379e6d8a3a82e9b1e2812b7904c7f46913140",
    "Windows.Forensics.Amcache": "410504c343352a3b58b1777f9facde19ca5892fbdf43de60c797fc972f9ddaa7",
    "Windows.Forensics.Bam": "c4730ad02aa145e4299702c8a603c01c2da33436def982c000aed545345c9064",
    "Windows.Forensics.CertUtil": "18391bbf9ecd2109bb4e8d142320d71e375a5e516d6f33727a111e54c1108e8c",
    "Windows.Forensics.FilenameSearch": "c7e06c797a5cb436ea0bb755313be13d4fa83d04fc09d1e519355fd23ab8d4b3",
    "Windows.Forensics.JumpLists": "91b3afafd55c9f79c488fecc549829168277184e1e6a37bbcd61adf8f1057bb6",
    "Windows.Forensics.Lnk": "1d07847fc1087df20ce420ea279a99b7b96b4fa9181407c5928555ccfec56695",
    "Windows.Forensics.Prefetch": "e029f063777e2df810a51a69db993a603f943757ead7836cd759f2d6dbf0fa47",
    "Windows.Forensics.RecentApps": "40945dd7ae534189b7357c309ce0b16cffd318018d8e4e4499e8e44607a53315",
    "Windows.Forensics.RecycleBin": "068ee802c83d03e08b22f9c57120fe390747d8a6b8186d91c0da8edb5a430bc7",
    "Windows.Forensics.SAM.Enriched": "6161565d7fd37287d8618fbe76b025fbcbf0d711740d25209ed6b08df5eab61a",
    "Windows.Forensics.SRUM": "c217e2772bb271f40c88cb74cb6c6f88b834282be99402b46113a87456b45b92",
    "Windows.Forensics.Shellbags": "2410b15c631b1c2644feaf576f7c7a35edb73cb05bd3da3b84448112afc85565",
    "Windows.Forensics.Timeline": "ccfdd2ade72d35a585995f1ed36dfc7889c66a5dcbb6c53000fd972a9e651571",
    "Windows.Forensics.Usn": "bc289343b0861e3f61d31dbd73e666cb9383958cc06e3de6a3f6a5640f19405f",
    "Windows.Memory.Acquisition": "9d17f920cf454d974386290c19f7d2f82f8da8aa7029a6c4b4e6dd7a729f55aa",
    "Windows.Memory.PEDump": "a190a247be2aca7cd336fa733db14c4fd76abee24732720e4b2daa4ceb94d684",
    "Windows.Memory.ProcessDump": "6feffad1f4e0fc75c6f220ae40abb3db5bfdb34fe4ae0d42c52a7c14e6365cd5",
    "Windows.Memory.ProcessInfo": "d90df808445b5564965bff5b49d7c3291798db347f989c5dcac34cee753b4d45",
    "Windows.NTFS.ADSHunter": "362551ccf03243922118dc7c194d9009417bd7f6272324eec5fcd72cd31509a7",
    "Windows.NTFS.ExtendedAttributes": "f5597d9be325d3237c9c5fde7c3c06ed0d6802cf0cd8457eab5dca5fb6b6d419",
    "Windows.NTFS.I30": "206a2a21465054ab1d2701d169c69c268ad217e3b33b09c7a438def37f94ee48",
    "Windows.NTFS.MFT": "06bf6dac1ded88b3e5a12e94a74799752f6f086bffc2156959f58bbe1106aaa1",
    "Windows.NTFS.Recover": "9af80759f3c18841bd58d6dc55a8ee94298acf1f0263c0a9224c6a6dad8ce99b",
    "Windows.Network.ArpCache": "60254ca2629ff8b91d4cda86f980da7323f494d1dd267f7f90ae5b7b29ad8e52",
    "Windows.Network.ListeningPorts": "b6c4b5800c4407d5fbdd39d0e83a6e6b8074d5c4cf01b594ab72e80836e58b0e",
    "Windows.Network.Netstat": "84d65deb8d4c4ecdc9e4714d767816b4d0001265d628e57b0021ff09f4cae4ab",
    "Windows.Network.NetstatEnriched": "51ce6fd17b68f2bd81222237c2738e8eb438938261e4f0468cfab8f645fe28a6",
    "Windows.Network.PacketCapture": "a5a323def546715bf1071ba72d14affd83761b50132a78a0ffeac53db614f514",
    "Windows.Packs.Persistence": "add9cb96ef8f9b0a62910f0109d0c98bc61d74adb1c50fb274a5ac0a670981ff",
    "Windows.Persistence.Debug": "d4ed00f181dbf63066d372dd5e5649ff08df6321e6437aa11b3d08dda3a8d2cd",
    "Windows.Persistence.PermanentWMIEvents": "b5056110fb4a455e7473fba4cf9366f845d99a3494c2353b74409b07b29b2401",
    "Windows.Persistence.PowershellProfile": "698ab017d6540786aa1faa5d9ef7be5f7d53711272b1dd7a69d4fc63f1be029a",
    "Windows.Persistence.PowershellRegistry": "b9a2f293153200200c8cca0e55bac6c18ef13ec14c2771e9155f0420c7976021",
    "Windows.Persistence.Wow64cpu": "bb2007ea6e01c658214ca363747181ed0f98c5f617202d1c05b85ec6093785cc",
    "Windows.Registry.AppCompatCache": "bef8a12366dca17a82a31c60144e7e4fedf54eddca280c51dc5dbbe451eb2bdc",
    "Windows.Registry.BackupRestore": "56132bd6dda7429a3295558d5198f9c28f3fe28256ddd473ebbf750cbb6bddda",
    "Windows.Registry.EnableUnsafeClientMailRules": "ee6b8add64a537fe2603e25d929ee5ff25aad6d591e385d1bec237a62b6fe770",
    "Windows.Registry.EnabledMacro": "2b54584356dc65b5d1284a062c058f0d382e3a5494ef896710f1828257dba774",
    "Windows.Registry.NTUser": "443b2e13d2f5e342a2d47bf8d2ca22c00adfbf231fd6e40586dff570ae540df6",
    "Windows.Registry.NTUser.Upload": "94b4b738f4909a6727c20517a3f652b711b203acee3188196017f3e7ceb57114",
    "Windows.Registry.PortProxy": "fe8f721691ee64e59e0c689c0d4a5c22fc67d936c0346d10cf494e1904681b2e",
    "Windows.Registry.RDP": "abf44a69d3f7a495e68e663e9a93269bcf321aba32a7b223928477885644f731",
    "Windows.Registry.RecentDocs": "659f93e80e3a5fb1a3686cc9671bc6739a0e433a033803f604630777fce08ad7",
    "Windows.Registry.UserAssist": "0adfb933dba053f39eb1c2e1c9da32d3c142ee35acfdd6b977abeb755dab2b96",
    "Windows.Registry.WDigest": "b11c7ce40091bce10f976aa8e5b58d26e26b88624c41b385861a2c0ac6441fd6",
    "Windows.Search.FileFinder": "9ad1a0d7831f8b94635757b49de1cd864a949a4fdf1ad7d96a5bf9bc8a14f91f",
    "Windows.Search.VSS": "c1e610d76f7180d8f4335bc9df93e66137d7dfceb32c0b50c4f189f09a57c46f",
    "Windows.Search.Yara": "462ed1bd9445033cc4ec85332ac8a5c7c8de77226283e5e264688aab5869249d",
    "Windows.Sys.AllUsers": "2c56abee0a5e5ee1b7c0c97136541af2ae3252957971cd30c8ff7356dfd8b1ad",
    "Windows.Sys.AppcompatShims": "f6d79a402f6622c1a726f18747127bcbbdf35e4f8513049f750a40b6d4c674e6",
    "Windows.Sys.CertificateAuthorities": "6f8ddc6e26cde8c513cff75d433155fb93f9876e92d8c38a1e46983e2282d266",
    "Windows.Sys.DiskInfo": "0516b67c7e11820d1abf1d2fa69b9e7d4d4c0989e30257e2e073957fa77fd563",
    "Windows.Sys.Drivers": "c2209c2dadfe48c554b38221b63ec06cae7db705e74875e92e5bba10ae91e2f8",
    "Windows.Sys.FirewallRules": "3c5c7ac240ff701e4a7eae995fe66880add2b177b8997b35c1eeffc8348e4239",
    "Windows.Sys.Interfaces": "0e47ccaaa48e369163d153a4889123ca7086c38f0bc5ffe0c57db55475ea15ad",
    "Windows.Sys.Programs": "2e10d84e6a503036ed2f724c4aceaa4fe21f771546a7ff1a1a7a6d5c6cf55412",
    "Windows.Sys.StartupItems": "b1096fef391dcf5a362de8000a1ffc8a2f558d1d3ffe441c909486c0be5b1a34",
    "Windows.Sys.Users": "88fe9532c485e092dab2d91ac889ea1636544a29c2ff6b4c2eb51fe385316f19",
    "Windows.Sysinternals.Autoruns": "dc47e8eb8ec90a502b6820e7ba761b97d226822e74a997fda5670c407ba2a60b",
    "Windows.System.AuditPolicy": "0e6ac74409265968c64e7d0cb1665a16cf23859162048b2047551a90d7887242",
    "Windows.System.CatFiles": "d0fd62db931f11db1e0cef64a08dd71921abd336ae7f142f31956bf391fefffe",
    "Windows.System.CmdShell": "49acc26ff4f3d2484ecf08a11fcfb0cb6a8e2132ef382af72135715e278277f6",
    "Windows.System.CriticalServices": "73f26a1681be0bf066deba11be73630284009c4d12e007b5f95c687ac4c58284",
    "Windows.System.DLLs": "7b0abd2456b65ed28ced2ca7ed2fcf44e7c1efa5bdd171dc48e6c182e498243e",
    "Windows.System.DNSCache": "88f8012c3e75c85cc8df2f0d3b2f82534c391d02cf2af71a79f5b72d9ce1ec26",
    "Windows.System.DomainRole": "fb242a92ff3a94afd8dc25de613d2c46c94254a7207884888f9e904b7fe7c2ba",
    "Windows.System.Handles": "98c9f431d48845afa10643c4dbb1b0b590e38e83fc63f27412b5657765b86791",
    "Windows.System.HostsFile": "761ac9333ab683caa2e08300fd446ddda7e82aa915b11603092babd2e0f6855b",
    "Windows.System.LocalAdmins": "b2bf7de503e4335e4a2ca024a8dc17be29cb3c0f61bfa875e04eea98067a0b85",
    "Windows.System.PowerShell": "47966b06e31ee16944dbfe9ad93afce5412d4d3100c0ef69122f28d3cb0651cd",
    "Windows.System.Powershell.ModuleAnalysisCache": "86db2e603d11f7938a7591db950bb62b61f2e1294eda051745484a8faaa8e161",
    "Windows.System.Powershell.PSReadline": "837cce513397d11b18a7000789d310d668c40bca35c00ea33b11ae491cfaf6be",
    "Windows.System.Pslist": "954142cf1a2c7a88182a06dee0ee121e1468ee3a7b35e6db3cd9bb405da9fdae",
    "Windows.System.RootCAStore": "276455208041a2ebcbc1866f3e2d973a3d2c065e8773b9783fe6d24122a7485f",
    "Windows.System.SVCHost": "b88ef4b0aaa26b6ada1cfeae708ce8d6dca994e2630eb296635acd72446d97dd",
    "Windows.System.Services": "c3bb373f74def7b730888556fa9d00f4c8ef3e72482052eec88400b77a77a6b6",
    "Windows.System.Shares": "7c4102a61a655502afe563230d12e135c95d1bcaea9a86ea0a25d281883487dc",
    "Windows.System.Signers": "023970644cea4d9f84217f806e9722423df79f2748094633eab168d179373786",
    "Windows.System.TaskScheduler": "a6cf0fe5dd1d16cef5ff3ea66b070672cdfb57b887706da32e87f878e8c75dc9",
    "Windows.System.Threads": "5974e9bd730f03e95d72be3cd8eef9ab73ebf9d8ffece61b771ecd850ff0464c",
    "Windows.System.UntrustedBinaries": "abe64307fde888bbcb75708062a22c32d9e15d05d84edd836749bbeb77e30938",
    "Windows.System.VAD": "22578a16e34ed14cd922b6a41301fb6ae88a96169fdcace23878259a6e0e8b1e",
    "Windows.System.WMIQuery": "a7efb1d1e4fe6ee6830df40578559c11d0bd58834165c944e11aeda3961f789d",
    "Windows.Timeline.MFT": "00bd10ffe9729d262f83308bffacc7e9ab5a0afbd8b2924ca8eeb08367459b84",
    "Windows.Timeline.Prefetch": "5d3d61e1eedab30178b36f592164bff697c05c557c41cf15f6e114853165281b",
    "Windows.Timeline.Registry.RunMRU": "93fd06a35ab2f9ac2d526ae26c947e80f2a61ac7ab9eeb92d25f6b1df8ff7d3f",
}

EXCLUDED_PARAMETER_TYPES = frozenset({"hidden", "upload", "upload_file"})
SUPPORTED_PARAMETER_TYPES = frozenset(
    {"", "string", "regex", "yara", "timestamp", "csv", "bool", "int", "int64", "float", "choices", "multichoice"}
)
YARA_ARTIFACTS = frozenset(
    {
        "Windows.Detection.Yara.NTFS",
        "Windows.Detection.Yara.PhysicalMemory",
        "Windows.Detection.Yara.Process",
    }
)
DEPENDENCY_WARNINGS = {
    "Windows.Sysinternals.Autoruns": "Terminal success requires the approved Sysinternals binary to be cached by Velociraptor.",
    "Windows.Network.PacketCapture": "Terminal success may require Velociraptor's approved packet-conversion tool dependency; this call does not enable networking.",
}


class ArtifactRegistryError(RuntimeError):
    """Safe startup failure; messages contain names/hashes, never raw definitions."""


@dataclass(frozen=True)
class ArtifactParameterSpec:
    name: str
    kind: str
    default: Any
    description: str
    friendly_name: str
    choices: tuple[str, ...]
    validating_regex: str

    @property
    def exposed(self) -> bool:
        return self.kind not in EXCLUDED_PARAMETER_TYPES


@dataclass(frozen=True)
class ArtifactSpec:
    name: str
    description: str
    definition_sha256: str
    parameters: tuple[ArtifactParameterSpec, ...]

    @property
    def exposed_parameters(self) -> tuple[ArtifactParameterSpec, ...]:
        return tuple(parameter for parameter in self.parameters if parameter.exposed)


def definition_sha256(raw_definition: str) -> str:
    if not isinstance(raw_definition, str):
        raise ArtifactRegistryError("approved artifact definition has no raw text")
    return hashlib.sha256(raw_definition.encode("utf-8")).hexdigest()


def _parameter_spec(artifact_name: str, raw: Mapping[str, Any]) -> ArtifactParameterSpec:
    if not isinstance(raw, Mapping):
        raise ArtifactRegistryError(f"artifact {artifact_name} has a non-object parameter")
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise ArtifactRegistryError(f"artifact {artifact_name} has an empty parameter name")
    if "`" in name or any(ord(character) < 32 for character in name):
        raise ArtifactRegistryError(f"artifact {artifact_name} has an unsafe parameter name")

    kind = raw.get("type") or ""
    if not isinstance(kind, str):
        raise ArtifactRegistryError(f"artifact {artifact_name} parameter {name} has a non-text type")
    kind = kind.lower()
    if kind not in SUPPORTED_PARAMETER_TYPES and kind not in EXCLUDED_PARAMETER_TYPES:
        raise ArtifactRegistryError(f"artifact {artifact_name} parameter {name} has unsupported type {kind!r}")

    choices_value = raw.get("choices") or []
    if not isinstance(choices_value, list) or any(not isinstance(choice, str) for choice in choices_value):
        raise ArtifactRegistryError(f"artifact {artifact_name} parameter {name} has invalid choices")
    choices = tuple(choices_value)
    if len(set(choices)) != len(choices):
        raise ArtifactRegistryError(f"artifact {artifact_name} parameter {name} has duplicate choices")
    if kind in {"choices", "multichoice"} and not choices:
        raise ArtifactRegistryError(f"artifact {artifact_name} parameter {name} has no choices")

    validating_regex = raw.get("validating_regex") or ""
    if not isinstance(validating_regex, str):
        raise ArtifactRegistryError(f"artifact {artifact_name} parameter {name} has invalid validating_regex")
    if validating_regex:
        try:
            re.compile(validating_regex)
        except re.error as exc:
            raise ArtifactRegistryError(
                f"artifact {artifact_name} parameter {name} has invalid validating_regex"
            ) from exc

    if artifact_name in YARA_ARTIFACTS and name == "YaraUrl":
        kind = "upload"

    return ArtifactParameterSpec(
        name=name,
        kind=kind,
        default=raw.get("default", ""),
        description=str(raw.get("description") or ""),
        friendly_name=str(raw.get("friendly_name") or ""),
        choices=choices,
        validating_regex=validating_regex,
    )


def validate_artifact_definitions(
    rows: list[dict[str, Any]],
    approved: Mapping[str, str] = APPROVED_WINDOWS_ARTIFACTS,
) -> tuple[ArtifactSpec, ...]:
    if not isinstance(rows, list):
        raise ArtifactRegistryError("root artifact metadata is not a list")
    by_name: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ArtifactRegistryError("root artifact metadata contains a non-object row")
        name = row.get("name")
        if name in approved:
            if name in by_name:
                duplicates.add(str(name))
            by_name[str(name)] = row
    if duplicates:
        raise ArtifactRegistryError("duplicate approved artifacts: " + ", ".join(sorted(duplicates)))

    missing = sorted(set(approved) - set(by_name))
    if missing:
        raise ArtifactRegistryError("missing approved artifacts: " + ", ".join(missing))

    specs: list[ArtifactSpec] = []
    for name, expected_hash in approved.items():
        row = by_name[name]
        artifact_type = row.get("type")
        if not isinstance(artifact_type, str) or artifact_type.upper() != "CLIENT":
            raise ArtifactRegistryError(f"approved artifact {name} is not CLIENT")
        raw_definition = row.get("raw")
        actual_hash = definition_sha256(raw_definition)
        if actual_hash != expected_hash:
            raise ArtifactRegistryError(
                f"approved artifact {name} definition changed: expected {expected_hash}, actual {actual_hash}"
            )
        parameters_value = row.get("parameters") or []
        if not isinstance(parameters_value, list):
            raise ArtifactRegistryError(f"artifact {name} parameters are not a list")
        parameters = tuple(_parameter_spec(name, parameter) for parameter in parameters_value)
        parameter_names = [parameter.name for parameter in parameters]
        if len(set(parameter_names)) != len(parameter_names):
            raise ArtifactRegistryError(f"artifact {name} has duplicate parameter names")
        specs.append(
            ArtifactSpec(
                name=name,
                description=str(row.get("description") or ""),
                definition_sha256=actual_hash,
                parameters=parameters,
            )
        )
    return tuple(specs)


def _literal_type(choices: tuple[str, ...]) -> Any:
    return Literal.__getitem__(choices)


def _parameter_annotation(parameter: ArtifactParameterSpec) -> Any:
    if parameter.kind in {"", "string", "regex", "yara", "timestamp", "csv"}:
        annotation: Any = StrictStr
    elif parameter.kind == "bool":
        annotation = StrictBool
    elif parameter.kind in {"int", "int64"}:
        annotation = StrictInt
    elif parameter.kind == "float":
        annotation = StrictFloat
    elif parameter.kind == "choices":
        annotation = _literal_type(parameter.choices)
    elif parameter.kind == "multichoice":
        annotation = list[_literal_type(parameter.choices)]
    else:  # pragma: no cover - registry validation makes this unreachable
        raise ArtifactRegistryError(f"unsupported public parameter type {parameter.kind!r}")

    schema_extra: dict[str, Any] = {
        "x-velociraptor-type": parameter.kind,
        "x-velociraptor-default": parameter.default,
    }
    formats = {
        "regex": "regex",
        "yara": "yara",
        "timestamp": "velociraptor-timestamp",
        "csv": "text/csv",
    }
    if parameter.kind in formats:
        schema_extra["format"] = formats[parameter.kind]
    field_kwargs: dict[str, Any] = {
        "alias": parameter.name,
        "title": parameter.friendly_name or parameter.name,
        "description": parameter.description,
        "json_schema_extra": schema_extra,
    }
    if parameter.validating_regex:
        field_kwargs["pattern"] = parameter.validating_regex
    return Annotated[annotation, Field(**field_kwargs)]


def _validate_runtime_parameters(
    spec: ArtifactSpec, arguments: Mapping[str, Any]
) -> dict[str, Any]:
    public = {parameter.name: parameter for parameter in spec.exposed_parameters}
    normalized: dict[str, Any] = {}
    for name, value in arguments.items():
        if value is None:
            continue
        parameter = public.get(name)
        if parameter is None:
            raise InvalidArgumentError(details={"field": name, "reason": "unknown"})
        if parameter.kind == "regex":
            try:
                re.compile(value)
            except re.error as exc:
                raise InvalidArgumentError(details={"field": name, "reason": "regex"}) from exc
        if parameter.validating_regex and re.search(parameter.validating_regex, value) is None:
            raise InvalidArgumentError(details={"field": name, "reason": "pattern"})
        normalized[name] = value
    return normalized


def make_artifact_handler(
    spec: ArtifactSpec,
    target: TargetContext,
    backend: VelociraptorBackend,
    *,
    index: int,
):
    def handler(**arguments: Any) -> Annotated[CallToolResult, FlowReferenceResult]:
        try:
            parameters = _validate_runtime_parameters(spec, arguments)
            flow = target.run_with_client(
                lambda client_id: backend.start_collection(
                    client_id,
                    spec.name,
                    parameters or None,
                )
            )
            public_flow = flow.model_copy(
                update={
                    "operation": "start_artifact_collection",
                    "warnings": [DEPENDENCY_WARNINGS[spec.name]]
                    if spec.name in DEPENDENCY_WARNINGS
                    else [],
                }
            )
            return success_result(public_flow)
        except Exception as exc:
            return error_result(exc, operation="start_artifact_collection")

    handler.__name__ = f"dynamic_artifact_{index:03d}"
    handler.__doc__ = spec.description
    handler.__signature__ = inspect.Signature(
        parameters=[
            inspect.Parameter(
                f"p{parameter_index}",
                inspect.Parameter.KEYWORD_ONLY,
                default=None,
                annotation=_parameter_annotation(parameter),
            )
            for parameter_index, parameter in enumerate(spec.exposed_parameters)
        ],
        return_annotation=Annotated[CallToolResult, FlowReferenceResult],
    )
    return handler


def _strict_tool_schema(tool: Any) -> None:
    tool.fn_metadata.arg_model.model_config["extra"] = "forbid"
    tool.fn_metadata.arg_model.model_rebuild(force=True)
    tool.parameters = tool.fn_metadata.arg_model.model_json_schema(by_alias=True)
    for property_schema in tool.parameters.get("properties", {}).values():
        property_schema.pop("default", None)
    Draft202012Validator.check_schema(tool.parameters)
    if tool.fn_metadata.output_schema is None:
        raise ArtifactRegistryError(f"tool {tool.name} has no output schema")
    Draft202012Validator.check_schema(tool.fn_metadata.output_schema)


def _register_on_server(
    server: MCPServer,
    specs: tuple[ArtifactSpec, ...],
    target: TargetContext,
    backend: VelociraptorBackend,
) -> None:
    for index, spec in enumerate(specs):
        handler = make_artifact_handler(spec, target, backend, index=index)
        server.add_tool(handler, name=spec.name, description=spec.description)
        tool = server._tool_manager.get_tool(spec.name)
        if tool is None:
            raise ArtifactRegistryError(f"tool {spec.name} was not registered")
        _strict_tool_schema(tool)


def register_dynamic_artifact_tools(
    server: MCPServer,
    rows: list[dict[str, Any]],
    target: TargetContext,
    backend: VelociraptorBackend,
    *,
    approved: Mapping[str, str] = APPROVED_WINDOWS_ARTIFACTS,
) -> tuple[ArtifactSpec, ...]:
    specs = validate_artifact_definitions(rows, approved)
    names = [spec.name for spec in specs]
    if len(set(names)) != len(names):
        raise ArtifactRegistryError("approved tool names are not unique")
    existing = set(server._tool_manager._tools)
    conflicts = sorted(existing.intersection(names))
    if conflicts:
        raise ArtifactRegistryError("dynamic tool name conflicts: " + ", ".join(conflicts))

    validation_server = MCPServer("velociraptor-dynamic-validation")
    _register_on_server(validation_server, specs, target, backend)
    _register_on_server(server, specs, target, backend)
    return specs
