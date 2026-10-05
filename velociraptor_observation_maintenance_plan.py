"""Internal finite acquisition plan; neither protocol input nor authority.

Plans include three transport attempts, single-chunk degradation, polling,
prepare/release reconciliation, child activation and actual final DELETE.
The caller may choose a smaller transfer budget only when it still contains
this controlled source; it never chooses the reserved headroom.
"""
from __future__ import annotations



def acquisition_plan(source, limits, budget, request_body_limit):
    from velociraptor_observation_controller import ControllerError
    if (type(source) is not dict or set(source)!={'files','bytes'}
            or any(type(n) is not int or n<0 for n in source.values())
            or not source['files']):raise ControllerError('maintenance_source_size')
    if any(type(limits.get(k)) is not int or limits[k]<=0 for k in
            ('max_files','max_metadata_bytes','max_package_bytes','max_chunk_bytes','max_duration_seconds','max_state_bytes')):
        raise ControllerError('maintenance_policy_limits')
    # Existing ZIP/manifest framing has a conservative per-member bound, plus
    # fixed manifest allowance. Never assume compressibility or caller totals.
    package=source['bytes']+limits['max_metadata_bytes']+source['files']*4096+65536
    if (source['files']>min(limits['max_files'],budget['max_files'])
            or source['bytes']>min(limits['max_logical_bytes'],budget['max_logical_bytes'])
            or package>min(limits['max_package_bytes'],budget['max_package_bytes'])
            or budget['max_metadata_bytes']<limits['max_metadata_bytes']):
        raise ControllerError('maintenance_transfer_capacity')
    chunk=min(1<<20,limits['max_chunk_bytes'],budget['max_chunk_bytes'])
    if type(chunk) is not int or chunk<=0:raise ControllerError('maintenance_chunk_plan')
    chunks=(package+chunk-1)//chunk
    # Polls at 100 ms in the existing coordinator. Whole policy duration is
    # reserved even if the caller advertises a shorter deadline.
    polls=10*limits['max_duration_seconds']+1
    attempts=3*(polls+chunks+24)
    binary=3*chunks
    calls=attempts+binary+8
    return dict(calls=calls,bytes=calls*(request_body_limit+8*limits['max_state_bytes']+65536)+6*package,
        attempts=attempts,binary=binary,sdk_work=3*attempts+2*binary+16)
