"""Read-only retained-installation preservation comparison after transport exit."""
import hashlib
import json
from pathlib import Path

REDIRECT='-A OUTPUT -d 127.0.0.2/32 -p tcp -m tcp --dport 443 -m comment --comment sbxr-qualification-v3 -j REDIRECT --to-ports 9443'


def require(value,reason):
    if not value:raise ValueError(reason)


def without_redirect(body):
    lines=body.splitlines();require(lines.count(REDIRECT)<=1,'duplicate transport redirect')
    require(all('sbxr-qualification-v3' not in line or line==REDIRECT for line in lines),'unknown qualification rule')
    return '\n'.join(line for line in lines if line!=REDIRECT)


def compare(before,after,original_files):
    require(set(before)==set(after),'preservation fields differ')
    require(before.get('archive_members')==after.get('archive_members'),'preserved archive members changed')
    for key in ('packages','holds','accounts','groups','ip6firewall','ip6firewall_normalized'):
        require(before[key]==after[key],'unrelated '+key+' changed')
    require(without_redirect(before['firewall_normalized'])==without_redirect(after['firewall_normalized']),'firewall change beyond transport rollback')
    require(REDIRECT not in after['firewall_normalized'].splitlines(),'transport redirect remains')
    for snap in (before,after):
        for key in ('firewall','ip6firewall'):
            require(hashlib.sha256(snap[key+'_normalized'].encode()).hexdigest()==snap[key],'firewall digest differs')
    expected=dict(before['files'])
    for path in ('/etc/hosts','/etc/ssl/certs/ca-certificates.crt'):
        if path in expected:
            require(path in original_files and 'sha256' in original_files[path],'original trust/hosts baseline missing')
            expected[path]=dict(original_files[path])
            # The original producer represents regular files by their digest;
            # newer snapshots also name the type. Only this known metadata
            # addition is normalized; all other recorded fields stay exact.
            expected[path].setdefault('kind','regular')
            require(expected[path]['kind']=='regular','original trust/hosts file type differs')
    observed={k:dict(v) if isinstance(v,dict) else v for k,v in after['files'].items()}
    # Match the existing preservation rule for an atomic hosts-file restoration.
    if '/etc/hosts' in expected:
        expected['/etc/hosts']=dict(expected['/etc/hosts']);expected['/etc/hosts'].pop('ino',None)
        observed['/etc/hosts'].pop('ino',None)
    # update-ca-certificates atomically replaces this generated bundle. Only
    # its inode may differ; require complete original and current metadata.
    ca='/etc/ssl/certs/ca-certificates.crt'
    if ca in expected:
        fields={'sha256','dev','ino','uid','gid','mode','nlink','size','kind'}
        for value in (expected[ca],observed.get(ca,{})):
            require(fields <= value.keys(),'incomplete CA bundle metadata')
            require(value['kind']=='regular' and value['nlink']==1 and 'target' not in value,'CA bundle is not a single-link regular file')
        expected[ca]=dict(expected[ca]);expected[ca].pop('ino')
        observed[ca].pop('ino')
    require(observed==expected,'preserved file changes beyond original trust/hosts restoration')
    return True


def verify_retained_transport(result,runtime,binding):
    # These files are producer-bound/pinned by the prepared caller before this
    # function is reached; no native path is read or changed here.
    prior=json.loads(Path(runtime['host_review_record']).read_text())
    require(prior['binding']==binding,'host preservation run differs')
    record=runtime['original_host_baseline'];raw=Path(record['source_file']).read_bytes()
    require(len(raw)==record['size'] and hashlib.sha256(raw).hexdigest()==record['sha256'],'original host baseline changed')
    return compare(prior['preservation'],result['post_preservation'],json.loads(raw)['files'])
