#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Кислов Роман Сергеевич
"""DESTRUCTIVE integration test for disposable ALT VMs only; run as root.
prepare OLD_RPM, reboot, boot, upgrade NEW_RPM, reboot, boot, remove NEW_RPM.
Uses the shipped unit unchanged. Never run against an existing installation.
"""
import hashlib, io, json, os, pathlib, pwd, socket, stat, subprocess, sys, tarfile, threading, time, urllib.request

STATE = pathlib.Path('/root/goprint-systemd-smoke.json')
ENV = pathlib.Path('/etc/goprint/environment')
DATA = pathlib.Path('/var/lib/goprint')
phase = sys.argv[1]

def run(*args):
    if args[0]=='apt-get':
        subprocess.run(args,check=True)
        return ''
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.output)
        raise

def ctl(*args):
    return run('systemctl', *args)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def api(path, value=None, method=None, mime='application/json'):
    token = next(s.split('=',1)[1] for s in ENV.read_text().splitlines() if s.startswith('GOPRINT_TOKEN='))
    data = json.dumps(value).encode() if value is not None and mime == 'application/json' else value
    req = urllib.request.Request('http://127.0.0.1:8631/api/'+path, data=data, method=method,
        headers={'Authorization':'Bearer '+token, 'Content-Type':mime})
    return json.load(urllib.request.urlopen(req, timeout=10))

def ready():
    for _ in range(120):
        try:
            assert ctl('is-active','goprint') == 'active'
            api('diagnostics')
            return
        except (OSError, subprocess.CalledProcessError, AssertionError): time.sleep(.25)
    raise AssertionError('systemd service/API did not become ready')

def stable():
    ready()
    assert ctl('is-enabled','goprint') == 'enabled'
    props = dict(line.split('=',1) for line in ctl('show','--all','goprint').splitlines() if '=' in line)
    for key, value in {'User':'goprint','Group':'goprint','ProtectSystem':'strict','ProtectHome':'yes',
                       'PrivateTmp':'yes','NoNewPrivileges':'yes','UMask':'0077','Result':'success','DropInPaths':''}.items():
        assert props[key] == value, (key,props[key])
    account = pwd.getpwnam('goprint')
    status = pathlib.Path('/proc/'+props['MainPID']+'/status').read_text()
    fields = dict(line.split(':',1) for line in status.splitlines() if ':' in line)
    assert set(fields['Uid'].split()) == {str(account.pw_uid)} and account.pw_uid != 0
    assert fields['NoNewPrivs'].strip() == '1'
    assert stat.S_IMODE(DATA.stat().st_mode) == 0o700 and DATA.stat().st_uid == account.pw_uid
    assert stat.S_IMODE(ENV.stat().st_mode) == 0o640 and ENV.stat().st_gid == account.pw_gid
    # Check actual mount namespace, in addition to configured systemd properties.
    root = pathlib.Path('/proc/'+props['MainPID']+'/root')
    assert (root/'tmp').stat().st_ino != pathlib.Path('/tmp').stat().st_ino
    mounts = pathlib.Path('/proc/'+props['MainPID']+'/mountinfo').read_text().splitlines()
    assert any(line.split()[4] == '/' and 'ro' in line.split()[5].split(',') for line in mounts)
    assert digest(ENV) == state['environment_sha256']
    assert api('jobs/'+state['job'])['state'] == 'queued'
    assert next(p for p in api('printers') if p['id']==state['printer'])['paused']
    assert 'ALT Linux' in api('filters')['status']
    return int(props['MainPID'])

def pdf():
    content='BT /F1 12 Tf 70 760 Td (GoPrint systemd VM) Tj ET\n'
    objects=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',f'<< /Length {len(content)} >>\nstream\n{content}endstream']
    body='%PDF-1.4\n'; offsets=[]
    for i,o in enumerate(objects): offsets.append(len(body)); body+=f'{i+1} 0 obj\n{o}\nendobj\n'
    xref=len(body); body+='xref\n0 6\n0000000000 65535 f \n'+''.join(f'{n:010d} 00000 n \n' for n in offsets)
    return (body+f'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n').encode()

def enqueue():
    return api('jobs?printer='+state['printer']+'&title=systemd-test.pdf',pdf(),mime='application/pdf')['id']

def print_queued():
    received=[]
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(('127.0.0.1',19100));listener.listen();listener.settimeout(30)
        def receive():
            conn,_=listener.accept()
            with conn:
                conn.settimeout(30); chunks=[]
                while True:
                    b=conn.recv(65536)
                    if not b: break
                    chunks.append(b)
                received.append(b''.join(chunks))
        thread=threading.Thread(target=receive,daemon=True);thread.start()
        api('printers/'+state['printer']+'/paused',{'paused':False},'PUT')
        for _ in range(120):
            job=api('jobs/'+state['job'])
            if job['state'] in ('submitted','failed','unknown'): break
            time.sleep(.25)
        assert job['state']=='submitted',job['state']
        thread.join(timeout=30)
        assert received and b'%!PS' in received[0] and b'GOPRINT_PPD_APPLIED' in received[0]
    api('printers/'+state['printer']+'/paused',{'paused':True},'PUT')
    state['job']=enqueue()

assert os.geteuid()==0 and pathlib.Path('/proc/1/comm').read_text().strip()=='systemd'
assert subprocess.run(['systemd-detect-virt','--container'],stdout=subprocess.DEVNULL).returncode != 0, 'Use a full VM, not a container'
if phase == 'prepare':
    assert not STATE.exists() and not (DATA/'queue.db').exists(), 'Disposable fresh VM required'
    run('apt-get','-y','install',str(pathlib.Path(sys.argv[2]).resolve()))
    assert subprocess.run(['systemctl','is-active','--quiet','goprint']).returncode != 0
    assert subprocess.run(['systemctl','is-enabled','--quiet','goprint']).returncode != 0
    run('/usr/sbin/goprint-setup')
    before=digest(ENV);run('/usr/sbin/goprint-setup');assert digest(ENV)==before
    # Import under the service UID before startup; do not weaken the shipped unit.
    account=pwd.getpwnam('goprint')
    source=pathlib.Path(__file__).parent/'tests/test.ppd'
    archive=DATA/'systemd-test-ppd.tar.gz'
    with tarfile.open(archive,'w:gz') as t:
        b=source.read_bytes();h=tarfile.TarInfo('test.ppd');h.size=len(b);t.addfile(h,io.BytesIO(b))
    archive.chmod(0o644)
    def demote(): os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
    subprocess.run(['goprint-ppds','-dir',str(DATA/'ppds'),'-archive',str(archive)],preexec_fn=demote,check=True)
    ctl('enable','--now','goprint');ready()
    profiles=api('drivers?q=GoPrint')['profiles'];assert len(profiles)==1
    printer=api('printers',{'name':'Systemd VM test','uri':'socket://127.0.0.1:19100','formats':['application/postscript'],'ppd_id':profiles[0]['id']})
    state={'environment_sha256':before,'printer':printer['id']}
    api('printers/'+state['printer']+'/paused',{'paused':True},'PUT')
    state['job']=enqueue();old=stable()
    ctl('stop','goprint');assert not pathlib.Path('/proc/'+str(old)).exists()
    ctl('start','goprint');stable()
    print_queued();stable()
elif phase in ('boot','upgrade','remove'):
    state=json.loads(STATE.read_text());stable()
    if phase=='boot':
        assert state['boot_id']!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        print_queued();stable()
    elif phase=='upgrade':
        old=stable();old_version=run('rpm','-q','goprint')
        run('apt-get','-y','install',str(pathlib.Path(sys.argv[2]).resolve()))
        assert run('rpm','-q','goprint')!=old_version
        assert stable()==old, 'RPM must not restart an active queue automatically'
        ctl('restart','goprint');old=stable()
        os.kill(old,9)
        for _ in range(120):
            time.sleep(.25)
            try:
                new=stable()
                if new!=old: break
            except (OSError,subprocess.CalledProcessError,AssertionError): pass
        else: raise AssertionError('Restart=on-failure did not recover the service')
        print_queued();stable()
    else:
        run('apt-get','-y','remove','goprint')
        assert subprocess.run(['systemctl','is-active','--quiet','goprint']).returncode != 0
        assert (DATA/'queue.db').exists() or list(DATA.glob('*.db'))
        pwd.getpwnam('goprint')
        saved=ENV if ENV.exists() else pathlib.Path(str(ENV)+'.rpmsave')
        assert digest(saved)==state['environment_sha256']
        run('apt-get','-y','install',str(pathlib.Path(sys.argv[2]).resolve()))
        if not ENV.exists() or digest(ENV)!=state['environment_sha256']:
            ENV.write_bytes(saved.read_bytes());os.chown(ENV,0,pwd.getpwnam('goprint').pw_gid);ENV.chmod(0o640)
        run('/usr/sbin/goprint-setup');ctl('enable','--now','goprint');stable();print_queued();stable()
else: raise SystemExit('Unknown phase')
state['boot_id']=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
STATE.write_text(json.dumps(state));STATE.chmod(0o600)
print('PASS:',phase,run('rpm','-q','goprint'),run('uname','-m'),run('uname','-r'),run('systemctl','--version').splitlines()[0])
