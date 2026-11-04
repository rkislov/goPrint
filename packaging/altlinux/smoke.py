#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Кислов Роман Сергеевич
"""Install/upgrade/remove an RPM in an isolated ALT container; no real printer."""
import io, json, os, pathlib, pwd, socket, stat, subprocess, sys, tarfile, tempfile, threading, time, urllib.request, urllib.parse
rpm = pathlib.Path(sys.argv[1]).resolve()
tag = sys.argv[2]
preflight = '--preflight' in sys.argv
subprocess.run(['apt-get', '-y', 'install', str(rpm)], check=True)
version = subprocess.check_output(['/usr/bin/goprintd', '-version'], text=True)
assert tag in version, version
account = pwd.getpwnam('goprint')
assert account.pw_uid != 0
unit = next(p for p in subprocess.check_output(['rpm','-ql','goprint'],text=True).splitlines() if p.endswith('/goprint.service'))
subprocess.run(['systemd-analyze','verify',unit],check=True)
assert stat.S_IMODE(pathlib.Path('/var/lib/goprint').stat().st_mode) == 0o700
subprocess.run(['/usr/sbin/goprint-setup'],check=True)
envpath = pathlib.Path('/etc/goprint/environment')
original = envpath.read_bytes()
assert stat.S_IMODE(envpath.stat().st_mode) == 0o640
assert envpath.stat().st_uid == 0 and envpath.stat().st_gid == account.pw_gid
subprocess.run(['/usr/sbin/goprint-setup'],check=True)
assert envpath.read_bytes() == original, 'setup rotated the existing token'
token = next(s.split('=',1)[1] for s in original.decode().splitlines() if s.startswith('GOPRINT_TOKEN='))
assert len(token) == 64

def demote():
    os.setgroups([]); os.setgid(account.pw_gid); os.setuid(account.pw_uid)
root = pathlib.Path(tempfile.mkdtemp(prefix='rpm-smoke-',dir='/var/lib/goprint'))
os.chown(root,account.pw_uid,account.pw_gid)
archive = root/'test-driver.tar.gz'
with tarfile.open(archive,'w:gz') as t:
    b=pathlib.Path('/packaging/tests/test.ppd').read_bytes();h=tarfile.TarInfo('test.ppd');h.size=len(b);h.mode=0o600;t.addfile(h,io.BytesIO(b))
archive.chmod(0o644)
subprocess.run(['/usr/bin/goprint-ppds','-dir',str(root/'data/ppds'),'-archive',str(archive)],preexec_fn=demote,check=True)
listen = socket.socket();listen.bind(('127.0.0.1',0));port=listen.getsockname()[1];listen.close()
env=dict(os.environ,GOPRINT_TOKEN=token)
log=open(root/'server.log','w')
process=subprocess.Popen(['/usr/bin/goprintd','-data',str(root/'data'),'-listen',f'127.0.0.1:{port}','-preload-ppds=false'],env=env,preexec_fn=demote,stdout=log,stderr=log)
base=f'http://127.0.0.1:{port}/api/'
def api(path,value=None,method=None,mime='application/json'):
    data=json.dumps(value).encode() if value is not None and mime=='application/json' else value
    req=urllib.request.Request(base+path,data=data,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':mime})
    return json.load(urllib.request.urlopen(req,timeout=10))
try:
    for _ in range(100):
        try: api('diagnostics');break
        except OSError:time.sleep(.1)
    else:raise AssertionError('server did not start')
    if not preflight:assert 'ALT Linux' in api('filters')['status']
    profiles=api('drivers?q=GoPrint')['profiles'];assert len(profiles)==1
    printer=socket.socket();printer.bind(('127.0.0.1',0));printer.listen();printer.settimeout(20);received=[]
    def receive():
        conn,_=printer.accept();conn.settimeout(20)
        with conn:
            b=b''
            while True:
                chunk=conn.recv(65536)
                if not chunk:break
                b+=chunk
            received.append(b)
    thread=threading.Thread(target=receive);thread.start()
    p=api('printers',{'name':'RPM smoke','uri':'socket://127.0.0.1:'+str(printer.getsockname()[1]),'formats':['application/postscript'],'ppd_id':profiles[0]['id']})
    content='BT /F1 12 Tf 70 760 Td (GoPrint RPM smoke) Tj ET\n'
    objects=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>','<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>','<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',f'<< /Length {len(content)} >>\nstream\n{content}endstream']
    pdf='%PDF-1.4\n';offsets=[]
    for i,o in enumerate(objects):offsets.append(len(pdf));pdf+=f'{i+1} 0 obj\n{o}\nendobj\n'
    xref=len(pdf);pdf+='xref\n0 6\n0000000000 65535 f \n';pdf+=''.join(f'{n:010d} 00000 n \n' for n in offsets);pdf+=f'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'
    job=api('jobs?'+urllib.parse.urlencode({'printer':p['id'],'title':'rpm-smoke.pdf'}),pdf.encode(),mime='application/pdf')
    for _ in range(150):
        state=api('jobs/'+job['id'])
        if state['state'] in ('submitted','failed','unknown'):break
        time.sleep(.1)
    assert state['state']=='submitted',state
    thread.join(timeout=20);printer.close();assert received and b'%!PS' in received[0] and b'GOPRINT_PPD_APPLIED' in received[0], 'PPD conversion not delivered'
finally:
    process.terminate();process.wait(timeout=30);log.close()
# Reinstall exercises config(noreplace) and upgrade script paths without resetting secrets.
survivor=pathlib.Path('/var/lib/goprint/rpm-smoke-survivor');survivor.write_text('keep state')
subprocess.run(['rpm','-U','--replacepkgs',str(rpm)],check=True)
assert envpath.read_bytes()==original and survivor.read_text()=='keep state'
subprocess.run(['rpm','-e','goprint'],check=True)
assert survivor.read_text()=='keep state'
pwd.getpwnam('goprint')
assert envpath.exists() or pathlib.Path(str(envpath)+'.rpmsave').exists()
print('PASS: RPM install, non-root daemon/API, PPD PDF→PS, config preservation, reinstall and removal; systemd unit verified (PID 1 not exercised).')
