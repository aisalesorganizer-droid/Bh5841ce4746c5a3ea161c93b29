#!/usr/bin/env python3
"""Read-only PE structural audit. Reads bytes only; never launches the sample."""
from __future__ import annotations
import argparse, base64, collections, csv, hashlib, json, math, re, struct, zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

DIR_NAMES = {0:'EXPORT',1:'IMPORT',2:'RESOURCE',3:'EXCEPTION',4:'CERTIFICATE',5:'BASE_RELOCATION',6:'DEBUG',7:'ARCHITECTURE',8:'GLOBAL_PTR',9:'TLS',10:'LOAD_CONFIG',11:'BOUND_IMPORT',12:'IAT',13:'DELAY_IMPORT',14:'CLR',15:'RESERVED'}
SCN = [(0x00000020,'CODE'),(0x00000040,'INITIALIZED_DATA'),(0x00000080,'UNINITIALIZED_DATA'),(0x02000000,'DISCARDABLE'),(0x04000000,'NOT_CACHED'),(0x08000000,'NOT_PAGED'),(0x10000000,'SHARED'),(0x20000000,'EXECUTE'),(0x40000000,'READ'),(0x80000000,'WRITE')]

def ent(data: bytes) -> float:
    if not data: return 0.0
    c=collections.Counter(data); n=len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def fmt_time(v):
    try: return {'unix':v,'utc':datetime.fromtimestamp(v,timezone.utc).isoformat(),'ph_time':datetime.fromtimestamp(v,timezone(timedelta(hours=8))).isoformat()}
    except Exception: return {'unix':v,'utc':None,'ph_time':None}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('sample', nargs='?', default='/mnt/data/Bh5841ce4746c5a3ea161c93b29.exe')
    ap.add_argument('--out', default='/mnt/data/Bh5841ce4746c5a3ea161c93b29_STAGE5_RESULTS')
    a=ap.parse_args(); p=Path(a.sample); b=p.read_bytes(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    if len(b)<0x100 or b[:2]!=b'MZ': raise SystemExit('Not a PE-shaped file')
    pe=struct.unpack_from('<I',b,0x3c)[0]
    if b[pe:pe+4]!=b'PE\0\0': raise SystemExit('Invalid PE signature')
    coff=pe+4; machine,nsec,ts,ptrsym,nsym,optsz,characteristics=struct.unpack_from('<HHIIIHH',b,coff)
    opt=coff+20; magic=struct.unpack_from('<H',b,opt)[0]
    if magic!=0x20b: raise SystemExit(f'Expected PE32+; got {magic:#x}')
    entry=struct.unpack_from('<I',b,opt+16)[0]; base=struct.unpack_from('<Q',b,opt+24)[0]
    sizeimage=struct.unpack_from('<I',b,opt+56)[0]; sizeheaders=struct.unpack_from('<I',b,opt+60)[0]
    dllchars=struct.unpack_from('<H',b,opt+70)[0]; ndirs=struct.unpack_from('<I',b,opt+108)[0]
    dirs=[struct.unpack_from('<II',b,opt+112+i*8) for i in range(min(ndirs,16))]
    st=opt+optsz; secs=[]
    for i in range(nsec):
        q=st+i*40; name=b[q:q+8].rstrip(b'\0').decode('latin1','replace')
        vs,va,rs,rp=struct.unpack_from('<IIII',b,q+8); ch=struct.unpack_from('<I',b,q+36)[0]
        raw=b[rp:rp+rs] if rp and rs and rp+rs<=len(b) else b''
        secs.append({'index':i,'name':name,'rva':va,'virtual_size':vs,'raw_offset':rp,'raw_size':rs,'raw_end':rp+rs,'virtual_end':va+max(vs,rs),'characteristics':ch,'characteristics_hex':hex(ch),'flags':[lab for bit,lab in SCN if ch&bit],'raw_entropy':round(ent(raw),6),'raw_backed':bool(rs and len(raw)==rs)})
    def sec_rva(r):
        for s in secs:
            if s['rva']<=r<s['rva']+max(s['virtual_size'],s['raw_size']): return s
        return None
    def off_rva(r):
        s=sec_rva(r)
        if not s: return None
        delta=r-s['rva']
        return s['raw_offset']+delta if delta<s['raw_size'] else None
    def va_info(va):
        if not va: return {'va':hex(va),'rva':None,'file_offset':None,'section':None}
        r=va-base; s=sec_rva(r); return {'va':hex(va),'rva':hex(r),'file_offset':hex(off_rva(r)) if off_rva(r) is not None else None,'section':s['name'] if s else None,'raw_backed':off_rva(r) is not None}
    overlay_start=max((s['raw_end'] for s in secs),default=sizeheaders); overlay=b[overlay_start:]
    # PE directory details and resource mapping
    directory=[]
    for i,(rva,size) in enumerate(dirs):
        directory.append({'index':i,'name':DIR_NAMES.get(i,str(i)),'rva_or_file_offset':hex(rva),'size':size,'file_offset':hex(off_rva(rva)) if i!=4 and rva and off_rva(rva) is not None else (hex(rva) if i==4 and rva else None)})
    # Exception runtime function table audit.
    exr,exs=dirs[3]; exoff=off_rva(exr); funcs=[]; begins_count=collections.Counter(); unwind_count=collections.Counter(); sorted_inc=0; prev=-1; valid=0; no_raw_begin=0; no_raw_unwind=0
    if exr and exs and exoff is not None:
        for i in range(exs//12):
            be,en,un=struct.unpack_from('<III',b,exoff+12*i); sb=sec_rva(be); su=sec_rva(un); ob=off_rva(be); ou=off_rva(un)
            ok=(be<en<=sizeimage and un<sizeimage)
            valid+=ok; sorted_inc+=(be>=prev); prev=be
            begins_count[(sb['name'] if sb else 'NO_SECTION',ob is not None)]+=1
            unwind_count[(su['name'] if su else 'NO_SECTION',ou is not None)]+=1
            no_raw_begin+=(ob is None); no_raw_unwind+=(ou is None)
            if i<12 or i>=exs//12-12:
                funcs.append({'index':i,'begin_rva':hex(be),'end_rva':hex(en),'unwind_rva':hex(un),'range_and_image_valid':ok,'begin_section':sb['name'] if sb else None,'begin_file_backed':ob is not None,'unwind_section':su['name'] if su else None,'unwind_file_backed':ou is not None})
    # TLS directory fields; IMAGE_TLS_DIRECTORY64 is 40 bytes.
    tls={}
    tr,tsz=dirs[9]; to=off_rva(tr)
    if tr and to is not None and to+40<=len(b):
        start,end,index,callbacks,zfill,tchars=struct.unpack_from('<QQQQII',b,to)
        tls={'directory_rva':hex(tr),'file_offset':hex(to),'start_raw_data':va_info(start),'end_raw_data':va_info(end),'address_of_index':va_info(index),'address_of_callbacks':va_info(callbacks),'zero_fill_size':zfill,'characteristics':hex(tchars),'callback_array_present':bool(callbacks)}
    # Load-config compact fields and guard flags.
    loadcfg={}; lr,lsz=dirs[10]; lo=off_rva(lr)
    if lr and lo is not None and lo+4<=len(b):
        declared=struct.unpack_from('<I',b,lo)[0]; loadcfg={'rva':hex(lr),'size':lsz,'file_offset':hex(lo),'declared_size':declared}
        if declared>=148 and lo+148<=len(b):
            # PE32+ offsets: SecurityCookie 88, GuardCFCheckFunctionPointer 112, GuardCFDispatchFunctionPointer 120,
            # GuardCFFunctionTable 128, GuardCFFunctionCount 136, GuardFlags 144.
            loadcfg.update({'security_cookie':va_info(struct.unpack_from('<Q',b,lo+88)[0]),'guard_cf_check':va_info(struct.unpack_from('<Q',b,lo+112)[0]),'guard_cf_dispatch':va_info(struct.unpack_from('<Q',b,lo+120)[0]),'guard_cf_function_table':va_info(struct.unpack_from('<Q',b,lo+128)[0]),'guard_cf_function_count':struct.unpack_from('<Q',b,lo+136)[0],'guard_flags':hex(struct.unpack_from('<I',b,lo+144)[0])})
    # Resource directory traversal: recurse within the declared resource directory size.
    resources={'directory_rva':hex(dirs[2][0]),'directory_size':dirs[2][1],'types':[],'manifest_type_24_present':False,'parse_error':None}
    rr,rsz=dirs[2]; ro=off_rva(rr); root_start=ro
    if rr and ro is not None and rsz:
        def read_dir(off,depth=0,pathids=()):
            if depth>4: return []
            if off<root_start or off+16>root_start+rsz: raise ValueError('resource directory header outside declared bounds')
            n_named,n_id=struct.unpack_from('<HH',b,off+12); total=n_named+n_id
            if total>4096 or off+16+8*total>root_start+rsz: raise ValueError('resource directory entries outside declared bounds')
            rows=[]
            for j in range(total):
                nm,val=struct.unpack_from('<II',b,off+16+j*8)
                if nm&0x80000000:
                    no=root_start+(nm&0x7fffffff)
                    if no+2>root_start+rsz: ident='INVALID_NAME'
                    else:
                        l=struct.unpack_from('<H',b,no)[0]; raw=b[no+2:min(no+2+2*l,root_start+rsz)]; ident=raw.decode('utf-16le','replace')
                else: ident=nm&0xffff
                isdir=bool(val&0x80000000); target=root_start+(val&0x7fffffff)
                if isdir:
                    rows.append({'id':ident,'children':read_dir(target,depth+1,pathids+(ident,))})
                else:
                    if target+16>root_start+rsz: rows.append({'id':ident,'data_error':'resource data entry outside resource directory'}); continue
                    data_rva,data_size,cp,res=struct.unpack_from('<IIII',b,target)
                    data_off=off_rva(data_rva)
                    rows.append({'id':ident,'data_rva':hex(data_rva),'size':data_size,'codepage':cp,'data_file_offset':hex(data_off) if data_off is not None else None,'raw_data_valid':data_off is not None and data_off+data_size<=len(b)})
            return rows
        try:
            rtree=read_dir(ro)
            resources['types']=rtree
            resources['manifest_type_24_present']=any(x.get('id')==24 for x in rtree)
        except Exception as e: resources['parse_error']=str(e)
    # Overlay config and checksum region.
    markers={}
    for m in [b'BEASTEXPIRY',b'BEASTTITLE',b'BEASTCOPYR',b'BEASTNAME',b'BEASTUSER',b'BEASTPASS',b'BEASTKEYS',b'LEYZKBEASTLANGX',b'BEASTSTAMP',b'BEASTCHK0',b'BHXTRL']:
        markers[m.decode('ascii')]=overlay.find(m)
    def prefixed_value(name):
        pos=overlay.find(name.encode())
        if pos<0 or pos+len(name)+2>len(overlay): return None
        # Values are usually a little-endian 16-bit length then bytes.
        n=struct.unpack_from('<H',overlay,pos+len(name))[0]; v=overlay[pos+len(name)+2:pos+len(name)+2+n]
        return {'length':n,'text':v.decode('utf8','replace') if len(v)==n else None,'hex':v.hex()}
    expiry=None; stamp=None
    pos=overlay.find(b'BEASTEXPIRY')
    if pos>=0 and pos+len(b'BEASTEXPIRY')+4<=len(overlay): expiry=fmt_time(struct.unpack_from('<I',overlay,pos+len(b'BEASTEXPIRY'))[0])
    pos=overlay.find(b'BEASTSTAMP')
    if pos>=0 and pos+len(b'BEASTSTAMP')+4<=len(overlay): stamp=fmt_time(struct.unpack_from('<I',overlay,pos+len(b'BEASTSTAMP'))[0])
    ckpos=overlay.find(b'BEASTCHK0'); ck=overlay[ckpos+9:ckpos+41] if ckpos>=0 else b''
    candidates={
      'whole_file':b,'pre_overlay_file':b[:overlay_start],'overlay_all':overlay,
      'overlay_before_chk':overlay[:ckpos] if ckpos>=0 else overlay,
      'overlay_without_digest_payload':(overlay[:ckpos]+overlay[ckpos+9+32:]) if ckpos>=0 else overlay,
      'whole_file_without_digest_payload':(b[:overlay_start+ckpos]+b[overlay_start+ckpos+9+32:]) if ckpos>=0 else b,
    }
    digest_tests={name:hashlib.sha256(buf).hexdigest() for name,buf in candidates.items()}
    digest_matches=[name for name,val in digest_tests.items() if ck and val==ck.hex()]
    b64start=overlay.find(b'LEYZKBEASTLANGX'); b64start=b64start+len(b'LEYZKBEASTLANGX') if b64start>=0 else -1
    b64end=overlay.find(b'BEASTSTAMP',b64start) if b64start>=0 else -1
    config={'base64_chars':None,'decoded_bytes':None,'decompressed_bytes':None,'json_keys':None,'decompression_error':None}
    if b64start>=0 and b64end>b64start:
        bb=re.sub(rb'\s+',b'',overlay[b64start:b64end]); config['base64_chars']=len(bb)
        try:
            dec=base64.b64decode(bb,validate=True); config['decoded_bytes']=len(dec)
            import zlib
            zz=zlib.decompress(dec); config['decompressed_bytes']=len(zz)
            j=json.loads(zz.decode('utf-8')); config['json_keys']=sorted(j.keys()); (out/'embedded_config.json').write_text(json.dumps(j,indent=2,ensure_ascii=False),encoding='utf-8')
        except Exception as e: config['decompression_error']=str(e)
    # ASCII and UTF16LE suspicious strings, offset and section attribution.
    patterns={
      'url':re.compile(r'(?i)https?://[^\s\x00"\']{4,}'),
      'ipv4_like':re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
      'sys_file':re.compile(r'(?i)\b[\w.-]{1,80}\.sys\b'),
      'network_or_driver_terms':re.compile(r'(?i)(?:WinHttp|WinINet|WSAConnect|connect\x00|send\x00|recv\x00|CreateService|StartService|NtLoadDriver|ZwLoadDriver|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|powershell\.exe|schtasks\.exe|RunOnce|CurrentVersion\\Run|webhook)'),
      'brand_or_loader_terms':re.compile(r'(?i)(?:crossfire|beasthax|b34sth4x|leyzk|spoof|debugger detected|load cheat|driver)'),
    }
    strhits={k:[] for k in patterns}
    for enc,pat in [('ascii',re.compile(rb'[ -~]{5,}')),('utf16le',re.compile(rb'(?:[\x20-\x7e]\x00){5,}'))]:
        for m in pat.finditer(b):
            try: text=m.group().decode('ascii' if enc=='ascii' else 'utf-16le')
            except Exception: continue
            sct=next((s['name'] for s in secs if s['raw_offset']<=m.start()<s['raw_end']), 'OVERLAY' if m.start()>=overlay_start else 'HEADERS/UNMAPPED')
            for k,rx in patterns.items():
                if rx.search(text) and len(strhits[k])<300: strhits[k].append({'encoding':enc,'file_offset':hex(m.start()),'section':sct,'text':text[:240]})
    # Raw bytes at entry point and direct-call targets. These are byte-level candidates, NOT confirmed runtime flow.
    ent_off=off_rva(entry); ep=b[ent_off:ent_off+64] if ent_off is not None else b''
    call_candidates=[]; current=entry; visited=set()
    for i in range(8):
        if current in visited: call_candidates.append({'rva':hex(current),'cycle':True}); break
        visited.add(current); off=off_rva(current)
        if off is None: call_candidates.append({'rva':hex(current),'file_backed':False}); break
        byt=b[off:off+16]; row={'rva':hex(current),'va':hex(base+current),'file_offset':hex(off),'bytes':byt.hex(' '),'section':sec_rva(current)['name'] if sec_rva(current) else None}
        if byt[:1]==b'\xe8' and len(byt)>=5:
            rel=struct.unpack_from('<i',byt,1)[0]; tgt=current+5+rel; row['direct_call_rel32_candidate']=hex(tgt); current=tgt
        else:
            call_candidates.append(row); break
        call_candidates.append(row)
    # JSON payload.
    exsum={'directory_rva':hex(exr),'directory_size':exs,'file_offset':hex(exoff) if exoff is not None else None,'record_count':exs//12,'remainder_bytes':exs%12,'valid_range_and_image_count':valid,'begin_rva_monotonic_count':sorted_inc,'begin_rva_monotonic':sorted_inc==(exs//12),'begin_rvas_without_raw_backing':no_raw_begin,'unwind_rvas_without_raw_backing':no_raw_unwind,'begin_section_counts':[{'section':k[0],'raw_backed':k[1],'count':v} for k,v in begins_count.most_common()],'unwind_section_counts':[{'section':k[0],'raw_backed':k[1],'count':v} for k,v in unwind_count.most_common()],'sample_records':funcs}
    payload={'analysis_mode':'read-only static; sample not executed','sample':p.name,'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'timestamp_pe':fmt_time(ts),'pe':{'machine':hex(machine),'section_count':nsec,'characteristics':hex(characteristics),'relocations_stripped':bool(characteristics&0x0001),'image_base':hex(base),'entry_rva':hex(entry),'entry_va':hex(base+entry),'entry_file_offset':hex(ent_off) if ent_off is not None else None,'entry_section':sec_rva(entry)['name'] if sec_rva(entry) else None,'size_of_image':hex(sizeimage),'size_of_headers':hex(sizeheaders),'dll_characteristics':hex(dllchars),'dynamic_base':bool(dllchars&0x40),'high_entropy_va':bool(dllchars&0x20),'nx_compat':bool(dllchars&0x100),'data_directories':directory},'sections':secs,'zero_raw_sections':[s for s in secs if s['raw_size']==0 and s['virtual_size']>0],'entry_bytes_hex':ep.hex(' '),'entry_decode_candidates':call_candidates,'exception_directory_audit':exsum,'tls_audit':tls,'load_config':loadcfg,'resources':resources,'overlay':{'start_file_offset':hex(overlay_start),'size':len(overlay),'footer_hex':overlay[-12:].hex(' '),'markers_relative_offsets':markers,'title':prefixed_value('BEASTTITLE'),'copyright':prefixed_value('BEASTCOPYR'),'name':prefixed_value('BEASTNAME'),'expiry_timestamp':expiry,'stamp_timestamp':stamp,'checksum_marker_hex':ck.hex(),'checksum_sha256_candidate_tests':digest_tests,'sha256_candidate_matches':digest_matches,'base64_config':config,'footer_length_value':struct.unpack_from('<I',overlay,len(overlay)-4)[0] if len(overlay)>=4 else None},'string_scan':{k:{'count':len(v),'hits':v[:80]} for k,v in strhits.items()},'limitations':['No execution or memory capture; packed/unpacked behavior is not established.','Raw byte sequences and linear disassembly in high-entropy regions may be data or anti-disassembly bait.','PE exception records can be structurally valid while pointing into zero-filled/unbacked areas; their runtime meaning is undetermined.','A manifest-like XML string in a section is not an active RT_MANIFEST unless the resource tree references it.']}
    (out/'stage5_results.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    with (out/'sections.csv').open('w',newline='',encoding='utf-8') as f:
        fields=['index','name','rva','virtual_size','raw_offset','raw_size','raw_end','virtual_end','characteristics_hex','flags','raw_entropy','raw_backed']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for s in secs: w.writerow({'index':s['index'],'name':s['name'],'rva':hex(s['rva']),'virtual_size':hex(s['virtual_size']),'raw_offset':hex(s['raw_offset']),'raw_size':hex(s['raw_size']),'raw_end':hex(s['raw_end']),'virtual_end':hex(s['virtual_end']),'characteristics_hex':s['characteristics_hex'],'flags':';'.join(s['flags']),'raw_entropy':s['raw_entropy'],'raw_backed':s['raw_backed']})
    with (out/'exception_directory_summary.csv').open('w',newline='',encoding='utf-8') as f:
        fields=['section','raw_backed','count']; w=csv.DictWriter(f,fieldnames=fields);w.writeheader(); w.writerows(exsum['begin_section_counts'])
    with (out/'entrypoint_candidates.txt').open('w',encoding='utf-8') as f:
        f.write(f'SHA-256: {payload["sha256"]}\nEntry RVA: {hex(entry)}\nFile offset: {hex(ent_off) if ent_off is not None else "N/A"}\nBytes: {ep.hex(" ")}\n\nThese are direct CALL byte candidates only; do not treat them as confirmed control flow.\n')
        for r in call_candidates: f.write(json.dumps(r)+'\n')
    print(json.dumps({'sample':p.name,'sha256':payload['sha256'],'size':len(b),'zero_raw_sections':len(payload['zero_raw_sections']),'exception_records':exsum['record_count'],'exception_sorted':exsum['begin_rva_monotonic'],'exception_records_valid':valid,'begin_rva_no_raw':no_raw_begin,'unwind_no_raw':no_raw_unwind,'tls_callbacks':tls.get('callback_array_present'),'resource_parse_error':resources.get('parse_error'),'manifest_resource_present':resources.get('manifest_type_24_present'),'overlay_size':len(overlay),'digest_match_candidates':digest_matches,'output':str(out)},indent=2))
if __name__=='__main__': main()
