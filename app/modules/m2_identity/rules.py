from app.domain import day,equivalence,volts
from app.errors import DomainError
from app.reasons import isolate
KEY_FIELDS=('cert','measured_at','value','measure_unit')
DEF_FIELDS=('device','parent','valid_from','valid_to','minimum','maximum','unit','revoked','lab','uncertainty','lead','version')
def apply(ctx):
    parsed=[];duplicates=0;conflicted=set()
    for r in ctx['rows']:
        try:
            if not r['cert'] or not r['device']:raise DomainError('MISSING','证书或设备为空')
            start,end=day(r['valid_from']),day(r['valid_to']);day(r['measured_at']);value=volts(r['value'],r['measure_unit']);minimum=volts(r['minimum'],r['unit']);maximum=volts(r['maximum'],r['unit'])
            if start>=end or minimum>maximum:raise DomainError('RANGE','证书区间无效')
            if r['revoked'] not in ('yes','no'):raise DomainError('REVOKED_FLAG','撤销标识无效')
            if r['lead'] and r['lead'] not in ('yes','no'):raise DomainError('LEAD_FLAG','主导标识无效')
            lead=r['lead'] or 'no'
            try: revision=int(r['version'])
            except ValueError:raise DomainError('VERSION','不支持的证书版本')
            if revision<1:raise DomainError('VERSION','不支持的证书版本')
            if r['lab'] and not str(r['uncertainty']).strip():raise DomainError('UNCERTAINTY','扩展不确定度必填')
            uncertainty=volts(r['uncertainty'],r['measure_unit']) if r['lab'] else None
            if r['lab'] and (uncertainty is None or uncertainty<=0):raise DomainError('UNCERTAINTY','扩展不确定度必须为正数')
            parsed.append({**r,'lead':lead,'revision':revision,'value_v':str(value),'min_v':str(minimum),'max_v':str(maximum),'u_v':str(uncertainty) if uncertainty is not None else ''})
        except DomainError as e:isolate(ctx,r,e.code,e.message)
    # Repeated business keys: an exact repeat is a duplicate; a repeat with a
    # differing definition conflicts and voids the certificate.
    grouped={}
    for item in parsed:grouped.setdefault(tuple(item[k] for k in KEY_FIELDS),[]).append(item)
    kept=[]
    for key,items in grouped.items():
        fingerprints={tuple(i[k] for k in DEF_FIELDS) for i in items}
        if len(fingerprints)==1 and len(items)>1:duplicates+=len(items)-1
        if len(fingerprints)>1:
            conflicted.add(key[0])
            for other in items:isolate(ctx,other,'CONFLICT','同证书定义冲突')
        kept.append(items[0])
    by_cert={}
    for item in kept:by_cert.setdefault(item['cert'],[]).append(item)
    # Internal certificates cannot be re-issued at a new version; an external lab
    # may supersede its own certificate only while the laboratory stays unique.
    for cert,items in by_cert.items():
        revisions={i['revision'] for i in items};labs={i['lab'] for i in items if i['lab']}
        if len(revisions)>1 and len(labs)!=1:
            conflicted.add(cert)
            for other in items:isolate(ctx,other,'CONFLICT','同证书版本冲突')
    # Supersession: within one certificate, the highest revision is current.
    for cert,items in by_cert.items():
        latest=max(i['revision'] for i in items)
        for item in items:item['superseded']=item['revision']<latest
    names=equivalence([item for items in by_cert.values() for item in items if item['cert'] not in conflicted])
    certs={};measurements=[];superseded=[]
    for cert,items in by_cert.items():
        for item in items:
            item['canonical']=names.get(item['device'],item['device'])
            if cert in conflicted:
                certs.setdefault(cert,{**item,'conflicted':True});continue
            if item['superseded']:
                superseded.append(item);continue
            measurements.append(item)
            if item['cert'] not in certs or item['revision']>certs[item['cert']]['revision']:certs[item['cert']]=item
    lead_groups={}
    for r in measurements:
        if r['lab'] and r['lead']=='yes' and not r['superseded']:lead_groups.setdefault(r['canonical'],set()).add(r['cert'])
    lead_conflict={cert for group in lead_groups.values() if len(group)>1 for cert in group}
    for cert in lead_conflict:
        certs[cert]['lead_conflict']=True
        for r in measurements:
            if r['cert']==cert and r['lab'] and r['lead']=='yes' and not r['superseded']:isolate(ctx,r,'LEAD_CONFLICT','同一标准器存在多个主导实验室')
    ctx.update(certs=certs,measurements=measurements,superseded=superseded,duplicates=duplicates,lead_conflict=sorted(lead_conflict))
    return {'rows':[{'证书':r['cert'],'设备':r['canonical'],'别名':r['alias'],'父证书':r['parent'],'实验室':r['lab'] or '—','版本':r['revision'],'定义状态':'冲突' if r['cert'] in conflicted else '一致','行号':r['行号']} for r in measurements],'metrics':[['证书',len(certs),'份'],['冲突定义',len(conflicted),'份'],['替代旧版',len(superseded),'条'],['重复',duplicates,'条']]}
