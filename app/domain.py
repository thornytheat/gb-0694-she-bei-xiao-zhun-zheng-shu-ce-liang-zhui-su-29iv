from datetime import date
from decimal import Decimal
from app.numeric import number
from app.errors import DomainError
def day(text):
    try:return date.fromisoformat(text)
    except ValueError:raise DomainError('DATE','日期格式无效')
def volts(value,unit):
    factors={'V':1,'mV':number('0.001')}
    if unit not in factors:raise DomainError('UNIT','电压单位无效')
    return number(value)*factors[unit]
def equivalence(rows):
    parents={}
    def find(x):
        parents.setdefault(x,x)
        if parents[x]!=x:parents[x]=find(parents[x])
        return parents[x]
    for r in rows:
        a,z=find(r['device']),find(r['alias'] or r['device']);parents[max(a,z)]=min(a,z)
    return {x:find(x) for x in list(parents)}
def trace(cert,certs):
    path=[];current=cert;child=None
    while current:
        if current in path:return {'valid':False,'code':'CYCLE','path':path+[current]}
        path.append(current)
        if current not in certs:return {'valid':False,'code':'MISSING_REFERENCE','path':path}
        r=certs[current]
        if r.get('superseded'):return {'valid':False,'code':'SUPERSEDED','path':path}
        if r['revoked']=='yes':return {'valid':False,'code':'REVOKED','path':path}
        if child and not day(r['valid_from'])<=day(child['valid_from'])<day(r['valid_to']):return {'valid':False,'code':'REFERENCE_EXPIRED','path':path}
        child=r;current=r['parent']
    return {'valid':True,'code':'TRACEABLE','path':path}
def descendants(start,certs):
    reached={start};todo=[start]
    while todo:
        node=todo.pop()
        for key,value in certs.items():
            if value['parent']==node and key not in reached:reached.add(key);todo.append(key)
    return sorted(reached)
def weighted_consensus(items, en_limit=Decimal('1')):
    """Inverse-variance weighted mean with iterative En screening. Starting from
    all labs, the single lab most inconsistent with the consensus of the others is
    removed and the consensus recomputed, until every survivor has En <= limit
    against its leave-one-out consensus. Returns reference, combined uncertainty,
    per-item En scores (survivors), and the sorted set of removed certificates."""
    pool=list(items);removed=set()
    while True:
        weights=[Decimal(1)/(x['u_v']**2) for x in pool]
        total=sum(weights)
        reference=sum(x['value_v']*w for x,w in zip(pool,weights))/total
        combined=(Decimal(1)/total).sqrt()
        ens=[]
        for x in pool:
            others=[y for y in pool if y is not x]
            if others:
                ow=[Decimal(1)/(y['u_v']**2) for y in others];ot=sum(ow)
                loo=sum(y['value_v']*w for y,w in zip(others,ow))/ot
                loo_comb=(Decimal(1)/ot).sqrt()
                ens.append(abs(x['value_v']-loo)/(x['u_v']**2+loo_comb**2).sqrt())
            else:
                ens.append(Decimal('0'))
        worst=max(range(len(pool)),key=lambda i:ens[i])
        if len(pool)>1 and ens[worst]>en_limit:
            removed.add(pool[worst]['cert']);pool.pop(worst);continue
        weights=[Decimal(1)/(x['u_v']**2) for x in pool]
        total=sum(weights)
        reference=sum(x['value_v']*w for x,w in zip(pool,weights))/total
        combined=(Decimal(1)/total).sqrt()
        scored=[{**x,'en':en,'weight':w/total} for x,w,en in zip(pool,weights,ens)]
        return reference,combined,scored,sorted(removed)
