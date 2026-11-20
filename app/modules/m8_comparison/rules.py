from decimal import Decimal
from app.domain import weighted_consensus
from app.numeric import number
def apply(ctx):
    certs,chains=ctx['certs'],ctx['chains']
    external=[r for r in ctx['measurements'] if r['lab']]
    old_external=[r for r in ctx.get('superseded',[]) if r['lab']]
    groups={}
    for r in external:groups.setdefault(r['canonical'],[]).append(r)
    compare_rows=[];group_summary=[];adopted=set()
    for standard in sorted(groups):
        members=groups[standard];eligibles=[];excluded={}
        for r in members:
            cert=r['cert'];c=certs[cert]
            if c.get('conflicted'):excluded[cert]='CONFLICT';continue
            if c.get('lead_conflict'):excluded[cert]='LEAD_CONFLICT';continue
            if c['revoked']=='yes':excluded[cert]='REVOKED';continue
            chain=chains.get(cert,{'valid':False,'code':'MISSING_REFERENCE'})
            if not chain['valid']:excluded[cert]=chain['code'];continue
            eligibles.append({'cert':cert,'lab':r['lab'],'lead':r['lead']=='yes','value_v':number(r['value_v']),'u_v':number(r['u_v']),'行号':r['行号']})
        reference=combined=None;scored=[];outliers=set();basis='无参考'
        if not eligibles:
            pass
        elif len(eligibles)==1:
            only=eligibles[0];reference=only['value_v'];combined=only['u_v'];scored=[{**only,'en':Decimal('0'),'weight':Decimal('1')}];basis='单源采信'
        else:
            reference,combined,scored,outliers=weighted_consensus(eligibles)
            basis='加权一致' if len(scored)>=2 else ('单源采信' if len(scored)==1 else '比对失败')
        for cert in outliers:excluded[cert]='EN_OUTLIER'
        kept={x['cert'] for x in scored}
        adopted|=kept
        score_by_cert={x['cert']:x for x in scored}
        for r in sorted(members,key=lambda x:x['cert']):
            cert=r['cert']
            if cert in excluded:
                verdict,en,weight,reason='排除','—','—',excluded[cert]
            else:
                s=score_by_cert[cert];verdict='采信';en=str(s['en']);weight=str(s['weight']);reason='LEAD' if s['lead'] else 'PARTICIPANT'
            compare_rows.append({'标准器':standard,'证书':cert,'实验室':r['lab'],'主导':'是' if r['lead']=='yes' else '否','校准值_V':r['value_v'],'不确定度_V':r['u_v'],'裁决':verdict,'En':en,'权重':weight,'原因码':reason,'行号':r['行号']})
        for r in sorted(old_external,key=lambda x:x['cert']):
            compare_rows.append({'标准器':r['canonical'],'证书':r['cert'],'实验室':r['lab'],'主导':'是' if r['lead']=='yes' else '否','校准值_V':r['value_v'],'不确定度_V':r['u_v'],'裁决':'排除','En':'—','权重':'—','原因码':'SUPERSEDED','行号':r['行号']})
        group_summary.append({'标准器':standard,'参考值_V':'' if reference is None else str(reference),'合成不确定度_V':'' if combined is None else str(combined),'采信实验室':','.join(sorted(certs[c]['lab'] for c in kept)),'采信证书':','.join(sorted(kept)),'排除证书':','.join(sorted(set(excluded)|{r['cert'] for r in old_external if r['canonical']==standard and r['cert'] not in kept})),'结论':basis})
    # Retest scope: every customer measurement whose chain crosses an external
    # comparison certificate that did not make it into the adopted reference set.
    comparison_certs={r['cert'] for r in external}|{r['cert'] for r in old_external}
    retest_rows=[]
    for m in ctx['measurements']:
        if m['lab']:continue
        path=set(chains.get(m['cert'],{'path':[]})['path'])
        tainted=sorted((path&comparison_certs)-adopted)
        if tainted:
            retest_rows.append({'测量证书':m['cert'],'设备':m['canonical'],'测量日':m['measured_at'],'拒用外校证书':','.join(tainted),'处理':'需复测','行号':m['行号']})
    ctx['adopted']=sorted(adopted);ctx['retest']=retest_rows
    return {'rows':compare_rows,'groups':group_summary,'retest':retest_rows,'metrics':[['比对标准器',len(group_summary),'台'],['采信外校证书',len(adopted),'份'],['排除外校证书',sum(1 for r in compare_rows if r['裁决']=='排除'),'份'],['需复测测量',len(retest_rows),'条']]}
