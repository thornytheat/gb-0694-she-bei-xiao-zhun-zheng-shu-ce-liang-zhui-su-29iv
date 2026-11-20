from decimal import Decimal
from app.domain import weighted_consensus
from app.pipeline import calculate

HEADER='cert,device,alias,parent,valid_from,valid_to,minimum,maximum,unit,revoked,measured_at,value,measure_unit,version,lab,uncertainty,lead'
def row(cert,device,parent,day,value,unit='V',revoked='no',version='1',lab='',unc='',lead='',minimum='0',maximum='1000'):
    return f'{cert},{device},别名,{parent},2026-01-01,2028-01-01,{minimum},{maximum},V,{revoked},{day},{value},{unit},{version},{lab},{unc},{lead}'
def run(rows):
    return calculate(HEADER+'\n'+'\n'.join(rows)+'\n')
def by_cert(stage):return {r['证书']:r for r in stage['rows']}
def group(ctx):return ctx['stages']['8']['groups'][0]

def _labs():
    return [
        {'cert':'A','value_v':Decimal('10.00'),'u_v':Decimal('0.05')},
        {'cert':'B','value_v':Decimal('10.40'),'u_v':Decimal('0.05')},
        {'cert':'D','value_v':Decimal('10.05'),'u_v':Decimal('0.20')},
        {'cert':'E','value_v':Decimal('10.03'),'u_v':Decimal('0.08')},
    ]
def test_consensus_is_weighted_not_lead_only_or_mean():
    ref,comb,scored,removed=weighted_consensus(_labs())
    assert removed==['B']
    weights={s['cert']:s['weight'] for s in scored}
    # Tightest uncertainty carries the largest weight, but nobody gets 100%.
    assert weights['A']>weights['E']>weights['D']
    assert all(0<w<1 for w in weights.values())
    # Reference is pulled toward A but is neither A alone nor the naive mean.
    assert Decimal('10.00')<ref<Decimal('10.10')
    assert ref!=sum(x['value_v'] for x in _labs())/4

def test_revoked_lab_never_enters_comparison(ctx):
    rows=by_cert(ctx['stages']['8'])
    assert rows['EXT-C']['裁决']=='排除' and rows['EXT-C']['原因码']=='REVOKED'
    assert 'EXT-C' not in group(ctx)['采信证书']

def test_superseded_certificate_excluded_and_chain_broken(ctx):
    rows=by_cert(ctx['stages']['8'])
    old=[r for r in ctx['stages']['8']['rows'] if r['证书']=='EXT-A' and r['原因码']=='SUPERSEDED']
    assert old and old[0]['裁决']=='排除'
    assert ctx['chains']['EXT-A']['code']=='TRACEABLE'
    assert any(r['证书']=='EXT-A' and r['裁决']=='采信' for r in ctx['stages']['8']['rows'])

def test_outlier_lab_excluded_without_diluting_consensus(ctx):
    rows=by_cert(ctx['stages']['8'])
    assert rows['EXT-B']['原因码']=='EN_OUTLIER' and rows['EXT-B']['裁决']=='排除'
    assert 'LAB-B' not in group(ctx)['采信实验室']

def test_reference_shows_every_adopted_lab(ctx):
    g=group(ctx)
    assert g['采信实验室']=='LAB-A,LAB-D,LAB-E'
    assert g['采信证书']=='EXT-A,EXT-D,EXT-E'
    assert g['结论']=='加权一致'

def test_retest_scope_matches_rejected_labs_only(ctx):
    tainted={r['测量证书']:r['拒用外校证书'] for r in ctx['stages']['8']['retest']}
    assert tainted=={'C1002':'EXT-B','C1003':'EXT-C'}
    # Customers of adopted labs (A, D, E) are never sent for retest.
    assert 'C1001' not in tainted

def test_rerun_same_data_is_identical(client):
    first=client.post('/api/run',json={}).get_json()
    again=client.post('/api/run',json={}).get_json()
    assert first['manifest']['run_id']==again['manifest']['run_id']
    assert first['stages']['8']['groups']==again['stages']['8']['groups']
    assert first['stages']['8']['retest']==again['stages']['8']['retest']

def test_upstream_cert_update_recomputes_reference_and_retest(raw):
    before=calculate(raw)
    # Amend the currently-valid LAB-A certificate (version 2): the reference moves.
    updated=raw.replace('2026-11-05,10.02,V,2,LAB-A,0.05,yes','2026-11-05,9.90,V,2,LAB-A,0.05,yes')
    after=calculate(updated)
    assert updated!=raw
    assert before['manifest']['run_id']!=after['manifest']['run_id']
    assert before['stages']['8']['groups'][0]['参考值_V']!=after['stages']['8']['groups'][0]['参考值_V']

def test_broken_traceability_lab_excluded():
    rows=[
        row('ROOT','REF','','2026-10-01','10',lab='ROOT-LAB',unc='0.01',lead='yes'),
        row('L1','STD-1','MISSING','2026-10-02','10.00',lab='LAB-1',unc='0.05'),
        row('L2','STD-1','ROOT','2026-10-03','10.02',lab='LAB-2',unc='0.05'),
    ]
    ctx=run(rows)
    rows_by=by_cert(ctx['stages']['8'])
    assert rows_by['L1']['裁决']=='排除' and rows_by['L1']['原因码']=='MISSING_REFERENCE'
    assert rows_by['L2']['裁决']=='采信'

def test_duplicate_lead_labs_flag_conflict():
    rows=[
        row('ROOT','REF','','2026-10-01','10'),
        row('L1','STD-1','ROOT','2026-10-02','10.00',lab='LAB-1',unc='0.05',lead='yes'),
        row('L2','STD-1','ROOT','2026-10-03','10.02',lab='LAB-2',unc='0.05',lead='yes'),
    ]
    ctx=run(rows)
    reasons={r['原因码'] for r in ctx['quarantine']}
    assert 'LEAD_CONFLICT' in reasons
    assert all(r['裁决']=='排除' for r in ctx['stages']['8']['rows'])

def test_single_eligible_lab_is_adopted_not_averaged_with_bad_ones():
    rows=[
        row('ROOT','REF','','2026-10-01','10'),
        row('L1','STD-1','ROOT','2026-10-02','10.00',lab='LAB-1',unc='0.05'),
        row('L2','STD-1','ROOT','2026-10-03','10.40',lab='LAB-2',unc='0.05',revoked='yes'),
    ]
    ctx=run(rows)
    g=group(ctx)
    assert g['结论']=='单源采信' and g['采信实验室']=='LAB-1' and g['参考值_V']=='10.00'

def test_module_endpoint_and_page_render(client):
    assert client.post('/api/m8',json={}).get_json()['stage']==8
    page=client.get('/work/8').data.decode()
    assert '08．外校比对' in page and '参考结论依据' in page and '已出测量复测范围' in page

def test_missing_uncertainty_is_quarantined():
    rows=[
        row('ROOT','REF','','2026-10-01','10'),
        row('L1','STD-1','ROOT','2026-10-02','10.00',lab='LAB-1',unc=''),
    ]
    ctx=run(rows)
    assert any(q['原因码']=='UNCERTAINTY' for q in ctx['quarantine'])

def test_failed_group_still_listed_and_customers_retested():
    header='cert,device,alias,parent,valid_from,valid_to,minimum,maximum,unit,revoked,measured_at,value,measure_unit,version,lab,uncertainty,lead'
    def r(cert,dev,alias,parent,day,val,lab='',unc='',lead='',rev='no'):
        return f'{cert},{dev},{alias},{parent},2026-01-01,2028-01-01,0,1000,V,{rev},{day},{val},V,1,{lab},{unc},{lead}'
    ctx=calculate('\n'.join([header,
        r('ROOT','REF','ref','','2026-10-01','10'),
        r('A1','STD-1','s1','ROOT','2026-10-02','10.00','L1','0.05','yes'),
        r('A2','STD-1','s1','ROOT','2026-10-03','10.02','L2','0.05'),
        r('B1','STD-2','s2','ROOT','2026-10-04','5.00','L3','0.05',rev='yes'),
        r('K1','D1','k1','A1','2026-11-01','5'),
        r('K2','D2','k2','B1','2026-11-02','5')])+'\n')
    groups=ctx['stages']['8']['groups']
    assert [g['结论'] for g in groups]==['加权一致','无参考']
    assert groups[1]['采信证书']=='' and 'B1' in groups[1]['排除证书']
    assert [x['测量证书'] for x in ctx['stages']['8']['retest']]==['K2']

