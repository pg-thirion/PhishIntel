from types import SimpleNamespace
import json
import pytest
from phishintel.intel import IntelPolicy, enrich, html_signals, triage, summary, one_edit


def message(**kw):
    defaults = dict(sender='a@example.org',reply_to='',return_path='',from_count=1,subject='',body='',links=(),attachments=(),html_codes=())
    return SimpleNamespace(**(defaults | kw))


@pytest.mark.parametrize('markup,code',[
    ('<form></form>','html_form'),('<input type=password>','password_field'),
    ('<img src="https://example.org/a">','remote_image'),
    ('<img src="https://example.org/a" width=1>','tracking_pixel'),
    ('<iframe src="https://example.org"></iframe>','active_content'),
    ('<div style="display: none">x</div>','hidden_html'),
    ('<a href="https://example.net">https://example.org</a>','anchor_mismatch'),
])
def test_html(markup,code):
    assert code in html_signals(markup)
    assert code in {f['code'] for f in enrich(message(html_codes=html_signals(markup)))['findings']}


@pytest.mark.parametrize('kwargs,code',[
    ({'from_count':2},'multiple_from'),({'sender':''},'missing_sender'),
    ({'return_path':'x@example.net'},'return_path_mismatch'),
    ({'links':('https://bit.ly/example',)},'shortened_url'),
    ({'links':('https://a.b.c.example.org',)},'deep_subdomain'),
    ({'links':('https://example.org:8443',)},'nonstandard_port'),
    ({'links':('https://%65xample.org',)},'encoded_authority'),
    ({'links':('https://example.org/?next=https%3A%2F%2Fexample.net',)},'redirect_parameter'),
    ({'links':('https://example.org:invalid',)},'url_parse_error'),
    ({'links':('https://watch.example.net',)},'watchlist_match'),
    ({'sender':'a@examp1e.org'},'lookalike_domain'),
    ({'attachments':('report\u202e.pdf',)},'bidi_filename'),
    ({'attachments':('report.pdf.exe',)},'double_extension'),
    ({'attachments':('report.zip',)},'archive_attachment'),
    ({'attachments':('report.html',)},'html_attachment'),
    ({'attachments':('report.docm',)},'macro_document'),
    ({'attachments':('(attached email)',)},'nested_email'),
    ({'subject':'Urgent'},'urgency_language'),
    ({'body':'Confirm your password'},'credential_request'),
    ({'body':'Send bank details'},'payment_request'),
    ({'body':'Purchase gift cards'},'gift_card_request'),
])
def test_indicators(kwargs,code):
    evidence = enrich(message(**kwargs),IntelPolicy(('example.net',),('example.org',)))
    assert code in {f['code'] for f in evidence['findings']}


def test_policy_validation(tmp_path):
    p = tmp_path/'policy.json'
    p.write_text(json.dumps({'watched':['Example.NET','example.net'],'protected':['example.org']}))
    assert IntelPolicy.load(p).watched == ('example.net',)
    p.write_text(json.dumps({'watched':['https://example.net']}))
    with pytest.raises(ValueError): IntelPolicy.load(p)
    p.write_text('[]')
    with pytest.raises(ValueError): IntelPolicy.load(p)


def test_boundaries_and_safe_summary():
    evidence = enrich(message(links=('https://notexample.net/path?secret=private',)*300),IntelPolicy(('example.net',),()))
    assert evidence['link_count'] == 1
    assert 'watchlist_match' not in {f['code'] for f in evidence['findings']}
    assert 'notexample[.]net' in evidence['domains']
    result = {'verdict':'Likely legitimate','score':.1,'phishing_terms':['secret']}
    decision = triage(result,evidence)
    assert decision['priority'] == 'routine' and decision['automatic_clearance'] is False
    assert 'secret' not in json.dumps(summary(result,evidence,decision))
    high = enrich(message(html_codes=('password_field',)))
    assert triage(result,high)['priority'] == 'high'
    assert triage({'verdict':'Needs review'},evidence)['priority'] == 'review'
    assert triage(result,evidence,[{'severity':'review'}])['priority'] == 'review'


def test_one_edit():
    assert one_edit('example.org','exmple.org')
    assert one_edit('example.org','examp1e.org')
    assert not one_edit('example.org','example.org')
    assert not one_edit('example.org','unrelated.net')

def test_mime_integration():
    from phishintel.email import parse_eml
    raw = (b"From: Alice <a@example.org>\r\nFrom: Bob <b@example.org>\r\n"
           b"Return-Path: <bounce@example.net>\r\nContent-Type: text/html\r\n\r\n"
           b"<form><input type=password></form><p>Confirm your password</p>")
    evidence = enrich(parse_eml(raw))
    codes = {f['code'] for f in evidence['findings']}
    assert {'multiple_from','return_path_mismatch','html_form','password_field','credential_request'} <= codes
