#!/usr/bin/env python3
"""Read-only external link audit. No third-party dependencies."""
import csv,html,os,re,ssl,time,urllib.request,urllib.error
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'audit-results';OUT.mkdir(exist_ok=True)
UA='Mozilla/5.0 (compatible; TransferPortalLinkAudit/1.0; +https://github.com/)'
HEADERS={'User-Agent':UA,'Accept':'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5'}
class LimitedRedirect(urllib.request.HTTPRedirectHandler):
 def __init__(self): super().__init__();self.history=[]
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  self.history.append({'status':code,'location':newurl})
  return super().redirect_request(req,fp,code,msg,headers,newurl)
def check(item):
 url=item['url'];start=time.monotonic();redir=LimitedRedirect();opener=urllib.request.build_opener(redir)
 row={'url':url,'used_by':item['used_by'],'http_status':'','final_url':'','redirects':'','page_title':'','content_type':'','result':'','error':'','elapsed_seconds':''}
 try:
  req=urllib.request.Request(url,headers=HEADERS,method='GET')
  with opener.open(req,timeout=22) as resp:
   row['http_status']=resp.status;row['final_url']=resp.geturl();row['content_type']=resp.headers.get('Content-Type','')
   raw=resp.read(160000)
   if 'html' in row['content_type'].lower():
    enc=resp.headers.get_content_charset() or 'utf-8'
    body=raw.decode(enc,errors='replace')
    m=re.search(r'<title\b[^>]*>(.*?)</title\s*>',body,re.I|re.S)
    if m: row['page_title']=re.sub(r'\s+',' ',html.unescape(re.sub(r'<[^>]*>','',m.group(1)))).strip()[:250]
   row['result']='PASS_HTTP' if 200<=resp.status<300 else 'REVIEW_HTTP'
 except urllib.error.HTTPError as e:
  row['http_status']=e.code;row['final_url']=e.geturl();row['result']='REVIEW_HTTP';row['error']=str(e.reason)[:250]
 except Exception as e:
  row['result']='REVIEW_CONNECTION';row['error']=f'{type(e).__name__}: {str(e)[:300]}'
 row['redirects']=' | '.join(f"{h['status']} -> {h['location']}" for h in redir.history)
 row['elapsed_seconds']=f'{time.monotonic()-start:.1f}'
 return row
with (ROOT/'audit/urls.csv').open(newline='',encoding='utf-8') as f: items=list(csv.DictReader(f))
# Low concurrency reduces load on university websites.
results=[]
with ThreadPoolExecutor(max_workers=4) as pool:
 for fut in as_completed([pool.submit(check,item) for item in items]):
  row=fut.result();results.append(row);print(row['result'],row['http_status'],row['url'],flush=True)
results.sort(key=lambda x:x['url'])
fields=['url','used_by','http_status','final_url','redirects','page_title','content_type','result','error','elapsed_seconds']
with (OUT/'link-audit-results.csv').open('w',newline='',encoding='utf-8') as f:
 w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(results)
from collections import Counter
c=Counter(r['result'] for r in results)
lines=['# Transfer Portal link audit',f"Run (UTC): {datetime.now(timezone.utc).isoformat()}",f"URLs checked: {len(results)}",'']
for status in ['PASS_HTTP','REVIEW_HTTP','REVIEW_CONNECTION']:lines.append(f'- {status}: {c[status]}')
lines+=['','**Important:** PASS_HTTP means a successful HTTP response, NOT that the page matches the intended degree or that credits transfer. Review page titles and destinations in the CSV. 403 and 429 can reflect bot protection rather than a broken student-facing link.','', '## URLs requiring review','']
for r in results:
 if r['result']!='PASS_HTTP':lines.append(f"- {r['result']} ({r['http_status'] or 'no status'}): {r['url']} — {r['error']}")
(OUT/'SUMMARY.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('SUMMARY',dict(c),'TOTAL',len(results))
