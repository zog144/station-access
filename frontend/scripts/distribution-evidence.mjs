// Candidate-only distribution evidence. Reuse release-plugin's reviewed Vite
// manifest; never synthesize legal permission from npm's license field.
import fs from 'node:fs'
import path from 'node:path'
import {hash} from './license-evidence.mjs'

const fail = message => {throw new Error('Frontend distribution evidence: '+message)}
const isHex = s => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s)
const equal = (a,b) => JSON.stringify(a) === JSON.stringify(b)
const file = (p) => fs.readFileSync(p)
const json = (p) => JSON.parse(fs.readFileSync(p,'utf8'))
const normalize = s => {
 if(typeof s !== 'string' || !s || s.includes('\\') || s.includes('\0') || s.startsWith('/')
    || s.split('/').some(x => x === '..' || x === '.' || x === '')) fail('unsafe relative file name')
 return s
}
function walk(root) {
 const result=[]
 function visit(folder) {
  for (const entry of fs.readdirSync(folder,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))) {
   const p=path.join(folder,entry.name)
   if(entry.isSymbolicLink()) fail('symlink in generated distribution: '+p)
   if(entry.isDirectory()) visit(p)
   else if(entry.isFile()) result.push(path.relative(root,p).split(path.sep).join('/'))
   else fail('unexpected distribution entry type: '+p)
  }
 }
 visit(root)
 return result.sort()
}
function packageName(lockedPath){
 const i=lockedPath.lastIndexOf('node_modules/')
 if(i<0)fail('non-package entry in npm lockfile: '+lockedPath)
 return lockedPath.slice(i+'node_modules/'.length)
}
export function inspectDistribution(frontendRoot,{ledgerPath=null,write=false}={}){
 const root=path.resolve(frontendRoot),dist=path.join(root,'dist')
 const manifest=json(path.join(dist,'frontend-build.json'))
 const lock=json(path.join(root,'package-lock.json'))
 const evidence=json(path.join(root,'license-evidence.json'))
 const pkg=json(path.join(root,'package.json'))
 if(manifest.schema!==2 || manifest.mode!=='production' || manifest.node_env!=='production')
  fail('not a reviewed production frontend build')
 if(pkg.private!==true || pkg.license!=='BSD-3-Clause OR GPL-3.0-only')
  fail('first-party source license or private package declaration changed')
 if(lock.lockfileVersion!==3 || lock.packages?.['']?.license!==pkg.license)
  fail('npm lockfile source declaration mismatch')
 if(!manifest.outputs || !manifest.dependencies?.length || !manifest.first_party_licenses?.length)
  fail('incomplete Vite release provenance')
 const expected=Object.keys(manifest.outputs).sort()
 const actual=walk(dist).filter(name=>name!=='frontend-build.json' && name!=='ADMIN-CREDENTIAL-FRONTEND-REVIEW.json')
 if(!equal(actual,expected)) fail('generated asset added, missing or untracked: '+JSON.stringify({expected,actual}))
 for(const name of expected){
  normalize(name)
  const expectedDigest=manifest.outputs[name]
  if(!isHex(expectedDigest) || hash(file(path.join(dist,name)))!==expectedDigest)
   fail('missing or modified generated asset: '+name)
 }
 if(!expected.includes('index.html') || !expected.includes(manifest.licenses)
    || !/^assets\/LICENSES-[a-f0-9]{12}\.txt$/.test(manifest.licenses))
  fail('generated complete license bundle is untracked')
 const html=file(path.join(dist,'index.html')).toString('utf8')
 const link='<link rel="license" href="/'+manifest.licenses+'" />'
 if(!html.includes(link)) fail('missing generated frontend license link')
 const legal=file(path.join(dist,manifest.licenses)).toString('utf8')
 if(!legal.trim())fail('generated LICENSES file is empty')
 if(manifest.licenses!=='assets/LICENSES-'+hash(legal).slice(0,12)+'.txt')
  fail('license filename digest does not match actual emitted legal text')
 for(const item of manifest.first_party_licenses){
  normalize(item.path.replace(/^\.\.\//,''))
  if(!isHex(item.sha256) || hash(file(path.resolve(root,item.path)))!==item.sha256)
   fail('first-party license source changed: '+item.path)
 }
 if(!legal.includes(pkg.license))fail('first-party license declaration missing in output')
 const included=new Map()
 const matchedLock=new Map()
 for(const dep of manifest.dependencies){
  const key=dep.name+'@'+dep.version
  if(included.has(key))fail('duplicate emitted npm dependency: '+key)
  const source=evidence.packages?.[key]
  if(!source || source.status!=='reviewed' || !source.reviewed_terms
     || source.declared_license!==dep.license)
   fail('missing reviewed dependency notice evidence: '+key)
  if(!Array.isArray(dep.notices) || !dep.notices.length ||
     dep.notices.some(note => !source.notices.some(item=>item.path===note.path && item.sha256===note.sha256)) ||
     source.notices.some(item => !dep.notices.some(note=>note.path===item.path && note.sha256===item.sha256)))
    fail('missing, changed or extra generated npm notice: '+key)
  if(!legal.includes('===== '+dep.name+' '+dep.version+' ====='))
   fail('missing included npm package heading: '+key)
  for(const item of dep.notices){
   if(!isHex(item.sha256) || !legal.includes('----- Upstream '+item.path+' (verbatim) -----'))
    fail('missing generated npm legal notice: '+key+'/'+item.path)
  }
  const locked=Object.entries(lock.packages).filter(([p,v])=>p && packageName(p)===dep.name && v.version===dep.version && v.resolved===dep.tarball && v.integrity===dep.integrity)
  if(locked.length!==1)fail('missing or ambiguous exact npm lock identity: '+key)
  for(const notice of dep.notices){
   const publishedNotice=file(path.join(root,locked[0][0],normalize(notice.path)))
   if(hash(publishedNotice)!==notice.sha256)
    fail('missing or modified published npm notice: '+key+'/'+notice.path)
   const exactText=publishedNotice.toString('utf8')
   if(!exactText.trim() || !legal.includes('----- Upstream '+notice.path+' (verbatim) -----\n'+exactText+'\n'))
    fail('reviewed npm notice omitted from generated license asset: '+key+'/'+notice.path)
  }
  matchedLock.set(locked[0][0],key)
  included.set(key,{name:dep.name,version:dep.version,license:dep.license,
                    lock_path:locked[0][0],tarball:dep.tarball,integrity:dep.integrity,
                    reviewed_terms:dep.reviewed_terms,
                    notices:dep.notices.map(n=>({path:n.path,sha256:n.sha256}))})
 }
 const chunks=manifest.coverage?.chunk_dependencies
 if(!chunks || typeof chunks!=='object'||Array.isArray(chunks))
  fail('missing per-emitted JavaScript dependency source mapping')
 const js=expected.filter(name=>name.endsWith('.js'))
 if(!equal(Object.keys(chunks).sort(),js))fail('emitted JS asset lacks source dependency map')
 const byOutput={}
 const assigned=new Set()
 for(const name of js){
  const keys=chunks[name]
  if(!Array.isArray(keys) || !equal([...new Set(keys)].sort(),keys))
   fail('ambiguous per-chunk dependency identities: '+name)
  for(const key of keys){
   if(!included.has(key)) fail('unreviewed npm dependency emitted in '+name+': '+key)
   assigned.add(key)
  }
  byOutput[name]={
   sha256:manifest.outputs[name],
   dependency_notices:keys.map(key=>({package:key,
     notices:included.get(key).notices.map(n=>n.path+'#sha256='+n.sha256)})),
   first_party_licenses:manifest.first_party_licenses.map(x=>x.path)
  }
 }
 for(const key of included.keys())
  if(!assigned.has(key) && !key.startsWith('vite@'))fail('reviewed npm dependency with no emitted JS provenance: '+key)
 for(const name of expected.filter(x=>!x.endsWith('.js'))){
  byOutput[name]={sha256:manifest.outputs[name],
    dependency_notices:name===manifest.licenses
      ? [...included].map(([key,v])=>({package:key,notices:v.notices.map(n=>n.path+'#sha256='+n.sha256)}))
      : [],
    first_party_licenses:manifest.first_party_licenses.map(x=>x.path)}
 }
 const npmInventory=Object.entries(lock.packages)
  .filter(([k])=>k)
  .sort(([a],[b])=>a.localeCompare(b))
  .map(([p,v])=>{
   const name=packageName(p),key=name+'@'+v.version
   if(typeof v.version!=='string'||!v.version || typeof v.resolved!=='string'||typeof v.integrity!=='string')
    fail('npm lock entry missing immutable archive identity: '+p)
   const bundled=matchedLock.get(p)===key
   return {lock_path:p,name,version:v.version,tarball:v.resolved,integrity:v.integrity,
     dev:!!v.dev,optional:!!v.optional,
     distribution_scope:bundled?'reviewed-emitted-bundle':'npm-build-test-lock-only-not-shipped',
     legal_status:bundled?'source-reviewed-not-rights-cleared':'not-reviewed-for-redistribution'}
  })
 const sourceSelection={mode:'source-review-only',host_discover_provenance_commit:'11376e09d7b9ff1251eca0549c2730406be1ca66',
   administrator_receiver_station_commit:'7e8829483c1f2d49b2a4e7f2d97c6c2b9e364a73',
   rights_holder_permission:'not-attested',native_credential_installation:'not-authorized'}
 if(ledgerPath){
  const bytes=file(ledgerPath),ledger=JSON.parse(bytes)
  const station=ledger.revisions?.find(x=>x.repository==='zog144/station-access')
  if(ledger.schema!=='zog-administrator-credential-candidate-provenance-v1'
      || station?.commit!==sourceSelection.administrator_receiver_station_commit
      || ledger.independent_rightsholder_permission!=='not-attested'
      || ledger.production_pin_change!=='forbidden')
   fail('exact administrator-credential candidate ledger changed or claimed new authority')
  sourceSelection.ledger_sha256=hash(bytes)
 }else sourceSelection.ledger_sha256=null
 const output={
  schema:'zog-station-admin-credential-frontend-distribution-evidence-v1',
  status:'source-inventory-only-not-distribution-rights-clearance',
  ...{source_selection:sourceSelection},
  production_pins:'unchanged-unapproved-candidate',
  browser_assets:{
   build_manifest_sha256:hash(file(path.join(dist,'frontend-build.json'))),
   generated_license_file:manifest.licenses,
   generated_license_sha256:hash(file(path.join(dist,manifest.licenses))),
   first_party_licenses:manifest.first_party_licenses,
   assets:byOutput
  },
  emitted_npm_dependencies:[...included.values()].sort((a,b)=>a.name.localeCompare(b.name)),
  npm_lock_inventory:npmInventory,
  distribution_exclusions:{
   installed_only_npm_entries:npmInventory.filter(x=>x.distribution_scope!=='reviewed-emitted-bundle').length,
   node_modules:'Not included in reviewed Vite output; any future distribution of node_modules requires separate notices and rights review',
   websocket_novnc:'Externally served noVNC is excluded from frontend bundle review',
   python_wheels:'Separate exact host-discover PR #5 wheel inventory; never inferred from frontend evidence'
  }
 }
 if(write)fs.writeFileSync(path.join(dist,'ADMIN-CREDENTIAL-FRONTEND-REVIEW.json'),JSON.stringify(output,null,2)+'\n')
 return output
}
if(import.meta.url === new URL('file://'+process.argv[1]).href){
 const root=path.resolve(process.argv[2]||'.')
 const index=process.argv.indexOf('--ledger')
 if(index<0 || !process.argv[index+1])fail('explicit --ledger path is required for candidate report')
 const r=inspectDistribution(root,{ledgerPath:path.resolve(process.argv[index+1]),write:true})
 console.log('Source-only frontend evidence: '+Object.keys(r.browser_assets.assets).length+' output assets; '+
  r.emitted_npm_dependencies.length+' emitted npm dependencies; '+r.npm_lock_inventory.length+' locked npm entries.')
 console.log('No rights-holder clearance, production repin, Credential Authority, Host STATE or native installation.')
}
