import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {test} from 'node:test'
import {inspectDistribution} from './distribution-evidence.mjs'
import {hash} from './license-evidence.mjs'

const root=path.resolve('.')
function tempFixture(callback){
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'station-frontend-distribution-'))
 const folder=path.join(temp,'frontend')
 try{
  fs.mkdirSync(folder,{recursive:true})
  for(const name of ['package.json','package-lock.json','license-evidence.json'])
   fs.copyFileSync(path.join(root,name),path.join(folder,name))
  fs.copyFileSync(path.join(root,'../LICENSE'),path.join(temp,'LICENSE'))
  fs.cpSync(path.join(root,'../LICENSES'),path.join(temp,'LICENSES'),{recursive:true})
  fs.cpSync(path.join(root,'dist'),path.join(folder,'dist'),{recursive:true})
  const manifest=JSON.parse(fs.readFileSync(path.join(folder,'dist/frontend-build.json'),'utf8'))
  const lock=JSON.parse(fs.readFileSync(path.join(folder,'package-lock.json'),'utf8'))
  for(const dep of manifest.dependencies){
   const [key]=Object.entries(lock.packages).find(([k,v])=>k && (k.endsWith('/'+dep.name) || k==='node_modules/'+dep.name) && v.version===dep.version && v.integrity===dep.integrity) || []
   assert.ok(key,'Fixture missing installed exact dependency '+dep.name)
   fs.mkdirSync(path.dirname(path.join(folder,key)),{recursive:true})
   fs.cpSync(path.join(root,key),path.join(folder,key),{recursive:true})
  }
  return callback(folder)
 }finally{fs.rmSync(temp,{recursive:true,force:true})}
}
const editManifest=(dir,callback)=>{
 const file=path.join(dir,'dist/frontend-build.json')
 const value=JSON.parse(fs.readFileSync(file,'utf8'))
 callback(value)
 fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n')
}

test('real production asset inventory maps each JS output to reviewed npm notice bytes',()=>{
 const result=inspectDistribution(root)
 assert.equal(result.status,'source-inventory-only-not-distribution-rights-clearance')
 assert.ok(result.emitted_npm_dependencies.length>0)
 assert.ok(result.npm_lock_inventory.length>result.emitted_npm_dependencies.length)
 assert.ok(Object.keys(result.browser_assets.assets).some(x=>x.endsWith('.js')))
 assert.ok(Object.values(result.browser_assets.assets).some(x=>x.dependency_notices.length))
 assert.equal(result.distribution_exclusions.python_wheels.includes('Separate'),true)
 assert.equal(result.source_selection.native_credential_installation,'not-authorized')
 assert.ok(result.npm_lock_inventory.some(x=>x.distribution_scope==='npm-build-test-lock-only-not-shipped'))
})

test('missing, extra, stale or altered dist output is never accepted',()=>{
 for(const mode of ['delete','extra','modified']){
  tempFixture(dir=>{
   const out=path.join(dir,'dist'),manifest=JSON.parse(fs.readFileSync(path.join(out,'frontend-build.json')))
   const target=Object.keys(manifest.outputs).find(x=>x.endsWith('.js'))
   assert.ok(target)
   if(mode==='delete')fs.unlinkSync(path.join(out,target))
   if(mode==='extra')fs.writeFileSync(path.join(out,'surprise-worker.js'),'// unreviewed')
   if(mode==='modified')fs.appendFileSync(path.join(out,target),'\n// tampered')
   assert.throws(()=>inspectDistribution(dir),/generated asset (added|missing|untracked)|missing or modified generated asset/)
  })
 }
})

test('missing and substituted npm legal notices fail even with unchanged source pins',()=>{
 for(const mode of ['missing','modified','manifest']){
  tempFixture(dir=>{
   const build=JSON.parse(fs.readFileSync(path.join(dir,'dist/frontend-build.json')))
   const dep=build.dependencies.find(x=>x.name==='react')
   assert.ok(dep)
   if(mode==='manifest'){
    editManifest(dir,m=>{
     m.dependencies.find(x=>x.name==='react').notices=[]
    })
   }else {
    const notice=path.join(dir,'node_modules/react',dep.notices[0].path)
    if(mode==='missing')fs.unlinkSync(notice)
    else fs.appendFileSync(notice,'\nUnapproved license replacement')
   }
   assert.throws(()=>inspectDistribution(dir),/missing, changed or extra generated npm notice|ENOENT|missing or modified published npm notice/)
  })
 }
})

test('forged asset-to-npm map, missing attribution link, or lock archive swap fails',()=>{
 tempFixture(dir=>{
  editManifest(dir,m=>{
   const chunk=Object.keys(m.coverage.chunk_dependencies)[0]
   m.coverage.chunk_dependencies[chunk].push('unreviewed@0.0.0')
  })
  assert.throws(()=>inspectDistribution(dir),/unreviewed npm dependency|ambiguous per-chunk/)
 })
 tempFixture(dir=>{
  const index=path.join(dir,'dist/index.html')
  fs.writeFileSync(index,fs.readFileSync(index,'utf8').replace('rel="license"','rel="stylesheet"'))
  const updated=fs.readFileSync(index)
  editManifest(dir,m=>{m.outputs['index.html']=hash(updated)})
  assert.throws(()=>inspectDistribution(dir),/missing generated frontend license link/)
 })
 tempFixture(dir=>{
  const locked=path.join(dir,'package-lock.json')
  const value=JSON.parse(fs.readFileSync(locked,'utf8'))
  value.packages['node_modules/react'].resolved='https://example.invalid/tampered.tar.gz'
  fs.writeFileSync(locked,JSON.stringify(value))
  assert.throws(()=>inspectDistribution(dir),/missing or ambiguous exact npm lock identity/)
 })
})

test('independent rights and production adoption claims in candidate ledger fail closed',()=>{
 tempFixture(dir=>{
  const out=path.join(dir,'synthetic-ledger.json')
  const ledger={schema:'zog-administrator-credential-candidate-provenance-v1',
    independent_rightsholder_permission:'not-attested',
    production_pin_change:'forbidden',
    revisions:[{repository:'zog144/station-access',commit:'7e8829483c1f2d49b2a4e7f2d97c6c2b9e364a73'}]}
  fs.writeFileSync(out,JSON.stringify(ledger))
  const result=inspectDistribution(dir,{ledgerPath:out})
  assert.equal(result.source_selection.rights_holder_permission,'not-attested')
  ledger.independent_rightsholder_permission='accepted'
  fs.writeFileSync(out,JSON.stringify(ledger))
  assert.throws(()=>inspectDistribution(dir,{ledgerPath:out}),/ledger changed or claimed new authority/)
  ledger.independent_rightsholder_permission='not-attested'
  ledger.revisions[0].commit='0'.repeat(40)
  fs.writeFileSync(out,JSON.stringify(ledger))
  assert.throws(()=>inspectDistribution(dir,{ledgerPath:out}),/ledger changed or claimed new authority/)
 })
})
