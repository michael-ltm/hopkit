import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createPublicKey,verify,createHash} from 'node:crypto';
const signed=JSON.parse(await readFile('public/downloads/release.json','utf8'));
const key=createPublicKey({key:{kty:'OKP',crv:'Ed25519',x:'ihdgSJDRX-pBIH6ORAanzGs4-JwAFNcmYreMXR2R8wU'},format:'jwk'});
if(!verify(null,Buffer.from(signed.payload),key,Buffer.from(signed.signature,'base64url')))throw Error('Invalid installer release signature');
const release=JSON.parse(signed.payload);
if(!/^0\.\d+\.\d+(?:[-.a-z0-9]+)?$/.test(release.version)||release.expires*1000<Date.now())throw Error('Invalid or expired release');
const posix=[],windows=[];
for(const asset of release.assets){
 if(!['darwin','linux','windows'].includes(asset.os)||!['amd64','arm64'].includes(asset.arch))throw Error('Unsupported release target');
 const name=`sshm-${asset.os}-${asset.arch}${asset.os==='windows'?'.exe':''}`;
 if(asset.url!==`https://sshm.yunmini.net/downloads/${name}`)throw Error('Unexpected release origin');
 const bytes=await readFile('public/downloads/'+name);
 if(bytes.length!==asset.size||createHash('sha256').update(bytes).digest('hex')!==asset.sha256)throw Error('Release asset mismatch: '+name);
 if(asset.os==='windows')windows.push(`    '${asset.arch}' = '${asset.sha256}'`);
 else posix.push(`    ${asset.os}-${asset.arch}) expected='${asset.sha256}' ;;`);
}
if(posix.length!==4||windows.length!==2)throw Error('Incomplete release');
const sh=(await readFile('installers/install.sh','utf8')).replace('@@POSIX_ASSETS@@',posix.join('\n')).replaceAll('@@VERSION@@',release.version);
const ps=(await readFile('installers/install.ps1','utf8')).replace('@@WINDOWS_ASSETS@@',windows.join('\n')).replaceAll('@@VERSION@@',release.version);
await writeFile('src/installers-generated.ts',`// Generated from verified release.\nexport const installSh = ${JSON.stringify(sh)};\nexport const installPs1 = ${JSON.stringify(ps)};\n`);
// Local QA copies; production serves these from the Worker.
await mkdir('dist',{recursive:true});await writeFile('dist/install.sh',sh);await writeFile('dist/install.ps1',ps);
