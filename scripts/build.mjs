import {readFile,mkdir,writeFile,copyFile} from 'node:fs/promises';
const report=JSON.parse(await readFile(new URL('../xdr/brute-force/result.json',import.meta.url),'utf8'));
await mkdir(new URL('../public/',import.meta.url),{recursive:true});
await writeFile(new URL('../public/report.json',import.meta.url),JSON.stringify(report,null,2));
console.log('Static report ready');
