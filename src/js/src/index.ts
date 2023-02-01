import '@phala/pink-env'
//import * as jp from 'jsonpath'

const pink = globalThis.pink;
//let scriptArgs = ["{\"a\": \"2\"}", "a"];

(function () {
  let j = JSON.parse(scriptArgs[0]) as any;
  const path = scriptArgs[1]
  let pp = path.split('.');
  for(let i = 0;i < pp.length;i++) {
    j = j[pp[i]];
  }
  console.log(j);
  return j;
})()
