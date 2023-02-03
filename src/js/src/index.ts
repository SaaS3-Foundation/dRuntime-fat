import '@phala/pink-env'
import * as R from 'ramda'

const pink = globalThis.pink;
let scriptArgs = ["{\"a\": \"2\"}", "a"];

(function () {
  const j = JSON.parse(scriptArgs[0]);
  const path = scriptArgs[1].split('.');
  const v = R.path(path, j);
  console.log(v);
  return v;
})()
