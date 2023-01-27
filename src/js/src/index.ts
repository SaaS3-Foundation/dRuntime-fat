import './polyfills.js'
import '@phala/pink-env'
import * as jp from 'jsonpath'

const pink = globalThis.pink;

(function () {
  const j = JSON.parse(scriptArgs[0])
  const path = scriptArgs[1]
  let t = jp.query(j, path);
  return t[0];
})()
