const fs = require('fs');
const path = require('path');

let acorn;
try {
  const acornPath = path.resolve(__dirname, '../../node_modules/acorn');
  acorn = require(acornPath);
} catch (e) {
  try {
    acorn = require('acorn');
  } catch (err) {
    console.error(`Failed to load acorn: ${err.message}`);
    process.exit(1);
  }
}

// Default static asset extension filter
const DEFAULT_EXT_FILTER = new Set([
  ".3g2", ".3gp", ".7z", ".apk", ".arj", ".avi", ".axd", ".bmp", ".csv", ".deb",
  ".dll", ".doc", ".drv", ".eot", ".exe", ".flv", ".gif", ".gifv", ".gz", ".h264",
  ".ico", ".iso", ".jar", ".jpeg", ".jpg", ".lock", ".m4a", ".m4v", ".map", ".mkv",
  ".mov", ".mp3", ".mp4", ".mpeg", ".mpg", ".msi", ".ogg", ".ogm", ".ogv", ".otf",
  ".pdf", ".pkg", ".png", ".ppt", ".psd", ".rar", ".rm", ".rpm", ".svg", ".swf",
  ".sys", ".tar.gz", ".tar", ".tif", ".tiff", ".ttf", ".txt", ".vob", ".wav", ".webm",
  ".webp", ".wmv", ".woff", ".woff2", ".xcf", ".xls", ".xlsx", ".zip"
]);

function isFilteredStaticExtension(val) {
  if (!val || typeof val !== 'string') {
    return false;
  }
  try {
    let pathname = val;
    if (val.includes('://')) {
      pathname = new URL(val).pathname;
    } else {
      // Remove query parameters and hash fragments like Go's path.Ext
      pathname = val.split('?')[0].split('#')[0];
    }
    const idx = pathname.lastIndexOf('.');
    if (idx !== -1) {
      const ext = pathname.slice(idx).toLowerCase();
      return DEFAULT_EXT_FILTER.has(ext);
    }
  } catch (e) {
    // Fallback to basic extension extraction
    const base = val.split('?')[0].split('#')[0];
    const idx = base.lastIndexOf('.');
    if (idx !== -1) {
      const ext = base.slice(idx).toLowerCase();
      return DEFAULT_EXT_FILTER.has(ext);
    }
  }
  return false;
}

let inputCode = '';
process.stdin.on('data', chunk => {
  inputCode += chunk;
});

process.stdin.on('end', () => {
  try {
    const ast = acorn.parse(inputCode, { ecmaVersion: 2020, sourceType: 'module', allowAwaitOutsideFunction: true });
    const endpoints = [];
    const seen = new Set();

    function addEndpoint(method, url, expr = null) {
      if (!url || typeof url !== 'string') return;
      const cleanUrl = url.trim();
      if (!cleanUrl || cleanUrl.startsWith('data:') || cleanUrl.startsWith('javascript:')) return;
      
      // Filter out static assets exactly like OpenRecon path validation filter
      if (isFilteredStaticExtension(cleanUrl)) {
        return;
      }
      
      const key = `${method.toUpperCase()} ${cleanUrl}`;
      if (!seen.has(key)) {
        seen.add(key);
        endpoints.push({ method: method.toUpperCase(), url: cleanUrl, expression: expr });
      }
    }

    function getTemplateLiteralString(node) {
      let url = '';
      const quasis = node.quasis;
      const expressions = node.expressions;
      for (let i = 0; i < quasis.length; i++) {
        url += quasis[i].value.cooked;
        if (i < expressions.length) {
          const expr = expressions[i];
          if (expr.type === 'Identifier') {
            url += `{${expr.name}}`;
          } else {
            url += `{var}`;
          }
        }
      }
      return url;
    }

    function walk(node) {
      if (!node) return;

      // 1. CallExpression: fetch(...) or axios.post(...)
      if (node.type === 'CallExpression') {
        let method = 'GET';
        let url = null;

        let expr = null;
        if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
          if (node.arguments.length > 0) {
            if (node.arguments[0].type === 'Literal') {
              url = node.arguments[0].value;
            } else if (node.arguments[0].type === 'TemplateLiteral') {
              url = getTemplateLiteralString(node.arguments[0]);
            }
          }
          if (node.arguments.length > 1 && node.arguments[1].type === 'ObjectExpression') {
            const methodProp = node.arguments[1].properties.find(p => p.key && p.key.name === 'method');
            if (methodProp && methodProp.value && methodProp.value.type === 'Literal') {
              method = methodProp.value.value.toUpperCase();
            }
          }
          expr = 'fetch("' + url + '")';
        } else if (node.callee.type === 'MemberExpression') {
          const obj = node.callee.object;
          const prop = node.callee.property;
          if (obj.type === 'Identifier' && ['axios', 'http', 'apiClient', 'client', 'instance'].includes(obj.name)) {
            if (prop.type === 'Identifier' && ['get', 'post', 'put', 'delete', 'patch'].includes(prop.name)) {
              method = prop.name.toUpperCase();
              if (node.arguments.length > 0) {
                if (node.arguments[0].type === 'Literal') {
                  url = node.arguments[0].value;
                } else if (node.arguments[0].type === 'TemplateLiteral') {
                  url = getTemplateLiteralString(node.arguments[0]);
                }
              }
              expr = obj.name + '.' + prop.name.toLowerCase() + '("' + url + '")';
            }
          }
        }

        if (url) {
          addEndpoint(method, url, expr);
        }
      }

      // 2. ObjectExpression property url/method config
      if (node.type === 'ObjectExpression') {
        const urlProp = node.properties.find(p => p.key && (p.key.name === 'url' || p.key.name === 'endpoint' || p.key.name === 'path'));
        if (urlProp && urlProp.value) {
          let urlVal = null;
          if (urlProp.value.type === 'Literal') {
            urlVal = urlProp.value.value;
          } else if (urlProp.value.type === 'TemplateLiteral') {
            urlVal = getTemplateLiteralString(urlProp.value);
          }

          if (urlVal) {
            let method = 'GET';
            const methodProp = node.properties.find(p => p.key && (p.key.name === 'method' || p.key.name === 'type'));
            if (methodProp && methodProp.value && methodProp.value.type === 'Literal') {
              method = methodProp.value.value.toUpperCase();
            }
            addEndpoint(method, urlVal, '{ url: "' + urlVal + '", method: "' + method + '" }');
          }
        }
      }

      // 3. String & Template Literals looking like API paths (including absolute HTTP/WS endpoints)
      if (node.type === 'Literal' && typeof node.value === 'string') {
        const val = node.value.trim();
        if ((val.startsWith('/') && !val.startsWith('//')) || /^(?:https?|wss?):\/\//i.test(val)) {
          if (/(?:\/api\/|\/v[0-9]|\/graphql|\/auth\/|\/oauth\/|\/rest\/|\/rpc\/)/i.test(val)) {
            addEndpoint('GET', val, '"' + val + '"');
          }
        }
      }
      if (node.type === 'TemplateLiteral') {
        const val = getTemplateLiteralString(node).trim();
        if ((val.startsWith('/') && !val.startsWith('//')) || /^(?:https?|wss?):\/\//i.test(val)) {
          if (/(?:\/api\/|\/v[0-9]|\/graphql|\/auth\/|\/oauth\/|\/rest\/|\/rpc\/)/i.test(val)) {
            addEndpoint('GET', val, '`' + val + '`');
          }
        }
      }

      // 4. NewExpression: new WebSocket(...) or new EventSource(...)
      if (node.type === 'NewExpression' && node.callee.type === 'Identifier') {
        const calleeName = node.callee.name;
        if (calleeName === 'WebSocket' || calleeName === 'EventSource') {
          if (node.arguments.length > 0) {
            let urlVal = null;
            if (node.arguments[0].type === 'Literal') {
              urlVal = node.arguments[0].value;
            } else if (node.arguments[0].type === 'TemplateLiteral') {
              urlVal = getTemplateLiteralString(node.arguments[0]);
            }
            if (urlVal) {
              const method = calleeName === 'WebSocket' ? 'WS' : 'SSE';
              addEndpoint(method, urlVal, 'new ' + calleeName + '("' + urlVal + '")');
            }
          }
        }
      }

      // Recurse child nodes
      for (const key in node) {
        const child = node[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            child.forEach(walk);
          } else if (child.type) {
            walk(child);
          }
        }
      }
    }

    walk(ast);
    process.stdout.write(JSON.stringify(endpoints));
    process.exit(0);
  } catch (e) {
    process.stdout.write('[]');
    process.exit(0);
  }
});
