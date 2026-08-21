const fs = require('fs');
const path = require('path');

// Resolve path to copy-packaged files
const technologyCorePath = path.resolve(__dirname, './technology_engine.js');
const categoriesPath = path.resolve(__dirname, '../data/technology_categories.json');
const technologiesPath = path.resolve(__dirname, '../data/technology_signatures.json');

let TechnologyEngine;
try {
  TechnologyEngine = require(technologyCorePath);
} catch (e) {
  console.error(`Failed to load TechnologyEngine core from: ${technologyCorePath}`);
  process.exit(1);
}

// Load categories
try {
  const categories = JSON.parse(fs.readFileSync(categoriesPath));
  TechnologyEngine.setCategories(categories);
} catch (e) {
  console.error(`Failed to load categories: ${e.message}`);
  process.exit(1);
}

// Load technologies
try {
  const technologies = JSON.parse(fs.readFileSync(technologiesPath));
  TechnologyEngine.setTechnologies(technologies);
} catch (e) {
  console.error(`Failed to load technologies: ${e.message}`);
  process.exit(1);
}

// Load JSDOM from local workspace node_modules
let JSDOM;
try {
  const jsdomPath = path.resolve(__dirname, '../../node_modules/jsdom');
  JSDOM = require(jsdomPath).JSDOM;
} catch (e) {
  try {
    // Try standard require if path resolve fails (e.g. global module resolution)
    JSDOM = require('jsdom').JSDOM;
  } catch (err) {
    console.error(`Failed to load JSDOM: ${err.message}`);
    process.exit(1);
  }
}

// Read input items from stdin
let inputData = '';
process.stdin.on('data', chunk => {
  inputData += chunk;
});

process.stdin.on('end', () => {
  try {
    const items = JSON.parse(inputData);
    
    // Structure input correctly for TechnologyEngine.analyze
    const analyzeItems = {
      url: items.url || '',
      html: items.html || '',
      headers: items.headers || {},
      cookies: items.cookies || {},
      meta: items.meta || {},
      scriptSrc: items.scriptSrc || [],
      scripts: items.scripts || [],
      css: (items.css || []).join('\n'),
      dns: items.dns || {},
      text: items.text || '',
      certIssuer: items.certIssuer || '',
      robots: items.robots || ''
    };

    // Statically resolve JS global chains by searching script content
    const jsItems = {};
    TechnologyEngine.technologies.forEach(tech => {
      if (tech.js) {
        Object.keys(tech.js).forEach(chain => {
          const lastPart = chain.split('.').pop();
          const escapedChain = chain.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
          const regexStr = `(?:\\b${escapedChain}\\b|\\b${lastPart}\\b)\\s*[:=]\\s*['"\`]([^'"\`]+)['"\`]`;
          const regex = new RegExp(regexStr, 'i');
          
          let matchedValue = null;
          for (const script of analyzeItems.scripts) {
            const m = regex.exec(script);
            if (m) {
              matchedValue = m[1];
              break;
            }
          }
          if (matchedValue === null) {
            const presenceRegex = new RegExp(`\\b${escapedChain}\\b`, 'i');
            for (const script of analyzeItems.scripts) {
              if (presenceRegex.test(script)) {
                matchedValue = true;
                break;
              }
            }
          }
          if (matchedValue !== null) {
            if (!jsItems[chain]) {
              jsItems[chain] = [];
            }
            jsItems[chain].push(matchedValue);
          }
        });
      }
    });
    analyzeItems.js = jsItems;

    // Run HTML and resource matching
    const detections = TechnologyEngine.analyze(analyzeItems);

    // Run DOM selector matching using JSDOM (ported from upstream driver.js getDom)
    let domMatches = [];
    if (analyzeItems.html) {
      const dom = new JSDOM(analyzeItems.html);
      const document = dom.window.document;
      
      const toScalar = (value) =>
        typeof value === 'string' || typeof value === 'number'
          ? value
          : !!value;

      domMatches = TechnologyEngine.technologies
        .filter(({ dom }) => dom && dom.constructor === Object)
        .reduce((technologies, { name, dom }) => {
          Object.keys(dom).forEach((selector) => {
            let nodes = [];
            try {
              nodes = document.querySelectorAll(selector);
            } catch (error) {
              // Continue
            }
            if (!nodes.length) {
              return;
            }

            dom[selector].forEach(({ exists, text, properties, attributes }) => {
              nodes.forEach((node) => {
                if (
                  technologies.filter(({ name: _name }) => _name === name)
                    .length >= 50
                ) {
                  return;
                }

                if (
                  exists &&
                  technologies.findIndex(
                    ({ name: _name, selector: _selector, exists }) =>
                      name === _name && selector === _selector && exists === ''
                  ) === -1
                ) {
                  technologies.push({
                    name,
                    selector,
                    exists: ''
                  });
                }

                if (text) {
                  const value = (
                    node.textContent ? node.textContent.trim() : ''
                  ).slice(0, 100000);

                  if (
                    value &&
                    technologies.findIndex(
                      ({ name: _name, selector: _selector, text }) =>
                        name === _name && selector === _selector && text === value
                    ) === -1
                  ) {
                    technologies.push({
                      name,
                      selector,
                      text: value
                    });
                  }
                }

                if (properties) {
                  Object.keys(properties).forEach((property) => {
                    if (
                      Object.prototype.hasOwnProperty.call(node, property) &&
                      technologies.findIndex(
                        ({
                          name: _name,
                          selector: _selector,
                          property: _property,
                          value
                        }) =>
                          name === _name &&
                          selector === _selector &&
                          property === _property &&
                          value === toScalar(value)
                      ) === -1
                    ) {
                      const value = node[property];
                      if (typeof value !== 'undefined') {
                        technologies.push({
                          name,
                          selector,
                          property,
                          value: toScalar(value)
                        });
                      }
                    }
                  });
                }

                if (attributes) {
                  Object.keys(attributes).forEach((attribute) => {
                    if (
                      node.hasAttribute(attribute) &&
                      technologies.findIndex(
                        ({
                          name: _name,
                          selector: _selector,
                          attribute: _attribute,
                          value
                        }) =>
                          name === _name &&
                          selector === _selector &&
                          attribute === _attribute &&
                          value === toScalar(value)
                      ) === -1
                    ) {
                      const value = node.getAttribute(attribute);
                      technologies.push({
                        name,
                        selector,
                        attribute,
                        value: toScalar(value)
                      });
                    }
                  });
                }
              });
            });
          });

          return technologies;
        }, []);
    }

    const domDetections = analyzeDom(domMatches);
    const allDetections = detections.concat(domDetections);
    const resolved = TechnologyEngine.resolve(allDetections);
    
    const rawDetections = allDetections.map(d => {
      let sourceName = '';
      if (d.pattern.type === 'headers' && analyzeItems.headers) {
        sourceName = Object.keys(analyzeItems.headers).find(k => 
          (Array.isArray(analyzeItems.headers[k]) ? analyzeItems.headers[k] : [analyzeItems.headers[k]]).some(v => v.includes(d.pattern.value))
        ) || '';
      } else if (d.pattern.type === 'cookies' && analyzeItems.cookies) {
        sourceName = Object.keys(analyzeItems.cookies).find(k => 
          (Array.isArray(analyzeItems.cookies[k]) ? analyzeItems.cookies[k] : [analyzeItems.cookies[k]]).some(v => v.includes(d.pattern.value))
        ) || '';
      } else if (d.pattern.type === 'meta' && analyzeItems.meta) {
        sourceName = Object.keys(analyzeItems.meta).find(k => 
          (Array.isArray(analyzeItems.meta[k]) ? analyzeItems.meta[k] : [analyzeItems.meta[k]]).some(v => v.includes(d.pattern.value))
        ) || '';
      } else if (d.pattern.type === 'scriptSrc') {
        sourceName = d.pattern.value || '';
      }
      return {
        name: d.technology.name,
        pattern: {
          type: d.pattern.type || 'unknown',
          value: (d.pattern.value || '').slice(0, 300),
          match: d.pattern.match || '',
          confidence: d.pattern.confidence || 100,
          source: sourceName
        },
        version: d.version || ''
      };
    });

    process.stdout.write(JSON.stringify({
      resolved: resolved,
      rawDetections: rawDetections
    }));
    process.exit(0);
  } catch (e) {
    console.error(`Error during execution: ${e.message}`);
    process.exit(1);
  }
});

function analyzeDom(dom, technologies = TechnologyEngine.technologies) {
  return dom
    .map(({ name, selector, exists, text, property, attribute, value }) => {
      const technology = technologies.find(({ name: _name }) => name === _name);
      if (!technology) return null;

      if (typeof exists !== 'undefined') {
        return TechnologyEngine.analyzeManyToMany(technology, 'dom.exists', {
          [selector]: ['']
        });
      }

      if (typeof text !== 'undefined') {
        return TechnologyEngine.analyzeManyToMany(technology, 'dom.text', {
          [selector]: [text]
        });
      }

      if (typeof property !== 'undefined') {
        return TechnologyEngine.analyzeManyToMany(technology, `dom.properties.${property}`, {
          [selector]: [value]
        });
      }

      if (typeof attribute !== 'undefined') {
        return TechnologyEngine.analyzeManyToMany(technology, `dom.attributes.${attribute}`, {
          [selector]: [value]
        });
      }
    })
    .flat()
    .filter(Boolean);
}
