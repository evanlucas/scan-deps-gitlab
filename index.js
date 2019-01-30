#!/usr/bin/env node

'use strict'

const {spawn} = require('child_process')
const os = require('os')
const path = require('path')
const fs = require('fs')

function getPriority(priority) {
  switch (priority.toLowerCase()) {
    case 'moderate':
      return 'Medium'
    case 'low':
      return 'Low'
    case 'high':
      return 'High'
    default:
      return 'Critical'
  }
}

function audit() {
  const tmp = os.tmpdir()
  const fp = path.join(tmp, 'audit.json')
  const child = spawn(`npm audit --json > ${fp}`, {
    shell: true
  })

  child.stdout.pipe(process.stdout)
  child.stderr.pipe(process.stderr)
  child.on('close', () => {
    // Don't check exit code because `npm audit --json` will exit with 1
    // if there are vulnerabilities.
    parse(fp)
  })
}

function parse(fp) {
  const result = []
  const audit = require(fp)
  const advisories = Object.values(audit.advisories)

  for (const advisory of advisories) {
    const {
      title
    , overview
    , recommendation
    , severity
    , url
    , module_name
    , findings
    } = advisory
    const cve = advisory.cves && advisory.cves.length
      ? advisory.cves[0]
      : null

    for (const finding of findings) {
      const paths = finding.paths.map((path) => {
        return path.replace(/\>/g, ' > ')
      }).join('\n')

      const identifiers = []
      for (const cve of advisory.cves) {
        identifiers.push({
          type: 'cve'
        , name: cve
        , value: cve
        , url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`
        })
      }
      result.push({
        description: `${overview}\n\nFound in:\n\n${paths}`
      , message: `${title} in ${module_name}`
      , category: 'dependency_scanning'
      , name: title
      , scanner: {
          id: 'npm-audit'
        , name: 'npm'
        }
      , cve: cve ? `package-lock.json:${module_name}:${cve}` : null
      , cwe: advisory.cwe
      , solution: recommendation
      , links: [{ url }]
      , priority: getPriority(severity)
      , identifiers
      , location: {
          file: 'package-lock.json'
        , dependency: {
            package: {
              name: module_name
            }
          , version: finding.version
          }
        }
      })
    }
  }
  const filename = 'gl-dependency-scanning-report.json'
  const out = {
    version: '2.0'
  , vulnerabilities: result
  }
  fs.writeFileSync(filename, JSON.stringify(out, null, 2), 'utf8')
}

if (require.main === module) {
  audit()
}
