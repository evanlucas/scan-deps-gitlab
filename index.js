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
    const {title, overview, recommendation, severity, url} = advisory
    const message = `${title}\n\n${overview}`
    const cve = advisory.cves && advisory.cves.length
      ? advisory.cves[0]
      : null
    result.push({
      message
    , cve
    , cwe: advisory.cwe
    , solution: recommendation
    , url
    , priority: getPriority(severity)
    })
  }
  const filename = 'gl-dependency-scanning-report.json'
  fs.writeFileSync(filename, JSON.stringify(result), 'utf8')
}

if (require.main === module) {
  audit()
}
