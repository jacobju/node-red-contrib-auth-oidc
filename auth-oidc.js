/**
 * version-auth-oidc v2
 * Copyright 2018 Nicolas Carlier
 * Modified to support dynamic discovery URL via msg.discoveryUrl
 *
 * Licensed under the Apache License, Version 2.0 (the 'License')
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

module.exports = function (RED) {
  'use strict'

  const jwks = require('jwks-rsa')
  const nJwt = require('njwt')
  const https = require('https')
  const http = require('http')

  function AuthOIDCNode (n) {
    RED.nodes.createNode(this, n)

    // Set node state
    this.name = n.name
    this.discovery = n.discovery
    this.verifierCache = new Map()

    const getVerifier = (discoveryUrl) => {
      if (this.verifierCache.has(discoveryUrl)) {
        return Promise.resolve(this.verifierCache.get(discoveryUrl))
      }

      return new Promise((resolve, reject) => {
        let scheme
        try {
          scheme = new URL(discoveryUrl).protocol
        } catch (err) {
          return reject(new Error('bad-discovery-endpoint'))
        }
        const protocol = (scheme === 'https:' ? https : http)

        protocol.get(discoveryUrl, res => {
          let data = ''
          res.setEncoding('utf8')
          res.on('data', chunk => {
            data += chunk
          })
          res.on('end', () => {
            let body = null
            try {
              body = JSON.parse(data)
            } catch (err) {
              console.error('Discovery error: bad response: %j', err)
              return reject(new Error('bad-discovery-response'))
            }
            if (!body || !body.jwks_uri) {
              console.error('Discovery error: bad response: %j', body)
              return reject(new Error('bad-discovery-response'))
            }
            console.log('JWKS URI loaded for %s: %j', discoveryUrl, body.jwks_uri)

            const options = {
              cache: true,
              cacheMaxAge: 60 * 60 * 1000,
              cacheMaxEntries: 3,
              jwksRequestsPerMinute: 10,
              rateLimit: true
            }

            const jwksClient = jwks(Object.assign(
              {},
              options,
              { jwksUri: body.jwks_uri })
            )
            const verifier = nJwt.createVerifier()
              .setSigningAlgorithm('RS256')
              .withKeyResolver((kid, cb) => {
                jwksClient.getSigningKey(kid, (err, key) => {
                  cb(err, key && (key.publicKey || key.rsaPublicKey))
                })
              })

            this.verifierCache.set(discoveryUrl, verifier)
            resolve(verifier)
          }).on('error', err => {
            console.log('Discovery error: %j', err)
            reject(new Error('bad-discovery-request'))
          })
        })
      })
    }

    // Se houver uma URL estática configurada, pré-carrega o status
    if (this.discovery) {
      getVerifier(this.discovery).then(() => {
        this.status({fill: 'blue', shape: 'ring', text: 'auth-oidc.status.ready'})
      }).catch(() => {
        this.status({fill: 'red', shape: 'ring', text: 'auth-oidc.status.bad-discovery-response'})
      })
    } else {
      this.status({fill: 'yellow', shape: 'ring', text: 'Aguardando msg.discoveryUrl'})
    }

    this.on('input', async (msg, send, done) => {
      send = send || function () { node.send.apply(node, arguments) }
      const node = this

      if (!msg.req || !msg.req.headers || !msg.req.headers['authorization']) {
        node.error(RED._('auth-oidc.error.no-access-token'), msg)
        node.status({fill: 'red', shape: 'ring', text: 'auth-oidc.status.no-access-token'})
        msg.error = 'NoAccessToken'
        msg.statusCode = 401
        send(msg)
        if (done) done()
        return
      }

      // Prioriza a URL dinâmica da mensagem; se não houver, usa a fixa do nó
      const discoveryUrl = msg.discoveryUrl || node.discovery

      if (!discoveryUrl) {
        node.error('Discovery URL não informada nem no nó nem em msg.discoveryUrl', msg)
        node.status({fill: 'red', shape: 'ring', text: 'auth-oidc.status.bad-discovery-endpoint'})
        msg.error = 'MissingDiscoveryURL'
        msg.statusCode = 400
        send(msg)
        if (done) done()
        return
      }

      try {
        const verifier = await getVerifier(discoveryUrl)
        const accessToken = msg.req.headers['authorization'].split(' ')[1]

        verifier.verify(accessToken, (err, jwt) => {
          if (err) {
            node.error(RED._('auth-oidc.error.bad-access-token', err), msg)
            node.status({fill: 'red', shape: 'ring', text: 'auth-oidc.status.bad-access-token'})
            msg.error = err
            msg.statusCode = 403
            send(msg)
            if (done) done()
            return
          }
          delete msg.error
          msg.access_token = jwt
          node.status({})
          send(msg)
          if (done) done()
        })
      } catch (err) {
        node.error('Falha no processo de OIDC Discovery: ' + err.message, msg)
        node.status({fill: 'red', shape: 'ring', text: 'auth-oidc.status.bad-discovery-response'})
        msg.error = err
        msg.statusCode = 500
        send(msg)
        if (done) done()
      }
    })
  }
  RED.nodes.registerType('auth-oidc', AuthOIDCNode)
}