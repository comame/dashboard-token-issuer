const { request } = require('https')
const { createServer } = require('http')
const { readFile } = require('fs')
const { resolve } = require('path')

const apiHost = 'https://s1.comame.dev:6443'

/** @returns {Promise<string>} */
async function getToken(token) {
    return new Promise((resolve) => {
        const req = request(apiHost + '/api/v1/namespaces/kubernetes-dashboard/serviceaccounts/kubernetes-dashboard/token', {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                'authorization': `Bearer ${token}`
            },
            rejectUnauthorized: false
        }, res => {
            let data = ''
            res.on('data', e => {
                data += e.toString()

            })
            res.on('end', () => {
                const json = JSON.parse(data)
                const token = json.status.token
                resolve(token)
            })
        })

        req.write(JSON.stringify({
            apiVersion: 'authentication.k8s.io/v1',
            kind: 'TokenRequest',
            metadata: {
                namespace: 'kubernetes-dashboard'
            },
            spec: {
                audiences: ['https://kubernetes.default.svc.cluster.local'],
                expirationSeconds: 60 * 60
            }
        }))

        req.end()
    })
}

createServer((req, res) => {
    console.log(req.url)
    if (req.url?.startsWith('/openid/callback')) {
        readFile(resolve(__dirname, './callback.html'), { encoding: 'utf-8' }, (_err, file) => {
            res.end(file)
        })
    } else if (req.method === 'POST' && req.url?.startsWith('/openid/token')) {
        console.log('token')
        let data = ''
        req.on('data', e => {
            data += e.toString()
        })
        req.on('end', async () => {
            console.log('req end')
            const body = JSON.parse(data)
            const token = await getToken(body.token)
            console.log(token)
            res.write(token)
            res.end()
        })
    } else {
        const redirectUri = encodeURIComponent('https://dash.cluster.comame.dev/openid/callback')
        const nonce = 'nonce'
        const url = `https://accounts.comame.xyz/authenticate?client_id=kubernetes&redirect_uri=${redirectUri}&scope=openid&response_type=id_token&nonce=${nonce}`
        res.setHeader('Location', url)
        res.statusCode = 302
        res.end()
    }
}).listen(8080)
