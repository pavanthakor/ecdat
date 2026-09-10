/*
 * Shape mirror of OWASP Juice Shop (upstream 1618a61) for ECDAT ADR-0034.
 * Juice Shop: Copyright (c) 2014-2026 Bjoern Kimminich & contributors. SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from '@juice-shop/models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nJUICEMIRRORSENTINELnotARealKeyJUICEMIRRORSENTINELnotARealKey0000\r\n-----END RSA PRIVATE KEY-----'

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'JUICEMIRRORHMACSENTINEL0').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (str.includes(nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email).digest('hex')
}

// ECDAT, what must happen here (ADR-0034):
//   line 21 -- a PEM block: js-pem-block fires, as it did in the real scan.
//              The PEM reaches TWO key parameters (jwt.sign at line 54,
//              createHmac in deluxeToken) and js-hardcoded-key must NOT
//              report it again: the shape rule owns a shaped literal. The
//              pre-ADR-0034 rule double-reported this line.
//   line 42 -- a literal HMAC key at the sink: js-hardcoded-key fires. The
//              pre-ADR-0034 rule never saw it -- no key-ish name holds it.
//   line 41 and line 54 -- MD5 and RS256, reported by their own rules.
// The PEM body and the HMAC key are filler with sentinels, not Juice Shop's.
