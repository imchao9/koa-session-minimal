const uid = require('uid-safe')
const deepEqual = require('deep-equal')
const Store = require('./store')
const MemoryStore = require('./memory_store')
const signature = require('cookie-signature');

const ONE_DAY = 24 * 3600 * 1000 // one day in milliseconds
const redis_key_prefix = 'sess'
const cookie_prefix = 's:'

const cookieOpt = (cookie, ctx) => {
  const obj = cookie instanceof Function ? cookie(ctx) : cookie
  const options = Object.assign({
    maxAge: 0, // default to use session cookie
    path: '/',
    httpOnly: true,
  }, obj || {}, {
    overwrite: true, // overwrite previous session cookie changes
    signed: false, // disable signed option
  })
  if (!(options.maxAge >= 0)) options.maxAge = 0
  return options
}

const deleteSession = (ctx, key, cookie, store, sid) => {
  const tmpCookie = Object.assign({}, cookie)
  delete tmpCookie.maxAge
  ctx.cookies.set(key, null, tmpCookie)
  store.destroy(`${redis_key_prefix}:${sid}`)
}

const saveSession = (ctx, key, cookie, store, sid, secret) => {
  const ttl = cookie.maxAge > 0 ? cookie.maxAge : ONE_DAY
  ctx.session.cookie = {
      path: '/',
      originalMaxAge: cookie.maxAge,
      _expires: new Date(new Date().getTime() + ttl),
      httpOnly: true
  };

  ctx.cookies.set(key, encodeURIComponent(`${cookie_prefix}${signature.sign(sid, secret)}`), cookie)
  store.set(`${redis_key_prefix}:${sid}`, ctx.session, ttl)
}

const cleanSession = (ctx) => {
  if (!ctx.session || typeof ctx.session !== 'object') ctx.session = {}
}

module.exports = (options) => {
  const opt = options || {}
  const key = opt.key || 'koa:sess'
  const secret = opt.secret || ''
  const store = new Store(opt.store || new MemoryStore())
  const getCookie = ctx => cookieOpt(opt.cookie, ctx)

  return async (ctx, next) => {
    // initialize session id and data
    const oldSid = ctx.cookies.get(key)

    let sid = oldSid

    const regenerateId = () => {
      sid = uid.sync(24);
    }

    if (!sid) {
      regenerateId()
      ctx.session = {}
    } else {
      if (sid.substr(0, 2) === 's:') {
          sid = signature.unsign(sid.slice(2), secret);
      }

      ctx.session = await store.get(`${redis_key_prefix}:${sid}`)
      cleanSession(ctx)
    }

    const oldData = JSON.parse(JSON.stringify(ctx.session))

    // expose session handler to ctx
    ctx.sessionHandler = {
      regenerateId,
    }

    await next()

    cleanSession(ctx)
    const hasData = Object.keys(ctx.session).length > 0

    if (sid === oldSid) { // session id not changed
      if (deepEqual(ctx.session, oldData)) return // session data not changed

      const cookie = getCookie(ctx)
      const action = hasData ? saveSession : deleteSession
      action(ctx, key, cookie, store, sid) // update or delete the existing session
    } else { // session id changed
      const cookie = getCookie(ctx)
      if (oldSid) deleteSession(ctx, key, cookie, store, oldSid) // delete old session
      if (hasData) saveSession(ctx, key, cookie, store, sid, secret) // save new session
    }
  }
}
