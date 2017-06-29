/**
 * A simple web action returning an HTTP Redirect based on
 *  params.success_redirect  or params.redirect_url.
 *  `success_redirect` may be used to override the default redirect_url parameter.
 * It sets the __Secure-auth_context and then it returns the redirect response.
 */
function redirect(params) {
  let ctx = params.context || {};
  let redirect = ctx.success_redirect || params.redirect_url;
  delete ctx.success_redirect; // we don't need it after redirecting
  return {
    headers: {
      'Location': redirect,
      'Set-Cookie': '__Secure-auth_context=' + JSON.stringify(ctx) + '; Secure; HttpOnly; Max-Age=600; Path=/api/v1/web/' + process.env['__OW_NAMESPACE'],
      'Content - Length': '0'
    },
    statusCode: 302,
    body: ""
  }
}
