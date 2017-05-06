require=(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
exports.OAuth = require("./lib/oauth").OAuth;
exports.OAuthEcho = require("./lib/oauth").OAuthEcho;
exports.OAuth2 = require("./lib/oauth2").OAuth2;
},{"./lib/oauth":3,"./lib/oauth2":4}],2:[function(require,module,exports){
// Returns true if this is a host that closes *before* it ends?!?!
module.exports.isAnEarlyCloseHost= function( hostName ) {
  return hostName && hostName.match(".*google(apis)?.com$")
}
},{}],3:[function(require,module,exports){
var crypto= require('crypto'),
    sha1= require('./sha1'),
    http= require('http'),
    https= require('https'),
    URL= require('url'),
    querystring= require('querystring'),
    OAuthUtils= require('./_utils');

exports.OAuth= function(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders) {
  this._isEcho = false;

  this._requestUrl= requestUrl;
  this._accessUrl= accessUrl;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;
  if( authorize_callback === undefined ) {
    this._authorize_callback= "oob";
  }
  else {
    this._authorize_callback= authorize_callback;
  }

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod )
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"}
  this._clientOptions= this._defaultClientOptions= {"requestTokenHttpMethod": "POST",
                                                    "accessTokenHttpMethod": "POST",
                                                    "followRedirects": true};
  this._oauthParameterSeperator = ",";
};

exports.OAuthEcho= function(realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders) {
  this._isEcho = true;

  this._realm= realm;
  this._verifyCredentials = verify_credentials;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod );
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"};
  this._oauthParameterSeperator = ",";
}

exports.OAuthEcho.prototype = exports.OAuth.prototype;

exports.OAuth.prototype._getTimestamp= function() {
  return Math.floor( (new Date()).getTime() / 1000 );
}

exports.OAuth.prototype._encodeData= function(toEncode){
 if( toEncode == null || toEncode == "" ) return ""
 else {
    var result= encodeURIComponent(toEncode);
    // Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong ;)
    return result.replace(/\!/g, "%21")
                 .replace(/\'/g, "%27")
                 .replace(/\(/g, "%28")
                 .replace(/\)/g, "%29")
                 .replace(/\*/g, "%2A");
 }
}

exports.OAuth.prototype._decodeData= function(toDecode) {
  if( toDecode != null ) {
    toDecode = toDecode.replace(/\+/g, " ");
  }
  return decodeURIComponent( toDecode);
}

exports.OAuth.prototype._getSignature= function(method, url, parameters, tokenSecret) {
  var signatureBase= this._createSignatureBase(method, url, parameters);
  return this._createSignature( signatureBase, tokenSecret );
}

exports.OAuth.prototype._normalizeUrl= function(url) {
  var parsedUrl= URL.parse(url, true)
   var port ="";
   if( parsedUrl.port ) {
     if( (parsedUrl.protocol == "http:" && parsedUrl.port != "80" ) ||
         (parsedUrl.protocol == "https:" && parsedUrl.port != "443") ) {
           port= ":" + parsedUrl.port;
         }
   }

  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";

  return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
}

// Is the parameter considered an OAuth parameter
exports.OAuth.prototype._isParameterNameAnOAuthParameter= function(parameter) {
  var m = parameter.match('^oauth_');
  if( m && ( m[0] === "oauth_" ) ) {
    return true;
  }
  else {
    return false;
  }
};

// build the OAuth request authorization header
exports.OAuth.prototype._buildAuthorizationHeaders= function(orderedParameters) {
  var authHeader="OAuth ";
  if( this._isEcho ) {
    authHeader += 'realm="' + this._realm + '",';
  }

  for( var i= 0 ; i < orderedParameters.length; i++) {
     // Whilst the all the parameters should be included within the signature, only the oauth_ arguments
     // should appear within the authorization header.
     if( this._isParameterNameAnOAuthParameter(orderedParameters[i][0]) ) {
      authHeader+= "" + this._encodeData(orderedParameters[i][0])+"=\""+ this._encodeData(orderedParameters[i][1])+"\""+ this._oauthParameterSeperator;
     }
  }

  authHeader= authHeader.substring(0, authHeader.length-this._oauthParameterSeperator.length);
  return authHeader;
}

// Takes an object literal that represents the arguments, and returns an array
// of argument/value pairs.
exports.OAuth.prototype._makeArrayOfArgumentsHash= function(argumentsHash) {
  var argument_pairs= [];
  for(var key in argumentsHash ) {
    if (argumentsHash.hasOwnProperty(key)) {
       var value= argumentsHash[key];
       if( Array.isArray(value) ) {
         for(var i=0;i<value.length;i++) {
           argument_pairs[argument_pairs.length]= [key, value[i]];
         }
       }
       else {
         argument_pairs[argument_pairs.length]= [key, value];
       }
    }
  }
  return argument_pairs;
}

// Sorts the encoded key value pairs by encoded name, then encoded value
exports.OAuth.prototype._sortRequestParams= function(argument_pairs) {
  // Sort by name, then value.
  argument_pairs.sort(function(a,b) {
      if ( a[0]== b[0] )  {
        return a[1] < b[1] ? -1 : 1;
      }
      else return a[0] < b[0] ? -1 : 1;
  });

  return argument_pairs;
}

exports.OAuth.prototype._normaliseRequestParams= function(args) {
  var argument_pairs= this._makeArrayOfArgumentsHash(args);
  // First encode them #3.4.1.3.2 .1
  for(var i=0;i<argument_pairs.length;i++) {
    argument_pairs[i][0]= this._encodeData( argument_pairs[i][0] );
    argument_pairs[i][1]= this._encodeData( argument_pairs[i][1] );
  }

  // Then sort them #3.4.1.3.2 .2
  argument_pairs= this._sortRequestParams( argument_pairs );

  // Then concatenate together #3.4.1.3.2 .3 & .4
  var args= "";
  for(var i=0;i<argument_pairs.length;i++) {
      args+= argument_pairs[i][0];
      args+= "="
      args+= argument_pairs[i][1];
      if( i < argument_pairs.length-1 ) args+= "&";
  }
  return args;
}

exports.OAuth.prototype._createSignatureBase= function(method, url, parameters) {
  url= this._encodeData( this._normalizeUrl(url) );
  parameters= this._encodeData( parameters );
  return method.toUpperCase() + "&" + url + "&" + parameters;
}

exports.OAuth.prototype._createSignature= function(signatureBase, tokenSecret) {
   if( tokenSecret === undefined ) var tokenSecret= "";
   else tokenSecret= this._encodeData( tokenSecret );
   // consumerSecret is already encoded
   var key= this._consumerSecret + "&" + tokenSecret;

   var hash= ""
   if( this._signatureMethod == "PLAINTEXT" ) {
     hash= key;
   }
   else if (this._signatureMethod == "RSA-SHA1") {
     key = this._privateKey || "";
     hash= crypto.createSign("RSA-SHA1").update(signatureBase).sign(key, 'base64');
   }
   else {
       if( crypto.Hmac ) {
         hash = crypto.createHmac("sha1", key).update(signatureBase).digest("base64");
       }
       else {
         hash= sha1.HMACSHA1(key, signatureBase);
       }
   }
   return hash;
}
exports.OAuth.prototype.NONCE_CHARS= ['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
              'o','p','q','r','s','t','u','v','w','x','y','z','A','B',
              'C','D','E','F','G','H','I','J','K','L','M','N','O','P',
              'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3',
              '4','5','6','7','8','9'];

exports.OAuth.prototype._getNonce= function(nonceSize) {
   var result = [];
   var chars= this.NONCE_CHARS;
   var char_pos;
   var nonce_chars_length= chars.length;

   for (var i = 0; i < nonceSize; i++) {
       char_pos= Math.floor(Math.random() * nonce_chars_length);
       result[i]=  chars[char_pos];
   }
   return result.join('');
}

exports.OAuth.prototype._createClient= function( port, hostname, method, path, headers, sslEnabled ) {
  var options = {
    host: hostname,
    port: port,
    path: path,
    method: method,
    headers: headers
  };
  var httpModel;
  if( sslEnabled ) {
    httpModel= https;
  } else {
    httpModel= http;
  }
  return httpModel.request(options);
}

exports.OAuth.prototype._prepareParameters= function( oauth_token, oauth_token_secret, method, url, extra_params ) {
  var oauthParameters= {
      "oauth_timestamp":        this._getTimestamp(),
      "oauth_nonce":            this._getNonce(this._nonceSize),
      "oauth_version":          this._version,
      "oauth_signature_method": this._signatureMethod,
      "oauth_consumer_key":     this._consumerKey
  };

  if( oauth_token ) {
    oauthParameters["oauth_token"]= oauth_token;
  }

  var sig;
  if( this._isEcho ) {
    sig = this._getSignature( "GET",  this._verifyCredentials,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
  }
  else {
    if( extra_params ) {
      for( var key in extra_params ) {
        if (extra_params.hasOwnProperty(key)) oauthParameters[key]= extra_params[key];
      }
    }
    var parsedUrl= URL.parse( url, false );

    if( parsedUrl.query ) {
      var key2;
      var extraParameters= querystring.parse(parsedUrl.query);
      for(var key in extraParameters ) {
        var value= extraParameters[key];
          if( typeof value == "object" ){
            // TODO: This probably should be recursive
            for(key2 in value){
              oauthParameters[key + "[" + key2 + "]"] = value[key2];
            }
          } else {
            oauthParameters[key]= value;
          }
        }
    }

    sig = this._getSignature( method,  url,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
  }

  var orderedParameters= this._sortRequestParams( this._makeArrayOfArgumentsHash(oauthParameters) );
  orderedParameters[orderedParameters.length]= ["oauth_signature", sig];
  return orderedParameters;
}

exports.OAuth.prototype._performSecureRequest= function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback ) {
  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);

  if( !post_content_type ) {
    post_content_type= "application/x-www-form-urlencoded";
  }
  var parsedUrl= URL.parse( url, false );
  if( parsedUrl.protocol == "http:" && !parsedUrl.port ) parsedUrl.port= 80;
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;

  var headers= {};
  var authorization = this._buildAuthorizationHeaders(orderedParameters);
  if ( this._isEcho ) {
    headers["X-Verify-Credentials-Authorization"]= authorization;
  }
  else {
    headers["Authorization"]= authorization;
  }

  headers["Host"] = parsedUrl.host

  for( var key in this._headers ) {
    if (this._headers.hasOwnProperty(key)) {
      headers[key]= this._headers[key];
    }
  }

  // Filter out any passed extra_params that are really to do with OAuth
  for(var key in extra_params) {
    if( this._isParameterNameAnOAuthParameter( key ) ) {
      delete extra_params[key];
    }
  }

  if( (method == "POST" || method == "PUT")  && ( post_body == null && extra_params != null) ) {
    // Fix the mismatch between the output of querystring.stringify() and this._encodeData()
    post_body= querystring.stringify(extra_params)
                       .replace(/\!/g, "%21")
                       .replace(/\'/g, "%27")
                       .replace(/\(/g, "%28")
                       .replace(/\)/g, "%29")
                       .replace(/\*/g, "%2A");
  }

  if( post_body ) {
      if ( Buffer.isBuffer(post_body) ) {
          headers["Content-length"]= post_body.length;
      } else {
          headers["Content-length"]= Buffer.byteLength(post_body);
      }
  } else {
      headers["Content-length"]= 0;
  }

  headers["Content-Type"]= post_content_type;

  var path;
  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";
  if( parsedUrl.query ) path= parsedUrl.pathname + "?"+ parsedUrl.query ;
  else path= parsedUrl.pathname;

  var request;
  if( parsedUrl.protocol == "https:" ) {
    request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, true);
  }
  else {
    request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
  }

  var clientOptions = this._clientOptions;
  if( callback ) {
    var data="";
    var self= this;

    // Some hosts *cough* google appear to close the connection early / send no content-length header
    // allow this behaviour.
    var allowEarlyClose= OAuthUtils.isAnEarlyCloseHost( parsedUrl.hostname );
    var callbackCalled= false;
    var passBackControl = function( response ) {
      if(!callbackCalled) {
        callbackCalled= true;
        if ( response.statusCode >= 200 && response.statusCode <= 299 ) {
          callback(null, data, response);
        } else {
          // Follow 301 or 302 redirects with Location HTTP header
          if((response.statusCode == 301 || response.statusCode == 302) && clientOptions.followRedirects && response.headers && response.headers.location) {
            self._performSecureRequest( oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body, post_content_type,  callback);
          }
          else {
            callback({ statusCode: response.statusCode, data: data }, data, response);
          }
        }
      }
    }

    request.on('response', function (response) {
      response.setEncoding('utf8');
      response.on('data', function (chunk) {
        data+=chunk;
      });
      response.on('end', function () {
        passBackControl( response );
      });
      response.on('close', function () {
        if( allowEarlyClose ) {
          passBackControl( response );
        }
      });
    });

    request.on("error", function(err) {
      if(!callbackCalled) {
        callbackCalled= true;
        callback( err )
      }
    });

    if( (method == "POST" || method =="PUT") && post_body != null && post_body != "" ) {
      request.write(post_body);
    }
    request.end();
  }
  else {
    if( (method == "POST" || method =="PUT") && post_body != null && post_body != "" ) {
      request.write(post_body);
    }
    return request;
  }

  return;
}

exports.OAuth.prototype.setClientOptions= function(options) {
  var key,
      mergedOptions= {},
      hasOwnProperty= Object.prototype.hasOwnProperty;

  for( key in this._defaultClientOptions ) {
    if( !hasOwnProperty.call(options, key) ) {
      mergedOptions[key]= this._defaultClientOptions[key];
    } else {
      mergedOptions[key]= options[key];
    }
  }

  this._clientOptions= mergedOptions;
};

exports.OAuth.prototype.getOAuthAccessToken= function(oauth_token, oauth_token_secret, oauth_verifier,  callback) {
  var extraParams= {};
  if( typeof oauth_verifier == "function" ) {
    callback= oauth_verifier;
  } else {
    extraParams.oauth_verifier= oauth_verifier;
  }

   this._performSecureRequest( oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessUrl, extraParams, null, null, function(error, data, response) {
         if( error ) callback(error);
         else {
           var results= querystring.parse( data );
           var oauth_access_token= results["oauth_token"];
           delete results["oauth_token"];
           var oauth_access_token_secret= results["oauth_token_secret"];
           delete results["oauth_token_secret"];
           callback(null, oauth_access_token, oauth_access_token_secret, results );
         }
   })
}

// Deprecated
exports.OAuth.prototype.getProtectedResource= function(url, method, oauth_token, oauth_token_secret, callback) {
  this._performSecureRequest( oauth_token, oauth_token_secret, method, url, null, "", null, callback );
}

exports.OAuth.prototype.delete= function(url, oauth_token, oauth_token_secret, callback) {
  return this._performSecureRequest( oauth_token, oauth_token_secret, "DELETE", url, null, "", null, callback );
}

exports.OAuth.prototype.get= function(url, oauth_token, oauth_token_secret, callback) {
  return this._performSecureRequest( oauth_token, oauth_token_secret, "GET", url, null, "", null, callback );
}

exports.OAuth.prototype._putOrPost= function(method, url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  var extra_params= null;
  if( typeof post_content_type == "function" ) {
    callback= post_content_type;
    post_content_type= null;
  }
  if ( typeof post_body != "string" && !Buffer.isBuffer(post_body) ) {
    post_content_type= "application/x-www-form-urlencoded"
    extra_params= post_body;
    post_body= null;
  }
  return this._performSecureRequest( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback );
}


exports.OAuth.prototype.put= function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("PUT", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
}

exports.OAuth.prototype.post= function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("POST", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
}

/**
 * Gets a request token from the OAuth provider and passes that information back
 * to the calling code.
 *
 * The callback should expect a function of the following form:
 *
 * function(err, token, token_secret, parsedQueryString) {}
 *
 * This method has optional parameters so can be called in the following 2 ways:
 *
 * 1) Primary use case: Does a basic request with no extra parameters
 *  getOAuthRequestToken( callbackFunction )
 *
 * 2) As above but allows for provision of extra parameters to be sent as part of the query to the server.
 *  getOAuthRequestToken( extraParams, callbackFunction )
 *
 * N.B. This method will HTTP POST verbs by default, if you wish to override this behaviour you will
 * need to provide a requestTokenHttpMethod option when creating the client.
 *
 **/
exports.OAuth.prototype.getOAuthRequestToken= function( extraParams, callback ) {
   if( typeof extraParams == "function" ){
     callback = extraParams;
     extraParams = {};
   }
  // Callbacks are 1.0A related
  if( this._authorize_callback ) {
    extraParams["oauth_callback"]= this._authorize_callback;
  }
  this._performSecureRequest( null, null, this._clientOptions.requestTokenHttpMethod, this._requestUrl, extraParams, null, null, function(error, data, response) {
    if( error ) callback(error);
    else {
      var results= querystring.parse(data);

      var oauth_token= results["oauth_token"];
      var oauth_token_secret= results["oauth_token_secret"];
      delete results["oauth_token"];
      delete results["oauth_token_secret"];
      callback(null, oauth_token, oauth_token_secret,  results );
    }
  });
}

exports.OAuth.prototype.signUrl= function(url, oauth_token, oauth_token_secret, method) {

  if( method === undefined ) {
    var method= "GET";
  }

  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
  var parsedUrl= URL.parse( url, false );

  var query="";
  for( var i= 0 ; i < orderedParameters.length; i++) {
    query+= orderedParameters[i][0]+"="+ this._encodeData(orderedParameters[i][1]) + "&";
  }
  query= query.substring(0, query.length-1);

  return parsedUrl.protocol + "//"+ parsedUrl.host + parsedUrl.pathname + "?" + query;
};

exports.OAuth.prototype.authHeader= function(url, oauth_token, oauth_token_secret, method) {
  if( method === undefined ) {
    var method= "GET";
  }

  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
  return this._buildAuthorizationHeaders(orderedParameters);
};

},{"./_utils":2,"./sha1":5,"crypto":undefined,"http":undefined,"https":undefined,"querystring":undefined,"url":undefined}],4:[function(require,module,exports){
var querystring= require('querystring'),
    crypto= require('crypto'),
    https= require('https'),
    http= require('http'),
    URL= require('url'),
    OAuthUtils= require('./_utils');

exports.OAuth2= function(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  this._clientId= clientId;
  this._clientSecret= clientSecret;
  this._baseSite= baseSite;
  this._authorizeUrl= authorizePath || "/oauth/authorize";
  this._accessTokenUrl= accessTokenPath || "/oauth/access_token";
  this._accessTokenName= "access_token";
  this._authMethod= "Bearer";
  this._customHeaders = customHeaders || {};
  this._useAuthorizationHeaderForGET= false;

  //our agent
  this._agent = undefined;
};

// Allows you to set an agent to use instead of the default HTTP or
// HTTPS agents. Useful when dealing with your own certificates.
exports.OAuth2.prototype.setAgent = function(agent) {
  this._agent = agent;
};

// This 'hack' method is required for sites that don't use
// 'access_token' as the name of the access token (for requests).
// ( http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-7 )
// it isn't clear what the correct value should be atm, so allowing
// for specific (temporary?) override for now.
exports.OAuth2.prototype.setAccessTokenName= function ( name ) {
  this._accessTokenName= name;
}

// Sets the authorization method for Authorization header.
// e.g. Authorization: Bearer <token>  # "Bearer" is the authorization method.
exports.OAuth2.prototype.setAuthMethod = function ( authMethod ) {
  this._authMethod = authMethod;
};


// If you use the OAuth2 exposed 'get' method (and don't construct your own _request call )
// this will specify whether to use an 'Authorize' header instead of passing the access_token as a query parameter
exports.OAuth2.prototype.useAuthorizationHeaderforGET = function(useIt) {
  this._useAuthorizationHeaderForGET= useIt;
}

exports.OAuth2.prototype._getAccessTokenUrl= function() {
  return this._baseSite + this._accessTokenUrl; /* + "?" + querystring.stringify(params); */
}

// Build the authorization header. In particular, build the part after the colon.
// e.g. Authorization: Bearer <token>  # Build "Bearer <token>"
exports.OAuth2.prototype.buildAuthHeader= function(token) {
  return this._authMethod + ' ' + token;
};

exports.OAuth2.prototype._chooseHttpLibrary= function( parsedUrl ) {
  var http_library= https;
  // As this is OAUth2, we *assume* https unless told explicitly otherwise.
  if( parsedUrl.protocol != "https:" ) {
    http_library= http;
  }
  return http_library;
};

exports.OAuth2.prototype._request= function(method, url, headers, post_body, access_token, callback) {

  var parsedUrl= URL.parse( url, true );
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) {
    parsedUrl.port= 443;
  }

  var http_library= this._chooseHttpLibrary( parsedUrl );


  var realHeaders= {};
  for( var key in this._customHeaders ) {
    realHeaders[key]= this._customHeaders[key];
  }
  if( headers ) {
    for(var key in headers) {
      realHeaders[key] = headers[key];
    }
  }
  realHeaders['Host']= parsedUrl.host;

  if (!realHeaders['User-Agent']) {
    realHeaders['User-Agent'] = 'Node-oauth';
  }

  if( post_body ) {
      if ( Buffer.isBuffer(post_body) ) {
          realHeaders["Content-Length"]= post_body.length;
      } else {
          realHeaders["Content-Length"]= Buffer.byteLength(post_body);
      }
  } else {
      realHeaders["Content-length"]= 0;
  }

  if( access_token && !('Authorization' in realHeaders)) {
    if( ! parsedUrl.query ) parsedUrl.query= {};
    parsedUrl.query[this._accessTokenName]= access_token;
  }

  var queryStr= querystring.stringify(parsedUrl.query);
  if( queryStr ) queryStr=  "?" + queryStr;
  var options = {
    host:parsedUrl.hostname,
    port: parsedUrl.port,
    path: parsedUrl.pathname + queryStr,
    method: method,
    headers: realHeaders
  };

  this._executeRequest( http_library, options, post_body, callback );
}

exports.OAuth2.prototype._executeRequest= function( http_library, options, post_body, callback ) {
  // Some hosts *cough* google appear to close the connection early / send no content-length header
  // allow this behaviour.
  var allowEarlyClose= OAuthUtils.isAnEarlyCloseHost(options.host);
  var callbackCalled= false;
  function passBackControl( response, result ) {
    if(!callbackCalled) {
      callbackCalled=true;
      if( !(response.statusCode >= 200 && response.statusCode <= 299) && (response.statusCode != 301) && (response.statusCode != 302) ) {
        callback({ statusCode: response.statusCode, data: result });
      } else {
        callback(null, result, response);
      }
    }
  }

  var result= "";

  //set the agent on the request options
  if (this._agent) {
    options.agent = this._agent;
  }

  var request = http_library.request(options);
  request.on('response', function (response) {
    response.on("data", function (chunk) {
      result+= chunk
    });
    response.on("close", function (err) {
      if( allowEarlyClose ) {
        passBackControl( response, result );
      }
    });
    response.addListener("end", function () {
      passBackControl( response, result );
    });
  });
  request.on('error', function(e) {
    callbackCalled= true;
    callback(e);
  });

  if( (options.method == 'POST' || options.method == 'PUT') && post_body ) {
     request.write(post_body);
  }
  request.end();
}

exports.OAuth2.prototype.getAuthorizeUrl= function( params ) {
  var params= params || {};
  params['client_id'] = this._clientId;
  return this._baseSite + this._authorizeUrl + "?" + querystring.stringify(params);
}

exports.OAuth2.prototype.getOAuthAccessToken= function(code, params, callback) {
  var params= params || {};
  params['client_id'] = this._clientId;
  params['client_secret'] = this._clientSecret;
  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam]= code;

  var post_data= querystring.stringify( params );
  var post_headers= {
       'Content-Type': 'application/x-www-form-urlencoded'
   };


  this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
    if( error )  callback(error);
    else {
      var results;
      try {
        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
        // responses should be in JSON
        results= JSON.parse( data );
      }
      catch(e) {
        // .... However both Facebook + Github currently use rev05 of the spec
        // and neither seem to specify a content-type correctly in their response headers :(
        // clients of these services will suffer a *minor* performance cost of the exception
        // being thrown
        results= querystring.parse( data );
      }
      var access_token= results["access_token"];
      var refresh_token= results["refresh_token"];
      delete results["refresh_token"];
      callback(null, access_token, refresh_token, results); // callback results =-=
    }
  });
}

// Deprecated
exports.OAuth2.prototype.getProtectedResource= function(url, access_token, callback) {
  this._request("GET", url, {}, "", access_token, callback );
}

exports.OAuth2.prototype.get= function(url, access_token, callback) {
  if( this._useAuthorizationHeaderForGET ) {
    var headers= {'Authorization': this.buildAuthHeader(access_token) }
    access_token= null;
  }
  else {
    headers= {};
  }
  this._request("GET", url, headers, "", access_token, callback );
}

},{"./_utils":2,"crypto":undefined,"http":undefined,"https":undefined,"querystring":undefined,"url":undefined}],5:[function(require,module,exports){
/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS 180-1
 * Version 2.2 Copyright Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 1;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = "="; /* base-64 pad character. "=" for strict RFC compliance   */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_sha1(s)    { return rstr2hex(rstr_sha1(str2rstr_utf8(s))); }
function b64_sha1(s)    { return rstr2b64(rstr_sha1(str2rstr_utf8(s))); }
function any_sha1(s, e) { return rstr2any(rstr_sha1(str2rstr_utf8(s)), e); }
function hex_hmac_sha1(k, d)
  { return rstr2hex(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_sha1(k, d)
  { return rstr2b64(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_sha1(k, d, e)
  { return rstr2any(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d)), e); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function sha1_vm_test()
{
  return hex_sha1("abc").toLowerCase() == "a9993e364706816aba3e25717850c26c9cd0d89d";
}

/*
 * Calculate the SHA1 of a raw string
 */
function rstr_sha1(s)
{
  return binb2rstr(binb_sha1(rstr2binb(s), s.length * 8));
}

/*
 * Calculate the HMAC-SHA1 of a key and some data (raw strings)
 */
function rstr_hmac_sha1(key, data)
{
  var bkey = rstr2binb(key);
  if(bkey.length > 16) bkey = binb_sha1(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binb_sha1(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
  return binb2rstr(binb_sha1(opad.concat(hash), 512 + 160));
}

/*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var remainders = Array();
  var i, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  /*
   * Repeatedly perform a long division. The binary array forms the dividend,
   * the length of the encoding is the divisor. Once computed, the quotient
   * forms the dividend for the next step. We stop when the dividend is zero.
   * All remainders are stored for later use.
   */
  while(dividend.length > 0)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[remainders.length] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  /* Append leading zero equivalents */
  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)))
  for(i = output.length; i < full_length; i++)
    output = encoding[0] + output;

  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/*
 * Convert a raw string to an array of big-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binb(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
  return output;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (24 - i % 32)) & 0xFF);
  return output;
}

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function binb_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = bit_rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(bit_rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = bit_rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

exports.HMACSHA1= function(key, data) {
  return b64_hmac_sha1(key, data);
}
},{}],6:[function(require,module,exports){
/* Base64 conversion functions
 *
 * Adaptions for node.js are Copyright (c) 2010 Håvard Stranden
 *
 * Copyright (c) 2010 Nick Galbreath
 * http://code.google.com/p/stringencoders/source/browse/#svn/trunk/javascript
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * base64 encode/decode compatible with window.btoa/atob
 *
 * window.atob/btoa is a Firefox extension to convert binary data (the "b")
 * to base64 (ascii, the "a").
 *
 * It is also found in Safari and Chrome.  It is not available in IE.
 *
 * if (!window.btoa) window.btoa = base64.encode
 * if (!window.atob) window.atob = base64.decode
 *
 * The original spec's for atob/btoa are a bit lacking
 * https://developer.mozilla.org/en/DOM/window.atob
 * https://developer.mozilla.org/en/DOM/window.btoa
 *
 * window.btoa and base64.encode takes a string where charCodeAt is [0,255]
 * If any character is not [0,255], then an exception is thrown.
 *
 * window.atob and base64.decode take a base64-encoded string
 * If the input length is not a multiple of 4, or contains invalid characters
 *   then an exception is thrown.
 *
 * -*- Mode: JS; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- 
 * vim: set sw=2 ts=2 et tw=80 : 
 */
var base64 = {};
base64.PADCHAR = '=';
base64.ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
base64.getbyte64 = function(s,i) {
    // This is oddly fast, except on Chrome/V8.
    //  Minimal or no improvement in performance by using a
    //   object with properties mapping chars to value (eg. 'A': 0)
    var idx = base64.ALPHA.indexOf(s.charAt(i));
    if (idx == -1) {
  throw "Cannot decode base64";
    }
    return idx;
}

base64.decode = function(s) {
    // convert to string
    s = "" + s;
    var getbyte64 = base64.getbyte64;
    var pads, i, b10;
    var imax = s.length
    if (imax == 0) {
        return s;
    }

    if (imax % 4 != 0) {
  throw "Cannot decode base64";
    }

    pads = 0
    if (s.charAt(imax -1) == base64.PADCHAR) {
        pads = 1;
        if (s.charAt(imax -2) == base64.PADCHAR) {
            pads = 2;
        }
        // either way, we want to ignore this last block
        imax -= 4;
    }

    var x = [];
    for (i = 0; i < imax; i += 4) {
        b10 = (getbyte64(s,i) << 18) | (getbyte64(s,i+1) << 12) |
            (getbyte64(s,i+2) << 6) | getbyte64(s,i+3);
        x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 0xff, b10 & 0xff));
    }

    switch (pads) {
    case 1:
        b10 = (getbyte64(s,i) << 18) | (getbyte64(s,i+1) << 12) | (getbyte64(s,i+2) << 6)
        x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 0xff));
        break;
    case 2:
        b10 = (getbyte64(s,i) << 18) | (getbyte64(s,i+1) << 12);
        x.push(String.fromCharCode(b10 >> 16));
        break;
    }
    return x.join('');
}

base64.getbyte = function(s,i) {
    var x = s.charCodeAt(i);
    if (x > 255) {
        throw "INVALID_CHARACTER_ERR: DOM Exception 5";
    }
    return x;
}


base64.encode = function(s) {
    if (arguments.length != 1) {
  throw "SyntaxError: Not enough arguments";
    }
    var padchar = base64.PADCHAR;
    var alpha   = base64.ALPHA;
    var getbyte = base64.getbyte;

    var i, b10;
    var x = [];

    // convert to string
    s = "" + s;

    var imax = s.length - s.length % 3;

    if (s.length == 0) {
        return s;
    }
    for (i = 0; i < imax; i += 3) {
        b10 = (getbyte(s,i) << 16) | (getbyte(s,i+1) << 8) | getbyte(s,i+2);
        x.push(alpha.charAt(b10 >> 18));
        x.push(alpha.charAt((b10 >> 12) & 0x3F));
        x.push(alpha.charAt((b10 >> 6) & 0x3f));
        x.push(alpha.charAt(b10 & 0x3f));
    }
    switch (s.length - imax) {
    case 1:
        b10 = getbyte(s,i) << 16;
        x.push(alpha.charAt(b10 >> 18) + alpha.charAt((b10 >> 12) & 0x3F) +
               padchar + padchar);
        break;
    case 2:
        b10 = (getbyte(s,i) << 16) | (getbyte(s,i+1) << 8);
        x.push(alpha.charAt(b10 >> 18) + alpha.charAt((b10 >> 12) & 0x3F) +
               alpha.charAt((b10 >> 6) & 0x3f) + padchar);
        break;
    }
    return x.join('');
}

exports.base64 = base64;

},{}],7:[function(require,module,exports){
/* Conversion functions used in OpenID for node.js
 *
 * http://ox.no/software/node-openid
 * http://github.com/havard/node-openid
 *
 * Copyright (C) 2010 by Håvard Stranden
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  
 * -*- Mode: JS; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- 
 * vim: set sw=2 ts=2 et tw=80 : 
 */

var base64 = require('./base64').base64;

function btwoc(i)
{
  if(i.charCodeAt(0) > 127)
  {
    return String.fromCharCode(0) + i;
  }
  return i;
}

function unbtwoc(i)
{
  if(i[0] === String.fromCharCode(0))
  {
    return i.substr(1);
  }

  return i;
}

exports.btwoc = btwoc;
exports.unbtwoc = unbtwoc;
exports.base64 = base64;

},{"./base64":6}],8:[function(require,module,exports){
/* A simple XRDS and Yadis parser written for OpenID for node.js
 *
 * http://ox.no/software/node-openid
 * http://github.com/havard/node-openid
 *
 * Copyright (C) 2010 by Håvard Stranden
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  
 * -*- Mode: JS; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- 
 * vim: set sw=2 ts=2 et tw=80 : 
 */

exports.parse  = function(data)
{
  data = data.replace(/\r|\n/g, '');
  var services = [];
  var serviceMatches = data.match(/<Service\s*(priority="\d+")?.*?>(.*?)<\/Service>/g);

  if(!serviceMatches)
  {
    return services;
  }

  for(var s = 0, len = serviceMatches.length; s < len; ++s)
  {
    var service = serviceMatches[s];
    var svcs = [];
    var priorityMatch = /<Service.*?priority="(.*?)".*?>/g.exec(service);
    var priority = 0;
    if(priorityMatch)
    {
      priority = parseInt(priorityMatch[1], 10);
    }

    var typeMatch = null;
    var typeRegex = new RegExp('<Type(\\s+.*?)?>(.*?)<\\/Type\\s*?>', 'g');
    while(typeMatch = typeRegex.exec(service))
    {
      svcs.push({ priority: priority, type: typeMatch[2] });
    }

    if(svcs.length == 0)
    {
      continue;
    }

    var idMatch = /<(Local|Canonical)ID\s*?>(.*?)<\/\1ID\s*?>/g.exec(service);
    if(idMatch)
    {
      for(var i = 0; i < svcs.length; i++)
      {
        var svc = svcs[i];
        svc.id = idMatch[2];
      }
    }
    
    var uriMatch = /<URI(\s+.*?)?>(.*?)<\/URI\s*?>/g.exec(service);
    if(!uriMatch)
    {
      continue;
    }

    for(var i = 0; i < svcs.length; i++)
    {
      var svc = svcs[i];
      svc.uri = uriMatch[2];
    }

    var delegateMatch = /<(.*?Delegate)\s*?>(.*)<\/\1\s*?>/g.exec(service);
    if(delegateMatch)
    {
      svc.delegate = delegateMatch[2];
    }

    services.push.apply(services, svcs);
  }

  services.sort(function(a, b) 
  { 
    return a.priority < b.priority 
      ? -1 
      : (a.priority == b.priority ? 0 : 1);
  });

  return services;
}

},{}],9:[function(require,module,exports){
/* OpenID for node.js
 *
 * http://ox.no/software/node-openid
 * http://github.com/havard/node-openid
 *
 * Copyright (C) 2010 by Håvard Stranden
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *
 * -*- Mode: JS; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- 
 * vim: set sw=2 ts=2 et tw=80 : 
 */

var convert = require('./lib/convert'),
    crypto = require('crypto'),
    http = require('http'),
    https = require('https'),
    querystring = require('querystring'),
    url = require('url'),
    xrds = require('./lib/xrds');

var _associations = {};
var _discoveries = {};

var openid = exports;

openid.RelyingParty = function(returnUrl, realm, stateless, strict, extensions)
{
  this.returnUrl = returnUrl;
  this.realm = realm || null;
  this.stateless = stateless;
  this.strict = strict;
  this.extensions = extensions;
}

openid.RelyingParty.prototype.authenticate = function(identifier, immediate, callback)
{
  openid.authenticate(identifier, this.returnUrl, this.realm, 
      immediate, this.stateless, callback, this.extensions, this.strict);
}

openid.RelyingParty.prototype.verifyAssertion = function(requestOrUrl, callback)
{
  openid.verifyAssertion(requestOrUrl, callback, this.stateless, this.extensions, this.strict);
}

var _isDef = function(e)
{
  var undefined;
  return e !== undefined;
}

var _toBase64 = function(binary)
{
  return convert.base64.encode(convert.btwoc(binary));
}

var _fromBase64 = function(str)
{
  return convert.unbtwoc(convert.base64.decode(str));
}

var _xor = function(a, b)
{
  if(a.length != b.length)
  {
    throw new Error('Length must match for xor');
  }

  var r = '';
  for(var i = 0; i < a.length; ++i)
  {
    r += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i));
  }

  return r;
}

openid.saveAssociation = function(provider, type, handle, secret, expiry_time_in_seconds, callback)
{
  setTimeout(function() {
    openid.removeAssociation(handle);
  }, expiry_time_in_seconds * 1000);
  _associations[handle] = {provider: provider, type : type, secret: secret};
  callback(null); // Custom implementations may report error as first argument
}

openid.loadAssociation = function(handle, callback)
{
  if(_isDef(_associations[handle]))
  {
    callback(null, _associations[handle]);
  }
  else
  {
    callback(null, null);
  }
}

openid.removeAssociation = function(handle)
{
  delete _associations[handle];
  return true;
}

openid.saveDiscoveredInformation = function(key, provider, callback)
{
  _discoveries[key] = provider;
  return callback(null);
}

openid.loadDiscoveredInformation = function(key, callback)
{
  if(!_isDef(_discoveries[key]))
  {
    return callback(null, null);
  }

  return callback(null, _discoveries[key]);
}

var _buildUrl = function(theUrl, params)
{
  theUrl = url.parse(theUrl, true);
  delete theUrl['search'];
  if(params)
  {
    if(!theUrl.query)
    {
      theUrl.query = params;
    }
    else
    {
      for(var key in params)
      {
        if(params.hasOwnProperty(key))
        {
          theUrl.query[key] = params[key];
        }
      }
    }
  }

  return url.format(theUrl);
}

var _proxyRequest = function(protocol, options)
{
  /* 
  If process.env['HTTP_PROXY_HOST'] and the env variable `HTTP_PROXY_POST`
  are set, make sure path and the header Host are set to target url.

  Similarly, `HTTPS_PROXY_HOST` and `HTTPS_PROXY_PORT` can be used
  to proxy HTTPS traffic.

  Proxies Example:
      export HTTP_PROXY_HOST=localhost
      export HTTP_PROXY_PORT=8080
      export HTTPS_PROXY_HOST=localhost
      export HTTPS_PROXY_PORT=8442

  Function returns protocol which should be used for network request, one of
  http: or https:
  */
  var targetHost = options.host;
  var newProtocol = protocol;
  if (!targetHost) return;
  var updateOptions = function (envPrefix) {
    var proxyHostname = process.env[envPrefix + '_PROXY_HOST'].trim();
    var proxyPort = parseInt(process.env[envPrefix + '_PROXY_PORT'], 10);
    if (proxyHostname.length > 0 && ! isNaN(proxyPort)) {

      if (! options.headers) options.headers = {};

      var targetHostAndPort = targetHost + ':' + options.port;

      options.host = proxyHostname;
      options.port = proxyPort;
      options.path = protocol + '//' + targetHostAndPort + options.path;
      options.headers['Host'] = targetHostAndPort;
    }
  };
  if ('https:' === protocol &&
      !! process.env['HTTPS_PROXY_HOST'] &&
      !! process.env['HTTPS_PROXY_PORT']) {
    updateOptions('HTTPS');
    // Proxy server request must be done via http... it is responsible for
    // Making the https request...    
    newProtocol = 'http:';
  } else if (!! process.env['HTTP_PROXY_HOST'] &&
             !! process.env['HTTP_PROXY_PORT']) {
    updateOptions('HTTP');
  }
  return newProtocol;
}

var _get = function(getUrl, params, callback, redirects)
{
  redirects = redirects || 5;
  getUrl = url.parse(_buildUrl(getUrl, params));

  var path = getUrl.pathname || '/';
  if(getUrl.query)
  {
    path += '?' + getUrl.query;
  }
  var options = 
  {
    host: getUrl.hostname,
    port: _isDef(getUrl.port) ? parseInt(getUrl.port, 10) :
      (getUrl.protocol == 'https:' ? 443 : 80),
    headers: { 'Accept' : 'application/xrds+xml,text/html,text/plain,*/*' },
    path: path
  };

  var protocol = _proxyRequest(getUrl.protocol, options);

  (protocol == 'https:' ? https : http).get(options, function(res)
  {
    var data = '';
    res.on('data', function(chunk)
    {
      data += chunk;
    });

    var isDone = false;
    var done = function()
    {
      if (isDone) return;
      isDone = true;

      if(res.headers.location && --redirects)
      {
        var redirectUrl = res.headers.location;
        if(redirectUrl.indexOf('http') !== 0)
        {
          redirectUrl = getUrl.protocol + '//' + getUrl.hostname + ':' + options.port + (redirectUrl.indexOf('/') === 0 ? redirectUrl : '/' + redirectUrl);
        }
        _get(redirectUrl, params, callback, redirects);
      }
      else
      {
        callback(data, res.headers, res.statusCode);
      }
    }

    res.on('end', function() { done(); });
    res.on('close', function() { done(); });
  }).on('error', function(error) 
  {
    return callback(error);
  });
}

var _post = function(postUrl, data, callback, redirects)
{
  redirects = redirects || 5;
  postUrl = url.parse(postUrl);

  var path = postUrl.pathname || '/';
  if(postUrl.query)
  {
    path += '?' + postUrl.query;
  }

  var encodedData = _encodePostData(data);
  var options = 
  {
    host: postUrl.hostname,
    path: path,
    port: _isDef(postUrl.port) ? postUrl.port :
      (postUrl.protocol == 'https:' ? 443 : 80),
    headers: 
    {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': encodedData.length
    },
    method: 'POST'
  };

  var protocol = _proxyRequest(postUrl.protocol, options);

  (protocol == 'https:' ? https : http).request(options, function(res)
  {
    var data = '';
    res.on('data', function(chunk)
    {
      data += chunk;
    });

    var isDone = false;
    var done = function()
    {
      if (isDone) return;
      isDone = true;

      if(res.headers.location && --redirects)
      {
        _post(res.headers.location, data, callback, redirects);
      }
      else
      {
        callback(data, res.headers, res.statusCode);
      }
    }

    res.on('end', function() { done(); });
    res.on('close', function() { done(); });
  }).on('error', function(error)
  {
    return callback(error);
  }).end(encodedData);
}

var _encodePostData = function(data)
{
  var encoded = querystring.stringify(data);
  return encoded;
}

var _decodePostData = function(data)
{
  var lines = data.split('\n');
  var result = {};
  for (var i = 0; i < lines.length ; i++) {
    var line = lines[i];
    if (line.length > 0 && line[line.length - 1] == '\r') {
      line = line.substring(0, line.length - 1);
    }
    var colon = line.indexOf(':');
    if (colon === -1)
    {
      continue;
    }
    var key = line.substr(0, line.indexOf(':'));
    var value = line.substr(line.indexOf(':') + 1);
    result[key] = value;
  }

  return result;
}

var _normalizeIdentifier = function(identifier)
{
  identifier = identifier.replace(/^\s+|\s+$/g, '');
  if(!identifier)
    return null;
  if(identifier.indexOf('xri://') === 0)
  {
    identifier = identifier.substring(6);
  }

  if(/^[(=@\+\$!]/.test(identifier))
  {
    return identifier;
  }

  if(identifier.indexOf('http') === 0)
  {
    return identifier;
  }
  return 'http://' + identifier;
}

var _parseXrds = function(xrdsUrl, xrdsData)
{
  var services = xrds.parse(xrdsData);
  if(services == null)
  {
    return null;
  }

  var providers = [];
  for(var i = 0, len = services.length; i < len; ++i)
  {
    var service = services[i];
    var provider = {};

    provider.endpoint = service.uri;
    if(/https?:\/\/xri./.test(xrdsUrl))
    {
      provider.claimedIdentifier = service.id;
    }
    if(service.type == 'http://specs.openid.net/auth/2.0/signon')
    {
      provider.version = 'http://specs.openid.net/auth/2.0';
      provider.localIdentifier = service.id;
    }
    else if(service.type == 'http://specs.openid.net/auth/2.0/server')
    {
      provider.version = 'http://specs.openid.net/auth/2.0';
    }
    else if(service.type == 'http://openid.net/signon/1.0' || 
      service.type == 'http://openid.net/signon/1.1')
    {
      provider.version = service.type;
      provider.localIdentifier = service.delegate;
    }
    else
    {
      continue;
    }
    providers.push(provider);
  }

  return providers;
}

var _matchMetaTag = function(html)
{
  var metaTagMatches = /<meta\s+.*?http-equiv="x-xrds-location"\s+(.*?)>/ig.exec(html);
  if(!metaTagMatches || metaTagMatches.length < 2)
  {
    return null;
  }

  var contentMatches = /content="(.*?)"/ig.exec(metaTagMatches[1]);
  if(!contentMatches || contentMatches.length < 2)
  {
    return null;
  }

  return contentMatches[1];
}

var _matchLinkTag = function(html, rel)
{
  var providerLinkMatches = new RegExp('<link\\s+.*?rel=["\'][^"\']*?' + rel + '[^"\']*?["\'].*?>', 'ig').exec(html);

  if(!providerLinkMatches || providerLinkMatches.length < 1)
  {
    return null;
  }

  var href = /href=["'](.*?)["']/ig.exec(providerLinkMatches[0]);

  if(!href || href.length < 2)
  {
    return null;
  }
  return href[1];
}

var _parseHtml = function(htmlUrl, html, callback, hops)
{
  var metaUrl = _matchMetaTag(html);
  if(metaUrl != null)
  {
    return _resolveXri(metaUrl, callback, hops + 1);
  }

  var provider = _matchLinkTag(html, 'openid2.provider');
  if(provider == null)
  {
    provider = _matchLinkTag(html, 'openid.server');
    if(provider == null)
    {
      callback(null);
    }
    else
    {
      var localId = _matchLinkTag(html, 'openid.delegate');
      callback([{ 
        version: 'http://openid.net/signon/1.1',
        endpoint: provider, 
        claimedIdentifier: htmlUrl,
        localIdentifier : localId 
      }]);
    }
  }
  else
  {
    var localId = _matchLinkTag(html, 'openid2.local_id');
    callback([{ 
      version: 'http://specs.openid.net/auth/2.0/signon', 
      endpoint: provider, 
      claimedIdentifier: htmlUrl,
      localIdentifier : localId 
    }]);
  }
}

var _parseHostMeta = function(hostMeta, callback)
{
  var match = /^Link: <([^\n\r]+)>;/.exec(hostMeta);
  if(match != null)
  {
    var xriUrl = match[0].slice(7,match.length - 4);
    _resolveXri(xriUrl, callback);
  }
  else
  {
    callback(null)
  }
}

var _resolveXri = function(xriUrl, callback, hops)
{
  if(!hops)
  {
    hops = 1;
  }
  else if(hops >= 5)
  {
    return callback(null);
  }

  _get(xriUrl, null, function(data, headers, statusCode)
  {
    if(statusCode != 200)
    {
      return callback(null);
    }

    var xrdsLocation = headers['x-xrds-location'];
    if(_isDef(xrdsLocation))
    {
      _get(xrdsLocation, null, function(data, headers, statusCode)
      {
        if(statusCode != 200 || data == null)
        {
          callback(null);
        }
        else
        {
          callback(_parseXrds(xrdsLocation, data));
        }
      });
    }
    else if(data != null)
    {
      var contentType = headers['content-type'];
      // text/xml is not compliant, but some hosting providers refuse header
      // changes, so text/xml is encountered
      if(contentType && (contentType.indexOf('application/xrds+xml') === 0 || contentType.indexOf('text/xml') === 0))
      {
        return callback(_parseXrds(xriUrl, data));
      }
      else
      {
        return _resolveHtml(xriUrl, callback, hops + 1, data);
      }
    }
  });
}

var _resolveHtml = function(identifier, callback, hops, data)
{
  if(!hops)
  {
    hops = 1;
  }
  else if(hops >= 5)
  {
    return callback(null);
  }

  if(data == null)
  {
    _get(identifier, null, function(data, headers, statusCode)
    {
      if(statusCode != 200 || data == null)
      {
        callback(null);
      }
      else
      {
        _parseHtml(identifier, data, callback, hops + 1);
      }
    });
  }
  else
  {
    _parseHtml(identifier, data, callback, hops);
  }

}

var _resolveHostMeta = function(identifier, strict, callback, fallBackToProxy)
{
  var host = url.parse(identifier);
  var hostMetaUrl;
  if(fallBackToProxy && !strict)
  {
    hostMetaUrl = 'https://www.google.com/accounts/o8/.well-known/host-meta?hd=' + host.host
  }
  else
  {
    hostMetaUrl = host.protocol + '//' + host.host + '/.well-known/host-meta';
  }
  if(!hostMetaUrl)
  {
    callback(null);
  }
  else
  {
    _get(hostMetaUrl, null, function(data, headers, statusCode)
    {
      if(statusCode != 200 || data == null)
      {
        if(!fallBackToProxy && !strict){
          _resolveHostMeta(identifier, strict, callback, true);
        }
        else{
          callback(null);
        }
      }
      else
      {
        //Attempt to parse the data but if this fails it may be because
        //the response to hostMetaUrl was some other http/html resource.
        //Therefore fallback to the proxy if no providers are found.
        _parseHostMeta(data, function(providers){
          if((providers == null || providers.length == 0) && !fallBackToProxy && !strict){
            _resolveHostMeta(identifier, strict, callback, true);
          }
          else{
            callback(providers);
          }
        });
      }
    });
  }
}

openid.discover = function(identifier, strict, callback)
{
  identifier = _normalizeIdentifier(identifier);
  if(!identifier) 
  {
    return callback({ message: 'Invalid identifier' }, null);
  }
  if(identifier.indexOf('http') !== 0)
  {
    // XRDS
    identifier = 'https://xri.net/' + identifier + '?_xrd_r=application/xrds%2Bxml';
  }

  // Try XRDS/Yadis discovery
  _resolveXri(identifier, function(providers)
  {
    if(providers == null || providers.length == 0)
    {
      // Fallback to HTML discovery
      _resolveHtml(identifier, function(providers)
      {
        if(providers == null || providers.length == 0){
          _resolveHostMeta(identifier, strict, function(providers){
            callback(null, providers);
          });
        }
        else{
          callback(null, providers);
        }
      });
    }
    else
    {
      // Add claimed identifier to providers with local identifiers
      // and OpenID 1.0/1.1 providers to ensure correct resolution 
      // of identities and services
      for(var i = 0, len = providers.length; i < len; ++i)
      {
        var provider = providers[i];
        if(!provider.claimedIdentifier && 
          (provider.localIdentifier || provider.version.indexOf('2.0') === -1))
        {
          provider.claimedIdentifier = identifier;
        }
      }
      callback(null, providers);
    }
  });
}

var _createDiffieHellmanKeyExchange = function(algorithm)
{
  var defaultPrime = 'ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr';

  var dh = crypto.createDiffieHellman(defaultPrime, 'base64');

  dh.generateKeys();

  return dh;
}

openid.associate = function(provider, callback, strict, algorithm)
{
  var params = _generateAssociationRequestParameters(provider.version, algorithm);
  if(!_isDef(algorithm))
  {
    algorithm = 'DH-SHA256';
  }

  var dh = null;
  if(algorithm.indexOf('no-encryption') === -1)
  {
    dh = _createDiffieHellmanKeyExchange(algorithm);
    params['openid.dh_modulus'] = _toBase64(dh.getPrime('binary'));
    params['openid.dh_gen'] = _toBase64(dh.getGenerator('binary'));
    params['openid.dh_consumer_public'] = _toBase64(dh.getPublicKey('binary'));
  }

  _post(provider.endpoint, params, function(data, headers, statusCode)
  {
    if ((statusCode != 200 && statusCode != 400) || data === null)
    {
      return callback({ 
        message: 'HTTP request failed' 
      }, { 
        error: 'HTTP request failed', 
        error_code: ''  + statusCode, 
        ns: 'http://specs.openid.net/auth/2.0' 
      });
    }
    
    data = _decodePostData(data);

    if(data.error_code == 'unsupported-type' || !_isDef(data.ns))
    {
      if(algorithm == 'DH-SHA1')
      {
        if(strict && provider.endpoint.toLowerCase().indexOf('https:') !== 0)
        {
          return callback({ message: 'Channel is insecure and no encryption method is supported by provider' }, null);
        }
        else
        {
          return openid.associate(provider, callback, strict, 'no-encryption-256');
        }
      }
      else if(algorithm == 'no-encryption-256')
      {
        if(strict && provider.endpoint.toLowerCase().indexOf('https:') !== 0)
        {
          return callback('Channel is insecure and no encryption method is supported by provider', null);
        }
        /*else if(provider.version.indexOf('2.0') === -1)
        {
          // 2011-07-22: This is an OpenID 1.0/1.1 provider which means
          // HMAC-SHA1 has already been attempted with a blank session
          // type as per the OpenID 1.0/1.1 specification.
          // (See http://openid.net/specs/openid-authentication-1_1.html#mode_associate)
          // However, providers like wordpress.com don't follow the 
          // standard and reject these requests, but accept OpenID 2.0
          // style requests without a session type, so we have to give
          // those a shot as well.
          callback({ message: 'Provider is OpenID 1.0/1.1 and does not support OpenID 1.0/1.1 association.' });
        }*/
        else
        {
          return openid.associate(provider, callback, strict, 'no-encryption');
        }
      }
      else if(algorithm == 'DH-SHA256')
      {
        return openid.associate(provider, callback, strict, 'DH-SHA1');
      }
    }

    if (data.error)
    {
      callback({ message: data.error }, data);
    }
    else
    {
      var secret = null;

      var hashAlgorithm = algorithm.indexOf('256') !== -1 ? 'sha256' : 'sha1';

      if(algorithm.indexOf('no-encryption') !== -1)
      {
        secret = data.mac_key;
      }
      else
      {
        var serverPublic = _fromBase64(data.dh_server_public);
        var sharedSecret = convert.btwoc(dh.computeSecret(serverPublic, 'binary', 'binary'));
        var hash = crypto.createHash(hashAlgorithm);
        hash.update(sharedSecret);
        sharedSecret = hash.digest('binary');
        var encMacKey = convert.base64.decode(data.enc_mac_key);
        secret = convert.base64.encode(_xor(encMacKey, sharedSecret));
      }

      if (!_isDef(data.assoc_handle)) {
        return callback({ message: 'OpenID provider does not seem to support association; you need to use stateless mode'}, null);
      }

      openid.saveAssociation(provider, hashAlgorithm,
        data.assoc_handle, secret, data.expires_in * 1, function(error)
        {
          if(error)
          {
            return callback(error);
          }
          callback(null, data);
        });
    }
  });
}

var _generateAssociationRequestParameters = function(version, algorithm)
{
  var params = {
    'openid.mode' : 'associate',
  };

  if(version.indexOf('2.0') !== -1)
  {
    params['openid.ns'] = 'http://specs.openid.net/auth/2.0';
  }

  if(algorithm == 'DH-SHA1')
  {
    params['openid.assoc_type'] = 'HMAC-SHA1';
    params['openid.session_type'] = 'DH-SHA1';
  }
  else if(algorithm == 'no-encryption-256')
  {
    if(version.indexOf('2.0') === -1)
    {
      params['openid.session_type'] = ''; // OpenID 1.0/1.1 requires blank
      params['openid.assoc_type'] = 'HMAC-SHA1';
    }
    else
    {
      params['openid.session_type'] = 'no-encryption';
      params['openid.assoc_type'] = 'HMAC-SHA256';
    }
  }
  else if(algorithm == 'no-encryption')
  {
    if(version.indexOf('2.0') !== -1)
    {
      params['openid.session_type'] = 'no-encryption';
    }
    params['openid.assoc_type'] = 'HMAC-SHA1';
  }
  else
  {
    params['openid.assoc_type'] = 'HMAC-SHA256';
    params['openid.session_type'] = 'DH-SHA256';
  }

  return params;
}

openid.authenticate = function(identifier, returnUrl, realm, immediate, stateless, callback, extensions, strict)
{
  openid.discover(identifier, strict, function(error, providers)
  {
    if(error)
    {
      return callback(error);
    }
    if(!providers || providers.length === 0)
    {
      return callback({ message: 'No providers found for the given identifier' }, null);
    }

    var providerIndex = -1;

    (function chooseProvider(error, authUrl)
    {
      if(!error && authUrl)
      {
        var provider = providers[providerIndex];

        if(provider.claimedIdentifier)
        {
          var useLocalIdentifierAsKey = provider.version.indexOf('2.0') === -1 && provider.localIdentifier && provider.claimedIdentifier != provider.localIdentifier;

          return openid.saveDiscoveredInformation(useLocalIdentifierAsKey ? provider.localIdentifier : provider.claimedIdentifier, 
            provider, function(error)
          {
            if(error)
            {
              return callback(error);
            }
            return callback(null, authUrl);
          });
        }
        else if(provider.version.indexOf('2.0') !== -1)
        {
          return callback(null, authUrl);
        }
        else
        {
          chooseProvider({ message: 'OpenID 1.0/1.1 provider cannot be used without a claimed identifier' });
        }
      }
      if(++providerIndex >= providers.length)
      {
        return callback({ message: 'No usable providers found for the given identifier' }, null);
      }

      var currentProvider = providers[providerIndex];
      if(stateless)
      {
        _requestAuthentication(currentProvider, null, returnUrl, 
          realm, immediate, extensions || {}, chooseProvider);
      }

      else
      {
        openid.associate(currentProvider, function(error, answer)
        {
          if(error || !answer || answer.error)
          {
            chooseProvider(error || answer.error, null);
          }
          else
          {
            _requestAuthentication(currentProvider, answer.assoc_handle, returnUrl, 
              realm, immediate, extensions || {}, chooseProvider);
          }
        });
        
      }
    })();
  });
}

var _requestAuthentication = function(provider, assoc_handle, returnUrl, realm, immediate, extensions, callback)
{
  var params = {
    'openid.mode' : immediate ? 'checkid_immediate' : 'checkid_setup'
  };

  if(provider.version.indexOf('2.0') !== -1)
  {
    params['openid.ns'] = 'http://specs.openid.net/auth/2.0';
  }

  for (var i in extensions)
  {
    if(!extensions.hasOwnProperty(i))
    {
      continue;
    }

    var extension = extensions[i];
    for (var key in extension.requestParams)
    {
      if (!extension.requestParams.hasOwnProperty(key)) { continue; }
      params[key] = extension.requestParams[key];
    }
  }

  if(provider.claimedIdentifier)
  {
    params['openid.claimed_id'] = provider.claimedIdentifier;
    if(provider.localIdentifier)
    {
      params['openid.identity'] = provider.localIdentifier;
    }
    else
    {
      params['openid.identity'] = provider.claimedIdentifier;
    }
  }
  else if(provider.version.indexOf('2.0') !== -1)
  {
    params['openid.claimed_id'] = params['openid.identity'] =
      'http://specs.openid.net/auth/2.0/identifier_select';
  }
  else {
    return callback({ message: 'OpenID 1.0/1.1 provider cannot be used without a claimed identifier' });
  }

  if(assoc_handle)
  {
    params['openid.assoc_handle'] = assoc_handle;
  }

  if(returnUrl)
  {
    // Value should be missing if RP does not want
    // user to be sent back
    params['openid.return_to'] = returnUrl;
  }

  if(realm)
  {
    if(provider.version.indexOf('2.0') !== -1) {
      params['openid.realm'] = realm;
    }
    else {
      params['openid.trust_root'] = realm;
    }
  }
  else if(!returnUrl)
  {
    return callback({ message: 'No return URL or realm specified' });
  }

  callback(null, _buildUrl(provider.endpoint, params));
}

openid.verifyAssertion = function(requestOrUrl, callback, stateless, extensions, strict)
{
  extensions = extensions || {};
  var assertionUrl = requestOrUrl;
  if(typeof(requestOrUrl) !== typeof(''))
  {
    if(requestOrUrl.method == 'POST') {
      if((requestOrUrl.headers['content-type'] || '').toLowerCase().indexOf('application/x-www-form-urlencoded') === 0) {
        // POST response received
        var data = '';
        
        requestOrUrl.on('data', function(chunk) {
          data += chunk;
        });
        
        requestOrUrl.on('end', function() {
          var params = querystring.parse(data);
          return _verifyAssertionData(params, callback, stateless, extensions, strict);
        });
      }
      else {
        return callback({ message: 'Invalid POST response from OpenID provider' });
      }
      
      return; // Avoid falling through to GET method assertion
    }
    else if(requestOrUrl.method != 'GET') {
      return callback({ message: 'Invalid request method from OpenID provider' });
    }
    assertionUrl = requestOrUrl.url;
  }

  assertionUrl = url.parse(assertionUrl, true);
  var params = assertionUrl.query;

  return _verifyAssertionData(params, callback, stateless, extensions, strict);
}

var _verifyAssertionData = function(params, callback, stateless, extensions, strict) {
  var assertionError = _getAssertionError(params);
  if(assertionError)
  {
    return callback({ message: assertionError }, { authenticated: false });
  }

  if (!_invalidateAssociationHandleIfRequested(params)) {
    return callback({ message: 'Unable to invalidate association handle'});
  }

  // TODO: Check nonce if OpenID 2.0
  _verifyDiscoveredInformation(params, stateless, extensions, strict, function(error, result)
  {
    return callback(error, result);
  });
};

var _getAssertionError = function(params)
{
  if(!_isDef(params))
  {
    return 'Assertion request is malformed';
  }
  else if(params['openid.mode'] == 'error')
  {
    return params['openid.error'];
  }
  else if(params['openid.mode'] == 'cancel')
  {
    return 'Authentication cancelled';
  }

  return null;
}

var _invalidateAssociationHandleIfRequested = function(params)
{
  if (params['is_valid'] == 'true' && _isDef(params['openid.invalidate_handle'])) {
    if(!openid.removeAssociation(params['openid.invalidate_handle'])) {
      return false;
    }
  }

  return true;
}

var _verifyDiscoveredInformation = function(params, stateless, extensions, strict, callback)
{
  var claimedIdentifier = params['openid.claimed_id'];
  var useLocalIdentifierAsKey = false;
  if(!_isDef(claimedIdentifier))
  {
    if(!_isDef(params['openid.ns']))
    {
      // OpenID 1.0/1.1 response without a claimed identifier
      // We need to load discovered information using the
      // local identifier
      useLocalIdentifierAsKey = true;
    }
    else {
      // OpenID 2.0+:
      // If there is no claimed identifier, then the
      // assertion is not about an identity
      return callback(null, { authenticated: false }); 
      }
  }

  if (useLocalIdentifierAsKey) {
    claimedIdentifier = params['openid.identity'];  
  }

  claimedIdentifier = _getCanonicalClaimedIdentifier(claimedIdentifier);
  openid.loadDiscoveredInformation(claimedIdentifier, function(error, provider)
  {
    if(error)
    {
      return callback({ message: 'An error occured when loading previously discovered information about the claimed identifier' });
    }

    if(provider)
    {
      return _verifyAssertionAgainstProviders([provider], params, stateless, extensions, callback);
    }
    else if (useLocalIdentifierAsKey) {
      return callback({ message: 'OpenID 1.0/1.1 response received, but no information has been discovered about the provider. It is likely that this is a fraudulent authentication response.' });
    }
    
    openid.discover(claimedIdentifier, strict, function(error, providers)
    {
      if(error)
      {
        return callback(error);
      }
      if(!providers || !providers.length)
      {
        return callback({ message: 'No OpenID provider was discovered for the asserted claimed identifier' });
      }

      _verifyAssertionAgainstProviders(providers, params, stateless, extensions, callback);
    });
  });
}

var _verifyAssertionAgainstProviders = function(providers, params, stateless, extensions, callback)
{
  for(var i = 0; i < providers.length; ++i)
  {
    var provider = providers[i];
    if(!!params['openid.ns'] && (!provider.version || provider.version.indexOf(params['openid.ns']) !== 0))
    {
      continue;
    }

    if(!!provider.version && provider.version.indexOf('2.0') !== -1)
    {
      var endpoint = params['openid.op_endpoint'];
      if (provider.endpoint != endpoint) 
      {
        continue;
      }
      if(provider.claimedIdentifier) {
        var claimedIdentifier = _getCanonicalClaimedIdentifier(params['openid.claimed_id']);
        if(provider.claimedIdentifier != claimedIdentifier) {
          return callback({ message: 'Claimed identifier in assertion response does not match discovered claimed identifier' });
        }
      }
    }

    if(!!provider.localIdentifier && provider.localIdentifier != params['openid.identity'])
    {
      return callback({ message: 'Identity in assertion response does not match discovered local identifier' });
    }

    return _checkSignature(params, provider, stateless, function(error, result)
    {
      if(error)
      {
        return callback(error);
      }
      if(extensions && result.authenticated)
      {
        for(var ext in extensions)
        {
          if (!extensions.hasOwnProperty(ext))
          { 
            continue; 
          }
          var instance = extensions[ext];
          instance.fillResult(params, result);
        }
      }

      return callback(null, result);
    });
  }

  callback({ message: 'No valid providers were discovered for the asserted claimed identifier' });
}

var _checkSignature = function(params, provider, stateless, callback)
{
  if(!_isDef(params['openid.signed']) ||
    !_isDef(params['openid.sig']))
  {
    return callback({ message: 'No signature in response' }, { authenticated: false });
  }

  if(stateless)
  {
    _checkSignatureUsingProvider(params, provider, callback);
  }
  else
  {
    _checkSignatureUsingAssociation(params, callback);
  }
}

var _checkSignatureUsingAssociation = function(params, callback)
{
  if (!_isDef(params['openid.assoc_handle']))
  {
    return callback({ message: 'No association handle in provider response. Find out whether the provider supports associations and/or use stateless mode.' });
  }
  openid.loadAssociation(params['openid.assoc_handle'], function(error, association)
  {
    if(error)
    {
      return callback({ message: 'Error loading association' }, { authenticated: false });
    }
    if(!association)
    {
      return callback({ message:'Invalid association handle' }, { authenticated: false });
    }
    if(association.provider.version.indexOf('2.0') !== -1 && association.provider.endpoint !== params['openid.op_endpoint'])
    {
      return callback({ message:'Association handle does not match provided endpoint' }, {authenticated: false});
    }
    
    var message = '';
    var signedParams = params['openid.signed'].split(',');
    for(var i = 0; i < signedParams.length; i++)
    {
      var param = signedParams[i];
      var value = params['openid.' + param];
      if(!_isDef(value))
      {
        return callback({ message: 'At least one parameter referred in signature is not present in response' }, { authenticated: false });
      }
      message += param + ':' + value + '\n';
    }

    var hmac = crypto.createHmac(association.type, convert.base64.decode(association.secret));
    hmac.update(message, 'utf8');
    var ourSignature = hmac.digest('base64');

    if(ourSignature == params['openid.sig'])
    {
      callback(null, { authenticated: true, claimedIdentifier: association.provider.version.indexOf('2.0') !== -1 ? params['openid.claimed_id'] : association.provider.claimedIdentifier });
    }
    else
    {
      callback({ message: 'Invalid signature' }, { authenticated: false });
    }
  });
}

var _checkSignatureUsingProvider = function(params, provider, callback)
{
  var requestParams = 
  {
    'openid.mode' : 'check_authentication'
  };
  for(var key in params)
  {
    if(params.hasOwnProperty(key) && key != 'openid.mode')
    {
      requestParams[key] = params[key];
    }
  }

  _post(_isDef(params['openid.ns']) ? (params['openid.op_endpoint'] || provider.endpoint) : provider.endpoint, requestParams, function(data, headers, statusCode)
  {
    if(statusCode != 200 || data == null)
    {
      return callback({ message: 'Invalid assertion response from provider' }, { authenticated: false });
    }
    else
    {
      data = _decodePostData(data);
      if(data['is_valid'] == 'true')
      {
        return callback(null, { authenticated: true, claimedIdentifier: provider.version.indexOf('2.0') !== -1 ? params['openid.claimed_id'] : params['openid.identity'] });
      }
      else
      {
        return callback({ message: 'Invalid signature' }, { authenticated: false });
      }
    }
  });

}


var _getCanonicalClaimedIdentifier = function(claimedIdentifier) {
  if(!claimedIdentifier) {
    return claimedIdentifier;
  }

  var index = claimedIdentifier.indexOf('#');
  if (index !== -1) {
    return claimedIdentifier.substring(0, index);
  }

  return claimedIdentifier;
};

/* ==================================================================
 * Extensions
 * ================================================================== 
 */

var _getExtensionAlias = function(params, ns) 
{
  for (var k in params)
    if (params[k] == ns)
      return k.replace("openid.ns.", "");
}

/* 
 * Simple Registration Extension
 * http://openid.net/specs/openid-simple-registration-extension-1_1-01.html
 */

var sreg_keys = ['nickname', 'email', 'fullname', 'dob', 'gender', 'postcode', 'country', 'language', 'timezone'];

openid.SimpleRegistration = function SimpleRegistration(options) 
{
  this.requestParams = {'openid.ns.sreg': 'http://openid.net/extensions/sreg/1.1'};
  if (options.policy_url)
    this.requestParams['openid.sreg.policy_url'] = options.policy_url;
  var required = [];
  var optional = [];
  for (var i = 0; i < sreg_keys.length; i++)
  {
    var key = sreg_keys[i];
    if (options[key]) 
    {
      if (options[key] == 'required')
      {
        required.push(key);
      }
      else
      {
        optional.push(key);
      }
    }
    if (required.length)
    {
      this.requestParams['openid.sreg.required'] = required.join(',');
    }
    if (optional.length)
    {
      this.requestParams['openid.sreg.optional'] = optional.join(',');
    }
  }
};

openid.SimpleRegistration.prototype.fillResult = function(params, result)
{
  var extension = _getExtensionAlias(params, 'http://openid.net/extensions/sreg/1.1') || 'sreg';
  for (var i = 0; i < sreg_keys.length; i++)
  {
    var key = sreg_keys[i];
    if (params['openid.' + extension + '.' + key])
    {
      result[key] = params['openid.' + extension + '.' + key];
    }
  }
};

/* 
 * User Interface Extension
 * http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html 
 */
openid.UserInterface = function UserInterface(options) 
{
  if (typeof(options) != 'object')
  {
    options = { mode: options || 'popup' };
  }

  this.requestParams = {'openid.ns.ui': 'http://specs.openid.net/extensions/ui/1.0'};
  for (var k in options) 
  {
    this.requestParams['openid.ui.' + k] = options[k];
  }
};

openid.UserInterface.prototype.fillResult = function(params, result)
{
  // TODO: Fill results
}

/* 
 * Attribute Exchange Extension
 * http://openid.net/specs/openid-attribute-exchange-1_0.html 
 * Also see:
 *  - http://www.axschema.org/types/ 
 *  - http://code.google.com/intl/en-US/apis/accounts/docs/OpenID.html#Parameters
 */
// TODO: count handling

var attributeMapping = 
{
    'http://axschema.org/contact/country/home': 'country'
  , 'http://axschema.org/contact/email': 'email'
  , 'http://axschema.org/namePerson/first': 'firstname'
  , 'http://axschema.org/pref/language': 'language'
  , 'http://axschema.org/namePerson/last': 'lastname'
  // The following are not in the Google document:
  , 'http://axschema.org/namePerson/friendly': 'nickname'
  , 'http://axschema.org/namePerson': 'fullname'
};

openid.AttributeExchange = function AttributeExchange(options) 
{ 
  this.requestParams = {'openid.ns.ax': 'http://openid.net/srv/ax/1.0',
    'openid.ax.mode' : 'fetch_request'};
  var required = [];
  var optional = [];
  for (var ns in options)
  {
    if (!options.hasOwnProperty(ns)) { continue; }
    if (options[ns] == 'required')
    {
      required.push(ns);
    }
    else
    {
      optional.push(ns);
    }
  }
  var self = this;
  required = required.map(function(ns, i) 
  {
    var attr = attributeMapping[ns] || 'req' + i;
    self.requestParams['openid.ax.type.' + attr] = ns;
    return attr;
  });
  optional = optional.map(function(ns, i)
  {
    var attr = attributeMapping[ns] || 'opt' + i;
    self.requestParams['openid.ax.type.' + attr] = ns;
    return attr;
  });
  if (required.length)
  {
    this.requestParams['openid.ax.required'] = required.join(',');
  }
  if (optional.length)
  {
    this.requestParams['openid.ax.if_available'] = optional.join(',');
  }
}

openid.AttributeExchange.prototype.fillResult = function(params, result)
{
  var extension = _getExtensionAlias(params, 'http://openid.net/srv/ax/1.0') || 'ax';
  var regex = new RegExp('^openid\\.' + extension + '\\.(value|type)\\.(\\w+)$');
  var aliases = {};
  var values = {};
  for (var k in params)
  {
    if (!params.hasOwnProperty(k)) { continue; }
    var matches = k.match(regex);
    if (!matches)
    {
      continue;
    }
    if (matches[1] == 'type')
    {
      aliases[params[k]] = matches[2];
    }
    else
    {
      values[matches[2]] = params[k];
    }
  }
  for (var ns in aliases) 
  {
    if (aliases[ns] in values)
    {
      result[aliases[ns]] = values[aliases[ns]];
      result[ns] = values[aliases[ns]];
    }
  }
}

openid.OAuthHybrid = function(options)
{
  this.requestParams = {
    'openid.ns.oauth'       : 'http://specs.openid.net/extensions/oauth/1.0',
    'openid.oauth.consumer' : options['consumerKey'],
    'openid.oauth.scope'    : options['scope']};
}

openid.OAuthHybrid.prototype.fillResult = function(params, result)
{
  var extension = _getExtensionAlias(params, 'http://specs.openid.net/extensions/oauth/1.0') || 'oauth'
    , token_attr = 'openid.' + extension + '.request_token';
  
  
  if(params[token_attr] !== undefined)
  {
    result['request_token'] = params[token_attr];
  }
};

/* 
 * Provider Authentication Policy Extension (PAPE)
 * http://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html
 * 
 * Note that this extension does not validate that the provider is obeying the
 * authentication request, it only allows the request to be made.
 *
 * TODO: verify requested 'max_auth_age' against response 'auth_time'
 * TODO: verify requested 'auth_level.ns.<cust>' (etc) against response 'auth_level.ns.<cust>'
 * TODO: verify requested 'preferred_auth_policies' against response 'auth_policies'
 *
 */

/* Just the keys that aren't open to customisation */
var pape_request_keys = ['max_auth_age', 'preferred_auth_policies', 'preferred_auth_level_types' ];
var pape_response_keys = ['auth_policies', 'auth_time']

/* Some short-hand mappings for auth_policies */ 
var papePolicyNameMap = 
{
    'phishing-resistant': 'http://schemas.openid.net/pape/policies/2007/06/phishing-resistant',
    'multi-factor': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor',
    'multi-factor-physical': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical',
    'none' : 'http://schemas.openid.net/pape/policies/2007/06/none'
}
 
openid.PAPE = function PAPE(options) 
{
  this.requestParams = {'openid.ns.pape': 'http://specs.openid.net/extensions/pape/1.0'};
  for (var k in options) 
  {
    if (k === 'preferred_auth_policies') {
      this.requestParams['openid.pape.' + k] = _getLongPolicyName(options[k]);
    } else {
      this.requestParams['openid.pape.' + k] = options[k];
    }
  }
  var util = require('util');
};

/* you can express multiple pape 'preferred_auth_policies', so replace each
 * with the full policy URI as per papePolicyNameMapping. 
 */
var _getLongPolicyName = function(policyNames) {
  var policies = policyNames.split(' ');   
  for (var i=0; i<policies.length; i++) {
    if (policies[i] in papePolicyNameMap) {
      policies[i] = papePolicyNameMap[policies[i]];
    }
  }
  return policies.join(' ');
}

var _getShortPolicyName = function(policyNames) {
  var policies = policyNames.split(' ');   
  for (var i=0; i<policies.length; i++) {
    for (shortName in papePolicyNameMap) {
      if (papePolicyNameMap[shortName] === policies[i]) {
        policies[i] = shortName;
      }
    }
  }
  return policies.join(' ');
}

openid.PAPE.prototype.fillResult = function(params, result)
{
  var extension = _getExtensionAlias(params, 'http://specs.openid.net/extensions/pape/1.0') || 'pape';
  var paramString = 'openid.' + extension + '.';
  var thisParam;
  for (var p in params) {
    if (params.hasOwnProperty(p)) {
      if (p.substr(0, paramString.length) === paramString) {
        thisParam = p.substr(paramString.length);
        if (thisParam === 'auth_policies') {
          result[thisParam] = _getShortPolicyName(params[p]);
        } else {
          result[thisParam] = params[p];
        }
      }
    }
  } 
}

},{"./lib/convert":7,"./lib/xrds":8,"crypto":undefined,"http":undefined,"https":undefined,"querystring":undefined,"url":undefined,"util":undefined}],10:[function(require,module,exports){
/**
 * `FacebookAuthorizationError` error.
 *
 * FacebookAuthorizationError represents an error in response to an
 * authorization request on Facebook.  Note that these responses don't conform
 * to the OAuth 2.0 specification.
 *
 * References:
 *   - https://developers.facebook.com/docs/reference/api/errors/
 *
 * @constructor
 * @param {string} [message]
 * @param {number} [code]
 * @access public
 */
function FacebookAuthorizationError(message, code) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'FacebookAuthorizationError';
  this.message = message;
  this.code = code;
  this.status = 500;
}

// Inherit from `Error`.
FacebookAuthorizationError.prototype.__proto__ = Error.prototype;


// Expose constructor.
module.exports = FacebookAuthorizationError;

},{}],11:[function(require,module,exports){
/**
 * `FacebookGraphAPIError` error.
 *
 * References:
 *   - https://developers.facebook.com/docs/reference/api/errors/
 *
 * @constructor
 * @param {string} [message]
 * @param {string} [type]
 * @param {number} [code]
 * @param {number} [subcode]
 * @param {string} [traceID]
 * @access public
 */
function FacebookGraphAPIError(message, type, code, subcode, traceID) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'FacebookGraphAPIError';
  this.message = message;
  this.type = type;
  this.code = code;
  this.subcode = subcode;
  this.traceID = traceID;
  this.status = 500;
}

// Inherit from `Error`.
FacebookGraphAPIError.prototype.__proto__ = Error.prototype;


// Expose constructor.
module.exports = FacebookGraphAPIError;

},{}],12:[function(require,module,exports){
/**
 * `FacebookTokenError` error.
 *
 * FacebookTokenError represents an error received from a Facebook's token
 * endpoint.  Note that these responses don't conform to the OAuth 2.0
 * specification.
 *
 * References:
 *   - https://developers.facebook.com/docs/reference/api/errors/
 *
 * @constructor
 * @param {string} [message]
 * @param {string} [type]
 * @param {number} [code]
 * @param {number} [subcode]
 * @param {string} [traceID]
 * @access public
 */
function FacebookTokenError(message, type, code, subcode, traceID) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'FacebookTokenError';
  this.message = message;
  this.type = type;
  this.code = code;
  this.subcode = subcode;
  this.traceID = traceID;
  this.status = 500;
}

// Inherit from `Error`.
FacebookTokenError.prototype.__proto__ = Error.prototype;


// Expose constructor.
module.exports = FacebookTokenError;

},{}],13:[function(require,module,exports){
// Load modules.
var Strategy = require('./strategy');


// Expose Strategy.
exports = module.exports = Strategy;

// Exports.
exports.Strategy = Strategy;

},{"./strategy":15}],14:[function(require,module,exports){
/**
 * Parse profile.
 *
 * @param {object|string} json
 * @return {object}
 * @access public
 */
exports.parse = function(json) {
  if ('string' == typeof json) {
    json = JSON.parse(json);
  }
  
  var profile = {};
  profile.id = json.id;
  profile.username = json.username;
  profile.displayName = json.name;
  profile.name = { familyName: json.last_name,
                   givenName: json.first_name,
                   middleName: json.middle_name };

  profile.gender = json.gender;
  profile.profileUrl = json.link;
  
  if (json.email) {
    profile.emails = [{ value: json.email }];
  }
  
  if (json.picture) {
    if (typeof json.picture == 'object' && json.picture.data) {
      // October 2012 Breaking Changes
      profile.photos = [{ value: json.picture.data.url }];
    } else {
      profile.photos = [{ value: json.picture }];
    }
  }
  
  return profile;
};

},{}],15:[function(require,module,exports){
// Load modules.
var OAuth2Strategy = require('passport-oauth2')
  , util = require('util')
  , uri = require('url')
  , crypto = require('crypto')
  , Profile = require('./profile')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError
  , FacebookAuthorizationError = require('./errors/facebookauthorizationerror')
  , FacebookTokenError = require('./errors/facebooktokenerror')
  , FacebookGraphAPIError = require('./errors/facebookgraphapierror');


/**
 * `Strategy` constructor.
 *
 * The Facebook authentication strategy authenticates requests by delegating to
 * Facebook using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Facebook application's App ID
 *   - `clientSecret`  your Facebook application's App Secret
 *   - `callbackURL`   URL to which Facebook will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new FacebookStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/facebook/callback'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://www.facebook.com/dialog/oauth';
  options.tokenURL = options.tokenURL || 'https://graph.facebook.com/oauth/access_token';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'facebook';
  this._profileURL = options.profileURL || 'https://graph.facebook.com/v2.5/me';
  this._profileFields = options.profileFields || null;
  this._enableProof = options.enableProof;
  this._clientSecret = options.clientSecret;
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);


/**
 * Authenticate request by delegating to Facebook using OAuth 2.0.
 *
 * @param {http.IncomingMessage} req
 * @param {object} options
 * @access protected
 */
Strategy.prototype.authenticate = function(req, options) {
  // Facebook doesn't conform to the OAuth 2.0 specification, with respect to
  // redirecting with error codes.
  //
  //   FIX: https://github.com/jaredhanson/passport-oauth/issues/16
  if (req.query && req.query.error_code && !req.query.error) {
    return this.error(new FacebookAuthorizationError(req.query.error_message, parseInt(req.query.error_code, 10)));
  }

  OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

/**
 * Return extra Facebook-specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `display`  Display mode to render dialog, { `page`, `popup`, `touch` }.
 *
 * @param {object} options
 * @return {object}
 * @access protected
 */
Strategy.prototype.authorizationParams = function (options) {
  var params = {};

  // https://developers.facebook.com/docs/reference/dialogs/oauth/
  if (options.display) {
    params.display = options.display;
  }
  
  // https://developers.facebook.com/docs/facebook-login/reauthentication/
  if (options.authType) {
    params.auth_type = options.authType;
  }
  if (options.authNonce) {
    params.auth_nonce = options.authNonce;
  }

  return params;
};

/**
 * Retrieve user profile from Facebook.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `facebook`
 *   - `id`               the user's Facebook ID
 *   - `username`         the user's Facebook username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *   - `name.middleName`  the user's middle name
 *   - `gender`           the user's gender: `male` or `female`
 *   - `profileUrl`       the URL of the profile for the user on Facebook
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var url = uri.parse(this._profileURL);
  if (this._enableProof) {
    // Secure API call by adding proof of the app secret.  This is required when
    // the "Require AppSecret Proof for Server API calls" setting has been
    // enabled.  The proof is a SHA256 hash of the access token, using the app
    // secret as the key.
    //
    // For further details, refer to:
    // https://developers.facebook.com/docs/reference/api/securing-graph-api/    
    var proof = crypto.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
    url.search = (url.search ? url.search + '&' : '') + 'appsecret_proof=' + proof;
  }
  if (this._profileFields) {
    var fields = this._convertProfileFields(this._profileFields);
    if (fields !== '') { url.search = (url.search ? url.search + '&' : '') + 'fields=' + fields; }
  }
  url = uri.format(url);

  this._oauth2.get(url, accessToken, function (err, body, res) {
    var json;
    
    if (err) {
      if (err.data) {
        try {
          json = JSON.parse(err.data);
        } catch (_) {}
      }
      
      if (json && json.error && typeof json.error == 'object') {
        return done(new FacebookGraphAPIError(json.error.message, json.error.type, json.error.code, json.error.error_subcode, json.error.fbtrace_id));
      }
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    
    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }

    var profile = Profile.parse(json);
    profile.provider = 'facebook';
    profile._raw = body;
    profile._json = json;

    done(null, profile);
  });
};

/**
 * Parse error response from Facebook OAuth 2.0 token endpoint.
 *
 * @param {string} body
 * @param {number} status
 * @return {Error}
 * @access protected
 */
Strategy.prototype.parseErrorResponse = function(body, status) {
  var json = JSON.parse(body);
  if (json.error && typeof json.error == 'object') {
    return new FacebookTokenError(json.error.message, json.error.type, json.error.code, json.error.error_subcode, json.error.fbtrace_id);
  }
  return OAuth2Strategy.prototype.parseErrorResponse.call(this, body, status);
};

/**
 * Convert Facebook profile to a normalized profile.
 *
 * @param {object} profileFields
 * @return {string}
 * @access protected
 */
Strategy.prototype._convertProfileFields = function(profileFields) {
  var map = {
    'id':          'id',
    'username':    'username',
    'displayName': 'name',
    'name':       ['last_name', 'first_name', 'middle_name'],
    'gender':      'gender',
    'birthday':    'birthday',
    'profileUrl':  'link',
    'emails':      'email',
    'photos':      'picture'
  };
  
  var fields = [];
  
  profileFields.forEach(function(f) {
    // return raw Facebook profile field to support the many fields that don't
    // map cleanly to Portable Contacts
    if (typeof map[f] === 'undefined') { return fields.push(f); };

    if (Array.isArray(map[f])) {
      Array.prototype.push.apply(fields, map[f]);
    } else {
      fields.push(map[f]);
    }
  });

  return fields.join(',');
};


// Expose constructor.
module.exports = Strategy;

},{"./errors/facebookauthorizationerror":10,"./errors/facebookgraphapierror":11,"./errors/facebooktokenerror":12,"./profile":14,"crypto":undefined,"passport-oauth2":30,"url":undefined,"util":undefined}],16:[function(require,module,exports){
/**
 * `APIError` error.
 *
 * References:
 *   - https://developer.github.com/v3/#client-errors
 *
 * @constructor
 * @param {string} [message]
 * @param {number} [code]
 * @access public
 */
function APIError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'APIError';
  this.message = message;
  this.status = 500;
}

// Inherit from `Error`.
APIError.prototype.__proto__ = Error.prototype;


// Expose constructor.
module.exports = APIError;

},{}],17:[function(require,module,exports){
arguments[4][13][0].apply(exports,arguments)
},{"./strategy":19,"dup":13}],18:[function(require,module,exports){
/**
 * Parse profile.
 *
 * @param {object|string} json
 * @return {object}
 * @access public
 */
exports.parse = function(json) {
  if ('string' == typeof json) {
    json = JSON.parse(json);
  }

  var profile = {};
  profile.id = String(json.id);
  profile.displayName = json.name;
  profile.username = json.login;
  profile.profileUrl = json.html_url;
  if (json.email) {
    profile.emails = [{ value: json.email }];
  }
  if (json.avatar_url) {
    profile.photos = [{ value: json.avatar_url }];
  }

  return profile;
};

},{}],19:[function(require,module,exports){
// Load modules.
var OAuth2Strategy = require('passport-oauth2')
  , util = require('util')
  , Profile = require('./profile')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError
  , APIError = require('./errors/apierror');


/**
 * `Strategy` constructor.
 *
 * The GitHub authentication strategy authenticates requests by delegating to
 * GitHub using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your GitHub application's Client ID
 *   - `clientSecret`  your GitHub application's Client Secret
 *   - `callbackURL`   URL to which GitHub will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'user', 'public_repo', 'repo', 'gist', or none.
 *                     (see http://developer.github.com/v3/oauth/#scopes for more info)
 *   — `userAgent`     All API requests MUST include a valid User Agent string.
 *                     e.g: domain name of your application.
 *                     (see http://developer.github.com/v3/#user-agent-required for more info)
 *
 * Examples:
 *
 *     passport.use(new GitHubStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/github/callback',
 *         userAgent: 'myapp.com'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://github.com/login/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://github.com/login/oauth/access_token';
  options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-github';
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'github';
  this._userProfileURL = options.userProfileURL || 'https://api.github.com/user';
  this._oauth2.useAuthorizationHeaderforGET(true);
  
  // NOTE: GitHub returns an HTTP 200 OK on error responses.  As a result, the
  //       underlying `oauth` implementation understandably does not parse the
  //       response as an error.  This code swizzles the implementation to
  //       handle this condition.
  var self = this;
  var _oauth2_getOAuthAccessToken = this._oauth2.getOAuthAccessToken;
  this._oauth2.getOAuthAccessToken = function(code, params, callback) {
    _oauth2_getOAuthAccessToken.call(self._oauth2, code, params, function(err, accessToken, refreshToken, params) {
      if (err) { return callback(err); }
      if (!accessToken) {
        return callback({
          statusCode: 400,
          data: JSON.stringify(params)
        });
      }
      callback(null, accessToken, refreshToken, params);
    });
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from GitHub.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `github`
 *   - `id`               the user's GitHub ID
 *   - `username`         the user's GitHub username
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on GitHub
 *   - `emails`           the user's email addresses
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var self = this;
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    var json;
    
    if (err) {
      if (err.data) {
        try {
          json = JSON.parse(err.data);
        } catch (_) {}
      }
      
      if (json && json.message) {
        return done(new APIError(json.message));
      }
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    
    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }
    
    var profile = Profile.parse(json);
    profile.provider  = 'github';
    profile._raw = body;
    profile._json = json;


    if (self._scope && self._scope.indexOf('user:email') !== -1) {
      self._oauth2._request('GET', self._userProfileURL + '/emails', { 'Accept': 'application/vnd.github.v3+json' }, '', accessToken, function(err, body, res) {
        if (err) {
          // If the attempt to fetch email addresses fails, return the profile
          // information that was obtained.
          return done(null, profile);
        }
        
        var json;
        try {
          json = JSON.parse(body);
        } catch (_) {
          // If the attempt to parse email addresses fails, return the profile
          // information that was obtained.
          return done(null, profile);
        }
        
        
        if (!json.length) {
          return done(null, profile);
        }
        
        profile.emails = profile.emails || [];
        var publicEmail = profile.emails[0];
        
        (json).forEach(function(email) {
          if (publicEmail && publicEmail.value == email.email) {
            profile.emails[0].primary = email.primary;
            profile.emails[0].verified = email.verified;
          } else {
            profile.emails.push({ value: email.email, primary: email.primary, verified: email.verified })
          }
        });
        done(null, profile);
      });
    }
    else {
      done(null, profile);
    }
  });
}


// Expose constructor.
module.exports = Strategy;

},{"./errors/apierror":16,"./profile":18,"passport-oauth2":30,"util":undefined}],20:[function(require,module,exports){
/**
 * Module dependencies.
 */
var Strategy = require('./strategy');


/**
 * Framework version.
 */
// removed pkginfo ...')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;

},{"./strategy":21,"pkginfo":62}],21:[function(require,module,exports){
/**
 * Module dependencies.
 */
var util = require('util')
  , OpenIDStrategy = require('passport-openid').Strategy;


/**
 * `Strategy` constructor.
 *
 * The Google authentication strategy authenticates requests by delegating to
 * Google using the OpenID 2.0 protocol.
 *
 * Applications must supply a `validate` callback which accepts an `identifier`,
 * and optionally a service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `returnURL`  URL to which Google will redirect the user after authentication
 *   - `realm`      the part of URL-space for which an OpenID authentication request is valid
 *   - `profile`    enable profile exchange, defaults to _true_
 *
 * Examples:
 *
 *     passport.use(new GoogleStrategy({
 *         returnURL: 'http://localhost:3000/auth/google/return',
 *         realm: 'http://localhost:3000/'
 *       },
 *       function(identifier, profile, done) {
 *         User.findByOpenID(identifier, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, validate) {
  options = options || {};
  options.providerURL = options.providerURL || 'https://www.google.com/accounts/o8/id';
  options.profile =  (options.profile === undefined) ? true : options.profile;

  OpenIDStrategy.call(this, options, validate);
  this.name = 'google';
}

/**
 * Inherit from `OpenIDStrategy`.
 */
util.inherits(Strategy, OpenIDStrategy);


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;

},{"passport-openid":37,"util":undefined}],22:[function(require,module,exports){
/**
 * `InternalOAuthError` error.
 *
 * InternalOAuthError wraps errors generated by node-oauth.  By wrapping these
 * objects, error messages can be formatted in a manner that aids in debugging
 * OAuth issues.
 *
 * @constructor
 * @param {String} [message]
 * @param {Object|Error} [err]
 * @api public
 */
function InternalOAuthError(message, err) {
  Error.call(this);
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
  this.oauthError = err;
}

// Inherit from `Error`.
InternalOAuthError.prototype.__proto__ = Error.prototype;

/**
 * Returns a string representing the error.
 *
 * @return {String}
 * @api public
 */
InternalOAuthError.prototype.toString = function() {
  var m = this.name;
  if (this.message) { m += ': ' + this.message; }
  if (this.oauthError) {
    if (this.oauthError instanceof Error) {
      m = this.oauthError.toString();
    } else if (this.oauthError.statusCode && this.oauthError.data) {
      m += ' (status: ' + this.oauthError.statusCode + ' data: ' + this.oauthError.data + ')';
    }
  }
  return m;
};


// Expose constructor.
module.exports = InternalOAuthError;

},{}],23:[function(require,module,exports){
// Load modules.
var Strategy = require('./strategy')
  , InternalOAuthError = require('./errors/internaloautherror');


// Expose Strategy.
exports = module.exports = Strategy;

// Exports.
exports.Strategy = Strategy;
exports.InternalOAuthError = InternalOAuthError;

},{"./errors/internaloautherror":22,"./strategy":25}],24:[function(require,module,exports){
function SessionStore(options) {
  if (!options.key) { throw new TypeError('Session-based request token store requires a session key'); }
  this._key = options.key;
}

SessionStore.prototype.get = function(req, token, cb) {
  if (!req.session) { return cb(new Error('OAuth authentication requires session support. Did you forget to use express-session middleware?')); }
  
  // Bail if the session does not contain the request token and corresponding
  // secret.  If this happens, it is most likely caused by initiating OAuth
  // from a different host than that of the callback endpoint (for example:
  // initiating from 127.0.0.1 but handling callbacks at localhost).
  if (!req.session[this._key]) { return cb(new Error('Failed to find request token in session')); }
  
  var tokenSecret = req.session[this._key].oauth_token_secret;
  return cb(null, tokenSecret);
};

SessionStore.prototype.set = function(req, token, tokenSecret, cb) {
  if (!req.session) { return cb(new Error('OAuth authentication requires session support. Did you forget to use express-session middleware?')); }
  
  if (!req.session[this._key]) { req.session[this._key] = {}; }
  req.session[this._key].oauth_token = token;
  req.session[this._key].oauth_token_secret = tokenSecret;
  cb();
};

SessionStore.prototype.destroy = function(req, token, cb) {
  delete req.session[this._key].oauth_token;
  delete req.session[this._key].oauth_token_secret;
  if (Object.keys(req.session[this._key]).length === 0) {
    delete req.session[this._key];
  }
  cb();
};


module.exports = SessionStore;

},{}],25:[function(require,module,exports){
// Load modules.
var passport = require('passport-strategy')
  , url = require('url')
  , util = require('util')
  , utils = require('./utils')
  , OAuth = require('oauth').OAuth
  , SessionRequestTokenStore = require('./requesttoken/session')
  , InternalOAuthError = require('./errors/internaloautherror');


/**
 * Creates an instance of `OAuthStrategy`.
 *
 * The OAuth authentication strategy authenticates requests using the OAuth
 * protocol.
 *
 * OAuth provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Twitter.  Delegating in this
 * manner involves a sequence of events, including redirecting the user to the
 * third-party service for authorization.  Once authorization has been obtained,
 * the user is redirected back to the application and a token can be used to
 * obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(token, tokenSecret, profile, cb) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `cb` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `requestTokenURL`       URL used to obtain an unauthorized request token
 *   - `accessTokenURL`        URL used to exchange a user-authorized request token for an access token
 *   - `userAuthorizationURL`  URL used to obtain user authorization
 *   - `consumerKey`           identifies client to service provider
 *   - `consumerSecret`        secret used to establish ownership of the consumer key
 *   - 'signatureMethod'       signature method used to sign the request (default: 'HMAC-SHA1')
 *   - `callbackURL`           URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback`     when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new OAuthStrategy({
 *         requestTokenURL: 'https://www.example.com/oauth/request_token',
 *         accessTokenURL: 'https://www.example.com/oauth/access_token',
 *         userAuthorizationURL: 'https://www.example.com/oauth/authorize',
 *         consumerKey: '123-456-789',
 *         consumerSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(token, tokenSecret, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function OAuthStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};
  
  if (!verify) { throw new TypeError('OAuthStrategy requires a verify callback'); }
  if (!options.requestTokenURL) { throw new TypeError('OAuthStrategy requires a requestTokenURL option'); }
  if (!options.accessTokenURL) { throw new TypeError('OAuthStrategy requires a accessTokenURL option'); }
  if (!options.userAuthorizationURL) { throw new TypeError('OAuthStrategy requires a userAuthorizationURL option'); }
  if (!options.consumerKey) { throw new TypeError('OAuthStrategy requires a consumerKey option'); }
  if (options.consumerSecret === undefined) { throw new TypeError('OAuthStrategy requires a consumerSecret option'); }
  
  passport.Strategy.call(this);
  this.name = 'oauth';
  this._verify = verify;
  
  // NOTE: The _oauth property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth = new OAuth(options.requestTokenURL, options.accessTokenURL,
                          options.consumerKey,  options.consumerSecret,
                          '1.0', null, options.signatureMethod || 'HMAC-SHA1',
                          null, options.customHeaders);
  
  this._userAuthorizationURL = options.userAuthorizationURL;
  this._callbackURL = options.callbackURL;
  this._key = options.sessionKey || 'oauth';
  this._requestTokenStore = options.requestTokenStore || new SessionRequestTokenStore({ key: this._key });
  this._trustProxy = options.proxy;
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

// Inherit from `passport.Strategy`.
util.inherits(OAuthStrategy, passport.Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth.
 *
 * @param {Object} req
 * @api protected
 */
OAuthStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  
  var self = this;
  var meta = {
    requestTokenURL: this._oauth._requestUrl,
    accessTokenURL: this._oauth._accessUrl,
    userAuthorizationURL:  this._userAuthorizationURL,
    consumerKey: this._oauth._consumerKey
  }
  
  if (req.query && req.query.oauth_token) {
    // The request being authenticated contains an oauth_token parameter in the
    // query portion of the URL.  This indicates that the service provider has
    // redirected the user back to the application, after authenticating the
    // user and obtaining their authorization.
    //
    // The value of the oauth_token parameter is the request token.  Together
    // with knowledge of the token secret (stored in the session), the request
    // token can be exchanged for an access token and token secret.
    //
    // This access token and token secret, along with the optional ability to
    // fetch profile information from the service provider, is sufficient to
    // establish the identity of the user.
    var oauthToken = req.query.oauth_token;
    
    function loaded(err, oauthTokenSecret, state) {
      if (err) { return self.error(err); }
      if (!oauthTokenSecret) {
        return self.fail(state, 403);
      }
    
      // NOTE: The oauth_verifier parameter will be supplied in the query portion
      //       of the redirect URL, if the server supports OAuth 1.0a.
      var oauthVerifier = req.query.oauth_verifier || null;
    
      self._oauth.getOAuthAccessToken(oauthToken, oauthTokenSecret, oauthVerifier, function(err, token, tokenSecret, params) {
        if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
      
        function destroyed(err) {
          if (err) { return self.error(err); }
      
          self._loadUserProfile(token, tokenSecret, params, function(err, profile) {
            if (err) { return self.error(err); }
        
            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }
              
              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }
        
            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, token, tokenSecret, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, token, tokenSecret, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(token, tokenSecret, params, profile, verified);
                } else { // arity == 4
                  self._verify(token, tokenSecret, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          });
        }
      
        // The request token has been exchanged for an access token.  Since the
        // request token is a single-use token, that data can be removed from the
        // store.
        try {
          var arity = self._requestTokenStore.destroy.length;
          if (arity == 4) {
            self._requestTokenStore.destroy(req, oauthToken, meta, destroyed);
          } else { // arity == 3
            self._requestTokenStore.destroy(req, oauthToken, destroyed);
          }
        } catch (ex) {
          return self.error(ex);
        }
      });
    }
    
    try {
      var arity = self._requestTokenStore.get.length;
      if (arity == 4) {
        this._requestTokenStore.get(req, oauthToken, meta, loaded);
      } else { // arity == 3
        this._requestTokenStore.get(req, oauthToken, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    // In order to authenticate via OAuth, the application must obtain a request
    // token from the service provider and redirect the user to the service
    // provider to obtain their authorization.  After authorization has been
    // approved the user will be redirected back the application, at which point
    // the application can exchange the request token for an access token.
    //
    // In order to successfully exchange the request token, its corresponding
    // token secret needs to be known.  The token secret will be temporarily
    // stored in the session, so that it can be retrieved upon the user being
    // redirected back to the application.
    
    var params = this.requestTokenParams(options);
    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      var parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
      }
    }
    params.oauth_callback = callbackURL;
    
    this._oauth.getOAuthRequestToken(params, function(err, token, tokenSecret, params) {
      if (err) { return self.error(self._createOAuthError('Failed to obtain request token', err)); }
      
      // NOTE: params will contain an oauth_callback_confirmed property set to
      //       true, if the server supports OAuth 1.0a.
      //       { oauth_callback_confirmed: 'true' }

      function stored(err) {
        if (err) { return self.error(err); }

        var parsed = url.parse(self._userAuthorizationURL, true);
        parsed.query.oauth_token = token;
        if (!params.oauth_callback_confirmed && callbackURL) {
          // NOTE: If oauth_callback_confirmed=true is not present when issuing a
          //       request token, the server does not support OAuth 1.0a.  In this
          //       circumstance, `oauth_callback` is passed when redirecting the
          //       user to the service provider.
          parsed.query.oauth_callback = callbackURL;
        }
        utils.merge(parsed.query, self.userAuthorizationParams(options));
        delete parsed.search;
        var location = url.format(parsed);
        self.redirect(location);
      }

      try {
        var arity = self._requestTokenStore.set.length;
        if (arity == 5) {
          self._requestTokenStore.set(req, token, tokenSecret, meta, stored);
        } else { // arity == 4
          self._requestTokenStore.set(req, token, tokenSecret, stored);
        }
      } catch (ex) {
        return self.error(ex);
      }
    });
  }
};

/**
 * Retrieve user profile from service provider.
 *
 * OAuth-based authentication strategies can overrride this function in order to
 * load the user's profile from the service provider.  This assists applications
 * (and users of those applications) in the initial registration process by
 * automatically submitting required information.
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
OAuthStrategy.prototype.userProfile = function(token, tokenSecret, params, done) {
  return done(null, {});
};

/**
 * Return extra parameters to be included in the request token request.
 *
 * Some OAuth providers require additional parameters to be included when
 * issuing a request token.  Since these parameters are not standardized by the
 * OAuth specification, OAuth-based authentication strategies can overrride this
 * function in order to populate these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
OAuthStrategy.prototype.requestTokenParams = function(options) {
  return {};
};

/**
 * Return extra parameters to be included in the user authorization request.
 *
 * Some OAuth providers allow additional, non-standard parameters to be included
 * when requesting authorization.  Since these parameters are not standardized
 * by the OAuth specification, OAuth-based authentication strategies can
 * overrride this function in order to populate these parameters as required by
 * the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
OAuthStrategy.prototype.userAuthorizationParams = function(options) {
  return {};
};

/**
 * Parse error response from OAuth endpoint.
 *
 * OAuth-based authentication strategies can overrride this function in order to
 * parse error responses received from the request token and access token
 * endpoints, allowing the most informative message to be displayed.
 *
 * If this function is not overridden, a generic error will be thrown.
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
OAuthStrategy.prototype.parseErrorResponse = function(body, status) {
  return null;
};

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
OAuthStrategy.prototype._loadUserProfile = function(token, tokenSecret, params, done) {
  var self = this;
  
  function loadIt() {
    return self.userProfile(token, tokenSecret, params, done);
  }
  function skipIt() {
    return done(null);
  }
  
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(token, tokenSecret, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
};

/**
 * Create an OAuth error.
 *
 * @param {String} message
 * @param {Object|Error} err
 * @api private
 */
OAuthStrategy.prototype._createOAuthError = function(message, err) {
  var e;
  if (err.statusCode && err.data) {
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    } catch (_) {}
  }
  if (!e) { e = new InternalOAuthError(message, err); }
  return e;
};


// Expose constructor.
module.exports = OAuthStrategy;

},{"./errors/internaloautherror":22,"./requesttoken/session":24,"./utils":26,"oauth":1,"passport-strategy":47,"url":undefined,"util":undefined}],26:[function(require,module,exports){
exports.merge = require('utils-merge');

/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy, assuming that the proxy has been flagged as trusted.
 *
 * @param {http.IncomingMessage} req
 * @param {Object} [options]
 * @return {String}
 * @api private
 */
exports.originalURL = function(req, options) {
  options = options || {};
  var app = req.app;
  if (app && app.get && app.get('trust proxy')) {
    options.proxy = true;
  }
  var trustProxy = options.proxy;
  
  var proto = (req.headers['x-forwarded-proto'] || '').toLowerCase()
    , tls = req.connection.encrypted || (trustProxy && 'https' == proto.split(/\s*,\s*/)[0])
    , host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host
    , protocol = tls ? 'https' : 'http'
    , path = req.url || '';
  return protocol + '://' + host + path;
};

},{"utils-merge":64}],27:[function(require,module,exports){
/**
 * `AuthorizationError` error.
 *
 * AuthorizationError represents an error in response to an authorization
 * request.  For details, refer to RFC 6749, section 4.1.2.1.
 *
 * References:
 *   - [The OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/rfc6749)
 *
 * @constructor
 * @param {String} [message]
 * @param {String} [code]
 * @param {String} [uri]
 * @param {Number} [status]
 * @api public
 */
function AuthorizationError(message, code, uri, status) {
  if (!status) {
    switch (code) {
      case 'access_denied': status = 403; break;
      case 'server_error': status = 502; break;
      case 'temporarily_unavailable': status = 503; break;
    }
  }

  Error.call(this);
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
  this.code = code || 'server_error';
  this.uri = uri;
  this.status = status || 500;
}

/**
 * Inherit from `Error`.
 */
AuthorizationError.prototype.__proto__ = Error.prototype;


/**
 * Expose `AuthorizationError`.
 */
module.exports = AuthorizationError;

},{}],28:[function(require,module,exports){
/**
 * `InternalOAuthError` error.
 *
 * InternalOAuthError wraps errors generated by node-oauth.  By wrapping these
 * objects, error messages can be formatted in a manner that aids in debugging
 * OAuth issues.
 *
 * @constructor
 * @param {String} [message]
 * @param {Object|Error} [err]
 * @api public
 */
function InternalOAuthError(message, err) {
  Error.call(this);
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
  this.oauthError = err;
}

/**
 * Inherit from `Error`.
 */
InternalOAuthError.prototype.__proto__ = Error.prototype;

/**
 * Returns a string representing the error.
 *
 * @return {String}
 * @api public
 */
InternalOAuthError.prototype.toString = function() {
  var m = this.name;
  if (this.message) { m += ': ' + this.message; }
  if (this.oauthError) {
    if (this.oauthError instanceof Error) {
      m = this.oauthError.toString();
    } else if (this.oauthError.statusCode && this.oauthError.data) {
      m += ' (status: ' + this.oauthError.statusCode + ' data: ' + this.oauthError.data + ')';
    }
  }
  return m;
};


/**
 * Expose `InternalOAuthError`.
 */
module.exports = InternalOAuthError;

},{}],29:[function(require,module,exports){
/**
 * `TokenError` error.
 *
 * TokenError represents an error received from a token endpoint.  For details,
 * refer to RFC 6749, section 5.2.
 *
 * References:
 *   - [The OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/rfc6749)
 *
 * @constructor
 * @param {String} [message]
 * @param {String} [code]
 * @param {String} [uri]
 * @param {Number} [status]
 * @api public
 */
function TokenError(message, code, uri, status) {
  Error.call(this);
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
  this.code = code || 'invalid_request';
  this.uri = uri;
  this.status = status || 500;
}

/**
 * Inherit from `Error`.
 */
TokenError.prototype.__proto__ = Error.prototype;


/**
 * Expose `TokenError`.
 */
module.exports = TokenError;

},{}],30:[function(require,module,exports){
// Load modules.
var Strategy = require('./strategy')
  , AuthorizationError = require('./errors/authorizationerror')
  , TokenError = require('./errors/tokenerror')
  , InternalOAuthError = require('./errors/internaloautherror');


// Expose Strategy.
exports = module.exports = Strategy;

// Exports.
exports.Strategy = Strategy;

exports.AuthorizationError = AuthorizationError;
exports.TokenError = TokenError;
exports.InternalOAuthError = InternalOAuthError;

},{"./errors/authorizationerror":27,"./errors/internaloautherror":28,"./errors/tokenerror":29,"./strategy":33}],31:[function(require,module,exports){
function NullStore(options) {
}

NullStore.prototype.store = function(req, cb) {
  cb();
}

NullStore.prototype.verify = function(req, providedState, cb) {
  cb(null, true);
}


module.exports = NullStore;

},{}],32:[function(require,module,exports){
var uid = require('uid2');

/**
 * Creates an instance of `SessionStore`.
 *
 * This is the state store implementation for the OAuth2Strategy used when
 * the `state` option is enabled.  It generates a random state and stores it in
 * `req.session` and verifies it when the service provider redirects the user
 * back to the application.
 *
 * This state store requires session support.  If no session exists, an error
 * will be thrown.
 *
 * Options:
 *
 *   - `key`  The key in the session under which to store the state
 *
 * @constructor
 * @param {Object} options
 * @api public
 */
function SessionStore(options) {
  if (!options.key) { throw new TypeError('Session-based state store requires a session key'); }
  this._key = options.key;
}

/**
 * Store request state.
 *
 * This implementation simply generates a random string and stores the value in
 * the session, where it will be used for verification when the user is
 * redirected back to the application.
 *
 * @param {Object} req
 * @param {Function} callback
 * @api protected
 */
SessionStore.prototype.store = function(req, callback) {
  if (!req.session) { return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); }

  var key = this._key;
  var state = uid(24);
  if (!req.session[key]) { req.session[key] = {}; }
  req.session[key].state = state;
  callback(null, state);
};

/**
 * Verify request state.
 *
 * This implementation simply compares the state parameter in the request to the
 * value generated earlier and stored in the session.
 *
 * @param {Object} req
 * @param {String} providedState
 * @param {Function} callback
 * @api protected
 */
SessionStore.prototype.verify = function(req, providedState, callback) {
  if (!req.session) { return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); }

  var key = this._key;
  if (!req.session[key]) {
   return callback(null, false, { message: 'Unable to verify authorization request state.' });
  }

  var state = req.session[key].state;
  if (!state) {
   return callback(null, false, { message: 'Unable to verify authorization request state.' });
  }

  delete req.session[key].state;
  if (Object.keys(req.session[key]).length === 0) {
   delete req.session[key];
  }

  if (state !== providedState) {
   return callback(null, false, { message: 'Invalid authorization request state.' });
  }

  return callback(null, true);
};

// Expose constructor.
module.exports = SessionStore;

},{"uid2":63}],33:[function(require,module,exports){
// Load modules.
var passport = require('passport-strategy')
  , url = require('url')
  , util = require('util')
  , utils = require('./utils')
  , OAuth2 = require('oauth').OAuth2
  , NullStateStore = require('./state/null')
  , SessionStateStore = require('./state/session')
  , AuthorizationError = require('./errors/authorizationerror')
  , TokenError = require('./errors/tokenerror')
  , InternalOAuthError = require('./errors/internaloautherror');


/**
 * Creates an instance of `OAuth2Strategy`.
 *
 * The OAuth 2.0 authentication strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new OAuth2Strategy({
 *         authorizationURL: 'https://www.example.com/oauth2/authorize',
 *         tokenURL: 'https://www.example.com/oauth2/token',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function OAuth2Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) { throw new TypeError('OAuth2Strategy requires a verify callback'); }
  if (!options.authorizationURL) { throw new TypeError('OAuth2Strategy requires a authorizationURL option'); }
  if (!options.tokenURL) { throw new TypeError('OAuth2Strategy requires a tokenURL option'); }
  if (!options.clientID) { throw new TypeError('OAuth2Strategy requires a clientID option'); }

  passport.Strategy.call(this);
  this.name = 'oauth2';
  this._verify = verify;

  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth2 = new OAuth2(options.clientID,  options.clientSecret,
      '', options.authorizationURL, options.tokenURL, options.customHeaders);

  this._callbackURL = options.callbackURL;
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._key = options.sessionKey || ('oauth2:' + url.parse(options.authorizationURL).hostname);

  if (options.store) {
    this._stateStore = options.store;
  } else {
    if (options.state) {
      this._stateStore = new SessionStateStore({ key: this._key });
    } else {
      this._stateStore = new NullStateStore();
    }
  }
  this._trustProxy = options.proxy;
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

// Inherit from `passport.Strategy`.
util.inherits(OAuth2Strategy, passport.Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
OAuth2Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }
  
  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId
  }

  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }
  
      var code = req.query.code;

      var params = self.tokenParams(options);
      params.grant_type = 'authorization_code';
      if (callbackURL) { params.redirect_uri = callbackURL; }

      self._oauth2.getOAuthAccessToken(code, params,
        function(err, accessToken, refreshToken, params) {
          if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

          self._loadUserProfile(accessToken, function(err, profile) {
            if (err) { return self.error(err); }

            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }
              
              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }

            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          });
        }
      );
    }
    
    var state = req.query.state;
    try {
      var arity = this._stateStore.verify.length;
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }

    var state = options.state;
    if (state) {
      params.state = state;
      
      var parsed = url.parse(this._oauth2._authorizeUrl, true);
      utils.merge(parsed.query, params);
      parsed.query['client_id'] = this._oauth2._clientId;
      delete parsed.search;
      var location = url.format(parsed);
      this.redirect(location);
    } else {
      function stored(err, state) {
        if (err) { return self.error(err); }

        if (state) { params.state = state; }
        var parsed = url.parse(self._oauth2._authorizeUrl, true);
        utils.merge(parsed.query, params);
        parsed.query['client_id'] = self._oauth2._clientId;
        delete parsed.search;
        var location = url.format(parsed);
        self.redirect(location);
      }
      
      try {
        var arity = this._stateStore.store.length;
        if (arity == 3) {
          this._stateStore.store(req, meta, stored);
        } else { // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};

/**
 * Retrieve user profile from service provider.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to load the user's profile from the service provider.  This assists
 * applications (and users of those applications) in the initial registration
 * process by automatically submitting required information.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
OAuth2Strategy.prototype.userProfile = function(accessToken, done) {
  return done(null, {});
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
OAuth2Strategy.prototype.authorizationParams = function(options) {
  return {};
};

/**
 * Return extra parameters to be included in the token request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting an access token.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @return {Object}
 * @api protected
 */
OAuth2Strategy.prototype.tokenParams = function(options) {
  return {};
};

/**
 * Parse error response from OAuth 2.0 endpoint.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to parse error responses received from the token endpoint, allowing the
 * most informative message to be displayed.
 *
 * If this function is not overridden, the body will be parsed in accordance
 * with RFC 6749, section 5.2.
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
OAuth2Strategy.prototype.parseErrorResponse = function(body, status) {
  var json = JSON.parse(body);
  if (json.error) {
    return new TokenError(json.error_description, json.error, json.error_uri);
  }
  return null;
};

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
OAuth2Strategy.prototype._loadUserProfile = function(accessToken, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, done);
  }
  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
};

/**
 * Create an OAuth error.
 *
 * @param {String} message
 * @param {Object|Error} err
 * @api private
 */
OAuth2Strategy.prototype._createOAuthError = function(message, err) {
  var e;
  if (err.statusCode && err.data) {
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    } catch (_) {}
  }
  if (!e) { e = new InternalOAuthError(message, err); }
  return e;
};


// Expose constructor.
module.exports = OAuth2Strategy;

},{"./errors/authorizationerror":27,"./errors/internaloautherror":28,"./errors/tokenerror":29,"./state/null":31,"./state/session":32,"./utils":34,"oauth":1,"passport-strategy":47,"url":undefined,"util":undefined}],34:[function(require,module,exports){
arguments[4][26][0].apply(exports,arguments)
},{"dup":26,"utils-merge":64}],35:[function(require,module,exports){
/**
 * `BadRequestError` error.
 *
 * @api public
 */
function BadRequestError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'BadRequestError';
  this.message = message || null;
};

/**
 * Inherit from `Error`.
 */
BadRequestError.prototype.__proto__ = Error.prototype;


/**
 * Expose `BadRequestError`.
 */
module.exports = BadRequestError;

},{}],36:[function(require,module,exports){
/**
 * `InternalOpenIDError` error.
 *
 * InternalOpenIDError wraps errors generated by node-openid.  By wrapping these
 * objects, error messages can be formatted in a manner that aids in debugging
 * OpenID issues.
 *
 * @api public
 */
function InternalOpenIDError(message, err) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'InternalOpenIDError';
  this.message = message;
  this.openidError = err;
};

/**
 * Inherit from `Error`.
 */
InternalOpenIDError.prototype.__proto__ = Error.prototype;

/**
 * Returns a string representing the error.
 *
 * @return {String}
 * @api public
 */
InternalOpenIDError.prototype.toString = function() {
  var m = this.message;
  if (this.openidError) {
    if (this.openidError instanceof Error) {
      m += ' (' + this.openidError + ')';
    }
    else if (this.openidError.message) {
      m += ' (message: ' + this.openidError.message + ')';
    }
  }
  return m;
}


/**
 * Expose `InternalOpenIDError`.
 */
module.exports = InternalOpenIDError;

},{}],37:[function(require,module,exports){
/**
 * Module dependencies.
 */
var openid = require('openid')
  , Strategy = require('./strategy')
  , BadRequestError = require('./errors/badrequesterror')
  , InternalOpenIDError = require('./errors/internalopeniderror');


/**
 * Framework version.
 */
// removed pkginfo ...')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;

exports.BadRequestError = BadRequestError;
exports.InternalOpenIDError = InternalOpenIDError;


/**
 * Register a discovery function.
 *
 * Under most circumstances, registering a discovery function is not necessary,
 * due to the fact that the OpenID specification standardizes a discovery
 * procedure.
 *
 * When authenticating against a set of pre-approved OpenID providers, assisting
 * the discovery process with this information is an optimization that avoids
 * network requests for well-known endpoints.  It is also useful in
 * circumstances where work-arounds need to be put in place to address issues
 * with buggy OpenID providers or the underlying openid module.
 *
 * Discovery functions accept an `identifier` and `done` callback, which should
 * be invoked with a `provider` object containing `version` and `endpoint`
 * properties (or an `err` if an exception occurred).
 *
 * Example:
 *
 *     openid.discover(function(identifier, done) {
 *       if (identifier.indexOf('https://openid.example.com/id/') == 0) {
 *         var provider = {};
 *         provider.version = 'http://specs.openid.net/auth/2.0';
 *         provider.endpoint = 'https://openid.examle.com/api/auth';
 *         return done(null, provider);
 *       }
 *       return done(null, null);
 *     })
 *
 * @param {Function} fn
 * @api public
 */
exports.discover = function(fn) {
  discoverers.push(fn);
};

var discoverers = [];

/**
 * Swizzle the underlying loadDiscoveredInformation function in the openid
 * module.
 */
var loadDiscoveredInformation = openid.loadDiscoveredInformation;
openid.loadDiscoveredInformation = function(key, callback) {
  var stack = discoverers;
  (function pass(i, err, provider) {
    // an error occurred or a provider was found, done
    if (err || provider) { return callback(err, provider); }
    
    var discover = stack[i];
    if (!discover) {
      // The list of custom discovery functions has been exhausted.  Call the
      // original implementation provided by the openid module.
      return loadDiscoveredInformation(key, callback);
    }
    
    try {
      discover(key, function(e, p) { pass(i + 1, e, p); });
    } catch(e) {
      return callback(e);
    }
  })(0);
}

},{"./errors/badrequesterror":35,"./errors/internalopeniderror":36,"./strategy":38,"openid":9,"pkginfo":62}],38:[function(require,module,exports){
/**
 * Module dependencies.
 */
var passport = require('passport')
  , openid = require('openid')
  , util = require('util')
  , BadRequestError = require('./errors/badrequesterror')
  , InternalOpenIDError = require('./errors/internalopeniderror');


/**
 * `Strategy` constructor.
 *
 * The OpenID authentication strategy authenticates requests using the OpenID
 * 2.0 or 1.1 protocol.
 *
 * OpenID provides a decentralized authentication protocol, whereby users can
 * authenticate using their choice of OpenID provider.  Authenticating in this
 * this manner involves a sequence of events, including prompting the user to
 * enter their OpenID identifer and redirecting the user to their OpenID
 * provider for authentication.  Once authenticated, the user is redirected back
 * to the application with an assertion regarding the identifier.
 *
 * Applications must supply a `verify` callback which accepts an `identifier`,
 * an optional service-specific `profile`, an optional set of policy extensions
 * and then calls the `done` callback supplying a `user`, which should be set to 
 * `false` if the credentials are not valid.  If an exception occured, `err` 
 * should be set.
 *
 * Options:
 *   - `returnURL`         URL to which the OpenID provider will redirect the user after authentication
 *   - `realm`             the part of URL-space for which an OpenID authentication request is valid
 *   - `profile`           enable profile exchange, defaults to _false_
 *   - `pape`              when present, enables the OpenID Provider Authentication Policy Extension
 *                         (http://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html)
 *   - `pape.maxAuthAge`   sets the PAPE maximum authentication age in seconds
 *   - `pape.preferredAuthPolicies` sets the preferred set of PAPE authentication policies for the 
 *                         relying party to use for example `multi-factor`, `multi-factor-physical`
 *                         or `phishing-resistant` (either an array or a string)
 *   - `identifierField`   field name where the OpenID identifier is found, defaults to 'openid_identifier'
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new OpenIDStrategy({
 *         returnURL: 'http://localhost:3000/auth/openid/return',
 *         realm: 'http://localhost:3000/'
 *       },
 *       function(identifier, done) {
 *         User.findByOpenID(identifier, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 *     passport.use(new OpenIDStrategy({
 *         returnURL: 'http://localhost:3000/auth/openid/return',
 *         realm: 'http://localhost:3000/',
 *         profile: true,
 *         pape: { maxAuthAge : 600 } 
 *       },
 *       function(identifier, profile, done) {
 *         User.findByOpenID(identifier, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (!options.returnURL) throw new Error('OpenID authentication requires a returnURL option');
  if (!verify) throw new Error('OpenID authentication strategy requires a verify callback');
  
  passport.Strategy.call(this);
  this.name = 'openid';
  this._verify = verify;
  this._profile = options.profile;
  this._pape = options.pape;
  this._passReqToCallback = options.passReqToCallback;
  
  var extensions = [];
  if (options.profile) {
    var sreg = new openid.SimpleRegistration({
      "fullname" : true,
      "nickname" : true, 
      "email" : true, 
      "dob" : true, 
      "gender" : true, 
      "postcode" : true,
      "country" : true, 
      "timezone" : true,
      "language" : true
    });
    extensions.push(sreg);
  }
  if (options.profile) {
    var ax = new openid.AttributeExchange({
      "http://axschema.org/namePerson" : "required",
      "http://axschema.org/namePerson/first": "required",
      "http://axschema.org/namePerson/last": "required",
      "http://axschema.org/contact/email": "required"
    });
    extensions.push(ax);
  }

  if (options.ui) {
    // ui: { mode: 'popup', icon: true, lang: 'fr-FR' }
    var ui = new openid.UserInterface(options.ui);
    extensions.push(ui);
  }

  if (options.pape) {
    var papeOptions = {};
    if (options.pape.hasOwnProperty("maxAuthAge")) {
      papeOptions.max_auth_age = options.pape.maxAuthAge;
	  }
    if (options.pape.preferredAuthPolicies) {
      if (typeof options.pape.preferredAuthPolicies === "string") {
        papeOptions.preferred_auth_policies = options.pape.preferredAuthPolicies;
      } else if (Array.isArray(options.pape.preferredAuthPolicies)) {
        papeOptions.preferred_auth_policies = options.pape.preferredAuthPolicies.join(" ");
      }
    }
    var pape = new openid.PAPE(papeOptions);
    extensions.push(pape);
  }
  
  if (options.oauth) {
    var oauthOptions = {};
    oauthOptions.consumerKey = options.oauth.consumerKey;
    oauthOptions.scope = options.oauth.scope;
    
    var oauth = new openid.OAuthHybrid(oauthOptions);
    extensions.push(oauth);
  }
  
  this._relyingParty = new openid.RelyingParty(
    options.returnURL,
    options.realm,
    (options.stateless === undefined) ? false : options.stateless,
    (options.secure === undefined) ? true : options.secure,
    extensions);
      
  this._providerURL = options.providerURL;
  this._identifierField = options.identifierField || 'openid_identifier';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Authenticate request by delegating to an OpenID provider using OpenID 2.0 or
 * 1.1.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {

  if (req.query && req.query['openid.mode']) {
    // The request being authenticated contains an `openid.mode` parameter in
    // the query portion of the URL.  This indicates that the OpenID Provider
    // is responding to a prior authentication request with either a positive or
    // negative assertion.  If a positive assertion is received, it will be
    // verified according to the rules outlined in the OpenID 2.0 specification.
    
    // NOTE: node-openid (0.3.1), which is used internally, will treat a cancel
    //       response as an error, setting `err` in the verifyAssertion
    //       callback.  However, for consistency with Passport semantics, a
    //       cancel response should be treated as an authentication failure,
    //       rather than an exceptional error.  As such, this condition is
    //       trapped and handled prior to being given to node-openid.
    
    if (req.query['openid.mode'] === 'cancel') { return this.fail({ message: 'OpenID authentication canceled' }); }
    
    var self = this;
    this._relyingParty.verifyAssertion(req.url, function(err, result) {
      if (err) { return self.error(new InternalOpenIDError('Failed to verify assertion', err)); }
      if (!result.authenticated) { return self.error(new Error('OpenID authentication failed')); }
      
      var profile = self._parseProfileExt(result);
      var pape = self._parsePAPEExt(result);
      var oauth = self._parseOAuthExt(result);

      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }
      
      
      var arity = self._verify.length;
      if (self._passReqToCallback) {
        if (arity == 6) {
          self._verify(req, result.claimedIdentifier, profile, pape, oauth, verified);
        } else if (arity == 5) {
          self._verify(req, result.claimedIdentifier, profile, pape, verified);
        } else if (arity == 4 || self._profile) {
          // self._profile check covers the case where callback uses `arguments`
          // and arity == 0
          self._verify(req, result.claimedIdentifier, profile, verified);
        } else {
          self._verify(req, result.claimedIdentifier, verified);
        }
      } else {
        if (arity == 5) {
          self._verify(result.claimedIdentifier, profile, pape, oauth, verified);
        } else if (arity == 4) {
          self._verify(result.claimedIdentifier, profile, pape, verified);
        } else if (arity == 3 || self._profile) {
          // self._profile check covers the case where callback uses `arguments`
          // and arity == 0
          self._verify(result.claimedIdentifier, profile, verified);
        } else {
          self._verify(result.claimedIdentifier, verified);
        }
      }
    });
  } else {
    // The request being authenticated is initiating OpenID authentication.  By
    // default, an `openid_identifier` parameter is expected as a parameter,
    // typically input by a user into a form.
    //
    // During the process of initiating OpenID authentication, discovery will be
    // performed to determine the endpoints used to authenticate with the user's
    // OpenID provider.  Optionally, and by default, an association will be
    // established with the OpenID provider which is used to verify subsequent
    // protocol messages and reduce round trips.
  
    var identifier = undefined;
    if (req.body && req.body[this._identifierField]) {
      identifier = req.body[this._identifierField];
    } else if (req.query && req.query[this._identifierField]) {
      identifier = req.query[this._identifierField];
    } else if (this._providerURL) {
      identifier = this._providerURL;
    }
    
    if (!identifier) { return this.fail(new BadRequestError('Missing OpenID identifier')); }

    var self = this;
    this._relyingParty.authenticate(identifier, false, function(err, providerUrl) {
      if (err || !providerUrl) { return self.error(new InternalOpenIDError('Failed to discover OP endpoint URL', err)); }
      self.redirect(providerUrl);
    });
  }
}

/** 
 * Register a function used to save associations.
 *
 * An association establishes a shared secret between a relying party and an
 * OpenID provider, which is used to verify subsequent protocol messages and
 * reduce round trips.  Registering a function allows an application to
 * implement storage of associations as necessary.
 *
 * The function accepts six arguments: `handle`, `provider`, `algorithm`,
 * `secret`, `expiresIn`, and `done` a callback to invoke when the association
 * has been saved.
 *
 * After the association has been saved, the corresponding `loadAssociation`
 * function will be used to load it when needed.
 *
 * Internally, this function makes use of `saveAssociation` in the underlying
 * node-openid module.  Refer to that for more information.  Note, however, that
 * the argument order has been modified to pass `handle` as the first argument,
 * as it is naturally the key used to later load the association.
 *
 * Examples:
 *
 *     strategy.saveAssociation(function(handle, provider, algorithm, secret, expiresIn, done) {
 *       saveAssoc(handle, provider, algorithm, secret, expiresIn, function(err) {
 *         if (err) { return done(err) }
 *         return done();
 *       });
 *     });
 *
 * References:
 *  - [Establishing Associations](http://openid.net/specs/openid-authentication-2_0.html#associations)
 *
 * @param {Function} fn
 * @return {Strategy} for chaining
 * @api public
 */
Strategy.prototype.saveAssociation = function(fn) {
  // wrap to make `handle` the first argument to `fn`.  this order is more
  // natural due to the fact that `handle` this is the "key" when subsequently
  // loading the association.
  openid.saveAssociation = function(provider, type, handle, secret, expiry, callback) {
    fn(handle, provider, type, secret, expiry, callback)
  }
  return this;  // return this for chaining
}

/** 
 * Register a function used to load associations.
 *
 * An association establishes a shared secret between a relying party and an
 * OpenID provider, which is used to verify subsequent protocol messages and
 * reduce round trips.  Registering a function allows an application to
 * implement loading of associations as necessary.
 *
 * The function accepts two arguments: `handle` and `done` a callback to invoke
 * when the association has been loaded.  `done` should be invoked with a
 * `provider`, `algorithm`, and `secret` (or `err` if an exception occurred).
 *
 * This function is used to retrieve associations previously saved with the
 * corresponding `saveAssociation` function.
 *
 * Internally, this function makes use of `loadAssociation` in the underlying
 * node-openid module.  Refer to that for more information.  Note, however, that
 * the callback is supplied with `provider`, `algorithm`, and `secret` as
 * individual arguments, rather than a single object containing them as
 * properties.
 *
 * Examples:
 *
 *     strategy.loadAssociation(function(handle, done) {
 *       loadAssoc(handle, function(err, provider, algorithm, secret) {
 *         if (err) { return done(err) }
 *         return done(null, provider, algorithm, secret)
 *       });
 *     });
 *
 * References:
 *  - [Establishing Associations](http://openid.net/specs/openid-authentication-2_0.html#associations)
 *
 * @param {Function} fn
 * @return {Strategy} for chaining
 * @api public
 */
Strategy.prototype.loadAssociation = function(fn) {
  // wrap to allow individual arguments to `done` callback.  this seems more
  // natural since these were individual arguments to the corresponding
  // `saveAssociation` function.
  openid.loadAssociation = function(handle, callback) {
    fn(handle, function(err, provider, algorithm, secret) {
      if (err) { return callback(err, null); }
      var obj = {
        provider: provider,
        type: algorithm,
        secret: secret
      }
      return callback(null, obj);
    });
  }
  return this;  // return this for chaining
}

/** 
 * Register a function used to cache discovered info.
 *
 * Caching discovered information about a provider can significantly speed up
 * the verification of positive assertions.  Registering a function allows an
 * application to implement storage of this info as necessary.
 *
 * The function accepts three arguments: `identifier` (which serves as a key to
 * the provider information), `provider` (the provider information being
 * cached), and `done` a callback to invoke when the information has been
 * stored.
 *
 * After the data has been cached, the corresponding `loadDiscoveredInfo`
 * function will be used to look it up when needed.
 *
 * This corresponds directly to the `saveDiscoveredInformation` provided by the
 * underlying node-openid module.  Refer to that for more information.
 *
 * Examples:
 *
 *     strategy.saveDiscoveredInfo(function(identifier, provider, done) {
 *       saveInfo(identifier, provider, function(err) {
 *         if (err) { return done(err) }
 *         return done();
 *       });
 *     };
 *
 * @param {Function} fn
 * @return {Strategy} for chaining
 * @api public
 */
Strategy.prototype.saveDiscoveredInfo = 
Strategy.prototype.saveDiscoveredInformation = function(fn) {
  openid.saveDiscoveredInformation = fn;
  return this;  // return this for chaining
}

/** 
 * Register a function used to load discovered info from cache.
 *
 * Caching discovered information about a provider can significantly speed up
 * the verification of positive assertions.  Registering a function allows an
 * application to implement laoding of this info as necessary.
 *
 * The function accepts two arguments: `identifier` (which serves as a key to
 * the provider information), and `done` a callback to invoke when the
 * information has been loaded.
 *
 * This function is used to retrieve data previously cached with the
 * corresponding `saveDiscoveredInfo` function.
 *
 * This corresponds directly to the `loadDiscoveredInformation` provided by the
 * underlying node-openid module.  Refer to that for more information.
 *
 * Examples:
 *
 *     strategy.loadDiscoveredInfo(function(identifier, done) {
 *       loadInfo(identifier, function(err, provider) {
 *         if (err) { return done(err) }
 *         return done();
 *       });
 *     });
 *
 * @param {Function} fn
 * @return {Strategy} for chaining
 * @api public
 */
Strategy.prototype.loadDiscoveredInfo =
Strategy.prototype.loadDiscoveredInformation = function(fn) {
  openid.loadDiscoveredInformation = fn;
  return this;  // return this for chaining
}

/**
 * Parse user profile from OpenID response.
 *
 * Profile exchange can take place via OpenID extensions, the two common ones in
 * use are Simple Registration and Attribute Exchange.  If an OpenID provider
 * supports these extensions, the parameters will be parsed to build the user's
 * profile.
 *
 * @param {Object} params
 * @api private
 */
Strategy.prototype._parseProfileExt = function(params) {
  var profile = {};
  
  // parse simple registration parameters
  profile.displayName = params['fullname'];
  profile.emails = [{ value: params['email'] }];
  
  // parse attribute exchange parameters
  profile.name = { familyName: params['lastname'],
                   givenName: params['firstname'] };
  if (!profile.displayName) {
    if (params['firstname'] && params['lastname']) {
      profile.displayName = params['firstname'] + ' ' + params['lastname'];
    }
  }
  if (!profile.emails) {
    profile.emails = [{ value: params['email'] }];
  }

  return profile;
}

Strategy.prototype._parsePAPEExt = function(params) {
  var pape = {};
  // parse PAPE parameters
  if (params['auth_policies']) {
  	pape.authPolicies = params['auth_policies'].split(' ');
  }
  if (params['auth_time']) {
    pape.authTime = new Date(params['auth_time']);
  }
  return pape;
}

Strategy.prototype._parseOAuthExt = function(params) {
  var oauth = {};
  // parse OAuth parameters
  if (params['request_token']) {
  	oauth.requestToken = params['request_token'];
  }
  return oauth;
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;

},{"./errors/badrequesterror":35,"./errors/internalopeniderror":36,"openid":9,"passport":42,"util":undefined}],39:[function(require,module,exports){
/**
 * Export actions prototype for strategies operating within an HTTP context.
 */
var actions = module.exports = {};


/**
 * Authenticate `user`, with optional `info`.
 *
 * Strategies should call this function to successfully authenticate a user.
 * `user` should be an object supplied by the application after it has been
 * given an opportunity to verify credentials.  `info` is an optional argument
 * containing additional user information.  This is useful for third-party
 * authentication strategies to pass profile details.
 *
 * @param {Object} user
 * @param {Object} info
 * @api public
 */
actions.success = function(user, info) {
  this.delegate.success.apply(this, arguments);
}

/**
 * Fail authentication, with optional `challenge` and `status`, defaulting to
 * 401.
 *
 * Strategies should call this function to fail an authentication attempt.
 *
 * @param {String} challenge
 * @param {Number} status
 * @api public
 */
actions.fail = function(challenge, status) {
  this.delegate.fail.apply(this, arguments);
}

/**
 * Redirect to `url` with optional `status`, defaulting to 302.
 *
 * Strategies should call this function to redirect the user (via their user
 * agent) to a third-party website for authentication.
 *
 * @param {String} url
 * @param {Number} status
 * @api public
 */
actions.redirect = function(url, status) {
  var res = this.res;
  if (typeof res.redirect == 'function') {
    // If possible use redirect method on the response
    // Assume Express API, optional status param comes first
    if (status) {
      res.redirect(status, url);
    } else {
      res.redirect(url);
    }
  } else {
    // Otherwise fall back to native methods
    res.statusCode = status || 302;
    res.setHeader('Location', url);
    res.setHeader('Content-Length', '0');
    res.end();
  }
}

/**
 * Pass without making a success or fail decision.
 *
 * Under most circumstances, Strategies should not need to call this function.
 * It exists primarily to allow previous authentication state to be restored,
 * for example from an HTTP session.
 *
 * @api public
 */
actions.pass = function() {
  this.next();
}

/**
 * Internal error while performing authentication.
 *
 * Strategies should call this function when an internal error occurs during the
 * process of performing authentication; for example, if the user directory is
 * not available.
 *
 * @param {Error} err
 * @api public
 */
actions.error = function(err) {
  this.next(err);
}


},{}],40:[function(require,module,exports){
/**
 * `Context` constructor.
 *
 * @api private
 */
function Context(delegate, req, res, next) {
  this.delegate = delegate;
  this.req = req;
  this.res = res;
  this.next = next;
}


/**
 * Expose `Context`.
 */
module.exports = Context;

},{}],41:[function(require,module,exports){
/**
 * Module dependencies.
 */
var http = require('http')
  , req = http.IncomingMessage.prototype;


/**
 * Intiate a login session for `user`.
 *
 * Options:
 *   - `session`  Save login state in session, defaults to _true_
 *
 * Examples:
 *
 *     req.logIn(user, { session: false });
 *
 *     req.logIn(user, function(err) {
 *       if (err) { throw err; }
 *       // session saved
 *     });
 *
 * @param {User} user
 * @param {Object} options
 * @param {Function} done
 * @api public
 */
req.login =
req.logIn = function(user, options, done) {
  if (!this._passport) throw new Error('passport.initialize() middleware not in use');
  
  if (!done && typeof options === 'function') {
    done = options;
    options = {};
  }
  options = options || {};
  var property = this._passport.instance._userProperty || 'user';
  var session = (options.session === undefined) ? true : options.session;
  
  this[property] = user;
  if (session) {
    var self = this;
    this._passport.instance.serializeUser(user, function(err, obj) {
      if (err) { self[property] = null; return done(err); }
      self._passport.session.user = obj;
      done();
    });
  } else {
    done && done();
  }
}

/**
 * Terminate an existing login session.
 *
 * @api public
 */
req.logout =
req.logOut = function() {
  if (!this._passport) throw new Error('passport.initialize() middleware not in use');
  
  var property = this._passport.instance._userProperty || 'user';
  
  this[property] = null;
  delete this._passport.session.user;
};

/**
 * Test if request is authenticated.
 *
 * @return {Boolean}
 * @api public
 */
req.isAuthenticated = function() {
  var property = 'user';
  if (this._passport && this._passport.instance._userProperty) {
    property = this._passport.instance._userProperty;
  }
  
  return (this[property]) ? true : false;
};

/**
 * Test if request is unauthenticated.
 *
 * @return {Boolean}
 * @api public
 */
req.isUnauthenticated = function() {
  return !this.isAuthenticated();
};

},{"http":undefined}],42:[function(require,module,exports){
/**
 * Module dependencies.
 */
var fs = require('fs')
  , path = require('path')
  , util = require('util')
  , Strategy = require('./strategy')
  , SessionStrategy = require('./strategies/session')
  , initialize = require('./middleware/initialize')
  , authenticate = require('./middleware/authenticate');


/**
 * `Passport` constructor.
 *
 * @api public
 */
function Passport() {
  this._key = 'passport';
  this._strategies = {};
  this._serializers = [];
  this._deserializers = [];
  this._infoTransformers = [];
  this._framework = null;
  
  this._userProperty = 'user';
  
  this.use(new SessionStrategy());
};

/**
 * Utilize the given `strategy` with optional `name`, overridding the strategy's
 * default name.
 *
 * Examples:
 *
 *     passport.use(new TwitterStrategy(...));
 *
 *     passport.use('api', new http.BasicStrategy(...));
 *
 * @param {String|Strategy} name
 * @param {Strategy} strategy
 * @return {Passport} for chaining
 * @api public
 */
Passport.prototype.use = function(name, strategy) {
  if (!strategy) {
    strategy = name;
    name = strategy.name;
  }
  if (!name) throw new Error('authentication strategies must have a name');
  
  this._strategies[name] = strategy;
  return this;
};

/**
 * Un-utilize the `strategy` with given `name`.
 *
 * In typical applications, the necessary authentication strategies are static,
 * configured once and always available.  As such, there is often no need to
 * invoke this function.
 *
 * However, in certain situations, applications may need dynamically configure
 * and de-configure authentication strategies.  The `use()`/`unuse()`
 * combination satisfies these scenarios.
 *
 * Examples:
 *
 *     passport.unuse('legacy-api');
 *
 * @param {String} name
 * @return {Passport} for chaining
 * @api public
 */
Passport.prototype.unuse = function(name) {
  delete this._strategies[name];
  return this;
}

/**
 * Setup Passport to be used under framework.
 *
 * By default, Passport exposes middleware that operate using Connect-style
 * middleware using a `fn(req, res, next)` signature.  Other popular frameworks
 * have different expectations, and this function allows Passport to be adapted
 * to operate within such environments.
 *
 * If you are using a Connect-compatible framework, including Express, there is
 * no need to invoke this function.
 *
 * Examples:
 *
 *     passport.framework(require('hapi-passport')());
 *
 * @param {Object} name
 * @return {Passport} for chaining
 * @api public
 */
Passport.prototype.framework = function(fw) {
  this._framework = fw;
  return this;
}

/**
 * Passport's primary initialization middleware.
 *
 * This middleware must be in use by the Connect/Express application for
 * Passport to operate.
 *
 * Options:
 *   - `userProperty`  Property to set on `req` upon login, defaults to _user_
 *
 * Examples:
 *
 *     app.configure(function() {
 *       app.use(passport.initialize());
 *     });
 *
 *     app.configure(function() {
 *       app.use(passport.initialize({ userProperty: 'currentUser' }));
 *     });
 *
 * @param {Object} options
 * @return {Function} middleware
 * @api public
 */
Passport.prototype.initialize = function(options) {
  options = options || {};
  this._userProperty = options.userProperty || 'user';
  
  if (this._framework && this._framework.initialize) {
    return this._framework.initialize().bind(this);
  }
  
  return initialize().bind(this);
}

/**
 * Middleware that will restore login state from a session.
 *
 * Web applications typically use sessions to maintain login state between
 * requests.  For example, a user will authenticate by entering credentials into
 * a form which is submitted to the server.  If the credentials are valid, a
 * login session is established by setting a cookie containing a session
 * identifier in the user's web browser.  The web browser will send this cookie
 * in subsequent requests to the server, allowing a session to be maintained.
 *
 * If sessions are being utilized, and a login session has been established,
 * this middleware will populate `req.user` with the current user.
 *
 * Note that sessions are not strictly required for Passport to operate.
 * However, as a general rule, most web applications will make use of sessions.
 * An exception to this rule would be an API server, which expects each HTTP
 * request to provide credentials in an Authorization header.
 *
 * Examples:
 *
 *     app.configure(function() {
 *       app.use(connect.cookieParser());
 *       app.use(connect.session({ secret: 'keyboard cat' }));
 *       app.use(passport.initialize());
 *       app.use(passport.session());
 *     });
 *
 * Options:
 *   - `pauseStream`      Pause the request stream before deserializing the user
 *                        object from the session.  Defaults to _false_.  Should
 *                        be set to true in cases where middleware consuming the
 *                        request body is configured after passport and the
 *                        deserializeUser method is asynchronous.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @api public
 */
Passport.prototype.session = function(options) {
  return this.authenticate('session', options);
}

/**
 * Middleware that will authenticate a request using the given `strategy` name,
 * with optional `options` and `callback`.
 *
 * Examples:
 *
 *     passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' })(req, res);
 *
 *     passport.authenticate('local', function(err, user) {
 *       if (!user) { return res.redirect('/login'); }
 *       res.end('Authenticated!');
 *     })(req, res);
 *
 *     passport.authenticate('basic', { session: false })(req, res);
 *
 *     app.get('/auth/twitter', passport.authenticate('twitter'), function(req, res) {
 *       // request will be redirected to Twitter
 *     });
 *     app.get('/auth/twitter/callback', passport.authenticate('twitter'), function(req, res) {
 *       res.json(req.user);
 *     });
 *
 * @param {String} strategy
 * @param {Object} options
 * @param {Function} callback
 * @return {Function} middleware
 * @api public
 */
Passport.prototype.authenticate = function(strategy, options, callback) {
  if (this._framework && this._framework.authenticate) {
    return this._framework.authenticate(strategy, options, callback).bind(this);
  }
  
  return authenticate(strategy, options, callback).bind(this);
}

/**
 * Middleware that will authorize a third-party account using the given
 * `strategy` name, with optional `options`.
 *
 * If authorization is successful, the result provided by the strategy's verify
 * callback will be assigned to `req.account`.  The existing login session and
 * `req.user` will be unaffected.
 *
 * This function is particularly useful when connecting third-party accounts
 * to the local account of a user that is currently authenticated.
 *
 * Examples:
 *
 *    passport.authorize('twitter-authz', { failureRedirect: '/account' });
 *
 * @param {String} strategy
 * @param {Object} options
 * @return {Function} middleware
 * @api public
 */
Passport.prototype.authorize = function(strategy, options, callback) {
  var fwAuthorize = this._framework && (this._framework.authorize || this._framework.authenticate);

  options = options || {};
  options.assignProperty = 'account';

  if (fwAuthorize) {
    return fwAuthorize(strategy, options, callback).bind(this);
  }
  
  return authenticate(strategy, options, callback).bind(this);
}

/**
 * Registers a function used to serialize user objects into the session.
 *
 * Examples:
 *
 *     passport.serializeUser(function(user, done) {
 *       done(null, user.id);
 *     });
 *
 * @api public
 */
Passport.prototype.serializeUser = function(fn, done) {
  if (typeof fn === 'function') {
    return this._serializers.push(fn);
  }
  
  // private implementation that traverses the chain of serializers, attempting
  // to serialize a user
  var user = fn;
  
  var stack = this._serializers;
  (function pass(i, err, obj) {
    // serializers use 'pass' as an error to skip processing
    if ('pass' === err) {
      err = undefined;
    }
    // an error or serialized object was obtained, done
    if (err || obj || obj === 0) { return done(err, obj); }
    
    var layer = stack[i];
    if (!layer) {
      return done(new Error('failed to serialize user into session'));
    }
    
    try {
      layer(user, function(e, o) { pass(i + 1, e, o); } )
    } catch(e) {
      return done(e);
    }
  })(0);
}

/**
 * Registers a function used to deserialize user objects out of the session.
 *
 * Examples:
 *
 *     passport.deserializeUser(function(id, done) {
 *       User.findById(id, function (err, user) {
 *         done(err, user);
 *       });
 *     });
 *
 * @api public
 */
Passport.prototype.deserializeUser = function(fn, done) {
  if (typeof fn === 'function') {
    return this._deserializers.push(fn);
  }
  
  // private implementation that traverses the chain of deserializers,
  // attempting to deserialize a user
  var obj = fn;
  
  var stack = this._deserializers;
  (function pass(i, err, user) {
    // deserializers use 'pass' as an error to skip processing
    if ('pass' === err) {
      err = undefined;
    }
    // an error or deserialized user was obtained, done
    if (err || user) { return done(err, user); }
    // a valid user existed when establishing the session, but that user has
    // since been removed
    if (user === null || user === false) { return done(null, false); }
    
    var layer = stack[i];
    if (!layer) {
      return done(new Error('failed to deserialize user out of session'));
    }
    
    try {
      layer(obj, function(e, u) { pass(i + 1, e, u); } )
    } catch(e) {
      return done(e);
    }
  })(0);
}

/**
 * Registers a function used to transform auth info.
 *
 * In some circumstances authorization details are contained in authentication
 * credentials or loaded as part of verification.
 *
 * For example, when using bearer tokens for API authentication, the tokens may
 * encode (either directly or indirectly in a database), details such as scope
 * of access or the client to which the token was issued.
 *
 * Such authorization details should be enforced separately from authentication.
 * Because Passport deals only with the latter, this is the responsiblity of
 * middleware or routes further along the chain.  However, it is not optimal to
 * decode the same data or execute the same database query later.  To avoid
 * this, Passport accepts optional `info` along with the authenticated `user`
 * in a strategy's `success()` action.  This info is set at `req.authInfo`,
 * where said later middlware or routes can access it.
 *
 * Optionally, applications can register transforms to proccess this info,
 * which take effect prior to `req.authInfo` being set.  This is useful, for
 * example, when the info contains a client ID.  The transform can load the
 * client from the database and include the instance in the transformed info,
 * allowing the full set of client properties to be convieniently accessed.
 *
 * If no transforms are registered, `info` supplied by the strategy will be left
 * unmodified.
 *
 * Examples:
 *
 *     passport.transformAuthInfo(function(info, done) {
 *       Client.findById(info.clientID, function (err, client) {
 *         info.client = client;
 *         done(err, info);
 *       });
 *     });
 *
 * @api public
 */
Passport.prototype.transformAuthInfo = function(fn, done) {
  if (typeof fn === 'function') {
    return this._infoTransformers.push(fn);
  }
  
  // private implementation that traverses the chain of transformers,
  // attempting to transform auth info
  var info = fn;
  
  var stack = this._infoTransformers;
  (function pass(i, err, tinfo) {
    // transformers use 'pass' as an error to skip processing
    if ('pass' === err) {
      err = undefined;
    }
    // an error or transformed info was obtained, done
    if (err || tinfo) { return done(err, tinfo); }
    
    var layer = stack[i];
    if (!layer) {
      // if no transformers are registered (or they all pass), the default
      // behavior is to use the un-transformed info as-is
      return done(null, info);
    }
    
    try {
      var arity = layer.length;
      if (arity == 1) {
        // sync
        var t = layer(info);
        pass(i + 1, null, t);
      } else {
        // async
        layer(info, function(e, t) { pass(i + 1, e, t); } )
      }
    } catch(e) {
      return done(e);
    }
  })(0);
}

/**
 * Return strategy with given `name`. 
 *
 * @param {String} name
 * @return {Strategy}
 * @api private
 */
Passport.prototype._strategy = function(name) {
  return this._strategies[name];
}


/**
 * Export default singleton.
 *
 * @api public
 */
exports = module.exports = new Passport();

/**
 * Framework version.
 */
// removed pkginfo ...')(module, 'version');

/**
 * Expose constructors.
 */
exports.Passport = Passport;
exports.Strategy = Strategy;


/**
 * Expose strategies.
 */
exports.strategies = {};
exports.strategies.SessionStrategy = SessionStrategy;


/**
 * HTTP extensions.
 */
require('./http/request');
},{"./http/request":41,"./middleware/authenticate":43,"./middleware/initialize":44,"./strategies/session":45,"./strategy":46,"fs":undefined,"path":undefined,"pkginfo":62,"util":undefined}],43:[function(require,module,exports){
/**
 * Module dependencies.
 */
var util = require('util')
  , actions = require('../context/http/actions')
  , Context = require('../context/http/context')


/**
 * Authenticates requests.
 *
 * Applies the `name`ed strategy (or strategies) to the incoming request, in
 * order to authenticate the request.  If authentication is successful, the user
 * will be logged in and populated at `req.user` and a session will be
 * established by default.  If authentication fails, an unauthorized response
 * will be sent.
 *
 * Options:
 *   - `session`          Save login state in session, defaults to _true_
 *   - `successRedirect`  After successful login, redirect to given URL
 *   - `failureRedirect`  After failed login, redirect to given URL
 *   - `assignProperty`   Assign the object provided by the verify callback to given property
 *
 * An optional `callback` can be supplied to allow the application to overrride
 * the default manner in which authentication attempts are handled.  The
 * callback has the following signature, where `user` will be set to the
 * authenticated user on a successful authentication attempt, or `false`
 * otherwise.  An optional `info` argument will be passed, containing additional
 * details provided by the strategy's verify callback.
 *
 *     app.get('/protected', function(req, res, next) {
 *       passport.authenticate('local', function(err, user, info) {
 *         if (err) { return next(err) }
 *         if (!user) { return res.redirect('/signin') }
 *         res.redirect('/account');
 *       })(req, res, next);
 *     });
 *
 * Note that if a callback is supplied, it becomes the application's
 * responsibility to log-in the user, establish a session, and otherwise perform
 * the desired operations.
 *
 * Examples:
 *
 *     passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' });
 *
 *     passport.authenticate('basic', { session: false });
 *
 *     passport.authenticate('twitter');
 *
 * @param {String} name
 * @param {Object} options
 * @param {Function} callback
 * @return {Function}
 * @api public
 */
module.exports = function authenticate(name, options, callback) {
  if (!callback && typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  
  // Cast `name` to an array, allowing authentication to pass through a chain of
  // strategies.  The first strategy to succeed, redirect, or error will halt
  // the chain.  Authentication failures will proceed through each strategy in
  // series, ultimately failing if all strategies fail.
  //
  // This is typically used on API endpoints to allow clients to authenticate
  // using their preferred choice of Basic, Digest, token-based schemes, etc.
  // It is not feasible to construct a chain of multiple strategies that involve
  // redirection (for example both Facebook and Twitter), since the first one to
  // redirect will halt the chain.
  if (!Array.isArray(name)) {
    name = [ name ];
  }
  
  return function authenticate(req, res, next) {
    var passport = this;
    
    // accumulator for failures from each strategy in the chain
    var failures = [];
    
    function allFailed() {
      if (callback) {
        if (failures.length == 1) {
          return callback(null, false, failures[0].challenge, failures[0].status);
        } else {
          var challenges = failures.map(function(f) { return f.challenge; });
          var statuses = failures.map(function(f) { return f.status; })
          return callback(null, false, challenges, statuses);
        }
      }
      
      // Strategies are ordered by priority.  For the purpose of flashing a
      // message, the first failure will be displayed.
      var failure = failures[0] || {}
        , challenge = failure.challenge || {};
    
      if (options.failureFlash) {
        var flash = options.failureFlash;
        if (typeof flash == 'string') {
          flash = { type: 'error', message: flash };
        }
        flash.type = flash.type || 'error';
      
        var type = flash.type || challenge.type || 'error';
        var msg = flash.message || challenge.message || challenge;
        if (typeof msg == 'string') {
          req.flash(type, msg);
        }
      }
      if (options.failureMessage) {
        var msg = options.failureMessage;
        if (typeof msg == 'boolean') {
          msg = challenge.message || challenge;
        }
        if (typeof msg == 'string') {
          req.session.messages = req.session.messages || [];
          req.session.messages.push(msg);
        }
      }
      if (options.failureRedirect) {
        return res.redirect(options.failureRedirect);
      }
    
      // When failure handling is not delegated to the application, the default
      // is to respond with 401 Unauthorized.  Note that the WWW-Authenticate
      // header will be set according to the strategies in use (see
      // actions#fail).  If multiple strategies failed, each of their challenges
      // will be included in the response.
      var rchallenge = []
        , rstatus;
      
      for (var j = 0, len = failures.length; j < len; j++) {
        var failure = failures[j]
          , challenge = failure.challenge || {}
          , status = failure.status;
        if (typeof challenge == 'number') {
          status = challenge;
          challenge = null;
        }
          
        rstatus = rstatus || status;
        if (typeof challenge == 'string') {
          rchallenge.push(challenge)
        }
      }
    
      res.statusCode = rstatus || 401;
      if (rchallenge.length) {
        res.setHeader('WWW-Authenticate', rchallenge);
      }
      res.end('Unauthorized');
    }
    
    (function attempt(i) {
      var delegate = {};
      delegate.success = function(user, info) {
        if (callback) {
          return callback(null, user, info);
        }
      
        info = info || {}
      
        if (options.successFlash) {
          var flash = options.successFlash;
          if (typeof flash == 'string') {
            flash = { type: 'success', message: flash };
          }
          flash.type = flash.type || 'success';
        
          var type = flash.type || info.type || 'success';
          var msg = flash.message || info.message || info;
          if (typeof msg == 'string') {
            req.flash(type, msg);
          }
        }
        if (options.successMessage) {
          var msg = options.successMessage;
          if (typeof msg == 'boolean') {
            msg = info.message || info;
          }
          if (typeof msg == 'string') {
            req.session.messages = req.session.messages || [];
            req.session.messages.push(msg);
          }
        }
        if (options.assignProperty) {
          req[options.assignProperty] = user;
          return next();
        }
      
        req.logIn(user, options, function(err) {
          if (err) { return next(err); }
          if (options.authInfo || options.authInfo === undefined) {
            passport.transformAuthInfo(info, function(err, tinfo) {
              if (err) { return next(err); }
              req.authInfo = tinfo;
              complete();
            });
          } else {
            complete();
          }
        
          function complete() {
            if (options.successReturnToOrRedirect) {
              var url = options.successReturnToOrRedirect;
              if (req.session && req.session.returnTo) {
                url = req.session.returnTo;
                delete req.session.returnTo;
              }
              return res.redirect(url);
            }
            if (options.successRedirect) {
              return res.redirect(options.successRedirect);
            }
            next();
          }
        });
      }
      delegate.fail = function(challenge, status) {
        // push this failure into the accumulator and attempt authentication
        // using the next strategy
        failures.push({ challenge: challenge, status: status });
        attempt(i + 1);
      }
    
      var layer = name[i];
      // If no more strategies exist in the chain, authentication has failed.
      if (!layer) { return allFailed(); }
    
      // Get the strategy, which will be used as prototype from which to create
      // a new instance.  Action functions will then be bound to the strategy
      // within the context of the HTTP request/response pair.
      var prototype = passport._strategy(layer);
      if (!prototype) { return next(new Error('no strategy registered under name: ' + layer)); }
    
      var strategy = Object.create(prototype);
      var context = new Context(delegate, req, res, next);
      augment(strategy, actions, context);
    
      strategy.authenticate(req, options);
    })(0); // attempt
  }
}


function augment(strategy, actions, ctx) {
  for (var method in actions) {
    strategy[method] = actions[method].bind(ctx);
  }
}

},{"../context/http/actions":39,"../context/http/context":40,"util":undefined}],44:[function(require,module,exports){
/**
 * Module dependencies.
 */
var util = require('util');


/**
 * Passport initialization.
 *
 * Intializes Passport for incoming requests, allowing authentication strategies
 * to be applied.
 *
 * If sessions are being utilized, applications must set up Passport with
 * functions to serialize a user into and out of a session.  For example, a
 * common pattern is to serialize just the user ID into the session (due to the
 * fact that it is desirable to store the minimum amount of data in a session).
 * When a subsequent request arrives for the session, the full User object can
 * be loaded from the database by ID.
 *
 * Note that additional middleware is required to persist login state, so we
 * must use the `connect.session()` middleware _before_ `passport.initialize()`.
 *
 * This middleware must be in use by the Connect/Express application for
 * Passport to operate.
 *
 * Examples:
 *
 *     app.configure(function() {
 *       app.use(connect.cookieParser());
 *       app.use(connect.session({ secret: 'keyboard cat' }));
 *       app.use(passport.initialize());
 *       app.use(passport.session());
 *     });
 *
 *     passport.serializeUser(function(user, done) {
 *       done(null, user.id);
 *     });
 *
 *     passport.deserializeUser(function(id, done) {
 *       User.findById(id, function (err, user) {
 *         done(err, user);
 *       });
 *     });
 *
 * @return {Function}
 * @api public
 */
module.exports = function initialize() {
  
  return function initialize(req, res, next) {
    var passport = this;
    req._passport = {};
    req._passport.instance = passport;

    //console.log('!! session: ' + util.inspect(req.session));
    
    if (req.session && req.session[passport._key]) {
      // load data from existing session
      req._passport.session = req.session[passport._key];
    } else if (req.session) {
      // initialize new session
      req.session[passport._key] = {};
      req._passport.session = req.session[passport._key];
    } else {
      // no session is available
      req._passport.session = {};
    }
    
    next();
  }
}

},{"util":undefined}],45:[function(require,module,exports){
/**
 * Module dependencies.
 */
var pause = require('pause')
  , util = require('util')
  , Strategy = require('../strategy');


/**
 * `SessionStrategy` constructor.
 *
 * @api protected
 */
function SessionStrategy() {
  Strategy.call(this);
  this.name = 'session';
}

/**
 * Inherit from `Strategy`.
 */
util.inherits(SessionStrategy, Strategy);

/**
 * Authenticate request based on the current session state.
 *
 * The session authentication strategy uses the session to restore any login
 * state across requests.  If a login session has been established, `req.user`
 * will be populated with the current user.
 *
 * This strategy is registered automatically by Passport.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
SessionStrategy.prototype.authenticate = function(req, options) {
  if (!req._passport) { return this.error(new Error('passport.initialize() middleware not in use')); }
  options = options || {};

  var self = this
    , su = req._passport.session.user;
  if (su || su === 0) {
    // NOTE: Stream pausing is desirable in the case where later middleware is
    //       listening for events emitted from request.  For discussion on the
    //       matter, refer to: https://github.com/jaredhanson/passport/pull/106
    
    var paused = options.pauseStream ? pause(req) : null;
    req._passport.instance.deserializeUser(su, function(err, user) {
      if (err) { return self.error(err); }
      if (!user) {
        delete req._passport.session.user;
        self.pass();
        if (paused) {
          paused.resume();
        }
        return;
      };
      var property = req._passport.instance._userProperty || 'user';
      req[property] = user;
      self.pass();
      if (paused) {
        paused.resume();
      }
    });
  } else {
    self.pass();
  }
}


/**
 * Expose `SessionStrategy`.
 */ 
module.exports = SessionStrategy;

},{"../strategy":46,"pause":61,"util":undefined}],46:[function(require,module,exports){
/**
 * Module dependencies.
 */
var util = require('util');


/**
 * `Strategy` constructor.
 *
 * @api public
 */
function Strategy() {
}

/**
 * Authenticate request.
 *
 * This function must be overridden by subclasses.  In abstract form, it always
 * throws an exception.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  throw new Error('Strategy#authenticate must be overridden by subclass');
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

},{"util":undefined}],47:[function(require,module,exports){
/**
 * Module dependencies.
 */
var Strategy = require('./strategy');


/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports.Strategy = Strategy;

},{"./strategy":48}],48:[function(require,module,exports){
/**
 * Creates an instance of `Strategy`.
 *
 * @constructor
 * @api public
 */
function Strategy() {
}

/**
 * Authenticate request.
 *
 * This function must be overridden by subclasses.  In abstract form, it always
 * throws an exception.
 *
 * @param {Object} req The request to authenticate.
 * @param {Object} [options] Strategy-specific options.
 * @api public
 */
Strategy.prototype.authenticate = function(req, options) {
  throw new Error('Strategy#authenticate must be overridden by subclass');
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

},{}],49:[function(require,module,exports){
/**
 * `APIError` error.
 *
 * References:
 *   - https://dev.twitter.com/overview/api/response-codes
 *
 * @constructor
 * @param {string} [message]
 * @param {number} [code]
 * @access public
 */
function APIError(message, code) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'APIError';
  this.message = message;
  this.code = code;
  this.status = 500;
}

// Inherit from `Error`.
APIError.prototype.__proto__ = Error.prototype;


// Expose constructor.
module.exports = APIError;

},{}],50:[function(require,module,exports){
arguments[4][13][0].apply(exports,arguments)
},{"./strategy":52,"dup":13}],51:[function(require,module,exports){
/**
 * Parse profile.
 *
 * @param {object|string} json
 * @return {object}
 * @api public
 */
exports.parse = function(json) {
  if ('string' == typeof json) {
    json = JSON.parse(json);
  }
  
  var profile = {};
  profile.id = String(json.id);
  if (json.id_str) { profile.id = json.id_str; }
  profile.username = json.screen_name;
  profile.displayName = json.name;
  if (json.email) {
    profile.emails = [{ value: json.email }];
  }
  profile.photos = [{ value: json.profile_image_url_https }];
  
  return profile;
};

},{}],52:[function(require,module,exports){
// Load modules.
var OAuthStrategy = require('passport-oauth1')
  , util = require('util')
  , uri = require('url')
  , XML = require('xtraverse')
  , Profile = require('./profile')
  , InternalOAuthError = require('passport-oauth1').InternalOAuthError
  , APIError = require('./errors/apierror');


/**
 * `Strategy` constructor.
 *
 * The Twitter authentication strategy authenticates requests by delegating to
 * Twitter using the OAuth protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `consumerKey`     identifies client to Twitter
 *   - `consumerSecret`  secret used to establish ownership of the consumer key
 *   - `callbackURL`     URL to which Twitter will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     passport.use(new TwitterStrategy({
 *         consumerKey: '123-456-789',
 *         consumerSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/twitter/callback'
 *       },
 *       function(token, tokenSecret, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
  options = options || {};
  options.requestTokenURL = options.requestTokenURL || 'https://api.twitter.com/oauth/request_token';
  options.accessTokenURL = options.accessTokenURL || 'https://api.twitter.com/oauth/access_token';
  options.userAuthorizationURL = options.userAuthorizationURL || 'https://api.twitter.com/oauth/authenticate';
  options.sessionKey = options.sessionKey || 'oauth:twitter';
  
  OAuthStrategy.call(this, options, verify);
  this.name = 'twitter';
  this._userProfileURL = options.userProfileURL || 'https://api.twitter.com/1.1/account/verify_credentials.json';
  this._skipExtendedUserProfile = (options.skipExtendedUserProfile !== undefined) ? options.skipExtendedUserProfile : false;
  this._includeEmail = (options.includeEmail !== undefined) ? options.includeEmail : false;
  this._includeStatus = (options.includeStatus !== undefined) ? options.includeStatus : true;
  this._includeEntities = (options.includeEntities !== undefined) ? options.includeEntities : true;
}

// Inherit from `OAuthStrategy`.
util.inherits(Strategy, OAuthStrategy);


/**
 * Authenticate request by delegating to Twitter using OAuth.
 *
 * @param {http.IncomingMessage} req
 * @param {object} [options]
 * @access protected
 */
Strategy.prototype.authenticate = function(req, options) {
  // When a user denies authorization on Twitter, they are presented with a link
  // to return to the application in the following format (where xxx is the
  // value of the request token):
  //
  //     http://www.example.com/auth/twitter/callback?denied=xxx
  //
  // Following the link back to the application is interpreted as an
  // authentication failure.
  if (req.query && req.query.denied) {
    return this.fail();
  }
  
  // Call the base class for standard OAuth authentication.
  OAuthStrategy.prototype.authenticate.call(this, req, options);
};

/**
 * Retrieve user profile from Twitter.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`        (equivalent to `user_id`)
 *   - `username`  (equivalent to `screen_name`)
 *
 * Note that because Twitter supplies basic profile information in query
 * parameters when redirecting back to the application, loading of Twitter
 * profiles *does not* result in an additional HTTP request, when the
 * `skipExtendedUserProfile` option is enabled.
 *
 * @param {string} token
 * @param {string} tokenSecret
 * @param {object} params
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function(token, tokenSecret, params, done) {
  if (!this._skipExtendedUserProfile) {
    var json;
    
    var url = uri.parse(this._userProfileURL);
    url.query = url.query || {};
    if (url.pathname.indexOf('/users/show.json') == (url.pathname.length - '/users/show.json'.length)) {
      url.query.user_id = params.user_id;
    }
    if (this._includeEmail == true) {
      url.query.include_email = true;
    }
    if (this._includeStatus == false) {
      url.query.skip_status = true;
    }
    if (this._includeEntities == false) {
      url.query.include_entities = false;
    }
    
    this._oauth.get(uri.format(url), token, tokenSecret, function (err, body, res) {
      if (err) {
        if (err.data) {
          try {
            json = JSON.parse(err.data);
          } catch (_) {}
        }
        
        if (json && json.errors && json.errors.length) {
          var e = json.errors[0];
          return done(new APIError(e.message, e.code));
        }
        return done(new InternalOAuthError('Failed to fetch user profile', err));
      }
      
      try {
        json = JSON.parse(body);
      } catch (ex) {
        return done(new Error('Failed to parse user profile'));
      }
      
      var profile = Profile.parse(json);
      profile.provider = 'twitter';
      profile._raw = body;
      profile._json = json;
      // NOTE: The "X-Access-Level" header is described here:
      //       https://dev.twitter.com/oauth/overview/application-permission-model
      //       https://dev.twitter.com/oauth/overview/application-permission-model-faq
      profile._accessLevel = res.headers['x-access-level'];
  
      done(null, profile);
    });
  } else {
    var profile = { provider: 'twitter' };
    profile.id = params.user_id;
    profile.username = params.screen_name;

    done(null, profile);
  }
};

/**
 * Return extra Twitter-specific parameters to be included in the user
 * authorization request.
 *
 * @param {object} options
 * @return {object}
 * @access protected
 */
Strategy.prototype.userAuthorizationParams = function(options) {
  var params = {};
  if (options.forceLogin) {
    params.force_login = options.forceLogin;
  }
  if (options.screenName) {
    params.screen_name = options.screenName;
  }
  return params;
};

/**
 * Parse error response from Twitter OAuth endpoint.
 *
 * @param {string} body
 * @param {number} status
 * @return {Error}
 * @access protected
 */
Strategy.prototype.parseErrorResponse = function(body, status) {
  var json, xml;
  
  try {
    json = JSON.parse(body);
    if (Array.isArray(json.errors) && json.errors.length > 0) {
      return new Error(json.errors[0].message);
    }
  } catch (ex) {
    xml = XML(body)
    return new Error(xml.children('error').t() || body);
  }
};


// Expose constructor.
module.exports = Strategy;

},{"./errors/apierror":49,"./profile":51,"passport-oauth1":23,"url":undefined,"util":undefined,"xtraverse":69}],53:[function(require,module,exports){
/**
 * Module dependencies.
 */
var SessionStrategy = require('./strategies/session');


/**
 * `Authenticator` constructor.
 *
 * @api public
 */
function Authenticator() {
  this._key = 'passport';
  this._strategies = {};
  this._serializers = [];
  this._deserializers = [];
  this._infoTransformers = [];
  this._framework = null;
  this._userProperty = 'user';
  
  this.init();
}

/**
 * Initialize authenticator.
 *
 * @api protected
 */
Authenticator.prototype.init = function() {
  this.framework(require('./framework/connect')());
  this.use(new SessionStrategy());
};

/**
 * Utilize the given `strategy` with optional `name`, overridding the strategy's
 * default name.
 *
 * Examples:
 *
 *     passport.use(new TwitterStrategy(...));
 *
 *     passport.use('api', new http.BasicStrategy(...));
 *
 * @param {String|Strategy} name
 * @param {Strategy} strategy
 * @return {Authenticator} for chaining
 * @api public
 */
Authenticator.prototype.use = function(name, strategy) {
  if (!strategy) {
    strategy = name;
    name = strategy.name;
  }
  if (!name) { throw new Error('Authentication strategies must have a name'); }
  
  this._strategies[name] = strategy;
  return this;
};

/**
 * Un-utilize the `strategy` with given `name`.
 *
 * In typical applications, the necessary authentication strategies are static,
 * configured once and always available.  As such, there is often no need to
 * invoke this function.
 *
 * However, in certain situations, applications may need dynamically configure
 * and de-configure authentication strategies.  The `use()`/`unuse()`
 * combination satisfies these scenarios.
 *
 * Examples:
 *
 *     passport.unuse('legacy-api');
 *
 * @param {String} name
 * @return {Authenticator} for chaining
 * @api public
 */
Authenticator.prototype.unuse = function(name) {
  delete this._strategies[name];
  return this;
};

/**
 * Setup Passport to be used under framework.
 *
 * By default, Passport exposes middleware that operate using Connect-style
 * middleware using a `fn(req, res, next)` signature.  Other popular frameworks
 * have different expectations, and this function allows Passport to be adapted
 * to operate within such environments.
 *
 * If you are using a Connect-compatible framework, including Express, there is
 * no need to invoke this function.
 *
 * Examples:
 *
 *     passport.framework(require('hapi-passport')());
 *
 * @param {Object} name
 * @return {Authenticator} for chaining
 * @api public
 */
Authenticator.prototype.framework = function(fw) {
  this._framework = fw;
  return this;
};

/**
 * Passport's primary initialization middleware.
 *
 * This middleware must be in use by the Connect/Express application for
 * Passport to operate.
 *
 * Options:
 *   - `userProperty`  Property to set on `req` upon login, defaults to _user_
 *
 * Examples:
 *
 *     app.use(passport.initialize());
 *
 *     app.use(passport.initialize({ userProperty: 'currentUser' }));
 *
 * @param {Object} options
 * @return {Function} middleware
 * @api public
 */
Authenticator.prototype.initialize = function(options) {
  options = options || {};
  this._userProperty = options.userProperty || 'user';
  
  return this._framework.initialize(this, options);
};

/**
 * Middleware that will authenticate a request using the given `strategy` name,
 * with optional `options` and `callback`.
 *
 * Examples:
 *
 *     passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' })(req, res);
 *
 *     passport.authenticate('local', function(err, user) {
 *       if (!user) { return res.redirect('/login'); }
 *       res.end('Authenticated!');
 *     })(req, res);
 *
 *     passport.authenticate('basic', { session: false })(req, res);
 *
 *     app.get('/auth/twitter', passport.authenticate('twitter'), function(req, res) {
 *       // request will be redirected to Twitter
 *     });
 *     app.get('/auth/twitter/callback', passport.authenticate('twitter'), function(req, res) {
 *       res.json(req.user);
 *     });
 *
 * @param {String} strategy
 * @param {Object} options
 * @param {Function} callback
 * @return {Function} middleware
 * @api public
 */
Authenticator.prototype.authenticate = function(strategy, options, callback) {
  return this._framework.authenticate(this, strategy, options, callback);
};

/**
 * Middleware that will authorize a third-party account using the given
 * `strategy` name, with optional `options`.
 *
 * If authorization is successful, the result provided by the strategy's verify
 * callback will be assigned to `req.account`.  The existing login session and
 * `req.user` will be unaffected.
 *
 * This function is particularly useful when connecting third-party accounts
 * to the local account of a user that is currently authenticated.
 *
 * Examples:
 *
 *    passport.authorize('twitter-authz', { failureRedirect: '/account' });
 *
 * @param {String} strategy
 * @param {Object} options
 * @return {Function} middleware
 * @api public
 */
Authenticator.prototype.authorize = function(strategy, options, callback) {
  options = options || {};
  options.assignProperty = 'account';
  
  var fn = this._framework.authorize || this._framework.authenticate;
  return fn(this, strategy, options, callback);
};

/**
 * Middleware that will restore login state from a session.
 *
 * Web applications typically use sessions to maintain login state between
 * requests.  For example, a user will authenticate by entering credentials into
 * a form which is submitted to the server.  If the credentials are valid, a
 * login session is established by setting a cookie containing a session
 * identifier in the user's web browser.  The web browser will send this cookie
 * in subsequent requests to the server, allowing a session to be maintained.
 *
 * If sessions are being utilized, and a login session has been established,
 * this middleware will populate `req.user` with the current user.
 *
 * Note that sessions are not strictly required for Passport to operate.
 * However, as a general rule, most web applications will make use of sessions.
 * An exception to this rule would be an API server, which expects each HTTP
 * request to provide credentials in an Authorization header.
 *
 * Examples:
 *
 *     app.use(connect.cookieParser());
 *     app.use(connect.session({ secret: 'keyboard cat' }));
 *     app.use(passport.initialize());
 *     app.use(passport.session());
 *
 * Options:
 *   - `pauseStream`      Pause the request stream before deserializing the user
 *                        object from the session.  Defaults to _false_.  Should
 *                        be set to true in cases where middleware consuming the
 *                        request body is configured after passport and the
 *                        deserializeUser method is asynchronous.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @api public
 */
Authenticator.prototype.session = function(options) {
  return this.authenticate('session', options);
};

/**
 * Registers a function used to serialize user objects into the session.
 *
 * Examples:
 *
 *     passport.serializeUser(function(user, done) {
 *       done(null, user.id);
 *     });
 *
 * @api public
 */
Authenticator.prototype.serializeUser = function(fn, req, done) {
  if (typeof fn === 'function') {
    return this._serializers.push(fn);
  }
  
  // private implementation that traverses the chain of serializers, attempting
  // to serialize a user
  var user = fn;

  // For backwards compatibility
  if (typeof req === 'function') {
    done = req;
    req = undefined;
  }
  
  var stack = this._serializers;
  (function pass(i, err, obj) {
    // serializers use 'pass' as an error to skip processing
    if ('pass' === err) {
      err = undefined;
    }
    // an error or serialized object was obtained, done
    if (err || obj || obj === 0) { return done(err, obj); }
    
    var layer = stack[i];
    if (!layer) {
      return done(new Error('Failed to serialize user into session'));
    }
    
    
    function serialized(e, o) {
      pass(i + 1, e, o);
    }
    
    try {
      var arity = layer.length;
      if (arity == 3) {
        layer(req, user, serialized);
      } else {
        layer(user, serialized);
      }
    } catch(e) {
      return done(e);
    }
  })(0);
};

/**
 * Registers a function used to deserialize user objects out of the session.
 *
 * Examples:
 *
 *     passport.deserializeUser(function(id, done) {
 *       User.findById(id, function (err, user) {
 *         done(err, user);
 *       });
 *     });
 *
 * @api public
 */
Authenticator.prototype.deserializeUser = function(fn, req, done) {
  if (typeof fn === 'function') {
    return this._deserializers.push(fn);
  }
  
  // private implementation that traverses the chain of deserializers,
  // attempting to deserialize a user
  var obj = fn;

  // For backwards compatibility
  if (typeof req === 'function') {
    done = req;
    req = undefined;
  }
  
  var stack = this._deserializers;
  (function pass(i, err, user) {
    // deserializers use 'pass' as an error to skip processing
    if ('pass' === err) {
      err = undefined;
    }
    // an error or deserialized user was obtained, done
    if (err || user) { return done(err, user); }
    // a valid user existed when establishing the session, but that user has
    // since been removed
    if (user === null || user === false) { return done(null, false); }
    
    var layer = stack[i];
    if (!layer) {
      return done(new Error('Failed to deserialize user out of session'));
    }
    
    
    function deserialized(e, u) {
      pass(i + 1, e, u);
    }
    
    try {
      var arity = layer.length;
      if (arity == 3) {
        layer(req, obj, deserialized);
      } else {
        layer(obj, deserialized);
      }
    } catch(e) {
      return done(e);
    }
  })(0);
};

/**
 * Registers a function used to transform auth info.
 *
 * In some circumstances authorization details are contained in authentication
 * credentials or loaded as part of verification.
 *
 * For example, when using bearer tokens for API authentication, the tokens may
 * encode (either directly or indirectly in a database), details such as scope
 * of access or the client to which the token was issued.
 *
 * Such authorization details should be enforced separately from authentication.
 * Because Passport deals only with the latter, this is the responsiblity of
 * middleware or routes further along the chain.  However, it is not optimal to
 * decode the same data or execute the same database query later.  To avoid
 * this, Passport accepts optional `info` along with the authenticated `user`
 * in a strategy's `success()` action.  This info is set at `req.authInfo`,
 * where said later middlware or routes can access it.
 *
 * Optionally, applications can register transforms to proccess this info,
 * which take effect prior to `req.authInfo` being set.  This is useful, for
 * example, when the info contains a client ID.  The transform can load the
 * client from the database and include the instance in the transformed info,
 * allowing the full set of client properties to be convieniently accessed.
 *
 * If no transforms are registered, `info` supplied by the strategy will be left
 * unmodified.
 *
 * Examples:
 *
 *     passport.transformAuthInfo(function(info, done) {
 *       Client.findById(info.clientID, function (err, client) {
 *         info.client = client;
 *         done(err, info);
 *       });
 *     });
 *
 * @api public
 */
Authenticator.prototype.transformAuthInfo = function(fn, req, done) {
  if (typeof fn === 'function') {
    return this._infoTransformers.push(fn);
  }
  
  // private implementation that traverses the chain of transformers,
  // attempting to transform auth info
  var info = fn;

  // For backwards compatibility
  if (typeof req === 'function') {
    done = req;
    req = undefined;
  }
  
  var stack = this._infoTransformers;
  (function pass(i, err, tinfo) {
    // transformers use 'pass' as an error to skip processing
    if ('pass' === err) {
      err = undefined;
    }
    // an error or transformed info was obtained, done
    if (err || tinfo) { return done(err, tinfo); }
    
    var layer = stack[i];
    if (!layer) {
      // if no transformers are registered (or they all pass), the default
      // behavior is to use the un-transformed info as-is
      return done(null, info);
    }
    
    
    function transformed(e, t) {
      pass(i + 1, e, t);
    }
    
    try {
      var arity = layer.length;
      if (arity == 1) {
        // sync
        var t = layer(info);
        transformed(null, t);
      } else if (arity == 3) {
        layer(req, info, transformed);
      } else {
        layer(info, transformed);
      }
    } catch(e) {
      return done(e);
    }
  })(0);
};

/**
 * Return strategy with given `name`. 
 *
 * @param {String} name
 * @return {Strategy}
 * @api private
 */
Authenticator.prototype._strategy = function(name) {
  return this._strategies[name];
};


/**
 * Expose `Authenticator`.
 */
module.exports = Authenticator;

},{"./framework/connect":55,"./strategies/session":60}],54:[function(require,module,exports){
/**
 * `AuthenticationError` error.
 *
 * @api private
 */
function AuthenticationError(message, status) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'AuthenticationError';
  this.message = message;
  this.status = status || 401;
}

/**
 * Inherit from `Error`.
 */
AuthenticationError.prototype.__proto__ = Error.prototype;


/**
 * Expose `AuthenticationError`.
 */
module.exports = AuthenticationError;

},{}],55:[function(require,module,exports){
/**
 * Module dependencies.
 */
var initialize = require('../middleware/initialize')
  , authenticate = require('../middleware/authenticate');
  
/**
 * Framework support for Connect/Express.
 *
 * This module provides support for using Passport with Express.  It exposes
 * middleware that conform to the `fn(req, res, next)` signature and extends
 * Node's built-in HTTP request object with useful authentication-related
 * functions.
 *
 * @return {Object}
 * @api protected
 */
exports = module.exports = function() {
  
  // HTTP extensions.
  exports.__monkeypatchNode();
  
  return {
    initialize: initialize,
    authenticate: authenticate
  };
};

exports.__monkeypatchNode = function() {
  var http = require('http');
  var IncomingMessageExt = require('../http/request');
  
  http.IncomingMessage.prototype.login =
  http.IncomingMessage.prototype.logIn = IncomingMessageExt.logIn;
  http.IncomingMessage.prototype.logout =
  http.IncomingMessage.prototype.logOut = IncomingMessageExt.logOut;
  http.IncomingMessage.prototype.isAuthenticated = IncomingMessageExt.isAuthenticated;
  http.IncomingMessage.prototype.isUnauthenticated = IncomingMessageExt.isUnauthenticated;
};

},{"../http/request":56,"../middleware/authenticate":58,"../middleware/initialize":59,"http":undefined}],56:[function(require,module,exports){
/**
 * Module dependencies.
 */
//var http = require('http')
//  , req = http.IncomingMessage.prototype;


var req = exports = module.exports = {};

/**
 * Intiate a login session for `user`.
 *
 * Options:
 *   - `session`  Save login state in session, defaults to _true_
 *
 * Examples:
 *
 *     req.logIn(user, { session: false });
 *
 *     req.logIn(user, function(err) {
 *       if (err) { throw err; }
 *       // session saved
 *     });
 *
 * @param {User} user
 * @param {Object} options
 * @param {Function} done
 * @api public
 */
req.login =
req.logIn = function(user, options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }
  options = options || {};
  
  var property = 'user';
  if (this._passport && this._passport.instance) {
    property = this._passport.instance._userProperty || 'user';
  }
  var session = (options.session === undefined) ? true : options.session;
  
  this[property] = user;
  if (session) {
    if (!this._passport) { throw new Error('passport.initialize() middleware not in use'); }
    if (typeof done != 'function') { throw new Error('req#login requires a callback function'); }
    
    var self = this;
    this._passport.instance.serializeUser(user, this, function(err, obj) {
      if (err) { self[property] = null; return done(err); }
      if (!self._passport.session) {
        self._passport.session = {};
      }
      self._passport.session.user = obj;
      if (!self.session) {
        self.session = {};
      }
      self.session[self._passport.instance._key] = self._passport.session;
      done();
    });
  } else {
    done && done();
  }
};

/**
 * Terminate an existing login session.
 *
 * @api public
 */
req.logout =
req.logOut = function() {
  var property = 'user';
  if (this._passport && this._passport.instance) {
    property = this._passport.instance._userProperty || 'user';
  }
  
  this[property] = null;
  if (this._passport && this._passport.session) {
    delete this._passport.session.user;
  }
};

/**
 * Test if request is authenticated.
 *
 * @return {Boolean}
 * @api public
 */
req.isAuthenticated = function() {
  var property = 'user';
  if (this._passport && this._passport.instance) {
    property = this._passport.instance._userProperty || 'user';
  }
  
  return (this[property]) ? true : false;
};

/**
 * Test if request is unauthenticated.
 *
 * @return {Boolean}
 * @api public
 */
req.isUnauthenticated = function() {
  return !this.isAuthenticated();
};

},{}],57:[function(require,module,exports){
/**
 * Module dependencies.
 */
var Passport = require('./authenticator')
  , SessionStrategy = require('./strategies/session');


/**
 * Export default singleton.
 *
 * @api public
 */
exports = module.exports = new Passport();

/**
 * Expose constructors.
 */
exports.Passport =
exports.Authenticator = Passport;
exports.Strategy = require('passport-strategy');

/**
 * Expose strategies.
 */
exports.strategies = {};
exports.strategies.SessionStrategy = SessionStrategy;

},{"./authenticator":53,"./strategies/session":60,"passport-strategy":47}],58:[function(require,module,exports){
/**
 * Module dependencies.
 */
var http = require('http')
  , IncomingMessageExt = require('../http/request')
  , AuthenticationError = require('../errors/authenticationerror');


/**
 * Authenticates requests.
 *
 * Applies the `name`ed strategy (or strategies) to the incoming request, in
 * order to authenticate the request.  If authentication is successful, the user
 * will be logged in and populated at `req.user` and a session will be
 * established by default.  If authentication fails, an unauthorized response
 * will be sent.
 *
 * Options:
 *   - `session`          Save login state in session, defaults to _true_
 *   - `successRedirect`  After successful login, redirect to given URL
 *   - `failureRedirect`  After failed login, redirect to given URL
 *   - `assignProperty`   Assign the object provided by the verify callback to given property
 *
 * An optional `callback` can be supplied to allow the application to overrride
 * the default manner in which authentication attempts are handled.  The
 * callback has the following signature, where `user` will be set to the
 * authenticated user on a successful authentication attempt, or `false`
 * otherwise.  An optional `info` argument will be passed, containing additional
 * details provided by the strategy's verify callback.
 *
 *     app.get('/protected', function(req, res, next) {
 *       passport.authenticate('local', function(err, user, info) {
 *         if (err) { return next(err) }
 *         if (!user) { return res.redirect('/signin') }
 *         res.redirect('/account');
 *       })(req, res, next);
 *     });
 *
 * Note that if a callback is supplied, it becomes the application's
 * responsibility to log-in the user, establish a session, and otherwise perform
 * the desired operations.
 *
 * Examples:
 *
 *     passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' });
 *
 *     passport.authenticate('basic', { session: false });
 *
 *     passport.authenticate('twitter');
 *
 * @param {String|Array} name
 * @param {Object} options
 * @param {Function} callback
 * @return {Function}
 * @api public
 */
module.exports = function authenticate(passport, name, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  
  var multi = true;
  
  // Cast `name` to an array, allowing authentication to pass through a chain of
  // strategies.  The first strategy to succeed, redirect, or error will halt
  // the chain.  Authentication failures will proceed through each strategy in
  // series, ultimately failing if all strategies fail.
  //
  // This is typically used on API endpoints to allow clients to authenticate
  // using their preferred choice of Basic, Digest, token-based schemes, etc.
  // It is not feasible to construct a chain of multiple strategies that involve
  // redirection (for example both Facebook and Twitter), since the first one to
  // redirect will halt the chain.
  if (!Array.isArray(name)) {
    name = [ name ];
    multi = false;
  }
  
  return function authenticate(req, res, next) {
    if (http.IncomingMessage.prototype.logIn
        && http.IncomingMessage.prototype.logIn !== IncomingMessageExt.logIn) {
      require('../framework/connect').__monkeypatchNode();
    }
    
    
    // accumulator for failures from each strategy in the chain
    var failures = [];
    
    function allFailed() {
      if (callback) {
        if (!multi) {
          return callback(null, false, failures[0].challenge, failures[0].status);
        } else {
          var challenges = failures.map(function(f) { return f.challenge; });
          var statuses = failures.map(function(f) { return f.status; });
          return callback(null, false, challenges, statuses);
        }
      }
      
      // Strategies are ordered by priority.  For the purpose of flashing a
      // message, the first failure will be displayed.
      var failure = failures[0] || {}
        , challenge = failure.challenge || {}
        , msg;
    
      if (options.failureFlash) {
        var flash = options.failureFlash;
        if (typeof flash == 'string') {
          flash = { type: 'error', message: flash };
        }
        flash.type = flash.type || 'error';
      
        var type = flash.type || challenge.type || 'error';
        msg = flash.message || challenge.message || challenge;
        if (typeof msg == 'string') {
          req.flash(type, msg);
        }
      }
      if (options.failureMessage) {
        msg = options.failureMessage;
        if (typeof msg == 'boolean') {
          msg = challenge.message || challenge;
        }
        if (typeof msg == 'string') {
          req.session.messages = req.session.messages || [];
          req.session.messages.push(msg);
        }
      }
      if (options.failureRedirect) {
        return res.redirect(options.failureRedirect);
      }
    
      // When failure handling is not delegated to the application, the default
      // is to respond with 401 Unauthorized.  Note that the WWW-Authenticate
      // header will be set according to the strategies in use (see
      // actions#fail).  If multiple strategies failed, each of their challenges
      // will be included in the response.
      var rchallenge = []
        , rstatus, status;
      
      for (var j = 0, len = failures.length; j < len; j++) {
        failure = failures[j];
        challenge = failure.challenge;
        status = failure.status;
          
        rstatus = rstatus || status;
        if (typeof challenge == 'string') {
          rchallenge.push(challenge);
        }
      }
    
      res.statusCode = rstatus || 401;
      if (res.statusCode == 401 && rchallenge.length) {
        res.setHeader('WWW-Authenticate', rchallenge);
      }
      if (options.failWithError) {
        return next(new AuthenticationError(http.STATUS_CODES[res.statusCode], rstatus));
      }
      res.end(http.STATUS_CODES[res.statusCode]);
    }
    
    (function attempt(i) {
      var layer = name[i];
      // If no more strategies exist in the chain, authentication has failed.
      if (!layer) { return allFailed(); }
    
      // Get the strategy, which will be used as prototype from which to create
      // a new instance.  Action functions will then be bound to the strategy
      // within the context of the HTTP request/response pair.
      var prototype = passport._strategy(layer);
      if (!prototype) { return next(new Error('Unknown authentication strategy "' + layer + '"')); }
    
      var strategy = Object.create(prototype);
      
      
      // ----- BEGIN STRATEGY AUGMENTATION -----
      // Augment the new strategy instance with action functions.  These action
      // functions are bound via closure the the request/response pair.  The end
      // goal of the strategy is to invoke *one* of these action methods, in
      // order to indicate successful or failed authentication, redirect to a
      // third-party identity provider, etc.
      
      /**
       * Authenticate `user`, with optional `info`.
       *
       * Strategies should call this function to successfully authenticate a
       * user.  `user` should be an object supplied by the application after it
       * has been given an opportunity to verify credentials.  `info` is an
       * optional argument containing additional user information.  This is
       * useful for third-party authentication strategies to pass profile
       * details.
       *
       * @param {Object} user
       * @param {Object} info
       * @api public
       */
      strategy.success = function(user, info) {
        if (callback) {
          return callback(null, user, info);
        }
      
        info = info || {};
        var msg;
      
        if (options.successFlash) {
          var flash = options.successFlash;
          if (typeof flash == 'string') {
            flash = { type: 'success', message: flash };
          }
          flash.type = flash.type || 'success';
        
          var type = flash.type || info.type || 'success';
          msg = flash.message || info.message || info;
          if (typeof msg == 'string') {
            req.flash(type, msg);
          }
        }
        if (options.successMessage) {
          msg = options.successMessage;
          if (typeof msg == 'boolean') {
            msg = info.message || info;
          }
          if (typeof msg == 'string') {
            req.session.messages = req.session.messages || [];
            req.session.messages.push(msg);
          }
        }
        if (options.assignProperty) {
          req[options.assignProperty] = user;
          return next();
        }
      
        req.logIn(user, options, function(err) {
          if (err) { return next(err); }
          
          function complete() {
            if (options.successReturnToOrRedirect) {
              var url = options.successReturnToOrRedirect;
              if (req.session && req.session.returnTo) {
                url = req.session.returnTo;
                delete req.session.returnTo;
              }
              return res.redirect(url);
            }
            if (options.successRedirect) {
              return res.redirect(options.successRedirect);
            }
            next();
          }
          
          if (options.authInfo !== false) {
            passport.transformAuthInfo(info, req, function(err, tinfo) {
              if (err) { return next(err); }
              req.authInfo = tinfo;
              complete();
            });
          } else {
            complete();
          }
        });
      };
      
      /**
       * Fail authentication, with optional `challenge` and `status`, defaulting
       * to 401.
       *
       * Strategies should call this function to fail an authentication attempt.
       *
       * @param {String} challenge
       * @param {Number} status
       * @api public
       */
      strategy.fail = function(challenge, status) {
        if (typeof challenge == 'number') {
          status = challenge;
          challenge = undefined;
        }
        
        // push this failure into the accumulator and attempt authentication
        // using the next strategy
        failures.push({ challenge: challenge, status: status });
        attempt(i + 1);
      };
      
      /**
       * Redirect to `url` with optional `status`, defaulting to 302.
       *
       * Strategies should call this function to redirect the user (via their
       * user agent) to a third-party website for authentication.
       *
       * @param {String} url
       * @param {Number} status
       * @api public
       */
      strategy.redirect = function(url, status) {
        // NOTE: Do not use `res.redirect` from Express, because it can't decide
        //       what it wants.
        //
        //       Express 2.x: res.redirect(url, status)
        //       Express 3.x: res.redirect(status, url) -OR- res.redirect(url, status)
        //         - as of 3.14.0, deprecated warnings are issued if res.redirect(url, status)
        //           is used
        //       Express 4.x: res.redirect(status, url)
        //         - all versions (as of 4.8.7) continue to accept res.redirect(url, status)
        //           but issue deprecated versions
        
        res.statusCode = status || 302;
        res.setHeader('Location', url);
        res.setHeader('Content-Length', '0');
        res.end();
      };
      
      /**
       * Pass without making a success or fail decision.
       *
       * Under most circumstances, Strategies should not need to call this
       * function.  It exists primarily to allow previous authentication state
       * to be restored, for example from an HTTP session.
       *
       * @api public
       */
      strategy.pass = function() {
        next();
      };
      
      /**
       * Internal error while performing authentication.
       *
       * Strategies should call this function when an internal error occurs
       * during the process of performing authentication; for example, if the
       * user directory is not available.
       *
       * @param {Error} err
       * @api public
       */
      strategy.error = function(err) {
        if (callback) {
          return callback(err);
        }
        
        next(err);
      };
      
      // ----- END STRATEGY AUGMENTATION -----
    
      strategy.authenticate(req, options);
    })(0); // attempt
  };
};

},{"../errors/authenticationerror":54,"../framework/connect":55,"../http/request":56,"http":undefined}],59:[function(require,module,exports){
/**
 * Passport initialization.
 *
 * Intializes Passport for incoming requests, allowing authentication strategies
 * to be applied.
 *
 * If sessions are being utilized, applications must set up Passport with
 * functions to serialize a user into and out of a session.  For example, a
 * common pattern is to serialize just the user ID into the session (due to the
 * fact that it is desirable to store the minimum amount of data in a session).
 * When a subsequent request arrives for the session, the full User object can
 * be loaded from the database by ID.
 *
 * Note that additional middleware is required to persist login state, so we
 * must use the `connect.session()` middleware _before_ `passport.initialize()`.
 *
 * If sessions are being used, this middleware must be in use by the
 * Connect/Express application for Passport to operate.  If the application is
 * entirely stateless (not using sessions), this middleware is not necessary,
 * but its use will not have any adverse impact.
 *
 * Examples:
 *
 *     app.use(connect.cookieParser());
 *     app.use(connect.session({ secret: 'keyboard cat' }));
 *     app.use(passport.initialize());
 *     app.use(passport.session());
 *
 *     passport.serializeUser(function(user, done) {
 *       done(null, user.id);
 *     });
 *
 *     passport.deserializeUser(function(id, done) {
 *       User.findById(id, function (err, user) {
 *         done(err, user);
 *       });
 *     });
 *
 * @return {Function}
 * @api public
 */
module.exports = function initialize(passport) {
  
  return function initialize(req, res, next) {
    req._passport = {};
    req._passport.instance = passport;

    if (req.session && req.session[passport._key]) {
      // load data from existing session
      req._passport.session = req.session[passport._key];
    }

    next();
  };
};

},{}],60:[function(require,module,exports){
/**
 * Module dependencies.
 */
var pause = require('pause')
  , util = require('util')
  , Strategy = require('passport-strategy');


/**
 * `SessionStrategy` constructor.
 *
 * @api public
 */
function SessionStrategy() {
  Strategy.call(this);
  this.name = 'session';
}

/**
 * Inherit from `Strategy`.
 */
util.inherits(SessionStrategy, Strategy);

/**
 * Authenticate request based on the current session state.
 *
 * The session authentication strategy uses the session to restore any login
 * state across requests.  If a login session has been established, `req.user`
 * will be populated with the current user.
 *
 * This strategy is registered automatically by Passport.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
SessionStrategy.prototype.authenticate = function(req, options) {
  if (!req._passport) { return this.error(new Error('passport.initialize() middleware not in use')); }
  options = options || {};

  var self = this, 
      su;
  if (req._passport.session) {
    su = req._passport.session.user;
  }

  if (su || su === 0) {
    // NOTE: Stream pausing is desirable in the case where later middleware is
    //       listening for events emitted from request.  For discussion on the
    //       matter, refer to: https://github.com/jaredhanson/passport/pull/106
    
    var paused = options.pauseStream ? pause(req) : null;
    req._passport.instance.deserializeUser(su, req, function(err, user) {
      if (err) { return self.error(err); }
      if (!user) {
        delete req._passport.session.user;
        self.pass();
        if (paused) {
          paused.resume();
        }
        return;
      }
      var property = req._passport.instance._userProperty || 'user';
      req[property] = user;
      self.pass();
      if (paused) {
        paused.resume();
      }
    });
  } else {
    self.pass();
  }
};


/**
 * Expose `SessionStrategy`.
 */
module.exports = SessionStrategy;

},{"passport-strategy":47,"pause":61,"util":undefined}],61:[function(require,module,exports){

module.exports = function(obj){
  var onData
    , onEnd
    , events = [];

  // buffer data
  obj.on('data', onData = function(data, encoding){
    events.push(['data', data, encoding]);
  });

  // buffer end
  obj.on('end', onEnd = function(data, encoding){
    events.push(['end', data, encoding]);
  });

  return {
    end: function(){
      obj.removeListener('data', onData);
      obj.removeListener('end', onEnd);
    },
    resume: function(){
      this.end();
      for (var i = 0, len = events.length; i < len; ++i) {
        obj.emit.apply(obj, events[i]);
      }
    }
  };
};
},{}],62:[function(require,module,exports){
(function (__dirname){
/*
 * pkginfo.js: Top-level include for the pkginfo module
 *
 * (C) 2011, Charlie Robbins
 *
 */
 
var fs = require('fs'),
    path = require('path');

//
// ### function pkginfo ([options, 'property', 'property' ..])
// #### @pmodule {Module} Parent module to read from.
// #### @options {Object|Array|string} **Optional** Options used when exposing properties.
// #### @arguments {string...} **Optional** Specified properties to expose.
// Exposes properties from the package.json file for the parent module on 
// it's exports. Valid usage:
//
// `require('pkginfo')()`
//
// `require('pkginfo')('version', 'author');`
//
// `require('pkginfo')(['version', 'author']);`
//
// `require('pkginfo')({ include: ['version', 'author'] });`
//
var pkginfo = module.exports = function (pmodule, options) {
  var args = [].slice.call(arguments, 2).filter(function (arg) {
    return typeof arg === 'string';
  });
  
  //
  // **Parse variable arguments**
  //
  if (Array.isArray(options)) {
    //
    // If the options passed in is an Array assume that
    // it is the Array of properties to expose from the
    // on the package.json file on the parent module.
    //
    options = { include: options };
  }
  else if (typeof options === 'string') {
    //
    // Otherwise if the first argument is a string, then
    // assume that it is the first property to expose from
    // the package.json file on the parent module.
    //
    options = { include: [options] };
  }
  
  //
  // **Setup default options**
  //
  options = options || { include: [] };
  
  if (args.length > 0) {
    //
    // If additional string arguments have been passed in
    // then add them to the properties to expose on the 
    // parent module. 
    //
    options.include = options.include.concat(args);
  }
  
  var pkg = pkginfo.read(pmodule, options.dir).package;
  Object.keys(pkg).forEach(function (key) {
    if (options.include.length > 0 && !~options.include.indexOf(key)) {
      return;
    }
    
    if (!pmodule.exports[key]) {
      pmodule.exports[key] = pkg[key];
    }
  });
  
  return pkginfo;
};

//
// ### function find (dir)
// #### @pmodule {Module} Parent module to read from.
// #### @dir {string} **Optional** Directory to start search from.
// Searches up the directory tree from `dir` until it finds a directory
// which contains a `package.json` file. 
//
pkginfo.find = function (pmodule, dir) {
  dir = dir || pmodule.filename;
  dir = path.dirname(dir); 
  
  var files = fs.readdirSync(dir);
  
  if (~files.indexOf('package.json')) {
    return path.join(dir, 'package.json');
  }
  
  if (dir === '/') {
    throw new Error('Could not find package.json up from: ' + dir);
  }
  else if (!dir || dir === '.') {
    throw new Error('Cannot find package.json from unspecified directory');
  }
  
  return pkginfo.find(pmodule, dir);
};

//
// ### function read (pmodule, dir)
// #### @pmodule {Module} Parent module to read from.
// #### @dir {string} **Optional** Directory to start search from.
// Searches up the directory tree from `dir` until it finds a directory
// which contains a `package.json` file and returns the package information.
//
pkginfo.read = function (pmodule, dir) { 
  dir = pkginfo.find(pmodule, dir);
  
  var data = fs.readFileSync(dir).toString();
      
  return {
    dir: dir, 
    package: JSON.parse(data)
  };
};

//
// Call `pkginfo` on this module and expose version.
//
pkginfo(module, {
  dir: __dirname,
  include: ['version'],
  target: pkginfo
});
}).call(this,"/Users/ddascal/Projects/bladerunner/experimental-openwhisk-passport-auth/node_modules/pkginfo/lib")
},{"fs":undefined,"path":undefined}],63:[function(require,module,exports){
/**
 * Module dependencies
 */

var crypto = require('crypto');

/**
 * 62 characters in the ascii range that can be used in URLs without special
 * encoding.
 */
var UIDCHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/**
 * Make a Buffer into a string ready for use in URLs
 *
 * @param {String}
 * @returns {String}
 * @api private
 */
function tostr(bytes) {
  var chars, r, i;

  r = [];
  for (i = 0; i < bytes.length; i++) {
    r.push(UIDCHARS[bytes[i] % UIDCHARS.length]);
  }

  return r.join('');
}

/**
 * Generate an Unique Id
 *
 * @param {Number} length  The number of chars of the uid
 * @param {Number} cb (optional)  Callback for async uid generation
 * @api public
 */

function uid(length, cb) {

  if (typeof cb === 'undefined') {
    return tostr(crypto.pseudoRandomBytes(length));
  } else {
    crypto.pseudoRandomBytes(length, function(err, bytes) {
       if (err) return cb(err);
       cb(null, tostr(bytes));
    })
  }
}

/**
 * Exports
 */

module.exports = uid;

},{"crypto":undefined}],64:[function(require,module,exports){
/**
 * Merge object b with object a.
 *
 *     var a = { foo: 'bar' }
 *       , b = { bar: 'baz' };
 *
 *     merge(a, b);
 *     // => { foo: 'bar', bar: 'baz' }
 *
 * @param {Object} a
 * @param {Object} b
 * @return {Object}
 * @api public
 */

exports = module.exports = function(a, b){
  if (a && b) {
    for (var key in b) {
      a[key] = b[key];
    }
  }
  return a;
};

},{}],65:[function(require,module,exports){
function DOMParser(options){
	this.options = options ||{locator:{}};
	
}
DOMParser.prototype.parseFromString = function(source,mimeType){
	var options = this.options;
	var sax =  new XMLReader();
	var domBuilder = options.domBuilder || new DOMHandler();//contentHandler and LexicalHandler
	var errorHandler = options.errorHandler;
	var locator = options.locator;
	var defaultNSMap = options.xmlns||{};
	var entityMap = {'lt':'<','gt':'>','amp':'&','quot':'"','apos':"'"}
	if(locator){
		domBuilder.setDocumentLocator(locator)
	}
	
	sax.errorHandler = buildErrorHandler(errorHandler,domBuilder,locator);
	sax.domBuilder = options.domBuilder || domBuilder;
	if(/\/x?html?$/.test(mimeType)){
		entityMap.nbsp = '\xa0';
		entityMap.copy = '\xa9';
		defaultNSMap['']= 'http://www.w3.org/1999/xhtml';
	}
	defaultNSMap.xml = defaultNSMap.xml || 'http://www.w3.org/XML/1998/namespace';
	if(source){
		sax.parse(source,defaultNSMap,entityMap);
	}else{
		sax.errorHandler.error("invalid doc source");
	}
	return domBuilder.doc;
}
function buildErrorHandler(errorImpl,domBuilder,locator){
	if(!errorImpl){
		if(domBuilder instanceof DOMHandler){
			return domBuilder;
		}
		errorImpl = domBuilder ;
	}
	var errorHandler = {}
	var isCallback = errorImpl instanceof Function;
	locator = locator||{}
	function build(key){
		var fn = errorImpl[key];
		if(!fn && isCallback){
			fn = errorImpl.length == 2?function(msg){errorImpl(key,msg)}:errorImpl;
		}
		errorHandler[key] = fn && function(msg){
			fn('[xmldom '+key+']\t'+msg+_locator(locator));
		}||function(){};
	}
	build('warning');
	build('error');
	build('fatalError');
	return errorHandler;
}

//console.log('#\n\n\n\n\n\n\n####')
/**
 * +ContentHandler+ErrorHandler
 * +LexicalHandler+EntityResolver2
 * -DeclHandler-DTDHandler 
 * 
 * DefaultHandler:EntityResolver, DTDHandler, ContentHandler, ErrorHandler
 * DefaultHandler2:DefaultHandler,LexicalHandler, DeclHandler, EntityResolver2
 * @link http://www.saxproject.org/apidoc/org/xml/sax/helpers/DefaultHandler.html
 */
function DOMHandler() {
    this.cdata = false;
}
function position(locator,node){
	node.lineNumber = locator.lineNumber;
	node.columnNumber = locator.columnNumber;
}
/**
 * @see org.xml.sax.ContentHandler#startDocument
 * @link http://www.saxproject.org/apidoc/org/xml/sax/ContentHandler.html
 */ 
DOMHandler.prototype = {
	startDocument : function() {
    	this.doc = new DOMImplementation().createDocument(null, null, null);
    	if (this.locator) {
        	this.doc.documentURI = this.locator.systemId;
    	}
	},
	startElement:function(namespaceURI, localName, qName, attrs) {
		var doc = this.doc;
	    var el = doc.createElementNS(namespaceURI, qName||localName);
	    var len = attrs.length;
	    appendElement(this, el);
	    this.currentElement = el;
	    
		this.locator && position(this.locator,el)
	    for (var i = 0 ; i < len; i++) {
	        var namespaceURI = attrs.getURI(i);
	        var value = attrs.getValue(i);
	        var qName = attrs.getQName(i);
			var attr = doc.createAttributeNS(namespaceURI, qName);
			this.locator &&position(attrs.getLocator(i),attr);
			attr.value = attr.nodeValue = value;
			el.setAttributeNode(attr)
	    }
	},
	endElement:function(namespaceURI, localName, qName) {
		var current = this.currentElement
		var tagName = current.tagName;
		this.currentElement = current.parentNode;
	},
	startPrefixMapping:function(prefix, uri) {
	},
	endPrefixMapping:function(prefix) {
	},
	processingInstruction:function(target, data) {
	    var ins = this.doc.createProcessingInstruction(target, data);
	    this.locator && position(this.locator,ins)
	    appendElement(this, ins);
	},
	ignorableWhitespace:function(ch, start, length) {
	},
	characters:function(chars, start, length) {
		chars = _toString.apply(this,arguments)
		//console.log(chars)
		if(chars){
			if (this.cdata) {
				var charNode = this.doc.createCDATASection(chars);
			} else {
				var charNode = this.doc.createTextNode(chars);
			}
			if(this.currentElement){
				this.currentElement.appendChild(charNode);
			}else if(/^\s*$/.test(chars)){
				this.doc.appendChild(charNode);
				//process xml
			}
			this.locator && position(this.locator,charNode)
		}
	},
	skippedEntity:function(name) {
	},
	endDocument:function() {
		this.doc.normalize();
	},
	setDocumentLocator:function (locator) {
	    if(this.locator = locator){// && !('lineNumber' in locator)){
	    	locator.lineNumber = 0;
	    }
	},
	//LexicalHandler
	comment:function(chars, start, length) {
		chars = _toString.apply(this,arguments)
	    var comm = this.doc.createComment(chars);
	    this.locator && position(this.locator,comm)
	    appendElement(this, comm);
	},
	
	startCDATA:function() {
	    //used in characters() methods
	    this.cdata = true;
	},
	endCDATA:function() {
	    this.cdata = false;
	},
	
	startDTD:function(name, publicId, systemId) {
		var impl = this.doc.implementation;
	    if (impl && impl.createDocumentType) {
	        var dt = impl.createDocumentType(name, publicId, systemId);
	        this.locator && position(this.locator,dt)
	        appendElement(this, dt);
	    }
	},
	/**
	 * @see org.xml.sax.ErrorHandler
	 * @link http://www.saxproject.org/apidoc/org/xml/sax/ErrorHandler.html
	 */
	warning:function(error) {
		console.warn('[xmldom warning]\t'+error,_locator(this.locator));
	},
	error:function(error) {
		console.error('[xmldom error]\t'+error,_locator(this.locator));
	},
	fatalError:function(error) {
		console.error('[xmldom fatalError]\t'+error,_locator(this.locator));
	    throw error;
	}
}
function _locator(l){
	if(l){
		return '\n@'+(l.systemId ||'')+'#[line:'+l.lineNumber+',col:'+l.columnNumber+']'
	}
}
function _toString(chars,start,length){
	if(typeof chars == 'string'){
		return chars.substr(start,length)
	}else{//java sax connect width xmldom on rhino(what about: "? && !(chars instanceof String)")
		if(chars.length >= start+length || start){
			return new java.lang.String(chars,start,length)+'';
		}
		return chars;
	}
}

/*
 * @link http://www.saxproject.org/apidoc/org/xml/sax/ext/LexicalHandler.html
 * used method of org.xml.sax.ext.LexicalHandler:
 *  #comment(chars, start, length)
 *  #startCDATA()
 *  #endCDATA()
 *  #startDTD(name, publicId, systemId)
 *
 *
 * IGNORED method of org.xml.sax.ext.LexicalHandler:
 *  #endDTD()
 *  #startEntity(name)
 *  #endEntity(name)
 *
 *
 * @link http://www.saxproject.org/apidoc/org/xml/sax/ext/DeclHandler.html
 * IGNORED method of org.xml.sax.ext.DeclHandler
 * 	#attributeDecl(eName, aName, type, mode, value)
 *  #elementDecl(name, model)
 *  #externalEntityDecl(name, publicId, systemId)
 *  #internalEntityDecl(name, value)
 * @link http://www.saxproject.org/apidoc/org/xml/sax/ext/EntityResolver2.html
 * IGNORED method of org.xml.sax.EntityResolver2
 *  #resolveEntity(String name,String publicId,String baseURI,String systemId)
 *  #resolveEntity(publicId, systemId)
 *  #getExternalSubset(name, baseURI)
 * @link http://www.saxproject.org/apidoc/org/xml/sax/DTDHandler.html
 * IGNORED method of org.xml.sax.DTDHandler
 *  #notationDecl(name, publicId, systemId) {};
 *  #unparsedEntityDecl(name, publicId, systemId, notationName) {};
 */
"endDTD,startEntity,endEntity,attributeDecl,elementDecl,externalEntityDecl,internalEntityDecl,resolveEntity,getExternalSubset,notationDecl,unparsedEntityDecl".replace(/\w+/g,function(key){
	DOMHandler.prototype[key] = function(){return null}
})

/* Private static helpers treated below as private instance methods, so don't need to add these to the public API; we might use a Relator to also get rid of non-standard public properties */
function appendElement (hander,node) {
    if (!hander.currentElement) {
        hander.doc.appendChild(node);
    } else {
        hander.currentElement.appendChild(node);
    }
}//appendChild and setAttributeNS are preformance key

//if(typeof require == 'function'){
	var XMLReader = require('./sax').XMLReader;
	var DOMImplementation = exports.DOMImplementation = require('./dom').DOMImplementation;
	exports.XMLSerializer = require('./dom').XMLSerializer ;
	exports.DOMParser = DOMParser;
//}

},{"./dom":66,"./sax":67}],66:[function(require,module,exports){
/*
 * DOM Level 2
 * Object DOMException
 * @see http://www.w3.org/TR/REC-DOM-Level-1/ecma-script-language-binding.html
 * @see http://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/ecma-script-binding.html
 */

function copy(src,dest){
	for(var p in src){
		dest[p] = src[p];
	}
}
/**
^\w+\.prototype\.([_\w]+)\s*=\s*((?:.*\{\s*?[\r\n][\s\S]*?^})|\S.*?(?=[;\r\n]));?
^\w+\.prototype\.([_\w]+)\s*=\s*(\S.*?(?=[;\r\n]));?
 */
function _extends(Class,Super){
	var pt = Class.prototype;
	if(Object.create){
		var ppt = Object.create(Super.prototype)
		pt.__proto__ = ppt;
	}
	if(!(pt instanceof Super)){
		function t(){};
		t.prototype = Super.prototype;
		t = new t();
		copy(pt,t);
		Class.prototype = pt = t;
	}
	if(pt.constructor != Class){
		if(typeof Class != 'function'){
			console.error("unknow Class:"+Class)
		}
		pt.constructor = Class
	}
}
var htmlns = 'http://www.w3.org/1999/xhtml' ;
// Node Types
var NodeType = {}
var ELEMENT_NODE                = NodeType.ELEMENT_NODE                = 1;
var ATTRIBUTE_NODE              = NodeType.ATTRIBUTE_NODE              = 2;
var TEXT_NODE                   = NodeType.TEXT_NODE                   = 3;
var CDATA_SECTION_NODE          = NodeType.CDATA_SECTION_NODE          = 4;
var ENTITY_REFERENCE_NODE       = NodeType.ENTITY_REFERENCE_NODE       = 5;
var ENTITY_NODE                 = NodeType.ENTITY_NODE                 = 6;
var PROCESSING_INSTRUCTION_NODE = NodeType.PROCESSING_INSTRUCTION_NODE = 7;
var COMMENT_NODE                = NodeType.COMMENT_NODE                = 8;
var DOCUMENT_NODE               = NodeType.DOCUMENT_NODE               = 9;
var DOCUMENT_TYPE_NODE          = NodeType.DOCUMENT_TYPE_NODE          = 10;
var DOCUMENT_FRAGMENT_NODE      = NodeType.DOCUMENT_FRAGMENT_NODE      = 11;
var NOTATION_NODE               = NodeType.NOTATION_NODE               = 12;

// ExceptionCode
var ExceptionCode = {}
var ExceptionMessage = {};
var INDEX_SIZE_ERR              = ExceptionCode.INDEX_SIZE_ERR              = ((ExceptionMessage[1]="Index size error"),1);
var DOMSTRING_SIZE_ERR          = ExceptionCode.DOMSTRING_SIZE_ERR          = ((ExceptionMessage[2]="DOMString size error"),2);
var HIERARCHY_REQUEST_ERR       = ExceptionCode.HIERARCHY_REQUEST_ERR       = ((ExceptionMessage[3]="Hierarchy request error"),3);
var WRONG_DOCUMENT_ERR          = ExceptionCode.WRONG_DOCUMENT_ERR          = ((ExceptionMessage[4]="Wrong document"),4);
var INVALID_CHARACTER_ERR       = ExceptionCode.INVALID_CHARACTER_ERR       = ((ExceptionMessage[5]="Invalid character"),5);
var NO_DATA_ALLOWED_ERR         = ExceptionCode.NO_DATA_ALLOWED_ERR         = ((ExceptionMessage[6]="No data allowed"),6);
var NO_MODIFICATION_ALLOWED_ERR = ExceptionCode.NO_MODIFICATION_ALLOWED_ERR = ((ExceptionMessage[7]="No modification allowed"),7);
var NOT_FOUND_ERR               = ExceptionCode.NOT_FOUND_ERR               = ((ExceptionMessage[8]="Not found"),8);
var NOT_SUPPORTED_ERR           = ExceptionCode.NOT_SUPPORTED_ERR           = ((ExceptionMessage[9]="Not supported"),9);
var INUSE_ATTRIBUTE_ERR         = ExceptionCode.INUSE_ATTRIBUTE_ERR         = ((ExceptionMessage[10]="Attribute in use"),10);
//level2
var INVALID_STATE_ERR        	= ExceptionCode.INVALID_STATE_ERR        	= ((ExceptionMessage[11]="Invalid state"),11);
var SYNTAX_ERR               	= ExceptionCode.SYNTAX_ERR               	= ((ExceptionMessage[12]="Syntax error"),12);
var INVALID_MODIFICATION_ERR 	= ExceptionCode.INVALID_MODIFICATION_ERR 	= ((ExceptionMessage[13]="Invalid modification"),13);
var NAMESPACE_ERR            	= ExceptionCode.NAMESPACE_ERR           	= ((ExceptionMessage[14]="Invalid namespace"),14);
var INVALID_ACCESS_ERR       	= ExceptionCode.INVALID_ACCESS_ERR      	= ((ExceptionMessage[15]="Invalid access"),15);


function DOMException(code, message) {
	if(message instanceof Error){
		var error = message;
	}else{
		error = this;
		Error.call(this, ExceptionMessage[code]);
		this.message = ExceptionMessage[code];
		if(Error.captureStackTrace) Error.captureStackTrace(this, DOMException);
	}
	error.code = code;
	if(message) this.message = this.message + ": " + message;
	return error;
};
DOMException.prototype = Error.prototype;
copy(ExceptionCode,DOMException)
/**
 * @see http://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/core.html#ID-536297177
 * The NodeList interface provides the abstraction of an ordered collection of nodes, without defining or constraining how this collection is implemented. NodeList objects in the DOM are live.
 * The items in the NodeList are accessible via an integral index, starting from 0.
 */
function NodeList() {
};
NodeList.prototype = {
	/**
	 * The number of nodes in the list. The range of valid child node indices is 0 to length-1 inclusive.
	 * @standard level1
	 */
	length:0, 
	/**
	 * Returns the indexth item in the collection. If index is greater than or equal to the number of nodes in the list, this returns null.
	 * @standard level1
	 * @param index  unsigned long 
	 *   Index into the collection.
	 * @return Node
	 * 	The node at the indexth position in the NodeList, or null if that is not a valid index. 
	 */
	item: function(index) {
		return this[index] || null;
	},
	toString:function(isHTML,nodeFilter){
		for(var buf = [], i = 0;i<this.length;i++){
			serializeToString(this[i],buf,isHTML,nodeFilter);
		}
		return buf.join('');
	}
};
function LiveNodeList(node,refresh){
	this._node = node;
	this._refresh = refresh
	_updateLiveList(this);
}
function _updateLiveList(list){
	var inc = list._node._inc || list._node.ownerDocument._inc;
	if(list._inc != inc){
		var ls = list._refresh(list._node);
		//console.log(ls.length)
		__set__(list,'length',ls.length);
		copy(ls,list);
		list._inc = inc;
	}
}
LiveNodeList.prototype.item = function(i){
	_updateLiveList(this);
	return this[i];
}

_extends(LiveNodeList,NodeList);
/**
 * 
 * Objects implementing the NamedNodeMap interface are used to represent collections of nodes that can be accessed by name. Note that NamedNodeMap does not inherit from NodeList; NamedNodeMaps are not maintained in any particular order. Objects contained in an object implementing NamedNodeMap may also be accessed by an ordinal index, but this is simply to allow convenient enumeration of the contents of a NamedNodeMap, and does not imply that the DOM specifies an order to these Nodes.
 * NamedNodeMap objects in the DOM are live.
 * used for attributes or DocumentType entities 
 */
function NamedNodeMap() {
};

function _findNodeIndex(list,node){
	var i = list.length;
	while(i--){
		if(list[i] === node){return i}
	}
}

function _addNamedNode(el,list,newAttr,oldAttr){
	if(oldAttr){
		list[_findNodeIndex(list,oldAttr)] = newAttr;
	}else{
		list[list.length++] = newAttr;
	}
	if(el){
		newAttr.ownerElement = el;
		var doc = el.ownerDocument;
		if(doc){
			oldAttr && _onRemoveAttribute(doc,el,oldAttr);
			_onAddAttribute(doc,el,newAttr);
		}
	}
}
function _removeNamedNode(el,list,attr){
	//console.log('remove attr:'+attr)
	var i = _findNodeIndex(list,attr);
	if(i>=0){
		var lastIndex = list.length-1
		while(i<lastIndex){
			list[i] = list[++i]
		}
		list.length = lastIndex;
		if(el){
			var doc = el.ownerDocument;
			if(doc){
				_onRemoveAttribute(doc,el,attr);
				attr.ownerElement = null;
			}
		}
	}else{
		throw DOMException(NOT_FOUND_ERR,new Error(el.tagName+'@'+attr))
	}
}
NamedNodeMap.prototype = {
	length:0,
	item:NodeList.prototype.item,
	getNamedItem: function(key) {
//		if(key.indexOf(':')>0 || key == 'xmlns'){
//			return null;
//		}
		//console.log()
		var i = this.length;
		while(i--){
			var attr = this[i];
			//console.log(attr.nodeName,key)
			if(attr.nodeName == key){
				return attr;
			}
		}
	},
	setNamedItem: function(attr) {
		var el = attr.ownerElement;
		if(el && el!=this._ownerElement){
			throw new DOMException(INUSE_ATTRIBUTE_ERR);
		}
		var oldAttr = this.getNamedItem(attr.nodeName);
		_addNamedNode(this._ownerElement,this,attr,oldAttr);
		return oldAttr;
	},
	/* returns Node */
	setNamedItemNS: function(attr) {// raises: WRONG_DOCUMENT_ERR,NO_MODIFICATION_ALLOWED_ERR,INUSE_ATTRIBUTE_ERR
		var el = attr.ownerElement, oldAttr;
		if(el && el!=this._ownerElement){
			throw new DOMException(INUSE_ATTRIBUTE_ERR);
		}
		oldAttr = this.getNamedItemNS(attr.namespaceURI,attr.localName);
		_addNamedNode(this._ownerElement,this,attr,oldAttr);
		return oldAttr;
	},

	/* returns Node */
	removeNamedItem: function(key) {
		var attr = this.getNamedItem(key);
		_removeNamedNode(this._ownerElement,this,attr);
		return attr;
		
		
	},// raises: NOT_FOUND_ERR,NO_MODIFICATION_ALLOWED_ERR
	
	//for level2
	removeNamedItemNS:function(namespaceURI,localName){
		var attr = this.getNamedItemNS(namespaceURI,localName);
		_removeNamedNode(this._ownerElement,this,attr);
		return attr;
	},
	getNamedItemNS: function(namespaceURI, localName) {
		var i = this.length;
		while(i--){
			var node = this[i];
			if(node.localName == localName && node.namespaceURI == namespaceURI){
				return node;
			}
		}
		return null;
	}
};
/**
 * @see http://www.w3.org/TR/REC-DOM-Level-1/level-one-core.html#ID-102161490
 */
function DOMImplementation(/* Object */ features) {
	this._features = {};
	if (features) {
		for (var feature in features) {
			 this._features = features[feature];
		}
	}
};

DOMImplementation.prototype = {
	hasFeature: function(/* string */ feature, /* string */ version) {
		var versions = this._features[feature.toLowerCase()];
		if (versions && (!version || version in versions)) {
			return true;
		} else {
			return false;
		}
	},
	// Introduced in DOM Level 2:
	createDocument:function(namespaceURI,  qualifiedName, doctype){// raises:INVALID_CHARACTER_ERR,NAMESPACE_ERR,WRONG_DOCUMENT_ERR
		var doc = new Document();
		doc.implementation = this;
		doc.childNodes = new NodeList();
		doc.doctype = doctype;
		if(doctype){
			doc.appendChild(doctype);
		}
		if(qualifiedName){
			var root = doc.createElementNS(namespaceURI,qualifiedName);
			doc.appendChild(root);
		}
		return doc;
	},
	// Introduced in DOM Level 2:
	createDocumentType:function(qualifiedName, publicId, systemId){// raises:INVALID_CHARACTER_ERR,NAMESPACE_ERR
		var node = new DocumentType();
		node.name = qualifiedName;
		node.nodeName = qualifiedName;
		node.publicId = publicId;
		node.systemId = systemId;
		// Introduced in DOM Level 2:
		//readonly attribute DOMString        internalSubset;
		
		//TODO:..
		//  readonly attribute NamedNodeMap     entities;
		//  readonly attribute NamedNodeMap     notations;
		return node;
	}
};


/**
 * @see http://www.w3.org/TR/2000/REC-DOM-Level-2-Core-20001113/core.html#ID-1950641247
 */

function Node() {
};

Node.prototype = {
	firstChild : null,
	lastChild : null,
	previousSibling : null,
	nextSibling : null,
	attributes : null,
	parentNode : null,
	childNodes : null,
	ownerDocument : null,
	nodeValue : null,
	namespaceURI : null,
	prefix : null,
	localName : null,
	// Modified in DOM Level 2:
	insertBefore:function(newChild, refChild){//raises 
		return _insertBefore(this,newChild,refChild);
	},
	replaceChild:function(newChild, oldChild){//raises 
		this.insertBefore(newChild,oldChild);
		if(oldChild){
			this.removeChild(oldChild);
		}
	},
	removeChild:function(oldChild){
		return _removeChild(this,oldChild);
	},
	appendChild:function(newChild){
		return this.insertBefore(newChild,null);
	},
	hasChildNodes:function(){
		return this.firstChild != null;
	},
	cloneNode:function(deep){
		return cloneNode(this.ownerDocument||this,this,deep);
	},
	// Modified in DOM Level 2:
	normalize:function(){
		var child = this.firstChild;
		while(child){
			var next = child.nextSibling;
			if(next && next.nodeType == TEXT_NODE && child.nodeType == TEXT_NODE){
				this.removeChild(next);
				child.appendData(next.data);
			}else{
				child.normalize();
				child = next;
			}
		}
	},
  	// Introduced in DOM Level 2:
	isSupported:function(feature, version){
		return this.ownerDocument.implementation.hasFeature(feature,version);
	},
    // Introduced in DOM Level 2:
    hasAttributes:function(){
    	return this.attributes.length>0;
    },
    lookupPrefix:function(namespaceURI){
    	var el = this;
    	while(el){
    		var map = el._nsMap;
    		//console.dir(map)
    		if(map){
    			for(var n in map){
    				if(map[n] == namespaceURI){
    					return n;
    				}
    			}
    		}
    		el = el.nodeType == ATTRIBUTE_NODE?el.ownerDocument : el.parentNode;
    	}
    	return null;
    },
    // Introduced in DOM Level 3:
    lookupNamespaceURI:function(prefix){
    	var el = this;
    	while(el){
    		var map = el._nsMap;
    		//console.dir(map)
    		if(map){
    			if(prefix in map){
    				return map[prefix] ;
    			}
    		}
    		el = el.nodeType == ATTRIBUTE_NODE?el.ownerDocument : el.parentNode;
    	}
    	return null;
    },
    // Introduced in DOM Level 3:
    isDefaultNamespace:function(namespaceURI){
    	var prefix = this.lookupPrefix(namespaceURI);
    	return prefix == null;
    }
};


function _xmlEncoder(c){
	return c == '<' && '&lt;' ||
         c == '>' && '&gt;' ||
         c == '&' && '&amp;' ||
         c == '"' && '&quot;' ||
         '&#'+c.charCodeAt()+';'
}


copy(NodeType,Node);
copy(NodeType,Node.prototype);

/**
 * @param callback return true for continue,false for break
 * @return boolean true: break visit;
 */
function _visitNode(node,callback){
	if(callback(node)){
		return true;
	}
	if(node = node.firstChild){
		do{
			if(_visitNode(node,callback)){return true}
        }while(node=node.nextSibling)
    }
}



function Document(){
}
function _onAddAttribute(doc,el,newAttr){
	doc && doc._inc++;
	var ns = newAttr.namespaceURI ;
	if(ns == 'http://www.w3.org/2000/xmlns/'){
		//update namespace
		el._nsMap[newAttr.prefix?newAttr.localName:''] = newAttr.value
	}
}
function _onRemoveAttribute(doc,el,newAttr,remove){
	doc && doc._inc++;
	var ns = newAttr.namespaceURI ;
	if(ns == 'http://www.w3.org/2000/xmlns/'){
		//update namespace
		delete el._nsMap[newAttr.prefix?newAttr.localName:'']
	}
}
function _onUpdateChild(doc,el,newChild){
	if(doc && doc._inc){
		doc._inc++;
		//update childNodes
		var cs = el.childNodes;
		if(newChild){
			cs[cs.length++] = newChild;
		}else{
			//console.log(1)
			var child = el.firstChild;
			var i = 0;
			while(child){
				cs[i++] = child;
				child =child.nextSibling;
			}
			cs.length = i;
		}
	}
}

/**
 * attributes;
 * children;
 * 
 * writeable properties:
 * nodeValue,Attr:value,CharacterData:data
 * prefix
 */
function _removeChild(parentNode,child){
	var previous = child.previousSibling;
	var next = child.nextSibling;
	if(previous){
		previous.nextSibling = next;
	}else{
		parentNode.firstChild = next
	}
	if(next){
		next.previousSibling = previous;
	}else{
		parentNode.lastChild = previous;
	}
	_onUpdateChild(parentNode.ownerDocument,parentNode);
	return child;
}
/**
 * preformance key(refChild == null)
 */
function _insertBefore(parentNode,newChild,nextChild){
	var cp = newChild.parentNode;
	if(cp){
		cp.removeChild(newChild);//remove and update
	}
	if(newChild.nodeType === DOCUMENT_FRAGMENT_NODE){
		var newFirst = newChild.firstChild;
		if (newFirst == null) {
			return newChild;
		}
		var newLast = newChild.lastChild;
	}else{
		newFirst = newLast = newChild;
	}
	var pre = nextChild ? nextChild.previousSibling : parentNode.lastChild;

	newFirst.previousSibling = pre;
	newLast.nextSibling = nextChild;
	
	
	if(pre){
		pre.nextSibling = newFirst;
	}else{
		parentNode.firstChild = newFirst;
	}
	if(nextChild == null){
		parentNode.lastChild = newLast;
	}else{
		nextChild.previousSibling = newLast;
	}
	do{
		newFirst.parentNode = parentNode;
	}while(newFirst !== newLast && (newFirst= newFirst.nextSibling))
	_onUpdateChild(parentNode.ownerDocument||parentNode,parentNode);
	//console.log(parentNode.lastChild.nextSibling == null)
	if (newChild.nodeType == DOCUMENT_FRAGMENT_NODE) {
		newChild.firstChild = newChild.lastChild = null;
	}
	return newChild;
}
function _appendSingleChild(parentNode,newChild){
	var cp = newChild.parentNode;
	if(cp){
		var pre = parentNode.lastChild;
		cp.removeChild(newChild);//remove and update
		var pre = parentNode.lastChild;
	}
	var pre = parentNode.lastChild;
	newChild.parentNode = parentNode;
	newChild.previousSibling = pre;
	newChild.nextSibling = null;
	if(pre){
		pre.nextSibling = newChild;
	}else{
		parentNode.firstChild = newChild;
	}
	parentNode.lastChild = newChild;
	_onUpdateChild(parentNode.ownerDocument,parentNode,newChild);
	return newChild;
	//console.log("__aa",parentNode.lastChild.nextSibling == null)
}
Document.prototype = {
	//implementation : null,
	nodeName :  '#document',
	nodeType :  DOCUMENT_NODE,
	doctype :  null,
	documentElement :  null,
	_inc : 1,
	
	insertBefore :  function(newChild, refChild){//raises 
		if(newChild.nodeType == DOCUMENT_FRAGMENT_NODE){
			var child = newChild.firstChild;
			while(child){
				var next = child.nextSibling;
				this.insertBefore(child,refChild);
				child = next;
			}
			return newChild;
		}
		if(this.documentElement == null && newChild.nodeType == ELEMENT_NODE){
			this.documentElement = newChild;
		}
		
		return _insertBefore(this,newChild,refChild),(newChild.ownerDocument = this),newChild;
	},
	removeChild :  function(oldChild){
		if(this.documentElement == oldChild){
			this.documentElement = null;
		}
		return _removeChild(this,oldChild);
	},
	// Introduced in DOM Level 2:
	importNode : function(importedNode,deep){
		return importNode(this,importedNode,deep);
	},
	// Introduced in DOM Level 2:
	getElementById :	function(id){
		var rtv = null;
		_visitNode(this.documentElement,function(node){
			if(node.nodeType == ELEMENT_NODE){
				if(node.getAttribute('id') == id){
					rtv = node;
					return true;
				}
			}
		})
		return rtv;
	},
	
	//document factory method:
	createElement :	function(tagName){
		var node = new Element();
		node.ownerDocument = this;
		node.nodeName = tagName;
		node.tagName = tagName;
		node.childNodes = new NodeList();
		var attrs	= node.attributes = new NamedNodeMap();
		attrs._ownerElement = node;
		return node;
	},
	createDocumentFragment :	function(){
		var node = new DocumentFragment();
		node.ownerDocument = this;
		node.childNodes = new NodeList();
		return node;
	},
	createTextNode :	function(data){
		var node = new Text();
		node.ownerDocument = this;
		node.appendData(data)
		return node;
	},
	createComment :	function(data){
		var node = new Comment();
		node.ownerDocument = this;
		node.appendData(data)
		return node;
	},
	createCDATASection :	function(data){
		var node = new CDATASection();
		node.ownerDocument = this;
		node.appendData(data)
		return node;
	},
	createProcessingInstruction :	function(target,data){
		var node = new ProcessingInstruction();
		node.ownerDocument = this;
		node.tagName = node.target = target;
		node.nodeValue= node.data = data;
		return node;
	},
	createAttribute :	function(name){
		var node = new Attr();
		node.ownerDocument	= this;
		node.name = name;
		node.nodeName	= name;
		node.localName = name;
		node.specified = true;
		return node;
	},
	createEntityReference :	function(name){
		var node = new EntityReference();
		node.ownerDocument	= this;
		node.nodeName	= name;
		return node;
	},
	// Introduced in DOM Level 2:
	createElementNS :	function(namespaceURI,qualifiedName){
		var node = new Element();
		var pl = qualifiedName.split(':');
		var attrs	= node.attributes = new NamedNodeMap();
		node.childNodes = new NodeList();
		node.ownerDocument = this;
		node.nodeName = qualifiedName;
		node.tagName = qualifiedName;
		node.namespaceURI = namespaceURI;
		if(pl.length == 2){
			node.prefix = pl[0];
			node.localName = pl[1];
		}else{
			//el.prefix = null;
			node.localName = qualifiedName;
		}
		attrs._ownerElement = node;
		return node;
	},
	// Introduced in DOM Level 2:
	createAttributeNS :	function(namespaceURI,qualifiedName){
		var node = new Attr();
		var pl = qualifiedName.split(':');
		node.ownerDocument = this;
		node.nodeName = qualifiedName;
		node.name = qualifiedName;
		node.namespaceURI = namespaceURI;
		node.specified = true;
		if(pl.length == 2){
			node.prefix = pl[0];
			node.localName = pl[1];
		}else{
			//el.prefix = null;
			node.localName = qualifiedName;
		}
		return node;
	}
};
_extends(Document,Node);


function Element() {
	this._nsMap = {};
};
Element.prototype = {
	nodeType : ELEMENT_NODE,
	hasAttribute : function(name){
		return this.getAttributeNode(name)!=null;
	},
	getAttribute : function(name){
		var attr = this.getAttributeNode(name);
		return attr && attr.value || '';
	},
	getAttributeNode : function(name){
		return this.attributes.getNamedItem(name);
	},
	setAttribute : function(name, value){
		var attr = this.ownerDocument.createAttribute(name);
		attr.value = attr.nodeValue = "" + value;
		this.setAttributeNode(attr)
	},
	removeAttribute : function(name){
		var attr = this.getAttributeNode(name)
		attr && this.removeAttributeNode(attr);
	},
	
	//four real opeartion method
	appendChild:function(newChild){
		if(newChild.nodeType === DOCUMENT_FRAGMENT_NODE){
			return this.insertBefore(newChild,null);
		}else{
			return _appendSingleChild(this,newChild);
		}
	},
	setAttributeNode : function(newAttr){
		return this.attributes.setNamedItem(newAttr);
	},
	setAttributeNodeNS : function(newAttr){
		return this.attributes.setNamedItemNS(newAttr);
	},
	removeAttributeNode : function(oldAttr){
		//console.log(this == oldAttr.ownerElement)
		return this.attributes.removeNamedItem(oldAttr.nodeName);
	},
	//get real attribute name,and remove it by removeAttributeNode
	removeAttributeNS : function(namespaceURI, localName){
		var old = this.getAttributeNodeNS(namespaceURI, localName);
		old && this.removeAttributeNode(old);
	},
	
	hasAttributeNS : function(namespaceURI, localName){
		return this.getAttributeNodeNS(namespaceURI, localName)!=null;
	},
	getAttributeNS : function(namespaceURI, localName){
		var attr = this.getAttributeNodeNS(namespaceURI, localName);
		return attr && attr.value || '';
	},
	setAttributeNS : function(namespaceURI, qualifiedName, value){
		var attr = this.ownerDocument.createAttributeNS(namespaceURI, qualifiedName);
		attr.value = attr.nodeValue = "" + value;
		this.setAttributeNode(attr)
	},
	getAttributeNodeNS : function(namespaceURI, localName){
		return this.attributes.getNamedItemNS(namespaceURI, localName);
	},
	
	getElementsByTagName : function(tagName){
		return new LiveNodeList(this,function(base){
			var ls = [];
			_visitNode(base,function(node){
				if(node !== base && node.nodeType == ELEMENT_NODE && (tagName === '*' || node.tagName == tagName)){
					ls.push(node);
				}
			});
			return ls;
		});
	},
	getElementsByTagNameNS : function(namespaceURI, localName){
		return new LiveNodeList(this,function(base){
			var ls = [];
			_visitNode(base,function(node){
				if(node !== base && node.nodeType === ELEMENT_NODE && (namespaceURI === '*' || node.namespaceURI === namespaceURI) && (localName === '*' || node.localName == localName)){
					ls.push(node);
				}
			});
			return ls;
			
		});
	}
};
Document.prototype.getElementsByTagName = Element.prototype.getElementsByTagName;
Document.prototype.getElementsByTagNameNS = Element.prototype.getElementsByTagNameNS;


_extends(Element,Node);
function Attr() {
};
Attr.prototype.nodeType = ATTRIBUTE_NODE;
_extends(Attr,Node);


function CharacterData() {
};
CharacterData.prototype = {
	data : '',
	substringData : function(offset, count) {
		return this.data.substring(offset, offset+count);
	},
	appendData: function(text) {
		text = this.data+text;
		this.nodeValue = this.data = text;
		this.length = text.length;
	},
	insertData: function(offset,text) {
		this.replaceData(offset,0,text);
	
	},
	appendChild:function(newChild){
		throw new Error(ExceptionMessage[HIERARCHY_REQUEST_ERR])
	},
	deleteData: function(offset, count) {
		this.replaceData(offset,count,"");
	},
	replaceData: function(offset, count, text) {
		var start = this.data.substring(0,offset);
		var end = this.data.substring(offset+count);
		text = start + text + end;
		this.nodeValue = this.data = text;
		this.length = text.length;
	}
}
_extends(CharacterData,Node);
function Text() {
};
Text.prototype = {
	nodeName : "#text",
	nodeType : TEXT_NODE,
	splitText : function(offset) {
		var text = this.data;
		var newText = text.substring(offset);
		text = text.substring(0, offset);
		this.data = this.nodeValue = text;
		this.length = text.length;
		var newNode = this.ownerDocument.createTextNode(newText);
		if(this.parentNode){
			this.parentNode.insertBefore(newNode, this.nextSibling);
		}
		return newNode;
	}
}
_extends(Text,CharacterData);
function Comment() {
};
Comment.prototype = {
	nodeName : "#comment",
	nodeType : COMMENT_NODE
}
_extends(Comment,CharacterData);

function CDATASection() {
};
CDATASection.prototype = {
	nodeName : "#cdata-section",
	nodeType : CDATA_SECTION_NODE
}
_extends(CDATASection,CharacterData);


function DocumentType() {
};
DocumentType.prototype.nodeType = DOCUMENT_TYPE_NODE;
_extends(DocumentType,Node);

function Notation() {
};
Notation.prototype.nodeType = NOTATION_NODE;
_extends(Notation,Node);

function Entity() {
};
Entity.prototype.nodeType = ENTITY_NODE;
_extends(Entity,Node);

function EntityReference() {
};
EntityReference.prototype.nodeType = ENTITY_REFERENCE_NODE;
_extends(EntityReference,Node);

function DocumentFragment() {
};
DocumentFragment.prototype.nodeName =	"#document-fragment";
DocumentFragment.prototype.nodeType =	DOCUMENT_FRAGMENT_NODE;
_extends(DocumentFragment,Node);


function ProcessingInstruction() {
}
ProcessingInstruction.prototype.nodeType = PROCESSING_INSTRUCTION_NODE;
_extends(ProcessingInstruction,Node);
function XMLSerializer(){}
XMLSerializer.prototype.serializeToString = function(node,isHtml,nodeFilter){
	return nodeSerializeToString.call(node,isHtml,nodeFilter);
}
Node.prototype.toString = nodeSerializeToString;
function nodeSerializeToString(isHtml,nodeFilter){
	var buf = [];
	var refNode = this.nodeType == 9?this.documentElement:this;
	var prefix = refNode.prefix;
	var uri = refNode.namespaceURI;
	
	if(uri && prefix == null){
		//console.log(prefix)
		var prefix = refNode.lookupPrefix(uri);
		if(prefix == null){
			//isHTML = true;
			var visibleNamespaces=[
			{namespace:uri,prefix:null}
			//{namespace:uri,prefix:''}
			]
		}
	}
	serializeToString(this,buf,isHtml,nodeFilter,visibleNamespaces);
	//console.log('###',this.nodeType,uri,prefix,buf.join(''))
	return buf.join('');
}
function needNamespaceDefine(node,isHTML, visibleNamespaces) {
	var prefix = node.prefix||'';
	var uri = node.namespaceURI;
	if (!prefix && !uri){
		return false;
	}
	if (prefix === "xml" && uri === "http://www.w3.org/XML/1998/namespace" 
		|| uri == 'http://www.w3.org/2000/xmlns/'){
		return false;
	}
	
	var i = visibleNamespaces.length 
	//console.log('@@@@',node.tagName,prefix,uri,visibleNamespaces)
	while (i--) {
		var ns = visibleNamespaces[i];
		// get namespace prefix
		//console.log(node.nodeType,node.tagName,ns.prefix,prefix)
		if (ns.prefix == prefix){
			return ns.namespace != uri;
		}
	}
	//console.log(isHTML,uri,prefix=='')
	//if(isHTML && prefix ==null && uri == 'http://www.w3.org/1999/xhtml'){
	//	return false;
	//}
	//node.flag = '11111'
	//console.error(3,true,node.flag,node.prefix,node.namespaceURI)
	return true;
}
function serializeToString(node,buf,isHTML,nodeFilter,visibleNamespaces){
	if(nodeFilter){
		node = nodeFilter(node);
		if(node){
			if(typeof node == 'string'){
				buf.push(node);
				return;
			}
		}else{
			return;
		}
		//buf.sort.apply(attrs, attributeSorter);
	}
	switch(node.nodeType){
	case ELEMENT_NODE:
		if (!visibleNamespaces) visibleNamespaces = [];
		var startVisibleNamespaces = visibleNamespaces.length;
		var attrs = node.attributes;
		var len = attrs.length;
		var child = node.firstChild;
		var nodeName = node.tagName;
		
		isHTML =  (htmlns === node.namespaceURI) ||isHTML 
		buf.push('<',nodeName);
		
		
		
		for(var i=0;i<len;i++){
			// add namespaces for attributes
			var attr = attrs.item(i);
			if (attr.prefix == 'xmlns') {
				visibleNamespaces.push({ prefix: attr.localName, namespace: attr.value });
			}else if(attr.nodeName == 'xmlns'){
				visibleNamespaces.push({ prefix: '', namespace: attr.value });
			}
		}
		for(var i=0;i<len;i++){
			var attr = attrs.item(i);
			if (needNamespaceDefine(attr,isHTML, visibleNamespaces)) {
				var prefix = attr.prefix||'';
				var uri = attr.namespaceURI;
				var ns = prefix ? ' xmlns:' + prefix : " xmlns";
				buf.push(ns, '="' , uri , '"');
				visibleNamespaces.push({ prefix: prefix, namespace:uri });
			}
			serializeToString(attr,buf,isHTML,nodeFilter,visibleNamespaces);
		}
		// add namespace for current node		
		if (needNamespaceDefine(node,isHTML, visibleNamespaces)) {
			var prefix = node.prefix||'';
			var uri = node.namespaceURI;
			var ns = prefix ? ' xmlns:' + prefix : " xmlns";
			buf.push(ns, '="' , uri , '"');
			visibleNamespaces.push({ prefix: prefix, namespace:uri });
		}
		
		if(child || isHTML && !/^(?:meta|link|img|br|hr|input)$/i.test(nodeName)){
			buf.push('>');
			//if is cdata child node
			if(isHTML && /^script$/i.test(nodeName)){
				while(child){
					if(child.data){
						buf.push(child.data);
					}else{
						serializeToString(child,buf,isHTML,nodeFilter,visibleNamespaces);
					}
					child = child.nextSibling;
				}
			}else
			{
				while(child){
					serializeToString(child,buf,isHTML,nodeFilter,visibleNamespaces);
					child = child.nextSibling;
				}
			}
			buf.push('</',nodeName,'>');
		}else{
			buf.push('/>');
		}
		// remove added visible namespaces
		//visibleNamespaces.length = startVisibleNamespaces;
		return;
	case DOCUMENT_NODE:
	case DOCUMENT_FRAGMENT_NODE:
		var child = node.firstChild;
		while(child){
			serializeToString(child,buf,isHTML,nodeFilter,visibleNamespaces);
			child = child.nextSibling;
		}
		return;
	case ATTRIBUTE_NODE:
		return buf.push(' ',node.name,'="',node.value.replace(/[<&"]/g,_xmlEncoder),'"');
	case TEXT_NODE:
		return buf.push(node.data.replace(/[<&]/g,_xmlEncoder));
	case CDATA_SECTION_NODE:
		return buf.push( '<![CDATA[',node.data,']]>');
	case COMMENT_NODE:
		return buf.push( "<!--",node.data,"-->");
	case DOCUMENT_TYPE_NODE:
		var pubid = node.publicId;
		var sysid = node.systemId;
		buf.push('<!DOCTYPE ',node.name);
		if(pubid){
			buf.push(' PUBLIC "',pubid);
			if (sysid && sysid!='.') {
				buf.push( '" "',sysid);
			}
			buf.push('">');
		}else if(sysid && sysid!='.'){
			buf.push(' SYSTEM "',sysid,'">');
		}else{
			var sub = node.internalSubset;
			if(sub){
				buf.push(" [",sub,"]");
			}
			buf.push(">");
		}
		return;
	case PROCESSING_INSTRUCTION_NODE:
		return buf.push( "<?",node.target," ",node.data,"?>");
	case ENTITY_REFERENCE_NODE:
		return buf.push( '&',node.nodeName,';');
	//case ENTITY_NODE:
	//case NOTATION_NODE:
	default:
		buf.push('??',node.nodeName);
	}
}
function importNode(doc,node,deep){
	var node2;
	switch (node.nodeType) {
	case ELEMENT_NODE:
		node2 = node.cloneNode(false);
		node2.ownerDocument = doc;
		//var attrs = node2.attributes;
		//var len = attrs.length;
		//for(var i=0;i<len;i++){
			//node2.setAttributeNodeNS(importNode(doc,attrs.item(i),deep));
		//}
	case DOCUMENT_FRAGMENT_NODE:
		break;
	case ATTRIBUTE_NODE:
		deep = true;
		break;
	//case ENTITY_REFERENCE_NODE:
	//case PROCESSING_INSTRUCTION_NODE:
	////case TEXT_NODE:
	//case CDATA_SECTION_NODE:
	//case COMMENT_NODE:
	//	deep = false;
	//	break;
	//case DOCUMENT_NODE:
	//case DOCUMENT_TYPE_NODE:
	//cannot be imported.
	//case ENTITY_NODE:
	//case NOTATION_NODE：
	//can not hit in level3
	//default:throw e;
	}
	if(!node2){
		node2 = node.cloneNode(false);//false
	}
	node2.ownerDocument = doc;
	node2.parentNode = null;
	if(deep){
		var child = node.firstChild;
		while(child){
			node2.appendChild(importNode(doc,child,deep));
			child = child.nextSibling;
		}
	}
	return node2;
}
//
//var _relationMap = {firstChild:1,lastChild:1,previousSibling:1,nextSibling:1,
//					attributes:1,childNodes:1,parentNode:1,documentElement:1,doctype,};
function cloneNode(doc,node,deep){
	var node2 = new node.constructor();
	for(var n in node){
		var v = node[n];
		if(typeof v != 'object' ){
			if(v != node2[n]){
				node2[n] = v;
			}
		}
	}
	if(node.childNodes){
		node2.childNodes = new NodeList();
	}
	node2.ownerDocument = doc;
	switch (node2.nodeType) {
	case ELEMENT_NODE:
		var attrs	= node.attributes;
		var attrs2	= node2.attributes = new NamedNodeMap();
		var len = attrs.length
		attrs2._ownerElement = node2;
		for(var i=0;i<len;i++){
			node2.setAttributeNode(cloneNode(doc,attrs.item(i),true));
		}
		break;;
	case ATTRIBUTE_NODE:
		deep = true;
	}
	if(deep){
		var child = node.firstChild;
		while(child){
			node2.appendChild(cloneNode(doc,child,deep));
			child = child.nextSibling;
		}
	}
	return node2;
}

function __set__(object,key,value){
	object[key] = value
}
//do dynamic
try{
	if(Object.defineProperty){
		Object.defineProperty(LiveNodeList.prototype,'length',{
			get:function(){
				_updateLiveList(this);
				return this.$$length;
			}
		});
		Object.defineProperty(Node.prototype,'textContent',{
			get:function(){
				return getTextContent(this);
			},
			set:function(data){
				switch(this.nodeType){
				case ELEMENT_NODE:
				case DOCUMENT_FRAGMENT_NODE:
					while(this.firstChild){
						this.removeChild(this.firstChild);
					}
					if(data || String(data)){
						this.appendChild(this.ownerDocument.createTextNode(data));
					}
					break;
				default:
					//TODO:
					this.data = data;
					this.value = data;
					this.nodeValue = data;
				}
			}
		})
		
		function getTextContent(node){
			switch(node.nodeType){
			case ELEMENT_NODE:
			case DOCUMENT_FRAGMENT_NODE:
				var buf = [];
				node = node.firstChild;
				while(node){
					if(node.nodeType!==7 && node.nodeType !==8){
						buf.push(getTextContent(node));
					}
					node = node.nextSibling;
				}
				return buf.join('');
			default:
				return node.nodeValue;
			}
		}
		__set__ = function(object,key,value){
			//console.log(value)
			object['$$'+key] = value
		}
	}
}catch(e){//ie8
}

//if(typeof require == 'function'){
	exports.DOMImplementation = DOMImplementation;
	exports.XMLSerializer = XMLSerializer;
//}

},{}],67:[function(require,module,exports){
//[4]   	NameStartChar	   ::=   	":" | [A-Z] | "_" | [a-z] | [#xC0-#xD6] | [#xD8-#xF6] | [#xF8-#x2FF] | [#x370-#x37D] | [#x37F-#x1FFF] | [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF] | [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] | [#x10000-#xEFFFF]
//[4a]   	NameChar	   ::=   	NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] | [#x203F-#x2040]
//[5]   	Name	   ::=   	NameStartChar (NameChar)*
var nameStartChar = /[A-Z_a-z\xC0-\xD6\xD8-\xF6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]///\u10000-\uEFFFF
var nameChar = new RegExp("[\\-\\.0-9"+nameStartChar.source.slice(1,-1)+"\\u00B7\\u0300-\\u036F\\u203F-\\u2040]");
var tagNamePattern = new RegExp('^'+nameStartChar.source+nameChar.source+'*(?:\:'+nameStartChar.source+nameChar.source+'*)?$');
//var tagNamePattern = /^[a-zA-Z_][\w\-\.]*(?:\:[a-zA-Z_][\w\-\.]*)?$/
//var handlers = 'resolveEntity,getExternalSubset,characters,endDocument,endElement,endPrefixMapping,ignorableWhitespace,processingInstruction,setDocumentLocator,skippedEntity,startDocument,startElement,startPrefixMapping,notationDecl,unparsedEntityDecl,error,fatalError,warning,attributeDecl,elementDecl,externalEntityDecl,internalEntityDecl,comment,endCDATA,endDTD,endEntity,startCDATA,startDTD,startEntity'.split(',')

//S_TAG,	S_ATTR,	S_EQ,	S_ATTR_NOQUOT_VALUE
//S_ATTR_SPACE,	S_ATTR_END,	S_TAG_SPACE, S_TAG_CLOSE
var S_TAG = 0;//tag name offerring
var S_ATTR = 1;//attr name offerring 
var S_ATTR_SPACE=2;//attr name end and space offer
var S_EQ = 3;//=space?
var S_ATTR_NOQUOT_VALUE = 4;//attr value(no quot value only)
var S_ATTR_END = 5;//attr value end and no space(quot end)
var S_TAG_SPACE = 6;//(attr value end || tag end ) && (space offer)
var S_TAG_CLOSE = 7;//closed el<el />

function XMLReader(){
	
}

XMLReader.prototype = {
	parse:function(source,defaultNSMap,entityMap){
		var domBuilder = this.domBuilder;
		domBuilder.startDocument();
		_copy(defaultNSMap ,defaultNSMap = {})
		parse(source,defaultNSMap,entityMap,
				domBuilder,this.errorHandler);
		domBuilder.endDocument();
	}
}
function parse(source,defaultNSMapCopy,entityMap,domBuilder,errorHandler){
	function fixedFromCharCode(code) {
		// String.prototype.fromCharCode does not supports
		// > 2 bytes unicode chars directly
		if (code > 0xffff) {
			code -= 0x10000;
			var surrogate1 = 0xd800 + (code >> 10)
				, surrogate2 = 0xdc00 + (code & 0x3ff);

			return String.fromCharCode(surrogate1, surrogate2);
		} else {
			return String.fromCharCode(code);
		}
	}
	function entityReplacer(a){
		var k = a.slice(1,-1);
		if(k in entityMap){
			return entityMap[k]; 
		}else if(k.charAt(0) === '#'){
			return fixedFromCharCode(parseInt(k.substr(1).replace('x','0x')))
		}else{
			errorHandler.error('entity not found:'+a);
			return a;
		}
	}
	function appendText(end){//has some bugs
		if(end>start){
			var xt = source.substring(start,end).replace(/&#?\w+;/g,entityReplacer);
			locator&&position(start);
			domBuilder.characters(xt,0,end-start);
			start = end
		}
	}
	function position(p,m){
		while(p>=lineEnd && (m = linePattern.exec(source))){
			lineStart = m.index;
			lineEnd = lineStart + m[0].length;
			locator.lineNumber++;
			//console.log('line++:',locator,startPos,endPos)
		}
		locator.columnNumber = p-lineStart+1;
	}
	var lineStart = 0;
	var lineEnd = 0;
	var linePattern = /.*(?:\r\n?|\n)|.*$/g
	var locator = domBuilder.locator;
	
	var parseStack = [{currentNSMap:defaultNSMapCopy}]
	var closeMap = {};
	var start = 0;
	while(true){
		try{
			var tagStart = source.indexOf('<',start);
			if(tagStart<0){
				if(!source.substr(start).match(/^\s*$/)){
					var doc = domBuilder.doc;
	    			var text = doc.createTextNode(source.substr(start));
	    			doc.appendChild(text);
	    			domBuilder.currentElement = text;
				}
				return;
			}
			if(tagStart>start){
				appendText(tagStart);
			}
			switch(source.charAt(tagStart+1)){
			case '/':
				var end = source.indexOf('>',tagStart+3);
				var tagName = source.substring(tagStart+2,end);
				var config = parseStack.pop();
				if(end<0){
					
	        		tagName = source.substring(tagStart+2).replace(/[\s<].*/,'');
	        		//console.error('#@@@@@@'+tagName)
	        		errorHandler.error("end tag name: "+tagName+' is not complete:'+config.tagName);
	        		end = tagStart+1+tagName.length;
	        	}else if(tagName.match(/\s</)){
	        		tagName = tagName.replace(/[\s<].*/,'');
	        		errorHandler.error("end tag name: "+tagName+' maybe not complete');
	        		end = tagStart+1+tagName.length;
				}
				//console.error(parseStack.length,parseStack)
				//console.error(config);
				var localNSMap = config.localNSMap;
				var endMatch = config.tagName == tagName;
				var endIgnoreCaseMach = endMatch || config.tagName&&config.tagName.toLowerCase() == tagName.toLowerCase()
		        if(endIgnoreCaseMach){
		        	domBuilder.endElement(config.uri,config.localName,tagName);
					if(localNSMap){
						for(var prefix in localNSMap){
							domBuilder.endPrefixMapping(prefix) ;
						}
					}
					if(!endMatch){
		            	errorHandler.fatalError("end tag name: "+tagName+' is not match the current start tagName:'+config.tagName );
					}
		        }else{
		        	parseStack.push(config)
		        }
				
				end++;
				break;
				// end elment
			case '?':// <?...?>
				locator&&position(tagStart);
				end = parseInstruction(source,tagStart,domBuilder);
				break;
			case '!':// <!doctype,<![CDATA,<!--
				locator&&position(tagStart);
				end = parseDCC(source,tagStart,domBuilder,errorHandler);
				break;
			default:
				locator&&position(tagStart);
				var el = new ElementAttributes();
				var currentNSMap = parseStack[parseStack.length-1].currentNSMap;
				//elStartEnd
				var end = parseElementStartPart(source,tagStart,el,currentNSMap,entityReplacer,errorHandler);
				var len = el.length;
				
				
				if(!el.closed && fixSelfClosed(source,end,el.tagName,closeMap)){
					el.closed = true;
					if(!entityMap.nbsp){
						errorHandler.warning('unclosed xml attribute');
					}
				}
				if(locator && len){
					var locator2 = copyLocator(locator,{});
					//try{//attribute position fixed
					for(var i = 0;i<len;i++){
						var a = el[i];
						position(a.offset);
						a.locator = copyLocator(locator,{});
					}
					//}catch(e){console.error('@@@@@'+e)}
					domBuilder.locator = locator2
					if(appendElement(el,domBuilder,currentNSMap)){
						parseStack.push(el)
					}
					domBuilder.locator = locator;
				}else{
					if(appendElement(el,domBuilder,currentNSMap)){
						parseStack.push(el)
					}
				}
				
				
				
				if(el.uri === 'http://www.w3.org/1999/xhtml' && !el.closed){
					end = parseHtmlSpecialContent(source,end,el.tagName,entityReplacer,domBuilder)
				}else{
					end++;
				}
			}
		}catch(e){
			errorHandler.error('element parse error: '+e)
			//errorHandler.error('element parse error: '+e);
			end = -1;
			//throw e;
		}
		if(end>start){
			start = end;
		}else{
			//TODO: 这里有可能sax回退，有位置错误风险
			appendText(Math.max(tagStart,start)+1);
		}
	}
}
function copyLocator(f,t){
	t.lineNumber = f.lineNumber;
	t.columnNumber = f.columnNumber;
	return t;
}

/**
 * @see #appendElement(source,elStartEnd,el,selfClosed,entityReplacer,domBuilder,parseStack);
 * @return end of the elementStartPart(end of elementEndPart for selfClosed el)
 */
function parseElementStartPart(source,start,el,currentNSMap,entityReplacer,errorHandler){
	var attrName;
	var value;
	var p = ++start;
	var s = S_TAG;//status
	while(true){
		var c = source.charAt(p);
		switch(c){
		case '=':
			if(s === S_ATTR){//attrName
				attrName = source.slice(start,p);
				s = S_EQ;
			}else if(s === S_ATTR_SPACE){
				s = S_EQ;
			}else{
				//fatalError: equal must after attrName or space after attrName
				throw new Error('attribute equal must after attrName');
			}
			break;
		case '\'':
		case '"':
			if(s === S_EQ || s === S_ATTR //|| s == S_ATTR_SPACE
				){//equal
				if(s === S_ATTR){
					errorHandler.warning('attribute value must after "="')
					attrName = source.slice(start,p)
				}
				start = p+1;
				p = source.indexOf(c,start)
				if(p>0){
					value = source.slice(start,p).replace(/&#?\w+;/g,entityReplacer);
					el.add(attrName,value,start-1);
					s = S_ATTR_END;
				}else{
					//fatalError: no end quot match
					throw new Error('attribute value no end \''+c+'\' match');
				}
			}else if(s == S_ATTR_NOQUOT_VALUE){
				value = source.slice(start,p).replace(/&#?\w+;/g,entityReplacer);
				//console.log(attrName,value,start,p)
				el.add(attrName,value,start);
				//console.dir(el)
				errorHandler.warning('attribute "'+attrName+'" missed start quot('+c+')!!');
				start = p+1;
				s = S_ATTR_END
			}else{
				//fatalError: no equal before
				throw new Error('attribute value must after "="');
			}
			break;
		case '/':
			switch(s){
			case S_TAG:
				el.setTagName(source.slice(start,p));
			case S_ATTR_END:
			case S_TAG_SPACE:
			case S_TAG_CLOSE:
				s =S_TAG_CLOSE;
				el.closed = true;
			case S_ATTR_NOQUOT_VALUE:
			case S_ATTR:
			case S_ATTR_SPACE:
				break;
			//case S_EQ:
			default:
				throw new Error("attribute invalid close char('/')")
			}
			break;
		case ''://end document
			//throw new Error('unexpected end of input')
			errorHandler.error('unexpected end of input');
			if(s == S_TAG){
				el.setTagName(source.slice(start,p));
			}
			return p;
		case '>':
			switch(s){
			case S_TAG:
				el.setTagName(source.slice(start,p));
			case S_ATTR_END:
			case S_TAG_SPACE:
			case S_TAG_CLOSE:
				break;//normal
			case S_ATTR_NOQUOT_VALUE://Compatible state
			case S_ATTR:
				value = source.slice(start,p);
				if(value.slice(-1) === '/'){
					el.closed  = true;
					value = value.slice(0,-1)
				}
			case S_ATTR_SPACE:
				if(s === S_ATTR_SPACE){
					value = attrName;
				}
				if(s == S_ATTR_NOQUOT_VALUE){
					errorHandler.warning('attribute "'+value+'" missed quot(")!!');
					el.add(attrName,value.replace(/&#?\w+;/g,entityReplacer),start)
				}else{
					if(currentNSMap[''] !== 'http://www.w3.org/1999/xhtml' || !value.match(/^(?:disabled|checked|selected)$/i)){
						errorHandler.warning('attribute "'+value+'" missed value!! "'+value+'" instead!!')
					}
					el.add(value,value,start)
				}
				break;
			case S_EQ:
				throw new Error('attribute value missed!!');
			}
//			console.log(tagName,tagNamePattern,tagNamePattern.test(tagName))
			return p;
		/*xml space '\x20' | #x9 | #xD | #xA; */
		case '\u0080':
			c = ' ';
		default:
			if(c<= ' '){//space
				switch(s){
				case S_TAG:
					el.setTagName(source.slice(start,p));//tagName
					s = S_TAG_SPACE;
					break;
				case S_ATTR:
					attrName = source.slice(start,p)
					s = S_ATTR_SPACE;
					break;
				case S_ATTR_NOQUOT_VALUE:
					var value = source.slice(start,p).replace(/&#?\w+;/g,entityReplacer);
					errorHandler.warning('attribute "'+value+'" missed quot(")!!');
					el.add(attrName,value,start)
				case S_ATTR_END:
					s = S_TAG_SPACE;
					break;
				//case S_TAG_SPACE:
				//case S_EQ:
				//case S_ATTR_SPACE:
				//	void();break;
				//case S_TAG_CLOSE:
					//ignore warning
				}
			}else{//not space
//S_TAG,	S_ATTR,	S_EQ,	S_ATTR_NOQUOT_VALUE
//S_ATTR_SPACE,	S_ATTR_END,	S_TAG_SPACE, S_TAG_CLOSE
				switch(s){
				//case S_TAG:void();break;
				//case S_ATTR:void();break;
				//case S_ATTR_NOQUOT_VALUE:void();break;
				case S_ATTR_SPACE:
					var tagName =  el.tagName;
					if(currentNSMap[''] !== 'http://www.w3.org/1999/xhtml' || !attrName.match(/^(?:disabled|checked|selected)$/i)){
						errorHandler.warning('attribute "'+attrName+'" missed value!! "'+attrName+'" instead2!!')
					}
					el.add(attrName,attrName,start);
					start = p;
					s = S_ATTR;
					break;
				case S_ATTR_END:
					errorHandler.warning('attribute space is required"'+attrName+'"!!')
				case S_TAG_SPACE:
					s = S_ATTR;
					start = p;
					break;
				case S_EQ:
					s = S_ATTR_NOQUOT_VALUE;
					start = p;
					break;
				case S_TAG_CLOSE:
					throw new Error("elements closed character '/' and '>' must be connected to");
				}
			}
		}//end outer switch
		//console.log('p++',p)
		p++;
	}
}
/**
 * @return true if has new namespace define
 */
function appendElement(el,domBuilder,currentNSMap){
	var tagName = el.tagName;
	var localNSMap = null;
	//var currentNSMap = parseStack[parseStack.length-1].currentNSMap;
	var i = el.length;
	while(i--){
		var a = el[i];
		var qName = a.qName;
		var value = a.value;
		var nsp = qName.indexOf(':');
		if(nsp>0){
			var prefix = a.prefix = qName.slice(0,nsp);
			var localName = qName.slice(nsp+1);
			var nsPrefix = prefix === 'xmlns' && localName
		}else{
			localName = qName;
			prefix = null
			nsPrefix = qName === 'xmlns' && ''
		}
		//can not set prefix,because prefix !== ''
		a.localName = localName ;
		//prefix == null for no ns prefix attribute 
		if(nsPrefix !== false){//hack!!
			if(localNSMap == null){
				localNSMap = {}
				//console.log(currentNSMap,0)
				_copy(currentNSMap,currentNSMap={})
				//console.log(currentNSMap,1)
			}
			currentNSMap[nsPrefix] = localNSMap[nsPrefix] = value;
			a.uri = 'http://www.w3.org/2000/xmlns/'
			domBuilder.startPrefixMapping(nsPrefix, value) 
		}
	}
	var i = el.length;
	while(i--){
		a = el[i];
		var prefix = a.prefix;
		if(prefix){//no prefix attribute has no namespace
			if(prefix === 'xml'){
				a.uri = 'http://www.w3.org/XML/1998/namespace';
			}if(prefix !== 'xmlns'){
				a.uri = currentNSMap[prefix || '']
				
				//{console.log('###'+a.qName,domBuilder.locator.systemId+'',currentNSMap,a.uri)}
			}
		}
	}
	var nsp = tagName.indexOf(':');
	if(nsp>0){
		prefix = el.prefix = tagName.slice(0,nsp);
		localName = el.localName = tagName.slice(nsp+1);
	}else{
		prefix = null;//important!!
		localName = el.localName = tagName;
	}
	//no prefix element has default namespace
	var ns = el.uri = currentNSMap[prefix || ''];
	domBuilder.startElement(ns,localName,tagName,el);
	//endPrefixMapping and startPrefixMapping have not any help for dom builder
	//localNSMap = null
	if(el.closed){
		domBuilder.endElement(ns,localName,tagName);
		if(localNSMap){
			for(prefix in localNSMap){
				domBuilder.endPrefixMapping(prefix) 
			}
		}
	}else{
		el.currentNSMap = currentNSMap;
		el.localNSMap = localNSMap;
		//parseStack.push(el);
		return true;
	}
}
function parseHtmlSpecialContent(source,elStartEnd,tagName,entityReplacer,domBuilder){
	if(/^(?:script|textarea)$/i.test(tagName)){
		var elEndStart =  source.indexOf('</'+tagName+'>',elStartEnd);
		var text = source.substring(elStartEnd+1,elEndStart);
		if(/[&<]/.test(text)){
			if(/^script$/i.test(tagName)){
				//if(!/\]\]>/.test(text)){
					//lexHandler.startCDATA();
					domBuilder.characters(text,0,text.length);
					//lexHandler.endCDATA();
					return elEndStart;
				//}
			}//}else{//text area
				text = text.replace(/&#?\w+;/g,entityReplacer);
				domBuilder.characters(text,0,text.length);
				return elEndStart;
			//}
			
		}
	}
	return elStartEnd+1;
}
function fixSelfClosed(source,elStartEnd,tagName,closeMap){
	//if(tagName in closeMap){
	var pos = closeMap[tagName];
	if(pos == null){
		//console.log(tagName)
		pos =  source.lastIndexOf('</'+tagName+'>')
		if(pos<elStartEnd){//忘记闭合
			pos = source.lastIndexOf('</'+tagName)
		}
		closeMap[tagName] =pos
	}
	return pos<elStartEnd;
	//} 
}
function _copy(source,target){
	for(var n in source){target[n] = source[n]}
}
function parseDCC(source,start,domBuilder,errorHandler){//sure start with '<!'
	var next= source.charAt(start+2)
	switch(next){
	case '-':
		if(source.charAt(start + 3) === '-'){
			var end = source.indexOf('-->',start+4);
			//append comment source.substring(4,end)//<!--
			if(end>start){
				domBuilder.comment(source,start+4,end-start-4);
				return end+3;
			}else{
				errorHandler.error("Unclosed comment");
				return -1;
			}
		}else{
			//error
			return -1;
		}
	default:
		if(source.substr(start+3,6) == 'CDATA['){
			var end = source.indexOf(']]>',start+9);
			domBuilder.startCDATA();
			domBuilder.characters(source,start+9,end-start-9);
			domBuilder.endCDATA() 
			return end+3;
		}
		//<!DOCTYPE
		//startDTD(java.lang.String name, java.lang.String publicId, java.lang.String systemId) 
		var matchs = split(source,start);
		var len = matchs.length;
		if(len>1 && /!doctype/i.test(matchs[0][0])){
			var name = matchs[1][0];
			var pubid = len>3 && /^public$/i.test(matchs[2][0]) && matchs[3][0]
			var sysid = len>4 && matchs[4][0];
			var lastMatch = matchs[len-1]
			domBuilder.startDTD(name,pubid && pubid.replace(/^(['"])(.*?)\1$/,'$2'),
					sysid && sysid.replace(/^(['"])(.*?)\1$/,'$2'));
			domBuilder.endDTD();
			
			return lastMatch.index+lastMatch[0].length
		}
	}
	return -1;
}



function parseInstruction(source,start,domBuilder){
	var end = source.indexOf('?>',start);
	if(end){
		var match = source.substring(start,end).match(/^<\?(\S*)\s*([\s\S]*?)\s*$/);
		if(match){
			var len = match[0].length;
			domBuilder.processingInstruction(match[1], match[2]) ;
			return end+2;
		}else{//error
			return -1;
		}
	}
	return -1;
}

/**
 * @param source
 */
function ElementAttributes(source){
	
}
ElementAttributes.prototype = {
	setTagName:function(tagName){
		if(!tagNamePattern.test(tagName)){
			throw new Error('invalid tagName:'+tagName)
		}
		this.tagName = tagName
	},
	add:function(qName,value,offset){
		if(!tagNamePattern.test(qName)){
			throw new Error('invalid attribute:'+qName)
		}
		this[this.length++] = {qName:qName,value:value,offset:offset}
	},
	length:0,
	getLocalName:function(i){return this[i].localName},
	getLocator:function(i){return this[i].locator},
	getQName:function(i){return this[i].qName},
	getURI:function(i){return this[i].uri},
	getValue:function(i){return this[i].value}
//	,getIndex:function(uri, localName)){
//		if(localName){
//			
//		}else{
//			var qName = uri
//		}
//	},
//	getValue:function(){return this.getValue(this.getIndex.apply(this,arguments))},
//	getType:function(uri,localName){}
//	getType:function(i){},
}




function _set_proto_(thiz,parent){
	thiz.__proto__ = parent;
	return thiz;
}
if(!(_set_proto_({},_set_proto_.prototype) instanceof _set_proto_)){
	_set_proto_ = function(thiz,parent){
		function p(){};
		p.prototype = parent;
		p = new p();
		for(parent in thiz){
			p[parent] = thiz[parent];
		}
		return p;
	}
}

function split(source,start){
	var match;
	var buf = [];
	var reg = /'[^']+'|"[^"]+"|[^\s<>\/=]+=?|(\/?\s*>|<)/g;
	reg.lastIndex = start;
	reg.exec(source);//skip <
	while(match = reg.exec(source)){
		buf.push(match);
		if(match[1])return buf;
	}
}

exports.XMLReader = XMLReader;


},{}],68:[function(require,module,exports){
/**
 * Module dependencies.
 */
var dom = require('xmldom')
  , DOMParser = dom.DOMParser
  , XMLSerializer = dom.XMLSerializer;


/**
 * Wraps and returns a new collection of elements.
 *
 * Examples:
 *
 *     $('<xml/>');
 *
 * @param {String|Node|Collection|Array} nodes XML string or DOM nodes to wrap.
 * @return {Collection} The wrapped nodes.
 * @api public
 */
function wrap(nodes) {
  nodes = nodes || [];
  if ('string' == typeof nodes) {
    nodes = new DOMParser().parseFromString(nodes);
  }

  if (nodes.attrNS && nodes._related) {
    // attempt to re-wrap Collection, return it directly
    return nodes;
  } else if (nodes.documentElement) {
    nodes = [ nodes.documentElement ];
  } else if (nodes.nodeType) {
    nodes = [ nodes ];
  }
  return new Collection(nodes);
}

/**
 * Returns an array consisting of unique elements.
 *
 * @param {Array} ar
 * @return {Array}
 * @api private
 */
function unique(ar) {
  var a = []
    , i = -1
    , j
    , has;
  while (++i < ar.length) {
    j = -1;
    has = false;
    while (++j < a.length) {
      if (a[j] === ar[i]) {
        has = true;
        break;
      }
    }
    if (!has) { a.push(ar[i]); }
  }
  return a;
}


/**
 * Creates an instance of `Collection`.
 *
 * @constructor
 * @param {Array} nodes DOM elements to wrap.
 * @api protected
 */
function Collection(nodes) {
  this.length = 0;
  if (nodes) {
    nodes = unique(nodes);
    this.length = nodes.length;
    // add each node to an index-based property on collection, in order to
    // appear "array"-like
    for (var i = 0, len = nodes.length; i < len; i++) {
      this[i] = nodes[i];
    }
  }
}

/**
 * Iterate over a set, executing a function for each matched element.
 *
 * Examples:
 *
 *     els.forEach(function(el) {
 *       console.log($(el.text()));
 *     });
 *
 * @param {Function} fn Function to execute for each element.
 * @param {Object} [scope] Object to use as `this` when executing `fn`.
 * @return {Collection} The wrapped root element.
 * @api public
 */
Collection.prototype.each =
Collection.prototype.forEach = function(fn, scope) {
  for (var i = 0, len = this.length; i < len; i++) {
    fn.call(scope, this[i], i, this);
  }
  return this;
};

/**
 * Tests whether all elements in the set pass the test implemented by the
 * provided function.
 *
 * Examples:
 *
 *     els.every(function(el) {
 *       return el.name() == 'foo';
 *     });
 * 
 * @param {Function} fn Function to test for each element.
 * @param {Object} [scope] Object to use as `this` when executing `fn`.
 * @return {Boolean} `true` if all elements pass, otherwise `false`.
 * @api public
 */
Collection.prototype.every = function(fn, scope) {
  var rv;
  for (var i = 0, len = this.length; i < len; i++) {
    rv = fn.call(scope, this[i], i, this);
    if (!rv) { return false; }
  }
  return true;
};

/**
 * Tests whether some elements in the set pass the test implemented by the
 * provided function.
 *
 * Examples:
 *
 *     els.some(function(el) {
 *       return el.name() == 'foo';
 *     });
 *
 * @param {Function} fn Function to test for each element.
 * @param {Object} [scope] Object to use as `this` when executing `fn`.
 * @return {Boolean} `true` if all elements pass, otherwise `false`.
 * @api public
 */
Collection.prototype.some = function(fn, scope) {
  var rv;
  for (var i = 0, len = this.length; i < len; i++) {
    rv = fn.call(scope, this[i], i, this);
    if (rv) { return false; }
  }
  return false;
};

/**
 * Iterate over a set, creating a new array with the results of executing a
 * function for each matched element.
 *
 * Examples:
 *
 *     els.map(function(el) {
 *       return $(el.text());
 *     });
 *
 * @param {Function} fn Function that produces an item in the new array from an
 *                      element in the set.
 * @param {Object} [scope] Object to use as `this` when executing `fn`.
 * @return {Array} The mapped array.
 * @api public
 */
Collection.prototype.map = function(fn, scope, filter) {
  var m = [], n;
  for (var i = 0, len = this.length; i < len; i++) {
    n = fn.call(scope, this[i], i, this);
    if (n || n === false || !filter) { m.push(n); }
  }
  return m;
};

/**
 * Get the wrapped root element of the first element in the set of matched
 * elements.
 *
 * Examples:
 *
 *     var root = grandchild.root()
 *       , xml = root.toString();
 *
 * @return {Collection} The wrapped root element.
 * @api public
 */
Collection.prototype.root =
Collection.prototype.tree = function() {
  return wrap((this[0] ? this[0].ownerDocument : []));
};

/**
 * Get the parent of each element in the current set of matched elements,
 * optionally filtered by a name and namespace.
 *
 * Note that this will only select from immediate parents of elements in
 * the set.  It will not traverse multiple levels up; to do that, you must
 * chain calls to this function.
 *
 * Examples:
 *
 *     var p = el.parent();
 *
 *     var p = el.parent('foo');
 *
 *     var p = el.parent('foo', 'urn:example:foo');
 *
 * @param {String} [name] XML element name.
 * @param {String} [ns] XML namespace in which element resides.
 * @return {Collection} The wrapped parent element (or elements).
 * @api public
 */
Collection.prototype.up =
Collection.prototype.parent = function(name, ns) {
  return this._related('parentNode', name, ns, 1);
};

/**
 * Get the children of each element in the set of matched elements, optionally
 * filtered by a name and namespace.
 *
 * Note that this will only select from immediate children of elements in
 * the set.  It will not traverse multiple levels down; to do that, you must
 * chain calls to this function.
 *
 * Examples:
 *
 *     var c = el.children();
 *
 *     var c = el.children('foo');
 *
 *     var c = el.children('foo', 'urn:example:foo');
 *
 * @param {String} [name] XML element name.
 * @param {String} [ns] XML namespace in which element resides.
 * @return {Collection} The wrapped children elements.
 * @api public
 */
Collection.prototype.children = function(name, ns) {
  var arr = [];
  this.forEach(function(n) {
    for (var c = n.firstChild; c; c = c.nextSibling) {
      if (c.nodeType === 1 && (!name || name === c.localName) && (!ns || ns === c.namespaceURI)) {
        arr.push(c);
      }
    }
  });
  return wrap(arr);
};

/**
 * Get the siblings of each element in the set of matched elements, optionally
 * filtered by a name and namespace.
 *
 * Examples:
 *
 *     var c = el.siblings();
 *
 *     var c = el.siblings('foo');
 *
 *     var c = el.siblings('foo', 'urn:example:foo');
 *
 * @param {String} [name] XML element name.
 * @param {String} [ns] XML namespace in which element resides.
 * @return {Collection} The wrapped sibling elements.
 * @api public
 */
Collection.prototype.siblings = function(name, ns) {
  var arr = [];
  this.forEach(function(n) {
    var it = n;
    for (n = n.parentNode.firstChild ; n; n = n.nextSibling) {
      if (n.nodeType === 1 && (!name || name === n.localName) && (!ns || ns === n.namespaceURI) && n !== it) {
        arr.push(n);
      }
    }
  });
  return wrap(arr);
};

/**
 * Get the wrapped element at position `i` in the set of matched elements.
 *
 * Examples:
 *
 *     var el = els.at(2);
 *
 * @param {String} i Index of element.
 * @return {Collection} The wrapped element.
 * @api public
 */
Collection.prototype.at = function(i) {
  return wrap(this[i]);
};

/**
 * Reduce the set of matched elements to the first in the set, optionally
 * filtered by a name and namespace.
 *
 * Examples:
 *
 *     var children = el.children();
 *
 *     for (var child = children.first(); child.length > 0; child = child.next()) {
 *       // process all child elements
 *     }
 *
 *     for (var child = children.first('foo'); child.length > 0; child = child.next('foo')) {
 *       // process <foo/> child elements
 *     }
 *
 *     for (var child = children.first('foo', 'urn:example:foo'); child.length > 0; child = child.next('foo', 'urn:example:foo')) {
 *       // process <foo xmlns="urn:example:foo"/> child elements
 *     }
 *
 * @param {String} [name] XML element name.
 * @param {String} [ns] XML namespace in which element resides.
 * @return {Collection} The wrapped first element.
 * @api public
 */
Collection.prototype.first = function(name, ns) {
  var n;
  for (var i = 0, len = this.length; i < len; ++i) {
    n = this[i];
    if ((!name || name === n.localName) && (!ns || ns === n.namespaceURI)) { return wrap(n); }
  }
  return wrap([]);
};

/**
 * Reduce the set of matched elements to the final one in the set, optionally
 * filtered by name and namespace.
 *
 * Examples:
 *
 *     var children = el.children();
 *
 *     for (var child = children.last(); child.length > 0; child = child.prev()) {
 *       // process all child elements in reverse
 *     }
 *
 *     for (var child = children.last('foo'); child.length > 0; child = child.prev('foo')) {
 *       // process <foo/> child elements in reverse
 *     }
 *
 *     for (var child = children.last('foo', 'urn:example:foo'); child.length > 0; child = child.prev('foo', 'urn:example:foo')) {
 *       // process <foo xmlns="urn:example:foo"/> child elements in reverse
 *     }
 *
 * @param {String} [name] XML element name.
 * @param {String} [ns] XML namespace in which element resides.
 * @return {Collection} The wrapped last element.
 * @api public
 */
Collection.prototype.last = function(name, ns) {
  var n;
  for (var i = this.length - 1; i > 0; --i) {
    n = this[i];
    if ((!name || name === n.localName) && (!ns || ns === n.namespaceURI)) { return wrap(n); }
  }
  return wrap([]);
};

/**
 * Get the immediately following sibling of each element in the set of matched
 * elements, optionally filtered by name and namespace.
 *
 * @param {String} [name] XML element name.
 * @param {String} [ns] XML namespace in which element resides.
 * @return {Collection} The wrapped next element (or elements).
 * @api public
 */
Collection.prototype.next = function(name, ns) {
  return this._related('nextSibling', name, ns);
};

/**
 * Get the immediately preceding sibling of each element in the set of matched
 * elements, optionally filtered by name and namespace.
 *
 * @param {String} [name] XML element name.
 * @param {String} [ns] XML namespace in which element resides.
 * @return {Collection} The wrapped next element (or elements).
 * @api public
 */
Collection.prototype.prev =
Collection.prototype.previous = function(name, ns) {
  return this._related('previousSibling', name, ns);
};

/**
 * Traverse a relation between elements, up to an optional limit and optionally
 * filtered by name and namespace.
 *
 * @param {String} rel Element relation.
 * @param {String} [name] XML element name.
 * @param {String} [ns] XML namespace in which element resides.
 * @param {Number} [limit] Maximum times the relation will be followed.
 * @return {Collection} The wrapped next element (or elements).
 * @api private
 */
Collection.prototype._related = function(rel, name, ns, limit) {
  limit = (limit !== undefined ? limit : Number.MAX_VALUE);
  return wrap(this.map(function(n) {
    var i = 0;
    n = n[rel];
    while (n && (n.nodeType !== 1 || (name && name !== n.localName) || (ns && ns !== n.namespaceURI)) && ++i < limit) {
      n = n[rel];
    }
    return (i < limit ? n : null);
  }, null, true));
};

/**
 * Test if the element has name, optionally within XML namspace.
 *
 * Examples:
 *
 *     var ok = el.is('foo');
 *
 *     var ok = el.is('foo', 'urn:example:foo');
 *
 * @param {String} name Element name to test for.
 * @param {String} [ns] XML namespace to test for.
 * @return {Boolean} `true` if test passes, otherwise `false`.
 * @api public
 */
Collection.prototype.is = function(name, ns) {
  return (name == this.name() && (!ns || ns === this.ns()));
};

/**
 * Returns XML element name of the first element in the set of matched elements.
 *
 * Examples:
 *
 *     var n = el.name();
 *
 * @return {String} XML element name.
 * @api public
 */
Collection.prototype.name = function() {
  return (this[0] ? this[0].localName : null);
};

/**
 * Returns XML namespace in which the first element in the set of matched
 * elements resides.
 *
 * Examples:
 *
 *     var ns = el.ns();
 *
 * @return {String} XML namespace.
 * @api public
 */
Collection.prototype.ns =
Collection.prototype.namespace = function() {
  return (this[0] ? this[0].namespaceURI : null);
};

/**
 * Get the value of an attribute for the first element in the set of matched
 * elements or set one or more attributes for every matched element.
 *
 * Examples:
 *
 *     var a = el.attr('foo');
 *
 *     el.attr('bar', 'baz');
 *
 *     el.attr({ bar: 'baz', qux: 'garply' });
 *
 * @param {String|Object} name Name of attribute or hash of keys and values.
 * @param {String} [val] Value to which attribute will be set.
 * @return {String|Collection} The value of attribute or `this` for chaining.
 * @api public
 */
Collection.prototype.attr = 
Collection.prototype.attrs = function(name, val) {
  if (val || typeof name == 'object') {
    var attrs = {};
    if (val) { attrs[name] = val; }
    else { attrs = name; }
    return this.forEach(function(n) {
      for (var name in attrs) {
        n && n.setAttribute(name, attrs[name]);
      }
    });
  }
  return (this[0] ? this[0].getAttribute(name) || null : null);
};

/**
 * Get the value of a namespaced attribute for the first element in the set of
 * matched elements or set the namespaced attributes for every matched element.
 *
 * Examples:
 *
 *     var a = el.attrNS('foo', 'urn:example:foo');
 *
 *     el.attr('bar', 'urn:example:foo', 'baz');
 *
 * @param {String} name Name of attribute.
 * @param {String} ns Namespace of attribute.
 * @param {String} [val] Value to which attribute will be set.
 * @return {String|Collection} The value of attribute or `this` for chaining.
 * @api public
 */
Collection.prototype.attrNS = function(name, ns, val) {
  if (val) {
    return this.forEach(function(n) {
      n && n.setAttributeNS(ns, name, val);
    });
  }
  return (this[0] ? this[0].getAttributeNS(ns, name) || null : null);
};

/**
 * Get the text contents for the first element in the set of matched elements or
 * set the text contents of the matched elements.
 *
 * Examples:
 *
 *     var t = el.text();
 *
 *     el.text('foo');
 *
 * @param {String} [val] Value to which text content will be set.
 * @return {String|Collection} The text content or `this` for chaining.
 * @api public
 */
Collection.prototype.t = 
Collection.prototype.text = function(val) {
  if (val) {
    return this.empty().forEach(function(n) {
      var doc = n.ownerDocument
        , c = doc.createTextNode(val);
      n.appendChild(c);
    });
  }
  return (this[0] ? this[0].textContent || null : null);
};

Collection.prototype.c = function(name, attrs, text) {
  var self = this;
  var arr = this.map(function(n) {
    var el = self._build(name, attrs);
    if (!el) { return; }
    if (text) {
      var doc = n.ownerDocument
        , txt = doc.createTextNode(text);
      el.appendChild(txt);
    }
    n.appendChild(el);
    return el;
  });
  return wrap(arr);
}

Collection.prototype._build = function(name, ns, attrs) {
  if (!this[0]) { return null; }
  if ('object' == typeof ns) {
    attrs = ns;
    ns = undefined;
  }
  attrs = attrs || {};

  if (attrs.xmlns) {
    ns = attrs.xmlns;
    delete attrs.xmlns;
  }
  
  var doc = this[0].ownerDocument
    , el;
  if (ns) {
    el = doc.createElementNS(ns, name);
    // FIXME: Hack to force xmldom to serialize the namespace.
    el.setAttribute('xmlns', ns);
  } else {
    el = doc.createElement(name);
  }
  for (var name in attrs) {
    el.setAttribute(name, attrs[name]);
  }
  return el;
};

/**
 * Remove all child nodes of the set of matched elements.
 *
 * Examples:
 *
 *     el.empty();
 *
 * @return {Collection} `this` for chaining.
 * @api public
 */
Collection.prototype.empty = function() {
  return this.forEach(function(n) {
    while (n.firstChild) {
      n.removeChild(n.firstChild);
    }
  });
};

/**
 * Returns serialized XML of the first element in the set of matched elements.
 *
 * Examples:
 *
 *     var xml = el.toString();
 *
 * @return {String} Serialized XML.
 * @api public
 */
Collection.prototype.toString = function() {
  return (this[0] ? new XMLSerializer().serializeToString(this[0]) : null);
};


/**
 * Expose `Collection`.
 */
exports = module.exports = Collection;

/**
 * Export functions.
 */
exports.wrap = wrap;

},{"xmldom":65}],69:[function(require,module,exports){
/**
 * Module dependencies.
 */
var Collection = require('./collection');

/**
 * Expose `wrap` as package function.
 */
module.exports = Collection.wrap;

},{"./collection":68}],"main-action":[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _passport = require('passport');

var _passport2 = _interopRequireDefault(_passport);

var _passportGithub = require('passport-github');

var _passportGithub2 = _interopRequireDefault(_passportGithub);

var _passportFacebook = require('passport-facebook');

var _passportFacebook2 = _interopRequireDefault(_passportFacebook);

var _passportTwitter = require('passport-twitter');

var _passportTwitter2 = _interopRequireDefault(_passportTwitter);

var _passportGoogle = require('passport-google');

var _passportGoogle2 = _interopRequireDefault(_passportGoogle);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _authenticate(params) {
    return new Promise(function (resolve, reject) {

        var passport_module_name = 'passport-' + params.auth_provider;

        var strategy_impl = null;

        try {
            strategy_impl = require(passport_module_name).Strategy;
        } catch (err) {
            console.log(err);
            reject({
                "message": "Could not load " + passport_module_name,
                "error": err.toString()
            });
        }

        var strategy = new strategy_impl({
            clientID: params.client_id,
            consumerKey: params.client_id,
            clientSecret: params.client_secret,
            consumerSecret: params.client_secret,
            callbackURL: params.callback_url
        }, function (accessToken, refreshToken, profile, done) {
            console.log("Logged in successfully ... ");
            response.body = {
                "token": accessToken,
                "refreshToken": refreshToken,
                "profile": profile
            };

            resolve(get_action_response(response));
        });

        // a lightweight request object to be used in the serverless context
        var request = {
            query: params, // expose query parameters
            session: strategy._requestTokenStore || strategy._stateStore // inherit the session from Passport
        };

        if (strategy._requestTokenStore) {
            // OAuth 1 requires a session
            strategy._requestTokenStore.get = function (req, token, cb) {
                // NOTE: The oauth_verifier parameter will be supplied in the query portion
                //       of the redirect URL, if the server supports OAuth 1.0a.
                var oauth_verifier = req.query.oauth_verifier || null;
                return cb(null, oauth_verifier);
            };
            strategy._requestTokenStore.destroy = function (req, token, cb) {
                // simply invoke the callback directly
                cb();
            };
        }

        // a lightweight response object to be used in the serverless context
        var response = {
            headers: {},
            setHeader: function setHeader(name, val) {
                response.headers[name] = val;
            },
            end: function end() {
                console.log("response end()");
                resolve(get_action_response(response));
            }
        };

        var get_action_response = function get_action_response(resp) {
            if (resp.body instanceof Error) {
                console.error(resp.body);
                resp.body = resp.body.toString();
            }
            return {
                headers: resp.headers,
                statusCode: resp.statusCode,
                body: resp.body || ''
            };
        };

        var next = function next(opts) {
            console.log("next()");
            response.body = opts;
            resolve(get_action_response(response));
        };

        _passport2.default.use(strategy);

        var scopes = params.scopes || null;
        if (scopes !== null) {
            scopes = scopes.split(",");
        }

        var res = _passport2.default.authenticate(params.auth_provider, {
            scope: scopes,
            successRedirect: '/success', // TODO: TBD should this be read from parameters ?
            failureRedirect: '/login' // TODO: TBD should this be read from parameters ?
        });

        res(request, response, next);
    });
}

/**
 * The entry point for the action.
 * @param params Input object
 * @returns {Promise}
 */
function main(params) {
    console.log(params);
    return _authenticate(params);
}

exports.default = main;

},{"passport":57,"passport-facebook":13,"passport-github":17,"passport-google":20,"passport-twitter":50}]},{},[]);
var main = require('main-action').default;
