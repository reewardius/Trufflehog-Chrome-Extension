// this is the background code...

// listen for our browerAction to be clicked
// for the current tab, inject the "inject.js" file & execute it


var currentTab;
var version = "1.0";

chrome.tabs.query( //get current Tab
    {
        currentWindow: true,
        active: true
    },
    function(tabArray) {
        currentTab = tabArray[0];
        chrome.tabs.executeScript(currentTab.ib, {
            file: 'inject.js'
        });
    }
)

chrome.storage.sync.get(['ranOnce'], function(ranOnce) {
    if (! ranOnce.ranOnce){
        chrome.storage.sync.set({"ranOnce": true});
        chrome.storage.sync.set({"originDenyList": ["https://www.google.com"]});
    }

})


let specifics = {
    "ACCESS_KEY": "(access_key|ACCESS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "ACCESS_TOKEN": "(access_token|ACCESS_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "AMAZONAWS": "(amazonaws|AMAZONAWS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "AMZN MWS Payment": "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AMZN MWS Payment": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "APISECRET": "(apiSecret|APISECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "APPKEY": "(appkey|APPKEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "APPLICATION_KEY": "(application_key|APPLICATION_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "APPSECRET": "(appsecret|APPSECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "AUTH key": "(auth|AUTH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "AWS s3": "s3-[a-zA-Z0-9-\.\_\/]",
    "AWS s3": "s3.amazonaws.com/[a-zA-Z0-9-\.\_]",
    "AWS s3": "s3://[a-zA-Z0-9-\.\_]+",
    "AWS_ACCESS": "(aws_access|AWS_ACCESS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "AWS_KEY": "(aws_key|AWS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "AWS_SECRET": "(aws_secret|AWS_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]7}",
    "AWS_TOKEN": "(aws_token|AWS_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Access Token for Prod": "access_token,production$[0-9a-z]{161[0-9a,]{32}",
    "Access Token for Prod": "access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Amazon MWS Payment": "amzn.mws]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12}",
    "Amazon Marketplace Web Service": "amzn\.mws\.[0-9a-f]{8}(?:-[0-9a-f]{4}){4}[0-9a-f]{8}",
    "Api Key": "(API|api)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{10}",
    "Api Key": "api[key|_key|\s+]+[a-zA-Z0-9_\-]{7,100}",
    "Api Secret Key": "(api_key|API_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Api Secret Key": "(api_secret|API_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Api Secret Key": "(apidocs|APIDOCS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Api Secret Key": "(apikey|APIKEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Api Secret Key": "(app_key|APP_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Api Secret Key": "(app_secret|APP_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Api Secret Key": "(appkeysecret|APPKEYSECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Api Token for Git": "\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    "AppSpot Key": "(appspot|APPSPOT)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Auth Token key": "(auth_token|AUTH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "BASHRCPASSWORD": "(bashrcpassword|BASHRCPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "BUCKET_PASSWORD": "(bucket_password|BUCKET_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Bank Token Id Stripe": "btok_",
    "Basic Header": "Basic [a-zA-Z0-9=:_\+\/-]{5,100}",
    "Basic Header": "Basic [a-zA-Z0-9]",
    "Bearer Token": "Bearer [\w-.=:_+/]{5,}",
    "Bearer Token": "Bearer [a-zA-Z0-9]",
    "Bearer Token": "ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
    "CLIENT_SECRET": "(client_secret|CLIENT_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "CLOUDFRONT": "(cloudfront|CLOUDFRONT)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "CODECOV_TOKEN": "(codecov_token|CODECOV_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "CONFIG": "(config|CONFIG)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "CONN.LOGIN": "(conn.login|CONN.LOGIN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "CONNECTIONSTRING": "(connectionstring|CONNECTIONSTRING)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "CONSUMER_KEY": "(consumer_key|CONSUMER_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "CREDENTIALS": "(credentials|CREDENTIALS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Certificate Private Key": "([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    "Cloudflare key": "key-[0-9a-zA-Z]{32}",
    "DATABASE_PASSWORD": "(database_password|DATABASE_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "DBPASSWD": "(dbpasswd|DBPASSWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "DBPASSWD": "(dbpassword|DBPASSWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "DBUSER": "(dbuser|DBUSER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{3}",
    "DB_PASSWORD": "(db_password|DB_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "DB_USERNAME": "(db_username|DB_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "DNSKEY": "AAAA[A-Za-z0-9_-]{5,100}:[A-Za-z0-9_-]{140}",
    "DOT-FILES": "(dot-files|DOT-FILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "DOTFILES": "(dotfiles|DOTFILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "ENCRYPTION_KEY": "(encryption_key|ENCRYPTION_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Email Matcher": "(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]{2,},
    "FABRICAPISECRET": "(fabricApiSecret|FABRICAPISECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "FB_SECRET": "(fb_secret|FB_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "FIREBASE": "(firebase|FIREBASE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "FTP": "(ftp|FTP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Facebook API": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook key": "(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}",
    "Facebook key2": "(?i)(facebook|fb).{0,20}['"][0-9]{13,17}",
    "GH_TOKEN": "(gh_token|GH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "GITHUB_KEY": "(github_key|GITHUB_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "GITHUB_TOKEN": "(github_token|GITHUB_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "GITLAB": "(gitlab|GITLAB)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "GMAIL_PASSWORD": "(gmail_password|GMAIL_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "GMAIL_USERNAME": "(gmail_username|GMAIL_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Github token jekyll": "(JEKYLL_GITHUB_TOKEN|JEKYLL_GITHUB_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Github token": "(GITHUB|github)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{10}",
    "Github": "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*",
    "Google Auth 2.0": "ya29\.[0-9A-Za-z\-_]+",
    "Google Cloud Platform": "AC[a-zA-Z0-9_\-]{32}",
    "Google Cloud Platform": "AP[a-zA-Z0-9_\-]{32}",
    "Google Services Api Key": "(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]",
    "HEROKUAPP": "(herokuapp|HEROKUAPP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "INTERNAL": "(internal|INTERNAL)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "IRC_PASS": "(irc_pass|IRC_PASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "KEY": "(key|KEY)(:|=)[0-9A-Za-z\\-]{10}",
    "KEYPASSWORD": "(keyPassword|KEYPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Key for Something": "R_[0-9a-f]{32}",
    "LDAP_PASSWORD": "(ldap_password|LDAP_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "LDAP_USERNAME": "(ldap_username|LDAP_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "LOGIN": "(login|LOGIN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "MAILCHIMP": "(mailchimp|MAILCHIMP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "MAILGUN": "(mailgun|MAILGUN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "MASTER_KEY": "(master_key|MASTER_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
    "MYDOTFILES": "(mydotfiles|MYDOTFILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "MYSQL": "(mysql|MYSQL)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "NODE_ENV": "(node_env|NODE_ENV)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "NPMRC_AUTH": "(npmrc_auth|NPMRC_AUTH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "OAUTH_TOKEN": "(oauth_token|OAUTH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "PASS": "(pass|PASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "PASSWD": "(passwd|PASSWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "PASSWORD": "(password|PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "PASSWORD": "(password|PASSWORD)(:|=| : | = )("|')[0-9A-Za-z\\-]{5,}",
    "PASSWORDS": "(passwords|PASSWORDS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
    "PEMPRIVATE": "(pemprivate|PEMPRIVATE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "PREPROD": "(preprod|PREPROD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "PRIVATE_KEY": "(private_key|PRIVATE_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "PROD": "(prod|PROD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "PWDS": "(pwds|PWDS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "PWDS": "(pwd|PWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Protocols": "(ftp|ftps|http|https)://[A-Za-z0-9-_:\.~]+(@)",
    "RDS.AMAZONAWS.COMPASSWORD": "(rds.amazonaws.compassword|RDS.AMAZONAWS.COMPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "RECAPTCHA Google": "6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$",
    "REDIS_PASSWORD": "(redis_password|REDIS_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "ROOT_PASSWORD": "(root_password|ROOT_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SECRET": "(secret|SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SECRET.PASSWORD": "(secret.password|SECRET.PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SECRETS": "(secrets|SECRETS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SECRET_ACCESS_KEY": "(secret_access_key|SECRET_ACCESS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SECRET_KEY": "(secret_key|SECRET_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SECRET_TOKEN": "(secret_token|SECRET_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SECURE": "(secure|SECURE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SECURITY_CREDENTIALS": "(security_credentials|SECURITY_CREDENTIALS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SEND.KEYS": "(send.keys|SEND.KEYS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SF_USERNAME": "(sf_username|SF_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SLACK_API": "(slack_api|SLACK_API)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SLACK_TOKEN": "(slack_token|SLACK_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SQL_PASSWORD": "(sql_password|SQL_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SSH": "(ssh|SSH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SSH2_AUTH_PASSWORD": "(ssh2_auth_password|SSH2_AUTH_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SSHPASS": "(sshpass|SSHPASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "STAGING": "(staging|STAGING)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "STG": "(stg|STG)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "STOREPASSWORD": "(storePassword|STOREPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "SWAGGER": "(swagger|SWAGGER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Salesforce key": "(SF_USERNAMEsalesforce|SF_USERNAMESALESFORCE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Secret Key": "secret[_-]?0(=| =|:| :)",
    "Secret Token": "token=[0-9A-Za-z\\-]{5,100}",
    "Secret key": "(SECRET|secret)(:|=| : | = )("|')[0-9A-Za-z\\-]{10}",
    "Skack Web Hook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Slack Bot API": "xoxb-[0-9A-Za-z\\-]{50}",
    "Slack Bot API": "xoxp-[0-9A-Za-z\\-]{71}",
    "Slack": "xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Slack": "xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
    "Square Key": "sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}",
    "Square Key": "sq0csp-[ 0-9A-Za-z\\-_]{43}",
    "Square Key": "sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}",
    "Square Key": "sqOatp-[0-9A-Za-z\\-_]{22}",
    "Stripe Key": "SK[0-9a-fA-F]{32}",
    "Stripe Key": "rk_live_[0-9a-zA-Z]{24}",
    "Stripe Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Key": "sk_live_[0-9a-z]{32}}",
    "Stripe key": "(?:r|s)k_live_[0-9a-zA-Z]{24},
    "TESTUSER": "(testuser|TESTUSER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "TEST_": "(test_|TEST_)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",    
    "TOKEN": "(token|TOKEN)(:|=| : | = )("|')[ 0-9A-Za-z\\-]{10}",
    "TOKEN": "TOKEN[\\-|_|A-Z0-9]*(\'|\")?(:|=)(\'|\")?[\\-|_|A-Z0-9]{10}",
    "Twitter key": "(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}",
    "authorizationToken Key": "(authorizationToken|AUTHORIZATIONTOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "aws_access_key_id": "(aws_access_key_id|AWS_ACCESS_KEY_ID)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "key": "(key|KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}",
    "Payeer Secret Payment Key":"P[0-9]{7}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "Advanced Cash Secret":"ac_[0-9a-zA-Z]{24}",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Authorize.Net API Login ID": "([0-9a-zA-Z]{16})",
    "Authorize.Net Transaction Key": "([0-9a-zA-Z]{16})",
    "Authorize.net API Login ID":"[a-zA-Z0-9]{1,20}",
    "Authorize.net Transaction Key":"[a-zA-Z0-9]{16}",
    "Braintree Private Key": "private_key_[0-9a-zA-Z]{32}",
    "Braintree Public Key": "public_key_[0-9a-zA-Z]{16}",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|\"][0-9a-f]{32}['|\"]",
    "GitHub": "[gG][iI][tT][hH][uU][bB].{0,20}['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "Github Auth Creds": "https:\/\/[a-zA-Z0-9]{40}@github\.com",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud OAuth": "\d+-[0-9A-Za-z_]{32}.apps.googleusercontent.com",
    "Google OAuth Access Token": "ya29.[\w-]+",
    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Json Web Token" : "eyJhbGciOiJ",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "PayPal Client ID": "A[0-9a-zA-Z]{16}",
    "PayPal Client ID": "A[a-zA-Z0-9_-]{21}[a-zA-Z0-9_]{1}",
    "PayPal Secret": "EC[0-9a-zA-Z]{32}",
    "PayPal Secret": "EC[a-zA-Z0-9]{217}",
    "Perfect Money Account":"[0-9]{7}",
    "Perfect Money Secret":"U[0-9]{7}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "Skrill Secret Payment":"SKRILL[A-Za-z0-9]{20}",
    "Slack Token": "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square Access Token":"sq0atp-[0-9A-Za-z\\-]{22}",
    "Square Application ID":"sq0appid-[0-9A-Za-z\\-]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Bank Account ID": "ba_[0-9a-zA-Z]{24}",
    "Stripe Connection token in a live environment.": "pst_live_[0-9a-zA-Z]{24}",
    "Stripe Live public key": "pk_live_[0-9a-zA-Z]{24}",
    "Stripe Live restricted key": "rk_live_[0-9a-zA-Z]{24}",
    "Stripe Live secret key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Platform Client ID": "ac_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Connection token": "pst_test_[0-9a-zA-Z]{24}",
    "Stripe Test public key": "pk_test_[0-9a-zA-Z]{24}",
    "Stripe Test restricted key": "rk_test_[0-9a-zA-Z]{24}",
    "Stripe Test secret key": "sk_test_[0-9a-zA-Z]{24}",
    "Stripe Webhook Endpoint ID": "we_[0-9a-zA-Z]{24}",
    "Stripe Webhook Secret": "whsec_[0-9a-zA-Z]{24}",
    "Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth 2": "[tT][wW][iI][tT][tT][eE][rR].*['"][0-9a-zA-Z]{35,44}['"]",
    "Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
    "VirusTotal": "virustotal[_-]?apikey(=| =|:| :)"             
}

let generics = {
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
}

let aws = {
    "AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
}

let denyList = ["AIDAAAAAAAAAAAAAAAAA"]

a = ""
b = ""




var checkData = function(data, src, regexes, fromEncoded=false, parentUrl=undefined, parentOrigin=undefined){
    var findings = [];
    for (let key in regexes){
        let re = new RegExp(regexes[key])
        let match = re.exec(data);
        if (Array.isArray(match)){match = match.toString()}
        if (denyList.includes(match)){
            continue;
        }
        if (match){
            let finding = {};
            finding = {src: src, match:match, key:key, encoded:fromEncoded, parentUrl:parentUrl};
            a = data;
            b = re;
            findings.push(finding);

        }
    }
    if (findings){
        chrome.storage.sync.get(["leakedKeys"], function(result) {
            if (Array.isArray(result.leakedKeys) || ! result.leakedKeys){
                var keys = {};
            }else{
                var keys = result.leakedKeys;
            };
            for (let finding of findings){
                if(Array.isArray(keys[parentOrigin])){
                    var newFinding = true;
                    for (key of keys[parentOrigin]){
                        if (key["src"] == finding["src"] && key["match"] == finding["match"] && key["key"] == finding["key"] && key["encoded"] == finding["encoded"] && key["parentUrl"] == finding["parentUrl"]){
                            newFinding = false;
                            break;
                        }
                    }
                    if(newFinding){
                        keys[parentOrigin].push(finding)
                        chrome.storage.sync.set({"leakedKeys": keys}, function(){
                            updateTabAndAlert(finding);
                        });
                    }
                }else{
                    keys[parentOrigin] = [finding];
                    chrome.storage.sync.set({"leakedKeys": keys}, function(){
                        updateTabAndAlert(finding);
                    })
                }
             }
        })
    }
    let decodedStrings = getDecodedb64(data);
    for (encoded of decodedStrings){
        checkData(encoded[1], src, regexes, encoded[0], parentUrl, parentOrigin);
    }
}
var updateTabAndAlert = function(finding){
    var key = finding["key"];
    var src = finding["src"];
    var match = finding["match"];
    var fromEncoded = finding["encoded"];
    chrome.storage.sync.get(["alerts"], function(result) {
        console.log(result.alerts)
        if (result.alerts == undefined || result.alerts){
            if (fromEncoded){
                alert(key + ": " + match + " found in " + src + " decoded from " + fromEncoded.substring(0,9) + "...");
            }else{
                alert(key + ": " + match + " found in " + src);
            }
        }
    })
    updateTab();
}

var updateTab = function(){
     chrome.tabs.getSelected(null, function(tab) {
        var tabId = tab.id;
        var tabUrl = tab.url;
        var origin = (new URL(tabUrl)).origin
        chrome.storage.sync.get(["leakedKeys"], function(result) {
            if (Array.isArray(result.leakedKeys[origin])){
                var originKeys = result.leakedKeys[origin].length.toString();
            }else{
                var originKeys = "";
            }
            chrome.browserAction.setBadgeText({text: originKeys});
            chrome.browserAction.setBadgeBackgroundColor({color: '#ff0000'});
        })
    });
}

chrome.tabs.onActivated.addListener(function(activeInfo) {
    updateTab();
});

var getStringsOfSet = function(word, char_set, threshold=20){
    let count = 0;
    let letters = "";
    let strings = [];
    if (! word){
        return []
    }
    for(let char of word){
        if (char_set.indexOf(char) > -1){
            letters += char;
            count += 1;
        } else{
            if ( count > threshold ){
                strings.push(letters);
            }
            letters = "";
            count = 0;
        }
    }
    if(count > threshold){
        strings.push(letters);
    }
    return strings
}

var getDecodedb64 = function(inputString){
    let b64CharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let encodeds = getStringsOfSet(inputString, b64CharSet);
    let decodeds = [];
    for (encoded of encodeds){
        try {
            let decoded = [encoded, atob(encoded)];
            decodeds.push(decoded);
        } catch(e) {
        }
    }
    return decodeds;
}

var checkIfOriginDenied = function(check_url, cb){
    let skip = false;
    chrome.storage.sync.get(["originDenyList"], function(result) {
        let originDenyList = result.originDenyList;
        for (origin of originDenyList){
            if(check_url.startsWith(origin)){
                skip = true;
            }
        }
        cb(skip);
    })
}
var checkForGitDir = function(data, url){
    if(data.startsWith("[core]")){
        alert(".git dir found in " + url + " feature to check this for secrets not supported");
    }

}
var js_url;
chrome.extension.onMessage.addListener(function(request, sender, sendResponse) {

    chrome.storage.sync.get(['generics'], function(useGenerics) {
        chrome.storage.sync.get(['specifics'], function(useSpecifics) {
            chrome.storage.sync.get(['aws'], function(useAws) {
                chrome.storage.sync.get(['checkEnv'], function(checkEnv) {
                    chrome.storage.sync.get(['checkGit'], function(checkGit) {
                        let regexes = {};
                        if(useGenerics["generics"] || useGenerics["generics"] == undefined){
                            regexes = {
                                ...regexes,
                                ...generics
                            }
                        }
                        if(useSpecifics["specifics"] || useSpecifics["specifics"] == undefined){
                            regexes = {
                                ...regexes,
                                ...specifics
                            }
                        }
                        if(useAws["aws"] || useAws["aws"] == undefined){
                            regexes = {
                                ...regexes,
                                ...aws
                            }
                        }
                        if (request.scriptUrl) {
                            let js_url = request.scriptUrl;
                            let parentUrl = request.parentUrl;
                            let parentOrigin = request.parentOrigin;
                            checkIfOriginDenied(js_url, function(skip){
                                if (!skip){
                                    fetch(js_url, {"credentials": 'include'})
                                        .then(response => response.text())
                                        .then(data => checkData(data, js_url, regexes, undefined, parentUrl, parentOrigin));
                                }

                            })

                        }else if(request.pageBody){
                            checkIfOriginDenied(request.origin, function(skip){
                                if (!skip){
                                    checkData(request.pageBody, request.origin, regexes, undefined, request.parentUrl, request.parentOrigin);
                                }
                            })
                        }else if(request.envFile){
                            if(checkEnv['checkEnv']){
                                fetch(request.envFile, {"credentials": 'include'})
                                    .then(response => response.text())
                                    .then(data => checkData(data, ".env file at " + request.envFile, regexes, undefined, request.parentUrl, request.parentOrigin));
                            }
                        }else if(request.openTabs){
                            for (tab of request.openTabs){
                                window.open(tab);
                                console.log(tab)
                            }
                        }else if(request.gitDir){
                            if(checkGit['checkGit']){
                            fetch(request.gitDir, {"credentials": 'include'})
                                    .then(response => response.text())
                                    .then(data => checkForGitDir(data, request.gitDir));
                            }

                        }
                    });
                });
            });

        });
    });



});
