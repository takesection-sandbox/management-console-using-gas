function getToken() {
    const properties = PropertiesService.getScriptProperties();
    const roleArn = properties.getProperty('ROLE_ARN');
    const token = ScriptApp.getIdentityToken();
    const body = token.split('.')[1];
    const base64 = Utilities.base64DecodeWebSafe(body, Utilities.Charset.UTF_8);
    const decoded = Utilities.newBlob(base64).getDataAsString();
    const payload = JSON.parse(decoded);
    return {
      'token': token,
      'role_arn': roleArn,
      'payload': payload
    };
}

function assumeRoleWithWebIdentity(roleArn, sessionName, oidcToken) {
    const role_arn = encodeURIComponent(roleArn);
    const role_session_name = encodeURIComponent(sessionName);
    const token = encodeURIComponent(oidcToken);
    const formData = `Action=AssumeRoleWithWebIdentity&RoleSessionName=${role_session_name}&RoleArn=${role_arn}&WebIdentityToken=${token}&DurationSeconds=3600&Version=2011-06-15`;

    const res = UrlFetchApp.fetch('https://sts.amazonaws.com/', {
        'method': 'post',
        'payload': formData
    });
    const xml = XmlService.parse(res.getContentText());
    const root = xml.getRootElement();
    const ns = root.getNamespace();
    const assumeRoleWithWebIdentityResult = root.getChild('AssumeRoleWithWebIdentityResult', ns);
    const credentials = assumeRoleWithWebIdentityResult.getChild('Credentials', ns);
    const roleCreds = {
        'sessionId': credentials.getChildText('AccessKeyId', ns),
        'sessionKey': credentials.getChildText('SecretAccessKey', ns),
        'sessionToken': credentials.getChildText('SessionToken', ns)
    };
    return roleCreds;
}

function getSigninToken(credentials) {
    // credentials { sessionId: '', sessionKey: '', sessionToken: '' }
    const req = "https://signin.aws.amazon.com/federation" +
        "?Action=getSigninToken" +
        "&SessionDuration=43200" +
        "&Session=" + encodeURIComponent(JSON.stringify(credentials));
    const res = UrlFetchApp.fetch(req);
    return JSON.parse(res.getContentText())['SigninToken'];
}

function getUrl() {
    const token = getToken();
    const roleCreds = assumeRoleWithWebIdentity(token.role_arn, token.payload.email, token.token);
    const signinToken = getSigninToken(roleCreds);
    const distination = encodeURIComponent('https://console.aws.amazon.com');
    return `https://signin.aws.amazon.com/federation?Action=login&Issuer=gmail.com&Destination=${distination}&SigninToken=${signinToken}`;
}

function doGet() {
    const properties = PropertiesService.getScriptProperties();

    const payload = getToken()['payload'];
    console.log('aud: ' + payload.aud + ' sub: ' + payload.sub + ' (' + payload.email + ')');

    var template = HtmlService.createTemplateFromFile('index.html');
    template.name = payload.name;
    template.sub = payload.sub;
    template.account_id = properties.getProperty('ACCOUNT_ID');
    const html = template.evaluate();
    var output = HtmlService.createHtmlOutput(html);
    output.setTitle("AWS管理コンソール");
    return output;
}