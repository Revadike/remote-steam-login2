const { EAuthSessionGuardType, EAuthTokenPlatformType, LoginSession } = require("steam-session");
const { generateAuthCode } = require("steam-totp");
const express = require("express");
const app = express();
const port = 443;

app.get("/", async(req, res) => {
    console.log("Received login request");

    let { "username": accountName, password, "shared_secret": sharedSecret, code } = req.query || req.body;
    if (!accountName || !password) {
        res.status(400);
        res.send({ "success": false, "error": "Please provide a username and password" });
        return;
    }

    let session = new LoginSession(EAuthTokenPlatformType.WebBrowser);
    let startResult = await session.startWithCredentials({
        accountName,
        password,
    });

    if (startResult.actionRequired && startResult.validActions.find(({ type }) => type === EAuthSessionGuardType.DeviceCode)) {
        let authCode = code || generateAuthCode(sharedSecret);
        await session.submitSteamGuardCode(authCode);
    } else if (startResult.actionRequired) {
        res.status(500);
        res.send({ "success": false, "error": "Login action is required, but we don't know how to handle it" });
        return;
    }

    session.once("authenticated", async() => {
        console.log(`Successfully logged in as ${session.accountName}`);
        let cookies = await session.getWebCookies();
        let cookieStr = cookies.join("; ");
        res.status(200);
        res.send({ "success": true, cookies, cookieStr });
    });

    session.once("timeout", () => {
        res.status(408);
        res.send({ "success": false, "error": "Login attempt timed out" });
    });

    session.once("error", (err) => {
        // This should ordinarily not happen. This only happens in case there's some kind of unexpected error while
        // polling, e.g. the network connection goes down or Steam chokes on something.
        res.status(500);
        res.send({ "success": false, "error": `FATAL ERROR: ${err.message}` });
    });
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
