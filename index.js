const CustomAuth = require("@toruslabs/customauth");
const BN = require("bn.js");
const jwt = require("jsonwebtoken");
const { TORUS_NETWORK } = require("@toruslabs/fetch-node-details");
require("dotenv").config();

const jwtKey = process.env.JWT_PRIVATE_KEY;
if (!jwtKey) {
  console.error("add your jwt private key in .env file");
  process.exit(1);
}

// replace your verifier name here.
const verifier =  "torus-test-health";
const jwtPrivateKey = `-----BEGIN PRIVATE KEY-----\n${jwtKey}\n-----END PRIVATE KEY-----`;
const generateIdToken = (email, alg) => {
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "torus-key-test",
    aud: "torus-key-test",
    name: email,
    email,
    scope: "email",
    iat,
    eat: iat + 120,
  };

  const algo = {
    expiresIn: 120,
    algorithm: alg,
  };

  return jwt.sign(payload, jwtPrivateKey, algo);
};

const enableOneKey = true;


const torusAqua = new CustomAuth.default({
    baseUrl: "https://example.com",
    enableOneKey,
    network: TORUS_NETWORK.AQUA,
});

const torusCyan = new CustomAuth.default({
    baseUrl: "https://example.com",
    enableOneKey,
    network: TORUS_NETWORK.CYAN,
});



async function loginToCyan(verifier, verifierId, idToken) {
    const cyanKeyDetails =  await torusCyan.getTorusKey(verifier, verifierId, { verifier_id: verifierId} , idToken);
    return cyanKeyDetails.privateKey;
}


/**
 * 
 * @param {*} verifier 
 * @param {*} verifierId 
 * @param {*} idToken 
 */
async function migrateUserFromCyanToAqua(aquaKeyDetails, verifier, verifierId, idToken) {
    // login with cyan first
    const cyanKeyDetails = await torusCyan.getTorusKey(verifier, verifierId, { verifier_id: verifierId} , idToken);

    // migrate cyan user to aqua
    await torusAqua.torus.setCustomKey({ metadataNonce: new BN(0), privKeyHex: aquaKeyDetails.privateKey, customKeyHex: cyanKeyDetails.privateKey });
    // user migrated, now aqua key details for this user will be returned same as cyan key details
    const metadataNonce = await torusAqua.torus.getMetadata({ pub_key_X: aquaKeyDetails.pubKey.pub_key_X, pub_key_Y: aquaKeyDetails.pubKey.pub_key_Y });
    const finalPrivKey = new BN(aquaKeyDetails.privateKey, 16).add(metadataNonce).umod(torusAqua.torus.ec.curve.n);
    return finalPrivKey.toString("hex");
}

/**
 * 
 * @param {*} isMigrated if set to true , then user will be migrated first to aqua network
 * @param {*} isCyanUser if set to true , then user key will be converted to same as cyan from aqua network
 * @param {*} verifier Your verifier name on aqua and cyan (should be same)
 * @param {*} verifierId  Your verifier id (user_id) on aqua and cyan (should be same)
 * @param {*} idToken idToken issued after authenticating user.
 * @returns  private key of user from aqua network
 */
async function loginToAqua(isCyanUser, isMigrated, verifier, verifierId, idToken) {
    const aquaKeyDetails = await torusAqua.getTorusKey(verifier, verifierId, { verifier_id: verifierId} , idToken);
    if (isCyanUser) {
        if (!isMigrated) {
           return migrateUserFromCyanToAqua(aquaKeyDetails, verifier, verifierId, idToken);
        } else {
            const metadataNonce = await torusAqua.torus.getMetadata({ pub_key_X: aquaKeyDetails.pubKey.pub_key_X, pub_key_Y: aquaKeyDetails.pubKey.pub_key_Y });
            const finalPrivKey = new BN(aquaKeyDetails.privateKey, 16).add(metadataNonce).umod(torusAqua.torus.ec.curve.n);
            return finalPrivKey.toString("hex")
        }

    } else {
        return aquaKeyDetails.privateKey;
    }
}




/**
 * This function test migration of a user from web3auth
 * cyan to aqua network.
 * 
 * Here we first create a new user on cyan. 
 * Then login with same user on aqua.
 *  By default login to aqua will give a different key than cyan.
    * But as our user is already logged in cyan and we want to get same key on aqua. 
    * We run a migration function in `loginToAqua` function, which will result in same key from aqua as well
    * om next call to loginToAqua function.
 * 
 */
async function testLoginMigration() {
    const verifierId = "hello11@test.com";
    let idToken = generateIdToken(verifierId,"ES256");

    // Login to Cyan
    const cyanKey = await loginToCyan(verifier, verifierId, idToken);


    // renew id token
    idToken = generateIdToken(verifierId,"ES256");

    console.log("cyan user Key", cyanKey);
    // Case 1. Login an existing cyan user to aqua
    // Note: we need to pass isCyanUser as true and isMigrated to false to loginToAqua
    // since user was first logged in to cyan, we need to migrate it to aqua for the first login.
    // subsequent logins will be handled by the aqua.
    let aquaKeyAfterMigration = await loginToAqua(true, false, verifier, verifierId, idToken);
    console.log("aqua user Key after migration", aquaKeyAfterMigration);

    if (cyanKey !== aquaKeyAfterMigration) {
        console.log("key are different after migration");
        throw new Error("key are different after migration");
    }

    // renew id token
    idToken = generateIdToken(verifierId,"ES256");

    // Case 2. Login a migrated user to aqua
    // Note: we pass isCyanUser as true and isMigrated as true to loginToAqua, 
    // since this cyan user is already migrated to aqua.
    aquaKeyAfterMigration = await loginToAqua(true, true, verifier, verifierId, idToken);
    console.log("aqua user Key after migration login", aquaKeyAfterMigration);

    if (cyanKey !== aquaKeyAfterMigration) {
        console.log("key are different after migration");
        throw new Error("key are different after migration");
    }

    // Case 3: Login a new user to aqua
    const verifierId1 = "hello12@test.com";
    // renew id token
    idToken = generateIdToken(verifierId1,"ES256");
    // This is not a cyan user so both isCyanUser and isMigrated should be false
   const newAquaUserKey= await loginToAqua(false, false, verifier, verifierId1, idToken);
    console.log("newAquaUserKey", newAquaUserKey);


}

(async ()=>{
  await testLoginMigration();
})();