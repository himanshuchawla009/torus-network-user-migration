// CAUTION: RUN THIS SCRIPT ONLY IF YOU ARE SURE ABOUT WHAT YOU ARE DOING.

const Torus = require("@toruslabs/torus.js").default;
const BN = require("bn.js");
const jwt = require("jsonwebtoken");
const fetchNodeDetails = require("@toruslabs/fetch-node-details/dist/fetchNodeDetails-node");
require("dotenv").config();

const TORUS_NETWORK = fetchNodeDetails.TORUS_NETWORK
console.log("fetchNodeDetails", fetchNodeDetails.default.PROXY_ADDRESS_AQUA);
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

const torusAqua = new Torus({
    signerHost: "https://signer-polygon.tor.us/api/sign",
    allowHost: "https://signer-polygon.tor.us/api/allow",
    network: "aqua",
    enableOneKey,
});
const TORUS_NODE_MANAGER_AQUA = new fetchNodeDetails.default({ network: TORUS_NETWORK.AQUA, proxyAddress: fetchNodeDetails.default.PROXY_ADDRESS_AQUA });
const torusCyan = new Torus({
    signerHost: "https://signer-polygon.tor.us/api/sign",
    allowHost: "https://signer-polygon.tor.us/api/allow",
    network: "cyan",
    enableOneKey,
});

const TORUS_NODE_MANAGER_CYAN = new fetchNodeDetails.default({ network: TORUS_NETWORK.CYAN, proxyAddress: fetchNodeDetails.default.PROXY_ADDRESS_CYAN });


async function loginToCyan(verifier, verifierId, idToken) {
    const verifierDetails = { verifier, verifierId };

    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER_CYAN.getNodeDetails(verifierDetails);

    const pubDetails = await torusCyan.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails, true);

    const retrieveSharesResponse = await torusCyan.retrieveShares(
        torusNodeEndpoints,
        torusIndexes,
        verifier,
        { verifier_id: verifierId },
        idToken
    );
    if (pubDetails.address.toLowerCase() !== retrieveSharesResponse.ethAddress.toLowerCase() ) {
        throw new Error("Failed to login with aqua");
    }
   return retrieveSharesResponse.privKey
}


/**
 * 
 * @param {*} verifier 
 * @param {*} verifierId 
 * @param {*} idToken 
 */
async function migrateUserFromCyanToAqua(aquaKey, verifier, verifierId, idToken) {
    // login with cyan first
    const cyanPrivKey = await loginToCyan(verifier, verifierId, idToken);

    // migrate cyan user to aqua
    await torusAqua.setCustomKey({ metadataNonce: new BN(0), privKeyHex: aquaKey, customKeyHex: cyanPrivKey });

    const keyPair = torusAqua.ec.keyFromPrivate(aquaKey);

    // user migrated, now aqua key details for this user will be returned same as cyan key details
    const metadataNonce = await torusAqua.getMetadata({ pub_key_X: keyPair.getPublic().getX().toString("hex"), pub_key_Y: keyPair.getPublic().getY().toString("hex"), });
    const finalPrivKey = new BN(aquaKey, 16).add(metadataNonce).umod(torusAqua.ec.curve.n);
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
    const verifierDetails = { verifier, verifierId };

    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER_AQUA.getNodeDetails(verifierDetails);

    // does the key assign
    const pubDetails = await torusAqua.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails, true);

    const retrieveSharesResponse = await torusAqua.retrieveShares(
        torusNodeEndpoints,
        torusIndexes,
        verifier,
        { verifier_id: verifierId },
        idToken
    );

    if (pubDetails.address.toLowerCase() !== retrieveSharesResponse.ethAddress.toLowerCase() ) {
        throw new Error("Failed to login with aqua");
    }

    if (isCyanUser) {
        if (!isMigrated) {
           return migrateUserFromCyanToAqua(retrieveSharesResponse.privKey, verifier, verifierId, idToken);
        } else {
            const keyPair = torusAqua.ec.keyFromPrivate(retrieveSharesResponse.privKey);

            const metadataNonce = await torusAqua.getMetadata({ pub_key_X: keyPair.getPublic().getX().toString("hex"), pub_key_Y: keyPair.getPublic().getY().toString("hex") });
            const finalPrivKey = new BN(retrieveSharesResponse.privKey, 16).add(metadataNonce).umod(torusCyan.ec.curve.n);
            return finalPrivKey.toString("hex")
        }

    } else {
        return retrieveSharesResponse.privKey;
    }
}



// CAUTION: RUN THIS SCRIPT ONLY IF YOU ARE SURE ABOUT WHAT YOU ARE DOING.

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
    const verifierId = "hello24@test.com";
    let idToken = generateIdToken(verifierId,"ES256");

    // Login to Cyan
    const cyanKey = await loginToCyan(verifier, verifierId, idToken);
    console.log(`logged in to cyan`, verifierId);

    // renew id token
    idToken = generateIdToken(verifierId,"ES256");
    // Case 1. Login an existing cyan user to aqua
    // Note: we need to pass isCyanUser as true and isMigrated to false to loginToAqua
    // since user was first logged in to cyan, we need to migrate it to aqua for the first login.
    // subsequent logins will be handled by the aqua.
    let aquaKeyAfterMigration = await loginToAqua(true, false, verifier, verifierId, idToken);

    if (cyanKey !== aquaKeyAfterMigration) {
        console.log("key are different after migration");
        throw new Error("key are different after migration");
    }
    console.log("cyan user migrated to aqua successfully");

    // renew id token
    idToken = generateIdToken(verifierId,"ES256");

    // Case 2. Login a migrated user to aqua
    // Note: we pass isCyanUser as true and isMigrated as true to loginToAqua, 
    // since this cyan user is already migrated to aqua.
    aquaKeyAfterMigration = await loginToAqua(true, true, verifier, verifierId, idToken);

    if (cyanKey !== aquaKeyAfterMigration) {
        console.log("key are different after migration");
        throw new Error("key are different after migration");
    }
    console.log("cyan user logged in to aqua successfully");


    // Case 3: Login a new user to aqua
    const verifierId1 = "hello12@test.com";
    // renew id token
    idToken = generateIdToken(verifierId1,"ES256");
    // This is not a cyan user so both isCyanUser and isMigrated should be false
   const newAquaUserKey= await loginToAqua(false, false, verifier, verifierId1, idToken);
   if (!newAquaUserKey) {
    console.log("Unable to login to aqua");
  }


}


// run this function to migrate users in bulk.
const migrateUsersFromCyan = async (users) => {
    users.forEach(async(user)=>{
        const { verifier, verifierId, idToken } = user;
        try {
            const aquaKey = await loginToAqua(true, false, verifier, verifierId, idToken);
            if (!aquaKey) {
                console.log("Unable to login to aqua");
            }
        } catch (error) {
            console.error(`failed to migrate user: ${verifierId} from cyan to aqua`, error);
        }
    })
}

(async ()=>{
  await testLoginMigration();

// migrateUsersFromCyan([{
//     verifier,
//     verifierId: "hello102@test.com",
//     idToken:  generateIdToken("hello102@test.com","ES256"),
// },
// {
//     verifier,
//     verifierId: "hello103@test.com",
//     idToken:  generateIdToken("hello103@test.com","ES256"),
// }])
})();