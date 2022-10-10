// CAUTION: RUN THIS SCRIPT ONLY IF YOU ARE SURE ABOUT WHAT YOU ARE DOING.

const Torus = require("@toruslabs/torus.js").default;
const BN = require("bn.js");
const jwt = require("jsonwebtoken");
const fetchNodeDetails = require("@toruslabs/fetch-node-details/dist/fetchNodeDetails-node");
require("dotenv").config();

const TORUS_NETWORK = fetchNodeDetails.TORUS_NETWORK
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

const torusMainnet = new Torus({
    network: "mainnet",
    enableOneKey,
});
const TORUS_NODE_MANAGER_MAINNET = new fetchNodeDetails.default({ network: TORUS_NETWORK.MAINNET, proxyAddress: fetchNodeDetails.default.PROXY_ADDRESS_MAINNET });
const torusTestnet = new Torus({
    network: "testnet",
    enableOneKey,
});

const TORUS_NODE_MANAGER_TESTNET = new fetchNodeDetails.default({ network: "https://rpc.ankr.com/eth_ropsten", proxyAddress: fetchNodeDetails.default.PROXY_ADDRESS_TESTNET });


async function loginToTestnet(verifier, verifierId, idToken) {
    const verifierDetails = { verifier, verifierId };

    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER_TESTNET.getNodeDetails(verifierDetails);

    const pubDetails = await torusTestnet.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails, true);

    const retrieveSharesResponse = await torusTestnet.retrieveShares(
        torusNodeEndpoints,
        torusIndexes,
        verifier,
        { verifier_id: verifierId },
        idToken
    );
    if (pubDetails.address.toLowerCase() !== retrieveSharesResponse.ethAddress.toLowerCase() ) {
        throw new Error("Failed to login with mainnet");
    }
   return retrieveSharesResponse.privKey
}


/**
 * 
 * @param {*} verifier 
 * @param {*} verifierId 
 * @param {*} idToken 
 */
async function migrateUserFromTestnetToMainnet(mainnetKey, verifier, verifierId, idToken) {
    // login with testnet first
    const testnetPrivKey = await loginToTestnet(verifier, verifierId, idToken);

    // migrate testnet user to mainnet
    await torusMainnet.setCustomKey({ metadataNonce: new BN(0), privKeyHex: mainnetKey, customKeyHex: testnetPrivKey });

    const keyPair = torusMainnet.ec.keyFromPrivate(mainnetKey);

    // user migrated, now mainnet key details for this user will be returned same as testnet key details
    const metadataNonce = await torusMainnet.getMetadata({ pub_key_X: keyPair.getPublic().getX().toString("hex"), pub_key_Y: keyPair.getPublic().getY().toString("hex"), });
    const finalPrivKey = new BN(mainnetKey, 16).add(metadataNonce).umod(torusMainnet.ec.curve.n);
    return finalPrivKey.toString("hex");
}

/**
 * 
 *  @param {*} isTestnetUser if set to true , then user key will be converted to same as testnet from mainnet network
 * @param {*} isMigrated if set to true , then user will be migrated first to mainnet
 * @param {*} verifier Your verifier name on testnet and mainnet (should be same)
 * @param {*} verifierId  Your verifier id (user_id) on testnet and mainnet (should be same)
 * @param {*} idToken idToken issued after authenticating user.
 * @returns  private key of user from mainnet
 */
async function loginToMainnet(isTestnetUser, isMigrated, verifier, verifierId, idToken) {
    const verifierDetails = { verifier, verifierId };

    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await TORUS_NODE_MANAGER_MAINNET.getNodeDetails(verifierDetails);

    // does the key assign
    const pubDetails = await torusMainnet.getPublicAddress(torusNodeEndpoints, torusNodePub, verifierDetails, true);

    const retrieveSharesResponse = await torusMainnet.retrieveShares(
        torusNodeEndpoints,
        torusIndexes,
        verifier,
        { verifier_id: verifierId },
        idToken
    );

    if (pubDetails.address.toLowerCase() !== retrieveSharesResponse.ethAddress.toLowerCase() ) {
        throw new Error("Failed to login with mainnet");
    }

    if (isTestnetUser) {
        if (!isMigrated) {
           return migrateUserFromTestnetToMainnet(retrieveSharesResponse.privKey, verifier, verifierId, idToken);
        } else {
            const keyPair = torusMainnet.ec.keyFromPrivate(retrieveSharesResponse.privKey);

            const metadataNonce = await torusMainnet.getMetadata({ pub_key_X: keyPair.getPublic().getX().toString("hex"), pub_key_Y: keyPair.getPublic().getY().toString("hex") });
            const finalPrivKey = new BN(retrieveSharesResponse.privKey, 16).add(metadataNonce).umod(torusTestnet.ec.curve.n);
            return finalPrivKey.toString("hex")
        }

    } else {
        return retrieveSharesResponse.privKey;
    }
}



// CAUTION: RUN THIS SCRIPT ONLY IF YOU ARE SURE ABOUT WHAT YOU ARE DOING.
/**
 * This function test migration of a user from web3auth
 * testnet to mainnet network.
 * 
 * Here we first create a new user on testnet. 
 * Then login with same user on mainnet.
 *  By default login to mainnet will give a different key than testnet.
    * But as our user is already logged in testnet and we want to get same key on mainnet. 
    * We run a migration function in `loginToMainnet` function, which will result in same key from mainnet as well
    * om next call to loginToMainnet function.
 * 
 */
async function testLoginMigration() {
    const verifierId = "hello24@test.com";
    let idToken = generateIdToken(verifierId,"ES256");

    // Login to testnet
    const testnetKey = await loginToTestnet(verifier, verifierId, idToken);
    console.log(`logged in to testnet`, verifierId);

    // renew id token
    idToken = generateIdToken(verifierId,"ES256");
    // Case 1. Login an existing testnet user to mainnet
    // Note: we need to pass isTestnetUser as true and isMigrated to false to loginToMainnet
    // since user was first logged in to testnet, we need to migrate it to mainnet for the first login.
    // subsequent logins will be handled by the mainnet.
    let mainnetKeyAfterMigration = await loginToMainnet(true, false, verifier, verifierId, idToken);

    if (testnetKey !== mainnetKeyAfterMigration) {
        console.log("key are different after migration");
        throw new Error("key are different after migration");
    }
    console.log("testnet user migrated to mainnet successfully");

    // renew id token
    idToken = generateIdToken(verifierId,"ES256");

    // Case 2. Login a migrated user to mainnet
    // Note: we pass isTestnetUser as true and isMigrated as true to loginToMainnet, 
    // since this testnet user is already migrated to mainnet.
    mainnetKeyAfterMigration = await loginToMainnet(true, true, verifier, verifierId, idToken);

    if (testnetKey !== mainnetKeyAfterMigration) {
        console.log("key are different after migration");
        throw new Error("key are different after migration");
    }
    console.log("testnet user logged in to mainnet successfully");


    // Case 3: Login a new user to mainnet
    const verifierId1 = "hello12@test.com";
    // renew id token
    idToken = generateIdToken(verifierId1,"ES256");
    // This is not a testnet user so both isTestnetUser and isMigrated should be false
   const newMainnnetUserKey= await loginToMainnet(false, false, verifier, verifierId1, idToken);
   if (!newMainnnetUserKey) {
    console.log("Unable to login to mainnet");
  } else {
    console.log("new user logged in to mainnet");
  }

}


// run this function to migrate users in bulk.
const migrateUsersFromTestnet = async (users) => {
    users.forEach(async(user)=>{
        const { verifier, verifierId, idToken } = user;
        try {
            const mainnetKey = await loginToMainnet(true, false, verifier, verifierId, idToken);
            if (!mainnetKey) {
                console.log("Unable to login to mainnet");
              }
        } catch (error) {
            console.error(`failed to migrate user: ${verifierId} from testnet to mainnet`, error);
        }
    })
}

(async ()=>{
  await testLoginMigration();

// migrateUsersFromTestnet([{
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