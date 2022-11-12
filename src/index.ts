import * as Axios from "axios";
import * as jsonwebtoken from "jsonwebtoken";
import { promisify } from "util";
const jwkToPem = require("jwk-to-pem");
var jwt = require("jsonwebtoken");
var AWS = require("aws-sdk");
AWS.config.update({ region: process.env.REGION });
const lambda = new AWS.Lambda({ region: process.env.REGION });
var ddb = new AWS.DynamoDB.DocumentClient({ apiVersion: "2012-08-10" });
const cognito = new AWS.CognitoIdentityServiceProvider({
  apiVersion: "2016-04-18",
});

export interface ClaimVerifyRequest {
  readonly token?: string;
}

export interface ClaimVerifyResult {
  readonly userName: string;
  readonly clientId: string;
  readonly isValid: boolean;
  readonly error?: any;
}

interface TokenHeader {
  kid: string;
  alg: string;
  dependencies: boolean;
}
interface PublicKey {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}
interface PublicKeyMeta {
  instance: PublicKey;
  pem: string;
}

interface PublicKeys {
  keys: PublicKey[];
}

interface MapOfKidToPublicKey {
  [key: string]: PublicKeyMeta;
}

interface Claim {
  token_use: string;
  auth_time: number;
  iss: string;
  exp: number;
  username: string;
  client_id: string;
}

const cognitoPoolId = process.env.COGNITO_POOL_ID;
const idClientAppAuth2 = process.env.ID_CLIENTE_APP_AUTH2;
const arnResource = process.env.ARN_RESOURCE;
const cognitoIssuer = `https://cognito-idp.us-east-2.amazonaws.com/${cognitoPoolId}`;
let cacheKeys: MapOfKidToPublicKey | undefined;

const getPublicKeys = async (): Promise<MapOfKidToPublicKey> => {
  if (!cacheKeys) {
    const url = `${cognitoIssuer}/.well-known/jwks.json`;
    const publicKeys = await Axios.default.get<PublicKeys>(url);
    cacheKeys = publicKeys.data.keys.reduce((agg, current) => {
      const pem = jwkToPem(current);
      agg[current.kid] = { instance: current, pem };
      return agg;
    }, {} as MapOfKidToPublicKey);
    return cacheKeys;
  } else {
    return cacheKeys;
  }
};

const verifyPromised = promisify(jsonwebtoken.verify.bind(jsonwebtoken));

exports.handler = async (event: any): Promise<any> => {
  let result: ClaimVerifyResult;
  let auth;
  let response;
  let infoToken;
  let claim;
  try {
    const token = event["headers"]["authorization"]
      ? event["headers"]["authorization"].replace("Bearer ", "")
      : "";
    const tokenSections = (token || "").split(".");
    if (tokenSections.length < 2) {
      throw new Error("requested token is invalid");
    }
    const headerJSON = Buffer.from(tokenSections[0], "base64").toString("utf8");
    const header = JSON.parse(headerJSON) as TokenHeader;

    const keys = await getPublicKeys();
    const key = keys[header.kid];
    if (key === undefined) {
      throw new Error("claim made for unknown kid");
    }
    claim = (await verifyPromised(token, key.pem)) as Claim;

    const currentSeconds = Math.floor(new Date().valueOf() / 1000);
    if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
      throw new Error("claim is expired or invalid");
    }
    if (claim.iss !== cognitoIssuer) {
      throw new Error("claim issuer is invalid");
    }
    if (claim.token_use !== "access") {
      throw new Error("claim use is not access");
    }
    auth = "Allow";
    response = {
      principalId: "abc123",
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Resource: [arnResource],
            Effect: auth,
          },
        ],
      },
    };
    return response;
  } catch (error) {
    auth = "Deny";
    response = {
      principalId: "abc123",
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Resource: [arnResource],
            Effect: auth,
          },
        ],
      },
      error
    };
    return response
  }
};
