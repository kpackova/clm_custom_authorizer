'use strict'
const authPolicy = require('./auth-policy');
const async = require('async');
const aws = require('aws-sdk');
var jwt_decode = require('jwt-decode');


exports.handler = (event, context, callback) => {
    async.waterfall([
            (next) => {
                next(null, event);
            },
            getRequestedApi,
            buildPolicy
        ],
        function (err, policy) {
            if (err) {
                console.log('ERROR:', err);
                callback('Unauthorized');
            } else {
                callback(null, policy);
            }
        }
    );
}


/**
  Get awsOptions and aws accountId
**/
function getRequestedApi(event, next) {
    console.log(event);
    const apiOptions = {};
    const tmp = event.methodArn.split(':');
    const apiGatewayArnTmp = tmp[5].split('/');
    const awsAccountId = tmp[4];
    apiOptions.region = tmp[3];
    apiOptions.restApiId = apiGatewayArnTmp[0];
    apiOptions.stage = apiGatewayArnTmp[1];
    next(null, event, awsAccountId, apiOptions);
}
/**
  Scopes are packed into API Gateway policy document
**/
function buildPolicy(event, awsAccountId, apiOptions, next) {
    var bearerToken = event.authorizationToken.split(' ');
    var decoded = jwt_decode(bearerToken[1]);

    const policy = new authPolicy(decoded.client_id, awsAccountId, apiOptions);

    let scopes = decoded.scope.split(' ');

    let allowedScopes = [];

    for (let scope of scopes) {
        //The expected format is 'resource_verb', for example '/numbers.add_POST'
        let scopeParts = scope.split('_');
        if (scopeParts.length != 2) {
            console.warn('Invalid claim: ' + scope);
            continue;
        }
        let claim = scopeParts[0].replace('.','/');
        policy.allowMethod(scopeParts[1], claim);
        allowedScopes.push(claim);
    }
    if (allowedScopes.length === 0)
        policy.denyAllMethods();

    let policyResponse = policy.build();

    policyResponse.context = {
        'token': 'AccessToken',
        'claims': allowedScopes.join(','),
        'caller_name': decoded.client_id
    };

    next(null, policyResponse);
}
