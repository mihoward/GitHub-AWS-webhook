"use strict";

const crypto = require('crypto');
const AWS = require('aws-sdk');

function signRequestBody(key, body) {
  return `sha1=${crypto.createHmac('sha1', key).update(body, 'utf-8').digest('hex')}`;
}

module.exports.webhookListener = async (event, context, callback) => {
  let error;

  const ssm = new AWS.SSM();
  const token = (await ssm.getParameter({  Name: 'github-webhook-secret', WithDecryption: true }).promise()).Parameter.Value;
  const headers = event.headers;
  const signature  = headers['x-hub-signature'];
  const githubEvent = headers['x-github-event'];
  const id = headers['x-github-delivery'];
  const calculatedSignature = signRequestBody(token, event.body);

  if (typeof token !== 'string') {
    error = 'Must provide a \'GITHUB_WEBHOOK_SECRET\' env variable';
    return callback(null, {
      statusCode: 401,
      headers: { 'Content-Type': 'text/plain' },
      body: error,
    });
  }

  if (!signature) {
    error = 'No X-Hub-Signature found on request';
    return callback(null, {
      statusCode: 401,
      headers: { 'Content-Type': 'text/plain' },
      body: error,
    });
  }

  if (!githubEvent) {
    error = 'No X-Github-Event found on request';
    return callback(null, {
      statusCode: 422,
      headers: { 'Content-Type': 'text/plain' },
      body: error,
    });
  }

  if (!id) {
    error = 'No X-Github-Delivery found on request';
    return callback(null, {
      statusCode: 401,
      headers: { 'Content-Type': 'text/plain' },
      body: error,
    });
  }

  if (signature !== calculatedSignature) {
    error = 'X-Hub-Signature incorrect. Github webhook token doesn\'t match';
    return callback(null, {
      statusCode: 401,
      headers: { 'Content-Type': 'text/plain' },
      body: error,
    });
  }

  // Write count of events to DynamoDB table
  const dynamodb = new AWS.DynamoDB();
  
  // Get today's date
  const currentDate = new Date().toISOString().split('T')[0];
  const params = {
    TableName: process.env.GITHB_EVENT_TABLE,
    Key: {
      date: { S: currentDate.toString() },
    },
    ExpressionAttributeValues: { ":one": {N: "1"} , ":zero": {N: "0"}},
    UpdateExpression: "SET eventCount = if_not_exists(eventCount, :zero) + :one"
  };
  
  try {
    let result = await dynamodb.updateItem(params).promise();
    console.log('Successfully wrote to DynamoDB table', JSON.stringify(result));
  } catch (err) {
    error = 'Error writing to DynamoDB table';
    return callback(null, {
      statusCode: 500,
      headers: { 'Content-Type': 'text/plain' },
      body: error,
    });
  }


  const response = {
    statusCode: 200,
    body: JSON.stringify({
      input: event,
    }),
  };
  return callback(null, response);
}
