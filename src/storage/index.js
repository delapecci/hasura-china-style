const express = require('express');
const Joi = require('@hapi/joi');
const Boom = require('boom');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const {
  HASURA_GRAPHQL_JWT_SECRET,
  HASURA_GRAPHQL_ADMIN_SECRET,
  STORAGE_PROVIDER
} = require('../config');

const { storagePermission } = require('./rules');

const router = express.Router();

let storageService;
if (STORAGE_PROVIDER === 's3') {
  storageService = require('./s3');
} else if (STORAGE_PROVIDER === 'qiniu') {
  storageService = require('./qiniu');
} else {
  storageService = require('./aliyun');
}

const admin_secret_is_ok = (req) => {
  const { headers } = req;
  return 'x-hasura-admin-secret' in headers && headers['x-hasura-admin-secret'] == HASURA_GRAPHQL_ADMIN_SECRET;
};

const get_claims_from_request = (req) => {
  const { jwt_token = '' } = req.cookies;
  const { authorization = '' } = req.headers;

  if (authorization === '' && jwt_token === '') {
    return void 0;
  }

  const token = authorization !== '' ? authorization.replace('Bearer ', '') : jwt_token;

  try {
    const decoded = jwt.verify(
      token,
      HASURA_GRAPHQL_JWT_SECRET.key,
      {
        algorithms: HASURA_GRAPHQL_JWT_SECRET.type,
      }
    );
    return decoded['https://hasura.io/jwt/claims'];
  } catch (e) {
    console.error(e);
    return void 0;
  }
};

router.get('/file/*', async (req, res, next) => {
  const key = `${req.params[0]}`;

  // if not admin, do JWT checks
  if (!admin_secret_is_ok(req)) {

    const claims = get_claims_from_request(req);

    if (claims === undefined) {
      return next(Boom.unauthorized('Incorrect JWT Token'));
    }

    // check access of key for jwt token claims
    if (!storagePermission(key, 'read', claims)) {
      return next(Boom.unauthorized('You are not allowed to read this file'));
    }
  }

  await storageService.getObject(req, res, next);

});


const upload = multer({
  storage: storageService.storage
});

const upload_auth = (req, res, next) => {

  // if not admin, do JWT checks
  if (!admin_secret_is_ok(req)) {

    const claims = get_claims_from_request(req);

    if (claims === undefined) {
      return next(Boom.unauthorized('Incorrect JWT Token'));
    }

    if (!storagePermission(req.key_prefix, 'write', claims)) {
      return next(Boom.unauthorized('You are not allowed to write files here'));
    }
  }

  // all uploaded files gets pushed in to this array
  // this array is returned back to the client once all uploads are
  // completed
  req.saved_files = [];

  // validation OK. Upload files
  next();
};

router.post('/upload', storageService.preUpload, upload_auth, upload.array('files', 50), function (req, res) {
  res.json(req.saved_files);
});

module.exports = router;
