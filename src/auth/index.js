const express = require('express');
const Joi = require('@hapi/joi');
const Boom = require('boom');
const bcrypt = require('bcryptjs');
const uuidv4 = require('uuid/v4');
const speakeasy = require('speakeasy');
const { graphql_client } = require('../graphql-client');

const {
  USER_FIELDS,
  USER_REGISTRATION_AUTO_ACTIVE,
  USER_MANAGEMENT_DATABASE_SCHEMA_NAME,
  REFETCH_TOKEN_EXPIRES,
  JWT_TOKEN_EXPIRES,
  HASURA_GRAPHQL_JWT_SECRET,
  SYSTEM_NAME
} = require('../config');

const auth_tools = require('./auth-tools');
const myBoom = require('../boom');
const verify_tool = require('../middlewares/verify');

let router = express.Router();

const schema_name = USER_MANAGEMENT_DATABASE_SCHEMA_NAME === 'public' ? '' :  USER_MANAGEMENT_DATABASE_SCHEMA_NAME.toString().toLowerCase() + '_';

router.post('/register', async (req, res, next) => {

  let hasura_data;
  let password_hash;

  const schema = Joi.object().keys({
    username: Joi.string().required(),
    password: Joi.string().required(),
    mobile: Joi.string().pattern(/^1[3456789]\d{9}$/).required(),
    register_data: Joi.object().allow(null),
  });

  const { error, value } = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const { username, mobile, password, register_data } = value;

  // check for duplicates
  let query = `
  query (
    $username: String!,
    $mobile: String!
  ) {
    ${schema_name}users (
      where: {
        _or: [
          { username: { _eq: $username } },
          { mobile: { _eq: $mobile } }
        ]
      }
    ) {
      id
    }
  }
  `;

  try {
    hasura_data = await graphql_client.request(query, {
      username, mobile
    });
  } catch (e) {
    console.error(e);
    return next(Boom.badImplementation("Unable to check for 'username' or 'mobile' duplication"));
  }

  if (hasura_data[`${schema_name}users`].length !== 0) {
    return next(Boom.unauthorized("The 'username' or 'mobile' already exist"));
  }

  // generate password_hash
  try {
    password_hash = await bcrypt.hash(password, 10);
  } catch(e) {
    console.error(e);
    return next(Boom.badImplementation("Unable to generate 'password hash'"));
  }

  // insert user
  query = `
  mutation (
    $user: ${schema_name}users_insert_input!
  ) {
    insert_${schema_name}users(
      objects: [$user]
    ) {
      affected_rows
    }
  }
  `;

  try {
    await graphql_client.request(query, {
      user: {
        username,
        mobile,
        password: password_hash,
        secret_token: uuidv4(),
        active: USER_REGISTRATION_AUTO_ACTIVE,
        register_data,
      },
    });
  } catch (e) {
    console.error(e);
    return next(Boom.badImplementation('Unable to create user.'));
  }

  res.send('OK');
});

router.post('/activate-account', async (req, res, next) => {
  let hasura_data;

  const schema = Joi.object().keys({
    secret_token: Joi.string().uuid({version: ['uuidv4']}).required(),
  });

  const { error, value } = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {
    secret_token,
  } = value;

  const query = `
  mutation activate_account (
    $secret_token: uuid!
    $new_secret_token: uuid!
    $now: timestamptz!
  ) {
    update_${schema_name}users (
      where: {
        _and: [
          {
            secret_token: { _eq: $secret_token }
          }, {
            secret_token_expires_at: { _gt: $now }
          },{
            active: { _eq: false }
          }
        ]
      }
      _set: {
        active: true,
        secret_token: $new_secret_token,
      }
    ) {
      affected_rows
    }
  }
  `;

  try {
    hasura_data = await graphql_client.request(query, {
      secret_token,
      new_secret_token: uuidv4(),
      now: new Date(),
    });
  } catch (e) {
    console.error(e);
    return next(Boom.unauthorized('Unable to find account for activation.'));
  }

  if (hasura_data[`update_${schema_name}users`].affected_rows === 0) {
    // console.error('Account already activated');
    return next(Boom.unauthorized('Account is already activated, the secret token has expired or there is no account.'));
  }

  res.send('OK');
});

router.post('/new-password', async (req, res, next) => {
  let hasura_data;
  let password_hash;

  const schema = Joi.object().keys({
    secret_token: Joi.string().uuid({version: ['uuidv4']}).required(),
    password: Joi.string().required(),
  });

  const { error, value } = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {
    secret_token,
    password,
  } = value;

  // update password and username activation token
  try {
    password_hash = await bcrypt.hash(password, 10);
  } catch(e) {
    console.error(e);
    return next(Boom.badImplementation(`Unable to generate 'password_hash'`));
  }

  const query = `
  mutation  (
    $secret_token: uuid!,
    $password_hash: String!,
    $new_secret_token: uuid!
    $now: timestamptz!
  ) {
    update_${schema_name}users (
      where: {
        _and: [
          {
            secret_token: { _eq: $secret_token}
          }, {
            secret_token_expires_at: { _gt: $now }
          }
        ]
      }
      _set: {
        password: $password_hash,
        secret_token: $new_secret_token
      }
    ) {
      affected_rows
    }
  }
  `;

  try {
    const new_secret_token = uuidv4();
    hasura_data = await graphql_client.request(query, {
      secret_token,
      password_hash,
      new_secret_token,
      now: new Date(),
    });
  } catch (e) {
    console.error(e);
    return next(Boom.unauthorized(`Unable to update 'password'`));
  }

  if (hasura_data.update_users.affected_rows === 0) {
    console.error('No user to update password for. Also maybe the secret token has expired');
    return next(Boom.badRequest(`Unable to update password for user`));
  }

  // return 200 OK
  res.send('OK');
});

router.post('/login', async (req, res, next) => {

  // validate username and password
  const schema = Joi.object().keys({
    username: Joi.string().required(),
    password: Joi.string().required(),
    totp_token: Joi.string().allow('')
  });

  const { error, value } = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const { username, password, totp_token } = value;

  let query = `
  query login_user(
    $username: String!
  ) {
    ${schema_name}users (
      where: {
        _or: [
          { username: { _eq: $username} },
          { mobile: { _eq: $username } }
        ]
      }
    ) {
      id
      password
      active
      default_role
      roles: users_x_roles {
        role
      },
      login_2fa: users_2fas {
        enable_totp,
        totp_code,
        enable_sms
      }
      ${USER_FIELDS.join('\n')}
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {
      username
    });
  } catch (e) {
    // TODO: trace log
    console.error(e);
    return next(myBoom.wrapError(500, 50000, `graphql <${e.message}>`));
  }

  if (hasura_data[`${schema_name}users`].length === 0) {
    // console.error("No user with this 'username'");
    return next(myBoom.wrapError(401, 40101, "Invalid 'username' or 'password'"));
  }

  // check if we got any user back
  const user = hasura_data[`${schema_name}users`][0];

  if (!user.active) {
    // console.error('User not activated');
    return next(myBoom.wrapError(401, 40102, "User not activated."));
  }

  // see if password hashes matches
  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    // TODO: audit log
    console.error('Password does not match');
    return next(myBoom.wrapError(401, 40103, "Password does not match."));
  }

  const login_2fa = user.login_2fa[0];
  if (login_2fa.enable_totp === true) {
    // 已启用TOTP两段式验证
    if (!!totp_token !== true || totp_token == '') {
      console.error('No 2FA token is provided')
      return next(myBoom.wrapError(401, 40104, "No 2FA token is provided."));
    } else {
      const totpVerified = speakeasy.totp.verify({
        secret: login_2fa.totp_code,
        encoding: 'base32',
        token: totp_token
      });
      if (totpVerified !== true) {
        console.error('Wrong 2FA token is provided')
        return next(myBoom.wrapError(401, 40104, "Wrong 2FA token is provided."));
      }
    }
  }

  const jwt_token = auth_tools.generateJwtToken(user);

  // generate refetch token and put in database
  query = `
  mutation (
    $refetch_token_data: ${schema_name}refetch_tokens_insert_input!
  ) {
    insert_${schema_name}refetch_tokens (
      objects: [$refetch_token_data]
    ) {
      affected_rows
    }
  }
  `;

  const refetch_token = uuidv4();
  try {
    await graphql_client.request(query, {
      refetch_token_data: {
        user_id: user.id,
        refetch_token: refetch_token,
        expires_at: new Date(new Date().getTime() + (REFETCH_TOKEN_EXPIRES * 60 * 1000)), // convert from minutes to milli seconds
      },
    });
  } catch (e) {
    console.error(e);
    return next(myBoom.wrapError(500, 50000, "Could not update 'refetch token' for user"));
  }

  res.cookie('jwt_token', jwt_token, {
    maxAge: JWT_TOKEN_EXPIRES * 60 * 1000, // convert from minute to milliseconds
    httpOnly: true,
  });

  // return jwt token and refetch token to client
  res.json({
    jwt_token,
    refetch_token,
    user_id: user.id,
  });
});

router.post('/refetch-token', async (req, res, next) => {

  // validate username and password
  const schema = Joi.object().keys({
    user_id: Joi.required(),
    refetch_token: Joi.string().required(),
  });

  const { error, value } = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const { refetch_token, user_id } = value;

  let query = `
  query get_refetch_token(
    $refetch_token: uuid!,
    $user_id: Int!,
    $current_timestampz: timestamptz!,
  ) {
    ${schema_name}refetch_tokens (
      where: {
        _and: [{
          refetch_token: { _eq: $refetch_token }
        }, {
          user_id: { _eq: $user_id }
        }, {
          user: { active: { _eq: true }}
        }, {
          expires_at: { _gte: $current_timestampz }
        }]
      }
    ) {
      user {
        id
        active
        default_role
        roles: users_x_roles {
          role
        },
        login_2fa: users_2fas {
          enable_totp,
          totp_code,
          enable_sms
        }
        ${USER_FIELDS.join('\n')}
      }
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {
      refetch_token,
      user_id,
      current_timestampz: new Date(),
    });
  } catch (e) {
    console.error(e);
    // console.error('Error connection to GraphQL');
    return next(Boom.unauthorized("Invalid 'refetch_token' or 'user_id'"));
  }

  if (hasura_data[`${schema_name}refetch_tokens`].length === 0) {
    // console.error('Incorrect user id or refetch token');
    return next(Boom.unauthorized("Invalid 'refetch_token' or 'user_id'"));
  }

  const user = hasura_data[`${schema_name}refetch_tokens`][0].user;

  // delete current refetch token and generate a new, and insert the
  // new refetch_token in the database
  // two mutations as transaction
  query = `
  mutation (
    $old_refetch_token: uuid!,
    $new_refetch_token_data: refetch_tokens_insert_input!
    $user_id: Int!
  ) {
    delete_${schema_name}refetch_tokens (
      where: {
        _and: [{
          refetch_token: { _eq: $old_refetch_token }
        }, {
          user_id: { _eq: $user_id }
        }]
      }
    ) {
      affected_rows
    }
    insert_${schema_name}refetch_tokens (
      objects: [$new_refetch_token_data]
    ) {
      affected_rows
    }
  }
  `;

  const new_refetch_token = uuidv4();
  try {
    await graphql_client.request(query, {
      old_refetch_token: refetch_token,
      new_refetch_token_data: {
        user_id: user_id,
        refetch_token: new_refetch_token,
        expires_at: new Date(new Date().getTime() + (REFETCH_TOKEN_EXPIRES * 60 * 1000)), // convert from minutes to milli seconds
      },
      user_id,
    });
  } catch (e) {
    console.error(e);
    // console.error('unable to create new refetch token and delete old');
    return next(Boom.unauthorized("Invalid 'refetch_token' or 'user_id'"));
  }

  // generate new jwt token
  const jwt_token = auth_tools.generateJwtToken(user);

  res.cookie('jwt_token', jwt_token, {
    maxAge: JWT_TOKEN_EXPIRES * 60 * 1000,
    httpOnly: true,
  });

  res.json({
    jwt_token,
    refetch_token: new_refetch_token,
    user_id,
  });
});

router.get('/user_info', verify_tool.jwt_verify, async (req, res, next) => {
  const { user } = req;
  let query = `
  query (
    $id: Int!
  ) {
    profile: ${schema_name}user_profiles_by_pk(user_id: $id) {
      avatar_img_path
      full_name
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {
      id: user.id,
    });
  } catch (e) {
    console.error(e);
    return next(Boom.unauthorized("Unable to get 'user'"));
  }

  // return user as json response
  res.json({
    user: req.user,
    profile: hasura_data.profile
  });
});

/**
 * 登录用户自行启动TOTP验证
 */
router.post('/enable-2fa-totp', verify_tool.jwt_verify, async (req, res, next) => {

  // get user_id from jwt claim
  const { user } = req;
  const user_id = user.id;

  if (user.login_2fa.length > 0 && (user.login_2fa)[0].enable_totp === true) {
    // 已经启动过TOTP验证
    res.send({
      totp_url: `otpauth://totp/${SYSTEM_NAME}:${user.username}?secret=${user.login_2fa.totp_code}`
    });
  } else {
    // 生成验证码
    const totp = speakeasy.generateSecret({ lenght: 20 });
    const totp_code = totp.base32;

    const query = `
    mutation upsert_2fa(
      $id: Int!
      $totp_code: String!
      $now: timestamptz!
    ) {
      insert_${schema_name}users_2fa (
        objects: [
          {
            user_id: $id,
            enable_totp: true,
            enable_sms: false,
            totp_code: $totp_code
          }
        ],
        on_conflict: {
          constraint: users_2fa_pkey,
          update_columns: [ enable_totp, totp_code, enable_sms ]
        }
      ) {
        returning {
          user_id
          enable_totp
          totp_code
          enable_sms
        }
      }
    }
    `;

    try {
      hasura_data = await graphql_client.request(query, {
        id: user_id,
        totp_code,
        now: new Date(),
      });
    } catch (e) {
      console.error(e);
      return next(Boom.unauthorized('Unable to enable TOTP for user.'));
    }

    res.send({
      totp_url: `otpauth://totp/${SYSTEM_NAME}:${user.username}?secret=${totp_code}`
    });
  }
});

module.exports = router;
