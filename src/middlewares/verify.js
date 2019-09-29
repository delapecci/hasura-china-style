const jwt = require('jsonwebtoken');
const { graphql_client } = require('../graphql-client');
const myBoom = require('../boom');

const {
  USER_FIELDS,
  USER_MANAGEMENT_DATABASE_SCHEMA_NAME,
  HASURA_GRAPHQL_JWT_SECRET,
} = require('../config');

const schema_name = USER_MANAGEMENT_DATABASE_SCHEMA_NAME === 'public' ? '' :  USER_MANAGEMENT_DATABASE_SCHEMA_NAME.toString().toLowerCase() + '_';

module.exports = {

  /**
   * 验证登录token中间件函数
   * @param {Request} req 请求对象
   * @param {Response} _res 响应对象
   * @param {Function} next 下一个中间件
   */
  jwt_verify: async (req, _res, next) => {
    // get jwt token
    if (!req.headers.authorization) {
      return next(myBoom.wrapError(400, 40001, 'no authorization header'));
    }

    const auth_split = req.headers.authorization.split(' ');

    if (auth_split[0] !== 'Bearer' || !auth_split[1]) {
      return next(myBoom.wrapError(400, 40001, 'malformed authorization header'));
    }

    // get jwt token
    const token = auth_split[1];

    // verify jwt token is OK
    let claims;
    try {
      jwt.exp
      claims = jwt.verify(
        token,
        HASURA_GRAPHQL_JWT_SECRET.key,
        {
          algorithms: HASURA_GRAPHQL_JWT_SECRET.type,
        }
      );
    } catch (e) {
      console.error(e);
      return next(myBoom.wrapError(401, 401405, 'Incorrect JWT Token'));
    }

    // get user_id from jwt claim
    const user_id = claims['https://hasura.io/jwt/claims']['x-hasura-user-id'];

    // get user from hasura (include ${USER_FIELDS.join('\n')})
    let query = `
    query (
      $id: Int!
    ) {
      user: ${schema_name}users_by_pk(id: $id) {
        id
        username
        active
        default_role
        roles: users_x_roles {
          role
        },
        login_2fa: users_2fas {
          enable_totp
          enable_sms
        }
        ${USER_FIELDS.join('\n')}
      }
    }
    `;

    let hasura_data;
    try {
      hasura_data = await graphql_client.request(query, {
        id: user_id,
      });
    } catch (e) {
      console.error(e);
      return next(Boom.unauthorized("Unable to get 'user'"));
    }

    req.user = Object.assign({}, hasura_data.user);
    next();
  }
};
